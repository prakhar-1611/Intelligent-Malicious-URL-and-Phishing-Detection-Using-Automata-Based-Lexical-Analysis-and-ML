import { useEffect, useRef, useState } from "react";
import cytoscape, { type Core } from "cytoscape";
import dagre from "cytoscape-dagre";
import type { Graph as G } from "../api";

cytoscape.use(dagre);

type Props = {
  graph: G;
  height?: number;
  highlight?: string[]; // node ids to fill (current / focused states)
  visited?: string[]; // node ids already visited
  danger?: boolean; // current state is an anomaly state
  follow?: boolean; // keep the highlighted state centred at a readable zoom (Live Trace)
};

// Above this many edges, labels are only drawn for the edges of the current / hovered state:
// drawing every character-class label on a dense mode DFA just stacks them on top of each other.
const DENSE_EDGES = 28;

/** Automaton graph: double green ring = accepting, red = anomaly state, indigo = start. */
export default function Graph({ graph, height = 460, highlight = [], visited = [], danger = false, follow = false }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const dense = graph.edges.length > DENSE_EDGES;
  const [allLabels, setAllLabels] = useState(!dense);
  // Without `follow`, the box takes the automaton's own shape: a long thin NFA gets a short wide box
  // instead of being shrunk into the middle of a tall empty one.
  const [boxH, setBoxH] = useState(height);

  useEffect(() => { setAllLabels(graph.edges.length <= DENSE_EDGES); }, [graph]);

  useEffect(() => {
    if (!ref.current) return;
    const n = graph.nodes.length;
    const elements = [
      ...graph.nodes.map((v) => ({
        data: { id: v.id, label: v.accept && v.tag ? `${v.label}\n${v.tag}` : v.label },
        classes: [v.accept ? "accept" : "", v.start ? "start" : "", v.anomaly ? "anomaly" : "", v.dead ? "dead" : ""].join(" "),
      })),
      ...graph.edges.map((e, i) => ({
        data: { id: `e${i}`, source: e.source, target: e.target, label: e.label.length > 16 ? e.label.slice(0, 15) + "…" : e.label, full: e.label },
        classes: [e.eps ? "eps" : "", e.source === e.target ? "loop" : "", graph.edges.length > DENSE_EDGES ? "thin" : ""].join(" "),
      })),
    ];
    cy.current?.destroy();
    const c = cytoscape({
      container: ref.current,
      elements,
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.25,
      layout: {
        name: "dagre", rankDir: "LR", ranker: "network-simplex",
        nodeSep: n > 20 ? 34 : 40, rankSep: n > 20 ? 120 : 68, edgeSep: 18, padding: 24, fit: false,
      } as any,
      style: [
        { selector: "node", style: {
            "background-color": "#ffffff", "border-width": 2, "border-color": "#64748b", width: 38, height: 38,
            label: "data(label)", "text-wrap": "wrap", "text-valign": "center", "text-halign": "center",
            "font-size": 12, "font-weight": 600, color: "#1e293b", "font-family": "system-ui, \"Segoe UI\", Roboto, sans-serif",
            "transition-property": "background-color, border-color", "transition-duration": 150 } },
        // accepting states: double ring, label (state + token) below the circle so it never squeezes inside
        { selector: "node.accept", style: { "border-style": "double", "border-width": 7, "border-color": "#16a34a",
            "text-valign": "bottom", "text-margin-y": 5, "font-size": 11, "line-height": 1.25,
            "text-background-color": "#ffffff", "text-background-opacity": 0.9, "text-background-padding": "2px",
            "text-background-shape": "roundrectangle" } },
        { selector: "node.start", style: { "border-color": "#4f46e5", "border-width": 4, "background-color": "#eef2ff" } },
        { selector: "node.accept.start", style: { "border-style": "double", "border-width": 7 } },
        { selector: "node.anomaly", style: { "border-color": "#dc2626", color: "#b91c1c" } },
        { selector: "node.dead", style: { "border-style": "dashed", opacity: 0.45 } },
        { selector: "node.visited", style: { "background-color": "#e0e7ff" } },
        { selector: "node.hl", style: { "background-color": "#fde047", "border-color": "#a16207" } },
        { selector: "node.hl-danger", style: { "background-color": "#fca5a5", "border-color": "#7f1d1d" } },
        { selector: "edge", style: {
            "curve-style": "bezier", "control-point-step-size": 46, width: 1.4, "line-color": "#94a3b8",
            "target-arrow-shape": "triangle", "target-arrow-color": "#94a3b8", "arrow-scale": 0.9,
            label: "", "font-size": 12, "font-family": "JetBrains Mono, Consolas, monospace", color: "#334155",
            "text-rotation": "autorotate", "text-margin-y": -9,
            "text-background-color": "#ffffff", "text-background-opacity": 1, "text-background-padding": "2px",
            "text-background-shape": "roundrectangle", "min-zoomed-font-size": 4 } },
        { selector: "edge.thin", style: { width: 1.1, opacity: 0.6 } },
        { selector: "edge.lbl", style: { label: "data(label)" } },
        { selector: "edge.loop", style: { "loop-direction": "-90deg", "loop-sweep": "-50deg", "control-point-step-size": 52,
            "text-rotation": "none", "text-margin-y": -4 } },
        { selector: "edge.eps", style: { "line-style": "dashed", "line-color": "#a78bfa", "target-arrow-color": "#a78bfa", color: "#6d28d9" } },
        { selector: "edge.focus", style: { "line-color": "#4f46e5", "target-arrow-color": "#4f46e5", width: 2.2, opacity: 1, color: "#3730a3", "z-index": 10 } },
        { selector: "edge.faded", style: { opacity: 0.25 } },
      ],
    });
    // hover a state: show and emphasise its outgoing edges, fade the rest
    c.on("mouseover", "node", (ev) => {
      const out = ev.target.outgoers("edge");
      c.edges().not(out).addClass("faded");
      out.addClass("focus lbl");
    });
    c.on("mouseout", "node", () => {
      c.edges().removeClass("faded");
      c.edges().removeClass("focus");
      c.emit("relabel");
    });
    c.on("mouseover", "edge", (ev) => { ev.target.addClass("lbl focus"); ref.current!.title = ev.target.data("full"); });
    c.on("mouseout", "edge", (ev) => { ev.target.removeClass("focus"); c.emit("relabel"); });
    cy.current = c;
    const bb = c.elements().boundingBox();
    const w = ref.current.clientWidth;
    if (follow) {
      setBoxH(height);
      c.resize();
      const z = (Math.min(w / (bb.w + 60), height / (bb.h + 60)));
      if (z >= 0.75) c.fit(undefined, 30); else c.zoom(0.95);
    } else {
      const z = Math.min(1.25, (w - 48) / bb.w);
      const maxH = n > 20 ? Math.max(height, 820) : height;
      const h = Math.max(240, Math.min(maxH, bb.h * z + 70));
      setBoxH(h);
      requestAnimationFrame(() => {
        if (c.destroyed()) return; // the graph was replaced before this frame
        c.resize(); c.fit(undefined, 28);
        if (c.zoom() > 1.25) { c.zoom(1.25); c.center(); }
      });
    }
    return () => { c.destroy(); cy.current = null; };
  }, [graph]);

  // Live Trace: glide to the current state so it stays readable on big machines
  useEffect(() => {
    const c = cy.current;
    if (!c || !follow || !highlight.length) return;
    const v = c.getElementById(highlight[0]);
    if (v.empty()) return;
    c.stop();
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    c.animate({ center: { eles: v }, zoom: Math.max(c.zoom(), 0.9) } as any, { duration: reduce ? 0 : 220 });
  }, [highlight, follow, graph]);

  // labels: all of them on small graphs, only the current state's edges on dense ones
  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    const relabel = () => {
      c.edges().removeClass("lbl");
      if (allLabels) c.edges().addClass("lbl");
      else highlight.forEach((id) => c.getElementById(id).outgoers("edge").addClass("lbl"));
    };
    relabel();
    c.off("relabel");
    c.on("relabel", relabel);
  }, [allLabels, highlight, graph]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.batch(() => {
      c.nodes().removeClass("hl hl-danger visited");
      c.edges().removeClass("focus");
      visited.forEach((id) => c.getElementById(id).addClass("visited"));
      highlight.forEach((id) => {
        const v = c.getElementById(id);
        v.addClass(danger ? "hl-danger" : "hl");
        if (dense) v.outgoers("edge").addClass("focus");
      });
    });
  }, [highlight, visited, danger, graph, dense]);

  const zoom = (f: number) => {
    const c = cy.current;
    if (c) c.zoom({ level: c.zoom() * f, renderedPosition: { x: c.width() / 2, y: c.height() / 2 } });
  };

  return (
    <div className="relative">
      <div ref={ref} style={{ height: boxH }} role="img" aria-label={`Automaton graph: ${graph.nodes.length} states, ${graph.edges.length} transitions`} className="w-full rounded-lg border border-slate-200 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:18px_18px] bg-white" />
      <div className="absolute top-2 right-2 flex gap-1 bg-white/95 rounded-lg border border-slate-200 p-1 shadow-sm text-xs text-slate-700">
        <button className="min-w-8 min-h-8 px-2 rounded hover:bg-slate-100 font-semibold" title="Zoom in" aria-label="Zoom in" onClick={() => zoom(1.25)}>+</button>
        <button className="min-w-8 min-h-8 px-2 rounded hover:bg-slate-100 font-semibold" title="Zoom out" aria-label="Zoom out" onClick={() => zoom(0.8)}>−</button>
        <button className="min-h-8 px-2 rounded hover:bg-slate-100" title="Fit to view" onClick={() => cy.current?.fit(undefined, 24)}>Fit</button>
        <label className="flex items-center gap-1 min-h-8 px-2 rounded hover:bg-slate-100 cursor-pointer select-none">
          <input type="checkbox" className="accent-indigo-600" checked={allLabels} onChange={(e) => setAllLabels(e.target.checked)} /> all labels
        </label>
      </div>
      {dense && !allLabels && (
        <div className="absolute bottom-2 left-2 right-2 sm:right-auto text-xs text-slate-600 bg-white/95 rounded px-2 py-0.5 border border-slate-200 tabular-nums">
          {graph.nodes.length} states · {graph.edges.length} edges · hover a state to see its transitions
        </div>
      )}
    </div>
  );
}
