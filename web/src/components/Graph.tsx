import { useEffect, useRef } from "react";
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
};

/** Automaton graph: double circle = accepting, red border = anomaly state, arrow-in = start. */
export default function Graph({ graph, height = 420, highlight = [], visited = [], danger = false }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const elements = [
      ...graph.nodes.map((n) => ({
        data: { id: n.id, label: n.tag ? `${n.label}\n${n.tag}` : n.label },
        classes: [n.accept ? "accept" : "", n.start ? "start" : "", n.anomaly ? "anomaly" : "", n.dead ? "dead" : ""].join(" "),
      })),
      ...graph.edges.map((e, i) => ({
        data: { id: `e${i}`, source: e.source, target: e.target, label: e.label.length > 18 ? e.label.slice(0, 17) + "…" : e.label },
        classes: e.eps ? "eps" : "",
      })),
    ];
    cy.current?.destroy();
    cy.current = cytoscape({
      container: ref.current,
      elements,
      wheelSensitivity: 0.2,
      layout: { name: "dagre", rankDir: "LR", nodeSep: 25, rankSep: 60 } as any,
      style: [
        { selector: "node", style: { "background-color": "#fff", "border-width": 2, "border-color": "#64748b", label: "data(label)",
            "text-wrap": "wrap", "text-valign": "center", "font-size": 9, width: 42, height: 42 } },
        { selector: "node.accept", style: { "border-style": "double", "border-width": 6, "border-color": "#16a34a" } },
        { selector: "node.start", style: { "border-color": "#4f46e5", "border-width": 4 } },
        { selector: "node.anomaly", style: { "border-color": "#dc2626", color: "#b91c1c" } },
        { selector: "node.dead", style: { "border-style": "dashed", opacity: 0.5 } },
        { selector: "node.visited", style: { "background-color": "#e0e7ff" } },
        { selector: "node.hl", style: { "background-color": "#facc15", "border-color": "#a16207" } },
        { selector: "node.hl-danger", style: { "background-color": "#f87171", "border-color": "#7f1d1d" } },
        { selector: "edge", style: { "curve-style": "bezier", "target-arrow-shape": "triangle", width: 1.2, "line-color": "#94a3b8",
            "target-arrow-color": "#94a3b8", label: "data(label)", "font-size": 8, "text-background-color": "#fff",
            "text-background-opacity": 0.85, "text-background-padding": "1px" } },
        { selector: "edge.eps", style: { "line-style": "dashed", "line-color": "#c4b5fd", "target-arrow-color": "#c4b5fd" } },
      ],
    });
    return () => { cy.current?.destroy(); cy.current = null; };
  }, [graph]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.nodes().removeClass("hl hl-danger visited");
    visited.forEach((id) => c.getElementById(id).addClass("visited"));
    highlight.forEach((id) => c.getElementById(id).addClass(danger ? "hl-danger" : "hl"));
  }, [highlight, visited, danger, graph]);

  return <div ref={ref} style={{ height }} className="w-full border rounded-lg bg-slate-50" />;
}
