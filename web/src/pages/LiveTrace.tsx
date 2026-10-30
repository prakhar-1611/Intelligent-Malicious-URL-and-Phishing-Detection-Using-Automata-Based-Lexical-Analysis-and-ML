import { useEffect, useMemo, useRef, useState } from "react";
import { api, type Graph as G } from "../api";
import { Card, DemoGrid, ErrorBox, PageHeader, Stat, StatStrip, UrlInput, visible } from "../components/common";
import Graph from "../components/Graph";
import { useAnalysis } from "../state";

type Modes = Record<string, { graph: G; offset: number; n_states: number }>;

export default function LiveTrace() {
  const { analysis: a, setAnalysis, focusStates } = useAnalysis();
  const [modes, setModes] = useState<Modes | null>(null);
  const [i, setI] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(350);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { api.scannerStates().then((r) => setModes(r.modes)).catch((e) => setError(e.message)); }, []);
  useEffect(() => { setI(0); setPlaying(false); }, [a]);
  useEffect(() => {
    if (!playing || !a) return;
    if (i >= a.steps.length - 1) { setPlaying(false); return; }
    const t = setTimeout(() => setI((x) => x + 1), speed);
    return () => clearTimeout(t);
  }, [playing, i, a, speed]);

  // keep the current character inside its scrolling strip; instant, it runs on every step during Play
  const strip = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const s = strip.current;
    const el = s?.querySelector<HTMLElement>('[aria-current="step"]');
    if (!s || !el) return;
    if (el.offsetTop < s.scrollTop) s.scrollTop = el.offsetTop;
    else if (el.offsetTop + el.offsetHeight > s.scrollTop + s.clientHeight) s.scrollTop = el.offsetTop + el.offsetHeight - s.clientHeight;
  }, [i, a]);

  async function run(u: string) {
    setBusy(true); setError(null);
    try { setAnalysis(await api.analyze(u)); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  const step = a?.steps[i];
  const visited = useMemo(() => {
    if (!a || !step) return [];
    return a.steps.slice(0, i).filter((s) => s.mode === step.mode && s.state >= 0).map((s) => `s${s.state}`);
  }, [a, i, step]);
  const focusInMode = useMemo(() => {
    if (!modes || !step) return [];
    const m = modes[step.mode];
    return focusStates.filter((g) => g >= m.offset && g < m.offset + m.n_states).map((g) => `s${g - m.offset}`);
  }, [focusStates, modes, step]);

  const total = modes ? Object.values(modes).reduce((n, m) => n + m.n_states, 0) : null;
  return (
    <div className="space-y-5">
      <PageHeader title="Live Trace"
        subtitle={`Watch the scanner walk the minimal DFA one character at a time. The same ${total ? `${total}-state ` : ""}machine reads every URL; only the path changes.`} />
      <Card>
        <UrlInput onSubmit={run} busy={busy} initial={a?.input ?? ""} />
      </Card>
      <ErrorBox error={error} />
      {!a && (
        <>
          <Card title="Pick a link to trace" right={<span className="text-xs text-slate-500">then press Play, or step through it</span>}>
            <DemoGrid onPick={run} />
          </Card>
          {modes && (
            <StatStrip cols="grid-cols-2 md:grid-cols-5 [&>*:last-child:nth-child(odd)]:col-span-2 md:[&>*:last-child:nth-child(odd)]:col-span-1">
              {Object.entries(modes).map(([m, v]) => (
                <Stat key={m} label={`${m} mode`} value={v.n_states} hint="minimal-DFA states" />
              ))}
            </StatStrip>
          )}
        </>
      )}
      {a && step && modes && (
        <>
          <Card>
            <div ref={strip} className="relative flex flex-wrap gap-1 font-mono text-sm max-h-48 overflow-y-auto" role="group" aria-label="Characters of the URL: pick one to jump to it">
              {a.steps.map((s, k) => (
                <button key={k} onClick={() => { setI(k); setPlaying(false); }} title={`char ${k}: mode ${s.mode}, state M${s.state}${s.accept ? `, accepts ${s.accept}` : ""}`}
                  aria-current={k === i ? "step" : undefined} aria-label={`character ${k}: ${visible(s.ch)}`}
                  className={`min-w-[1.6rem] px-1 py-0.5 rounded-md border border-slate-200 transition-colors duration-150 ${k === i ? (s.anomaly ? "bg-rose-600 text-white border-rose-600" : "bg-yellow-300 border-yellow-500") :
                    k < i ? (s.anomaly ? "bg-rose-100 border-rose-300" : "bg-indigo-50") : "bg-white"} ${s.state < 0 ? "border-rose-500" : ""}`}>
                  {visible(s.ch) === " " ? "␠" : visible(s.ch)}
                </button>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-3 mt-4">
              <div className="flex rounded-lg border border-slate-200 overflow-hidden">
                <button className="px-3 py-1.5 text-sm hover:bg-slate-50 disabled:opacity-40 flex items-center gap-1.5" disabled={i === 0}
                  aria-label="Step back" onClick={() => { setPlaying(false); setI(Math.max(0, i - 1)); }}><Icon d="M10 3 5 8l5 5" />step</button>
                <button className="px-4 py-1.5 text-sm bg-indigo-600 hover:bg-indigo-700 text-white font-medium flex items-center gap-1.5 min-w-[5.5rem] justify-center transition-colors" onClick={() => {
                  if (i >= a.steps.length - 1) setI(0); setPlaying(!playing); }}>
                  {playing ? <><Icon d="M5 3v10M11 3v10" />Pause</> : <><Icon d="M5 3v10l8-5z" fill />Play</>}</button>
                <button className="px-3 py-1.5 text-sm hover:bg-slate-50 disabled:opacity-40 flex items-center gap-1.5" disabled={i >= a.steps.length - 1}
                  aria-label="Step forward" onClick={() => { setPlaying(false); setI(Math.min(a.steps.length - 1, i + 1)); }}>step<Icon d="m6 3 5 5-5 5" /></button>
              </div>
              <label className="text-sm text-slate-600 flex items-center gap-2">speed
                <input type="range" className="accent-indigo-600" min={60} max={900} step={20} value={960 - speed} onChange={(e) => setSpeed(960 - Number(e.target.value))} />
              </label>
              <div className="flex flex-wrap gap-2 sm:ml-auto text-xs tabular-nums">
                <span className="px-2 py-1 rounded-md bg-slate-100">char <b className="font-mono">{i}/{a.steps.length - 1}</b></span>
                <span className="px-2 py-1 rounded-md bg-indigo-50 text-indigo-800">mode <b>{step.mode}</b></span>
                <span className="px-2 py-1 rounded-md bg-slate-100">state <b className="font-mono">{step.state >= 0 ? `M${step.state}` : "dead (ERROR)"}</b> · g{step.g}</span>
                {step.accept && <span className={`px-2 py-1 rounded-md ${step.anomaly ? "bg-rose-100 text-rose-800" : "bg-emerald-100 text-emerald-800"}`}>
                  accepting <b>{step.accept}</b></span>}
              </div>
            </div>
          </Card>
          <Card title={`${step.mode} mode: minimal DFA (${modes[step.mode].n_states} states)`}
            right={<span className="text-xs text-slate-500 text-right">yellow = current · red = anomaly · lilac = visited · hover a state for its transitions</span>}>
            <Graph graph={modes[step.mode].graph} height={560} follow
              highlight={[...(step.state >= 0 ? [`s${step.state}`] : []), ...focusInMode]}
              visited={visited} danger={step.anomaly} />
          </Card>
        </>
      )}
    </div>
  );
}

/** 16px stroke icon for the transport controls. */
function Icon({ d, fill = false }: { d: string; fill?: boolean }) {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true" fill={fill ? "currentColor" : "none"}
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
  );
}
