import { useEffect, useMemo, useState } from "react";
import { api, type Graph as G } from "../api";
import { Card, ErrorBox, UrlInput, visible } from "../components/common";
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

  return (
    <div className="space-y-4">
      <Card title="Live Trace: the scanner walking the minimal DFA, one character at a time">
        <UrlInput onSubmit={run} busy={busy} initial={a?.input ?? ""} />
      </Card>
      <ErrorBox error={error} />
      {a && step && modes && (
        <>
          <Card>
            <div className="flex flex-wrap gap-0.5 font-mono text-sm">
              {a.steps.map((s, k) => (
                <button key={k} onClick={() => { setI(k); setPlaying(false); }} title={`char ${k}: mode ${s.mode}, state M${s.state}${s.accept ? `, accepts ${s.accept}` : ""}`}
                  className={`px-1 rounded border ${k === i ? (s.anomaly ? "bg-rose-500 text-white" : "bg-yellow-300") :
                    k < i ? (s.anomaly ? "bg-rose-100 border-rose-300" : "bg-indigo-50") : "bg-white"} ${s.state < 0 ? "border-rose-500" : ""}`}>
                  {visible(s.ch) === " " ? "␠" : visible(s.ch)}
                </button>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-3 mt-3">
              <button className="px-3 py-1 rounded border" onClick={() => setI(Math.max(0, i - 1))}>◀ step</button>
              <button className="px-3 py-1 rounded bg-indigo-600 text-white" onClick={() => {
                if (i >= a.steps.length - 1) setI(0); setPlaying(!playing); }}>{playing ? "Pause" : "Play"}</button>
              <button className="px-3 py-1 rounded border" onClick={() => setI(Math.min(a.steps.length - 1, i + 1))}>step ▶</button>
              <label className="text-sm flex items-center gap-2">speed
                <input type="range" min={60} max={900} step={20} value={960 - speed} onChange={(e) => setSpeed(960 - Number(e.target.value))} />
              </label>
              <span className="text-sm text-slate-600">
                char {i}/{a.steps.length - 1} · mode <b>{step.mode}</b> · state <b className="font-mono">{step.state >= 0 ? `M${step.state}` : "dead (ERROR)"}</b>
                {" "}· global g{step.g}
                {step.accept && <> · accepting <b className={step.anomaly ? "text-rose-600" : "text-emerald-700"}>{step.accept}</b></>}
              </span>
            </div>
          </Card>
          <Card title={`${step.mode} mode: minimal DFA (${modes[step.mode].n_states} states)`}
            right={<span className="text-xs text-slate-500">yellow = current · red = anomaly state · lilac = visited in this mode</span>}>
            <Graph graph={modes[step.mode].graph} height={520}
              highlight={[...(step.state >= 0 ? [`s${step.state}`] : []), ...focusInMode]}
              visited={visited} danger={step.anomaly} />
          </Card>
        </>
      )}
    </div>
  );
}
