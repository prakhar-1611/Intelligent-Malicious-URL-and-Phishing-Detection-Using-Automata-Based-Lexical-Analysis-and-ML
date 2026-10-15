import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, type Explanation } from "../api";
import { Card, ErrorBox, HighlightedUrl, UrlInput } from "../components/common";
import { useAnalysis } from "../state";

const GROUP_COLOR: Record<string, string> = {
  lexical: "#6366f1", domain: "#0ea5e9", encoding: "#f59e0b", automata: "#ef4444", path_query: "#10b981", symtab: "#8b5cf6",
};

export default function Explain() {
  const { analysis: a, setAnalysis, setFocusStates } = useAnalysis();
  const [sel, setSel] = useState<Explanation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nav = useNavigate();

  async function run(u: string) {
    setBusy(true); setError(null); setSel(null);
    try { setAnalysis(await api.analyze(u)); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  const data = (a?.explanation ?? []).map((e) => ({ ...e, c: e.contribution ?? 0 }));

  return (
    <div className="space-y-4">
      <Card title="Explain a verdict">
        <UrlInput onSubmit={run} busy={busy} initial={a?.input ?? ""} />
      </Card>
      <ErrorBox error={error} />
      {a && (
        <div className="grid lg:grid-cols-5 gap-4">
          <div className="lg:col-span-3">
            <Card title={`SHAP contributions (log-odds) · ${a.model}`}>
              {data.some((d) => d.contribution != null) ? (
                <ResponsiveContainer width="100%" height={Math.max(220, data.length * 34)}>
                  <BarChart data={data} layout="vertical" margin={{ left: 150, right: 20 }}>
                    <XAxis type="number" />
                    <YAxis type="category" dataKey="feature" width={150} tick={{ fontSize: 11 }} />
                    <Tooltip formatter={(v: number) => v.toFixed(4)} />
                    <Bar dataKey="c" onClick={(d: any) => { setSel(d); setFocusStates(d.states); }} cursor="pointer">
                      {data.map((d) => <Cell key={d.feature} fill={d.c > 0 ? "#e11d48" : "#059669"}
                        opacity={sel && sel.feature !== d.feature ? 0.35 : 1} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-sm text-slate-500">No trained model loaded: showing the flags that drive the heuristic score.</div>
              )}
              <div className="flex flex-wrap gap-3 text-xs mt-2">
                {Object.entries(GROUP_COLOR).map(([g, c]) => <span key={g} className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded" style={{ background: c }} />{g}</span>)}
              </div>
              <div className="text-xs text-slate-500 mt-2">Red pushes towards malicious, green towards benign. Click a bar.</div>
            </Card>
          </div>
          <div className="lg:col-span-2 space-y-4">
            <Card title="Feature → evidence">
              <div className="space-y-1 max-h-72 overflow-auto">
                {a.explanation.map((e) => (
                  <button key={e.feature} onClick={() => { setSel(e); setFocusStates(e.states); }}
                    className={`w-full text-left text-sm rounded px-2 py-1 border ${sel?.feature === e.feature ? "bg-yellow-50 border-yellow-400" : "border-transparent hover:bg-slate-50"}`}>
                    <span className="inline-block w-2 h-2 rounded-full mr-2" style={{ background: GROUP_COLOR[e.group] }} />
                    <span className="font-mono">{e.feature}</span> = {e.value}
                    <div className="text-xs text-slate-500 ml-4">{e.description}</div>
                  </button>
                ))}
              </div>
            </Card>
            {sel && (
              <Card title={`Evidence for ${sel.feature}`}>
                <HighlightedUrl text={a.input} spans={sel.spans} tone="focus" />
                <div className="text-sm mt-2 space-y-1">
                  {sel.flags.length > 0 && <div>Flags: <span className="font-mono text-rose-600">{sel.flags.join(", ")}</span></div>}
                  {sel.states.length > 0 && (
                    <div>
                      Min-DFA states: <span className="font-mono">{sel.states.map((s) => `g${s}`).join(", ")}</span>
                      <button className="ml-2 text-indigo-600 hover:underline" onClick={() => nav("/trace")}>show in Live Trace →</button>
                    </div>
                  )}
                  {!sel.spans.length && !sel.states.length && <div className="text-slate-500">This feature is a whole-input statistic.</div>}
                </div>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
