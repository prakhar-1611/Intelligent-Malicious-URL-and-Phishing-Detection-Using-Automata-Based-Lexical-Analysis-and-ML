import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, ErrorBox } from "../components/common";
import Graph from "../components/Graph";

const STAGES = [
  { key: "regex", label: "1 · Regex → syntax tree" },
  { key: "nfa", label: "2 · Thompson NFA" },
  { key: "dfa", label: "3 · Subset-construction DFA" },
  { key: "min", label: "4 · Hopcroft-minimal DFA" },
];

function Tree({ node }: { node: any }) {
  return (
    <li>
      <span className={`font-mono text-xs px-1 rounded ${node.op === "lit" ? "bg-sky-100" : "bg-violet-100"}`}>{node.label}</span>
      {node.children && <ul className="ml-4 border-l pl-2">{node.children.map((c: any, i: number) => <Tree key={i} node={c} />)}</ul>}
    </li>
  );
}

export default function AutomataLab() {
  const [list, setList] = useState<{ rules: string[]; examples: string[]; modes: string[] } | null>(null);
  const [name, setName] = useState("LABEL_A");
  const [custom, setCustom] = useState("");
  const [useCustom, setUseCustom] = useState(false);
  const [stage, setStage] = useState("nfa");
  const [view, setView] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { api.automataList().then(setList).catch((e) => setError(e.message)); }, []);

  useEffect(() => {
    setError(null);
    const st = stage === "regex" ? "min" : stage;
    const p = useCustom && custom ? api.custom(custom, st) : api.automaton(name, st);
    p.then(setView).catch((e) => { setError(e.message); setView(null); });
  }, [name, stage, useCustom, custom]);

  const s = view?.stats;
  return (
    <div className="space-y-4">
      <Card title="Automata Lab: step through the compiler pipeline">
        <div className="flex flex-wrap gap-3 items-end">
          <label className="text-sm">Rule / example / lexer mode
            <select className="block border rounded px-2 py-1 font-mono text-sm" value={name}
              onChange={(e) => { setName(e.target.value); setUseCustom(false); }}>
              {list && <>
                <optgroup label="Review 1 figures">{list.examples.map((r) => <option key={r}>{r}</option>)}</optgroup>
                <optgroup label="Token rules">{list.rules.map((r) => <option key={r}>{r}</option>)}</optgroup>
                <optgroup label="Combined lexer modes">{list.modes.map((r) => <option key={r}>{r}</option>)}</optgroup>
              </>}
            </select>
          </label>
          <form className="flex gap-2 items-end" onSubmit={(e) => { e.preventDefault(); setUseCustom(true); }}>
            <label className="text-sm">…or type a regex
              <input className="block border rounded px-2 py-1 font-mono text-sm w-64" value={custom} maxLength={120}
                placeholder="e.g. a(b|c)*d  or  {LABEL}" onChange={(e) => setCustom(e.target.value)} />
            </label>
            <button className="bg-indigo-600 text-white rounded px-3 py-1 text-sm">Build</button>
          </form>
        </div>
        <div className="flex flex-wrap gap-2 mt-4">
          {STAGES.map((t) => (
            <button key={t.key} onClick={() => setStage(t.key)}
              className={`px-3 py-1.5 rounded-lg text-sm border ${stage === t.key ? "bg-indigo-600 text-white border-indigo-600" : "bg-white hover:bg-slate-50"}`}>
              {t.label}
            </button>
          ))}
        </div>
      </Card>
      <ErrorBox error={error} />
      {view && (
        <div className="grid lg:grid-cols-4 gap-4">
          <div className="lg:col-span-3">
            <Card title={`${view.name} · ${STAGES.find((x) => x.key === stage)?.label}`}>
              {stage === "regex" ? (
                view.ast ? (
                  <div className="space-y-3">
                    <div className="text-sm">Pattern: <code className="font-mono bg-slate-100 px-1">{view.pattern}</code></div>
                    <div className="text-sm">Postfix (shunting-yard, explicit ·): <code className="font-mono bg-slate-100 px-1">{view.postfix}</code></div>
                    <ul className="text-sm max-h-[420px] overflow-auto"><Tree node={view.ast} /></ul>
                  </div>
                ) : (
                  <div className="text-sm space-y-1">
                    <div className="text-slate-500">A lexer mode combines these rules under one start state (ε-edges), each accept state tagged (token, priority):</div>
                    {view.rules.map((r: any) => (
                      <div key={r.name} className="font-mono text-xs"><b>{r.name}</b> (prio {r.priority}{r.flag ? `, ${r.flag}` : ""}): {r.pattern}</div>
                    ))}
                  </div>
                )
              ) : (
                <Graph graph={view.graph} height={520} />
              )}
              <div className="text-xs text-slate-500 mt-2">
                Double green circle = accepting · red = anomaly state · indigo border = start · dashed lilac edge = ε · the dead state is hidden.
              </div>
            </Card>
          </div>
          <Card title="State counts">
            {s && (
              <table className="w-full text-sm">
                <tbody>
                  <tr><td>Thompson NFA</td><td className="text-right font-mono">{s.nfa}</td></tr>
                  <tr><td>Subset DFA</td><td className="text-right font-mono">{s.dfa}</td></tr>
                  <tr><td>Hopcroft min</td><td className="text-right font-mono">{s.min}</td></tr>
                  <tr><td>Moore min</td><td className="text-right font-mono">{s.moore}</td></tr>
                  <tr><td>Hopcroft = Moore</td><td className="text-right">{s.hopcroft_eq_moore ? "✅" : "❌"}</td></tr>
                  <tr><td>alphabet k</td><td className="text-right font-mono">{s.k_before} → {s.k_after}</td></tr>
                  {s.conflicts_resolved != null && <tr><td>priority conflicts</td><td className="text-right font-mono">{s.conflicts_resolved}</td></tr>}
                </tbody>
              </table>
            )}
            <p className="text-xs text-slate-500 mt-3">DFA counts include the explicit dead state. Subset construction can blow up exponentially;
              compare the NFA and DFA columns to see whether it did for this rule.</p>
          </Card>
        </div>
      )}
    </div>
  );
}
