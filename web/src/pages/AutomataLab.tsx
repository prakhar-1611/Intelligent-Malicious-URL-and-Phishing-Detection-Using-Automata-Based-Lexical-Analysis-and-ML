import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, ErrorBox, PageHeader, Stat, StatStrip } from "../components/common";
import Graph from "../components/Graph";

const STAGES = [
  { key: "regex", label: "1 · Regex → syntax tree" },
  { key: "nfa", label: "2 · Thompson NFA" },
  { key: "dfa", label: "3 · Subset-construction DFA" },
  { key: "min", label: "4 · Hopcroft-minimal DFA" },
];

const STAGE_NOTE: Record<string, string> = {
  regex: "The rule as written, parsed like a tiny programming language.",
  nfa: "One fragment per operator, glued with ε-edges. Easy to build; several moves may be possible.",
  dfa: "Each state is a set of NFA states, so there is exactly one move per character.",
  min: "Equivalent states merged (Hopcroft, checked by Moore): the table the scanner actually runs.",
};

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
    <div className="space-y-5">
      <PageHeader title="Automata Lab"
        subtitle={`How the scanner is built, offline and once: pick any of the ${list ? `${list.rules.length} ` : ""}token rules, a lexer mode, or type your own regex, then step through the four stages.`} />
      <Card>
        <div className="flex flex-wrap gap-4 items-end">
          <label className="text-sm text-slate-700 font-medium min-w-0">Rule / example / lexer mode
            <select className="block mt-1 max-w-full border border-slate-300 rounded-lg px-2 py-1.5 font-mono text-sm font-normal bg-white focus:outline-none focus:ring-2 focus:ring-indigo-400" value={name}
              onChange={(e) => { setName(e.target.value); setUseCustom(false); }}>
              {list && <>
                <optgroup label="Review 1 figures">{list.examples.map((r) => <option key={r}>{r}</option>)}</optgroup>
                <optgroup label="Token rules">{list.rules.map((r) => <option key={r}>{r}</option>)}</optgroup>
                <optgroup label="Combined lexer modes">{list.modes.map((r) => <option key={r}>{r}</option>)}</optgroup>
              </>}
            </select>
          </label>
          <form className="flex gap-2 items-end min-w-0" onSubmit={(e) => { e.preventDefault(); setUseCustom(true); }}>
            <label className="text-sm text-slate-700 font-medium min-w-0">…or type a regex
              <input className="block mt-1 border border-slate-300 rounded-lg px-2 py-1.5 font-mono text-sm font-normal w-full sm:w-64 focus:outline-none focus:ring-2 focus:ring-indigo-400" value={custom} maxLength={120} spellCheck={false}
                placeholder="e.g. a(b|c)*d  or  {LABEL}" onChange={(e) => setCustom(e.target.value)} />
            </label>
            <button disabled={!custom.trim()} className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg px-4 py-1.5 text-sm font-medium shrink-0 active:scale-[0.96] motion-reduce:active:scale-100 transition-[transform,background-color] duration-150">Build</button>
          </form>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-5">
          {STAGES.map((t, k) => (
            <button key={t.key} onClick={() => setStage(t.key)} aria-pressed={stage === t.key}
              className={`relative text-left px-3 py-2 rounded-lg text-sm border transition-colors ${stage === t.key ? "bg-indigo-600 text-white border-indigo-600" : "bg-white border-slate-200 hover:border-indigo-300 hover:bg-indigo-50/40"}`}>
              <div className={`text-xs font-medium tabular-nums ${stage === t.key ? "text-indigo-100" : "text-slate-500"}`}>Stage {k + 1}</div>
              <div className="font-medium">{t.label.replace(/^\d · /, "")}</div>
            </button>
          ))}
        </div>
      </Card>
      <ErrorBox error={error} />
      {view && s && (
        <StatStrip cols="grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
          <Stat label="Thompson NFA" value={s.nfa} hint="states" />
          <Stat label="Subset DFA" value={s.dfa} hint="incl. dead state" />
          <Stat label="Hopcroft min" value={s.min} hint="states" />
          <Stat label="Moore min" value={s.moore} hint={s.hopcroft_eq_moore ? "agrees with Hopcroft" : "DISAGREES with Hopcroft"} tone={s.hopcroft_eq_moore ? "emerald" : "rose"} />
          <Stat label="Alphabet k" value={`${s.k_before}→${s.k_after}`} hint="symbol classes" />
          <Stat label="Conflicts" value={s.conflicts_resolved ?? 0} hint="resolved by priority" tone="slate" />
        </StatStrip>
      )}
      {view && (
        <div>
          <div>
            <Card title={`${view.name} · ${STAGES.find((x) => x.key === stage)?.label}`}
              right={<span className="hidden sm:block text-xs text-slate-500 max-w-md text-right">{STAGE_NOTE[stage]}</span>}>
              <p className="sm:hidden -mt-2 mb-3 text-xs text-slate-500">{STAGE_NOTE[stage]}</p>
              {stage === "regex" ? (
                view.ast ? (
                  <div className="grid md:grid-cols-2 gap-5">
                    <div className="space-y-3">
                      <div>
                        <div className="text-xs font-semibold text-slate-600">Pattern</div>
                        <code className="block mt-1 font-mono text-sm bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 break-all">{view.pattern}</code>
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-slate-600">Postfix (shunting-yard, explicit ·)</div>
                        <code className="block mt-1 font-mono text-sm bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 break-all">{view.postfix}</code>
                      </div>
                      <p className="text-sm text-slate-600 leading-relaxed">The parser tokenises the pattern, inserts the invisible concatenation
                        operator as <b>·</b>, converts infix to postfix by operator precedence (* &gt; · &gt; |), then builds the syntax tree on the right.
                        Thompson's construction turns each tree node into one NFA fragment.</p>
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-600 mb-2">Syntax tree</div>
                      <ul className="text-sm max-h-[460px] overflow-auto bg-slate-50 border border-slate-200 rounded-lg p-3"><Tree node={view.ast} /></ul>
                    </div>
                  </div>
                ) : (
                  <div className="text-sm space-y-1">
                    <div className="text-slate-500">A lexer mode combines these rules under one start state (ε-edges), each accept state tagged (token, priority):</div>
                    {view.rules.map((r: any) => (
                      <div key={r.name} className="font-mono text-xs break-all"><b>{r.name}</b> (prio {r.priority}{r.flag ? `, ${r.flag}` : ""}): {r.pattern}</div>
                    ))}
                  </div>
                )
              ) : (
                <Graph graph={view.graph} height={560} />
              )}
              {stage !== "regex" && <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500 mt-3">
                <span><span className="inline-block w-3 h-3 rounded-full border-[3px] border-double border-emerald-600 align-middle mr-1" />accepting (label below)</span>
                <span><span className="inline-block w-3 h-3 rounded-full border-2 border-indigo-600 bg-indigo-50 align-middle mr-1" />start</span>
                <span><span className="inline-block w-3 h-3 rounded-full border-2 border-rose-600 align-middle mr-1" />anomaly state</span>
                <span><span className="inline-block w-5 border-t-2 border-dashed border-violet-400 align-middle mr-1" />ε-edge</span>
                <span>dead state hidden · drag to pan, scroll to zoom</span>
              </div>}
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
