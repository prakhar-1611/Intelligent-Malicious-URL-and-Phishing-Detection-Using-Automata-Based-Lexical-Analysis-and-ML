import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Card, DemoGrid, ErrorBox, FlagList, HighlightedUrl, HowItWorks, PageHeader, TokenChips, UrlInput, VerdictCard } from "../components/common";
import { useAnalysis } from "../state";

export default function Analyze() {
  const { analysis: a, setAnalysis } = useAnalysis();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nav = useNavigate();

  async function run(url: string) {
    setBusy(true);
    setError(null);
    try {
      setAnalysis(await api.analyze(url));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader title="Analyse a link"
        subtitle="Paste any URL. The custom lexer reads it with minimal DFAs, raises security flags, and the model returns a calibrated verdict with reasons." />
      <Card>
        <UrlInput onSubmit={run} busy={busy} initial={a?.input ?? ""} />
      </Card>
      <ErrorBox error={error} />
      {!a && (
        <>
          <Card title="How it works"><HowItWorks /></Card>
          <Card title="Try an example" right={<span className="text-xs text-slate-500">one click analyses it · nothing is opened</span>}>
            <DemoGrid onPick={run} />
          </Card>
        </>
      )}
      {a && (
        <>
          <Card><VerdictCard a={a} /></Card>
          <div className="grid lg:grid-cols-2 gap-4 items-start">
            <Card title="Token stream" right={<span className="text-xs text-slate-500">hover a chip for type and position</span>}>
              <TokenChips tokens={a.tokens} />
              <div className="mt-3 text-xs text-slate-500">
                {a.lexemes.length} raw lexemes from the minimal DFAs · {a.scan_stats.backtracked} characters re-scanned by
                maximal munch · {a.scan_stats.errors} panic-mode errors
              </div>
            </Card>
            <Card title="Security flags (evidence, not verdicts)">
              <HighlightedUrl text={a.input} spans={a.flags} />
              <div className="mt-3"><FlagList flags={a.flags} /></div>
            </Card>
          </div>
          <div className="grid lg:grid-cols-2 gap-4 items-start">
            <Card title="Why? (top contributions)" right={
              <button className="text-sm text-indigo-600 hover:underline" onClick={() => nav("/explain")}>Open Explain →</button>}>
              <ul className="text-sm space-y-1">
                {a.explanation.slice(0, 5).map((e) => (
                  <li key={e.feature} className="flex justify-between gap-2">
                    <span className="font-mono">{e.feature}</span>
                    <span className={e.contribution != null && e.contribution > 0 ? "text-rose-600" : "text-emerald-600"}>
                      {e.contribution == null ? "flag" : (e.contribution > 0 ? "+" : "") + e.contribution.toFixed(3)}
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
            <Card title="Symbol table" right={<span className="text-xs text-slate-500">
              {a.symtab.size} symbols · {a.symtab.buckets} buckets · longest chain {a.symtab.max_chain}</span>}>
              <div className="max-h-64 overflow-auto">
                <table className="w-full text-[13px]">
                  <thead className="text-slate-500 bg-white sticky top-0 border-b border-slate-200"><tr><th className="text-left font-normal px-2 py-1.5">lexeme</th><th className="font-normal text-left px-2">kind</th><th className="font-normal text-right px-2">freq</th><th className="font-normal text-right px-2">pos</th><th className="font-normal text-left px-2">flags</th></tr></thead>
                  <tbody>
                    {a.symtab.symbols.map((s: any, i: number) => (
                      <tr key={i} className="border-t border-slate-100 align-top">
                        <td className="font-mono break-all px-2 py-1">{s.lexeme}</td><td className="px-2 py-1 text-slate-600">{s.kind}</td>
                        <td className="px-2 py-1 text-right tabular-nums">{s.freq}</td><td className="px-2 py-1 text-right tabular-nums">{s.first}</td>
                        <td className="px-2 py-1 text-rose-700 break-words">{s.flags.join(", ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <button className="mt-2 text-sm text-indigo-600 hover:underline" onClick={() => nav("/trace")}>
                Watch the scanner run over this URL in Live Trace →
              </button>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
