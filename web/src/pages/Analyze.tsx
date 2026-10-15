import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Card, ErrorBox, FlagList, HighlightedUrl, TokenChips, UrlInput, VerdictCard } from "../components/common";
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
    <div className="space-y-4">
      <Card title="Analyse a URL">
        <UrlInput onSubmit={run} busy={busy} initial={a?.input ?? ""} />
      </Card>
      <ErrorBox error={error} />
      {a && (
        <>
          <Card><VerdictCard a={a} /></Card>
          <div className="grid lg:grid-cols-2 gap-4">
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
          <div className="grid lg:grid-cols-2 gap-4">
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
              <div className="max-h-56 overflow-auto">
                <table className="w-full text-xs">
                  <thead className="text-slate-500"><tr><th className="text-left">lexeme</th><th>kind</th><th>freq</th><th>pos</th><th>flags</th></tr></thead>
                  <tbody>
                    {a.symtab.symbols.map((s: any, i: number) => (
                      <tr key={i} className="border-t">
                        <td className="font-mono break-all">{s.lexeme}</td><td className="text-center">{s.kind}</td>
                        <td className="text-center">{s.freq}</td><td className="text-center">{s.first}</td>
                        <td className="text-rose-600">{s.flags.join(", ")}</td>
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
