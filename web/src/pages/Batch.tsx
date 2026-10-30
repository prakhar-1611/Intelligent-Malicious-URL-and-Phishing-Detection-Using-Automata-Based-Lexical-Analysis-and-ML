import { useState } from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import { Card, ErrorBox, PageHeader, SafeText, Stat, StatStrip } from "../components/common";
import { BATCH_DEMO } from "../demos";

type Row = { url_defanged: string; verdict?: string; score?: number; registered_domain?: string; flags?: string[]; error?: string };

function parseUrls(text: string): string[] {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return [];
  const header = lines[0].toLowerCase().split(",");
  const col = header.indexOf("url");
  const body = col >= 0 ? lines.slice(1) : lines;
  return body.map((l) => (col >= 0 ? l.split(",")[col] : l.split(",")[0]).replace(/^"|"$/g, "")).filter(Boolean);
}

export default function Batch() {
  const [text, setText] = useState("");
  const [rows, setRows] = useState<Row[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    const urls = parseUrls(text).slice(0, 5000);
    if (!urls.length) return;
    setBusy(true); setError(null); setRows([]);
    try {
      const out: Row[] = [];
      for (let k = 0; k < urls.length; k += 500) {
        const r = await api.batch(urls.slice(k, k + 500));
        out.push(...r.results);
        setRows([...out]);
      }
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  function exportCsv() {
    const lines = ["url_defanged,verdict,score,registered_domain,flags"];
    rows.forEach((r) => lines.push([r.url_defanged, r.verdict ?? "", r.score ?? "", r.registered_domain ?? "",
      (r.flags ?? []).join(" ")].map((x) => `"${String(x).replace(/"/g, '""')}"`).join(",")));
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "batch_results_defanged.csv";
    a.click();
  }

  const summary = ["Safe", "Suspicious", "Malicious"].map((v) => ({ v, n: rows.filter((r) => r.verdict === v).length }));
  const flagCounts: Record<string, number> = {};
  rows.forEach((r) => (r.flags ?? []).forEach((f) => (flagCounts[f] = (flagCounts[f] ?? 0) + 1)));
  const flagData = Object.entries(flagCounts).map(([f, n]) => ({ f, n })).sort((a, b) => b.n - a.n);

  const nUrls = parseUrls(text).length;
  const count = (v: string) => rows.filter((r) => r.verdict === v).length;
  return (
    <div className="space-y-5">
      <PageHeader title="Batch analysis"
        subtitle="Check many links at once: paste them, upload a CSV, or load the demo set. Every link is lexed, scored and explained; none is ever opened." />
      <div className="grid lg:grid-cols-3 gap-5">
        <Card className="lg:col-span-2" title="Links to analyse" right={<span className="text-xs text-slate-500 tabular-nums">{nUrls} link{nUrls === 1 ? "" : "s"} ready</span>}>
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={14} spellCheck={false} aria-label="URLs to analyse, one per line"
            className="w-full font-mono text-xs leading-5 border border-slate-200 rounded-lg p-3 bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-indigo-400"
            placeholder={"One URL per line, or a CSV with a url column\n\nhttps://www.wikipedia.org/\nhttp://3232235777/login"} />
          <div className="flex flex-wrap items-center gap-2 mt-3">
            <button onClick={run} disabled={busy || !nUrls} className="bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg px-5 py-2 text-sm font-medium disabled:opacity-50 tabular-nums active:scale-[0.96] motion-reduce:active:scale-100 transition-[transform,background-color] duration-150">
              {busy ? `Analysing… ${rows.length}` : `Analyse ${nUrls || "all"}`}
            </button>
            <button onClick={() => setText(BATCH_DEMO.join("\n"))} className="border border-indigo-200 text-indigo-700 hover:bg-indigo-50 rounded-lg px-4 py-2 text-sm">
              Load demo set ({BATCH_DEMO.length})
            </button>
            <label className="border border-slate-200 hover:bg-slate-50 rounded-lg px-4 py-2 text-sm cursor-pointer focus-within:ring-2 focus-within:ring-indigo-400">
              Upload CSV / TXT
              <input type="file" accept=".csv,.txt" className="sr-only" onChange={async (e) => {
                const f = e.target.files?.[0]; e.target.value = ""; if (f) setText(await f.text()); }} />
            </label>
            {text && <button onClick={() => { setText(""); setRows([]); }} className="text-sm text-slate-500 hover:text-slate-800 px-2">Clear</button>}
            {rows.length > 0 && <button onClick={exportCsv} className="sm:ml-auto border border-slate-200 hover:bg-slate-50 rounded-lg px-4 py-2 text-sm">Export CSV (defanged)</button>}
          </div>
        </Card>
        <div className="space-y-5">
          <StatStrip cols="grid-cols-3">
            <Stat label="Safe" value={count("Safe")} tone="emerald" />
            <Stat label="Suspicious" value={count("Suspicious")} tone="amber" />
            <Stat label="Malicious" value={count("Malicious")} tone="rose" />
          </StatStrip>
          <Card title="How batch mode works">
            <ol className="text-sm text-slate-600 space-y-2 list-decimal ml-4">
              <li>Links are sent to the API in chunks of 500 (up to 5,000).</li>
              <li>Each one runs through the same minimal DFAs, flag checks and gradient-boosted model as the Analyze page.</li>
              <li>You get a verdict, a score and the flags raised, plus summary charts.</li>
              <li>Export saves the results with every URL defanged (<code className="text-xs bg-slate-100 px-1 rounded">hxxp://evil[.]example</code>).</li>
            </ol>
            <div className="mt-4 text-xs text-slate-500 border-t border-slate-100 pt-3">
              The demo set mixes 4 real sites with 11 attack tricks: hidden IPs, the @ trick, punycode, look-alike letters, deep subdomains,
              odd ports, open redirects and double encoding.
            </div>
          </Card>
        </div>
      </div>
      <ErrorBox error={error} />
      {rows.length > 0 && (
        <>
          <div className="grid md:grid-cols-2 gap-4 items-start">
            <Card title="Verdicts">
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={summary}><XAxis dataKey="v" /><YAxis allowDecimals={false} /><Tooltip />
                  <Bar dataKey="n" isAnimationActive={false}>{summary.map((s) => <Cell key={s.v} fill={s.v === "Safe" ? "#059669" : s.v === "Suspicious" ? "#f59e0b" : "#e11d48"} />)}</Bar>
                </BarChart>
              </ResponsiveContainer>
            </Card>
            <Card title="Flags raised">
              <ResponsiveContainer width="100%" height={Math.max(200, flagData.length * 26)}>
                <BarChart data={flagData} layout="vertical" margin={{ left: 8, right: 16 }}>
                  <XAxis type="number" allowDecimals={false} /><YAxis type="category" dataKey="f" width={170} tick={{ fontSize: 11, fontFamily: "JetBrains Mono, Consolas, monospace" }} /><Tooltip />
                  <Bar dataKey="n" fill="#6366f1" isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </Card>
          </div>
          <Card title={`Results (${rows.length})`}>
            <div className="max-h-[480px] overflow-auto">
              <table className="w-full min-w-[640px] text-[13px]">
                <thead className="text-slate-500 sticky top-0 bg-white border-b border-slate-200"><tr><th className="text-left font-normal px-2 py-2">URL (defanged)</th><th className="font-normal px-2">verdict</th><th className="font-normal px-2 text-right">score</th><th className="font-normal text-left px-2">flags</th></tr></thead>
                <tbody>
                  {rows.map((r, k) => (
                    <tr key={k} className="border-t border-slate-100 align-top hover:bg-slate-50">
                      <td className="py-1.5 px-2 max-w-[28rem]"><SafeText text={r.url_defanged} /></td>
                      <td className={`px-2 py-1.5 text-center font-semibold whitespace-nowrap ${r.error ? "text-slate-600" : r.verdict === "Malicious" ? "text-rose-700" : r.verdict === "Suspicious" ? "text-amber-700" : "text-emerald-700"}`}>{r.verdict ?? r.error}</td>
                      <td className="px-2 py-1.5 text-right font-mono tabular-nums">{r.score?.toFixed(3)}</td>
                      <td className="px-2 py-1.5 font-mono text-[11px] text-slate-700 break-words">{(r.flags ?? []).join(" ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
