import { useState } from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import { Card, ErrorBox, SafeText } from "../components/common";

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

  return (
    <div className="space-y-4">
      <Card title="Batch analysis">
        <div className="flex flex-wrap gap-3 items-center mb-2">
          <input type="file" accept=".csv,.txt" className="text-sm" onChange={async (e) => {
            const f = e.target.files?.[0]; if (f) setText(await f.text()); }} />
          <span className="text-xs text-slate-500">CSV with a <code>url</code> column, or one URL per line (max 5000). Nothing is fetched.</span>
        </div>
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={6} spellCheck={false}
          className="w-full font-mono text-xs border rounded-lg p-2" placeholder={"https://example.com\nhttp://3232235777/login"} />
        <div className="flex gap-2 mt-2">
          <button onClick={run} disabled={busy} className="bg-indigo-600 text-white rounded-lg px-4 py-2 text-sm disabled:opacity-50">
            {busy ? `Analysing… ${rows.length}` : "Analyse all"}
          </button>
          {rows.length > 0 && <button onClick={exportCsv} className="border rounded-lg px-4 py-2 text-sm">Export CSV (defanged)</button>}
        </div>
      </Card>
      <ErrorBox error={error} />
      {rows.length > 0 && (
        <>
          <div className="grid md:grid-cols-2 gap-4">
            <Card title="Verdicts">
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={summary}><XAxis dataKey="v" /><YAxis allowDecimals={false} /><Tooltip />
                  <Bar dataKey="n">{summary.map((s) => <Cell key={s.v} fill={s.v === "Safe" ? "#059669" : s.v === "Suspicious" ? "#f59e0b" : "#e11d48"} />)}</Bar>
                </BarChart>
              </ResponsiveContainer>
            </Card>
            <Card title="Flags raised">
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={flagData} layout="vertical" margin={{ left: 140 }}>
                  <XAxis type="number" allowDecimals={false} /><YAxis type="category" dataKey="f" width={140} tick={{ fontSize: 10 }} /><Tooltip />
                  <Bar dataKey="n" fill="#6366f1" />
                </BarChart>
              </ResponsiveContainer>
            </Card>
          </div>
          <Card title={`Results (${rows.length})`}>
            <div className="max-h-[480px] overflow-auto">
              <table className="w-full text-xs">
                <thead className="text-slate-500 sticky top-0 bg-white"><tr><th className="text-left">URL (defanged)</th><th>verdict</th><th>score</th><th className="text-left">flags</th></tr></thead>
                <tbody>
                  {rows.map((r, k) => (
                    <tr key={k} className="border-t align-top">
                      <td className="py-1 pr-2"><SafeText text={r.url_defanged} /></td>
                      <td className={`text-center font-semibold ${r.verdict === "Malicious" ? "text-rose-600" : r.verdict === "Suspicious" ? "text-amber-600" : "text-emerald-700"}`}>{r.verdict ?? r.error}</td>
                      <td className="text-center font-mono">{r.score?.toFixed(3)}</td>
                      <td className="font-mono text-[10px]">{(r.flags ?? []).join(" ")}</td>
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
