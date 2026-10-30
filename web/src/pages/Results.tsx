import { useEffect, useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import { Card, ErrorBox, PageHeader, Stat, StatStrip } from "../components/common";

function Table({ head, rows }: { head: string[]; rows: (string | number | null | undefined)[][] }) {
  return (
    <div className="overflow-auto -mx-1 px-1">
      <table className="w-full min-w-[520px] text-[13px]">
        <thead className="text-slate-500 border-b border-slate-200"><tr>{head.map((h, j) => <th key={h} className={`px-3 py-2 font-normal ${j ? "text-right" : "text-left"}`}>{h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-t border-slate-100 hover:bg-slate-50">
          {r.map((c, j) => <td key={j} className={`px-3 py-1.5 tabular-nums ${j ? "text-right text-slate-800" : "text-left font-mono font-medium text-slate-900"}`}>{c ?? <span className="text-slate-400">—</span>}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

function Missing({ what, cmd }: { what: string; cmd: string }) {
  return <div className="text-sm text-slate-600">No {what} yet. Run <code className="font-mono text-xs bg-slate-100 px-1.5 py-0.5 rounded">{cmd}</code> to produce it.</div>;
}

export default function Results() {
  const [res, setRes] = useState<{ files: Record<string, any>; figures: string[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.results().then(setRes).catch((e) => setError(e.message)); }, []);
  const header = <PageHeader title="Experiment results"
    subtitle="Every number on this page is read from artifacts/results/*.json, produced by the experiment scripts. Nothing is typed in by hand." />;
  if (error) return <div className="space-y-5">{header}<ErrorBox error={`Could not load results: ${error}`} /></div>;
  if (!res) return (
    <div className="space-y-5" aria-busy="true">
      {header}
      <StatStrip cols="grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }, (_, k) => <div key={k} className="bg-white px-4 py-3"><div className="text-[13px] text-slate-400">Loading…</div><div className="h-7 w-20 mt-1 rounded bg-slate-100" /></div>)}
      </StatStrip>
      <div className="h-64 rounded-xl border border-slate-200 bg-white" />
    </div>
  );
  const f = res.files;
  const mc = f.model_comparison;
  const mcd = f.model_comparison_domain_only;
  const roc = mc?.best?.curves_test?.roc?.map(([x, y]: number[]) => ({ fpr: x, tpr: y }));

  const modelRows = (m: any) => Object.entries(m.models).map(([name, r]: [string, any]) => [
    name, `${r.cv_grouped_5fold.mean_pr_auc} ± ${r.cv_grouped_5fold.std_pr_auc}`, r.test.precision, r.test.recall,
    r.test.f1, r.test.fpr, r.test.roc_auc, r.test.pr_auc]);

  const best = mc?.models?.[mc?.best?.model]?.test;
  const mal = mc?.best?.test_at_malicious_threshold;
  return (
    <div className="space-y-5">
      {header}
      {best && (
        <StatStrip cols="grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
          <Stat label="Test PR-AUC" value={best.pr_auc.toFixed(3)} hint={mc.best.model} tone="indigo" />
          <Stat label="Recall" value={`${(best.recall * 100).toFixed(1)}%`} hint="phishing caught" tone="emerald" />
          <Stat label="False alarms" value={`${(best.fpr * 100).toFixed(2)}%`} hint="at threshold 0.5" tone="amber" />
          {mal && <Stat label="Malicious tier precision" value={`${(mal.precision * 100).toFixed(1)}%`} hint={`FPR ${(mal.fpr * 100).toFixed(2)}%`} tone="rose" />}
          {f.latency && <Stat label="Per URL" value={`${f.latency.total.mean_ms.toFixed(2)} ms`} hint="lex + features + model" tone="violet" />}
          {f.automata_stats && <Stat label="Min-DFA states" value={f.automata_stats.modes.reduce((a: number, m: any) => a + m.min, 0)} hint={`${f.automata_stats.modes.length} lexer modes`} tone="slate" />}
        </StatStrip>
      )}
      <Card title="Model comparison (time-based test split, threshold 0.5)">
        {mc ? <Table head={["model", "CV PR-AUC (grouped 5-fold)", "precision", "recall", "F1", "FPR", "ROC-AUC", "PR-AUC"]} rows={modelRows(mc)} />
          : <Missing what="model results" cmd="python -m ml.train" />}
        {mcd && <>
          <div className="text-sm font-semibold mt-4 mb-1">Domain-only control (path and query removed: no path shortcut possible)</div>
          <Table head={["model", "CV PR-AUC (grouped 5-fold)", "precision", "recall", "F1", "FPR", "ROC-AUC", "PR-AUC"]} rows={modelRows(mcd)} />
        </>}
      </Card>
      {mc && (
        <div className="grid lg:grid-cols-2 gap-4 items-start">
          <Card title={`ROC curve: ${mc.best.model} (calibrated)`}>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={roc} margin={{ top: 8, right: 16, bottom: 20, left: 4 }}><CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="fpr" type="number" domain={[0, 1]} tickFormatter={(v) => v.toFixed(1)} tick={{ fontSize: 12 }}
                  label={{ value: "false positive rate", position: "bottom", offset: 2, fontSize: 12, fill: "#475569" }} />
                <YAxis domain={[0, 1]} tick={{ fontSize: 12 }} label={{ value: "true positive rate", angle: -90, position: "insideLeft", fontSize: 12, fill: "#475569", style: { textAnchor: "middle" } }} />
                <Tooltip formatter={(v: number) => v.toFixed(4)} labelFormatter={(v: number) => `FPR ${Number(v).toFixed(4)}`} />
                <Line type="linear" dataKey="tpr" stroke="#4f46e5" strokeWidth={2} dot={false} name="TPR" isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </Card>
          <Card title="Policy on the test split (calibrated thresholds)">
            <div className="text-xs text-slate-500 mb-2">Thresholds: suspicious ≥ {mc.best.thresholds.suspicious.toFixed(3)}, malicious ≥ {mc.best.thresholds.malicious.toFixed(3)} ({mc.best.thresholds.source})</div>
            <Table head={["true class", "Safe", "Suspicious", "Malicious"]}
              rows={Object.entries(mc.best.test_policy).map(([k, v]: [string, any]) => [k, v.Safe, v.Suspicious, v.Malicious])} />
            <div className="text-xs mt-3">Binary at the malicious threshold: P {mc.best.test_at_malicious_threshold.precision} · R {mc.best.test_at_malicious_threshold.recall} · FPR {mc.best.test_at_malicious_threshold.fpr}</div>
            {(() => { const c = mc.best.test_at_malicious_threshold.confusion; return (
              <div className="grid grid-cols-2 gap-1 mt-3 text-center text-xs max-w-xs tabular-nums rounded-lg overflow-hidden">
                <div className="bg-emerald-100 text-emerald-900 p-2">TN {c.tn}</div><div className="bg-rose-100 text-rose-900 p-2">FP {c.fp}</div>
                <div className="bg-amber-100 text-amber-900 p-2">FN {c.fn}</div><div className="bg-emerald-200 text-emerald-950 p-2">TP {c.tp}</div>
              </div>); })()}
          </Card>
        </div>
      )}
      <Card title="Ablation: do automata features help?">
        {f.ablation ? <Table head={["config", "#features", "CV PR-AUC", "test PR-AUC", "test F1", "test FPR"]}
          rows={f.ablation.rows.map((r: any) => [r.config, r.n_features, `${r.cv_pr_auc_mean} ± ${r.cv_pr_auc_std}`, r.test.pr_auc, r.test.f1, r.test.fpr])} />
          : <Missing what="ablation" cmd="python -m ml.ablation" />}
        {f.ablation_domain_only && <>
          <div className="text-sm font-semibold mt-4 mb-1">Ablation, domain-only</div>
          <Table head={["config", "#features", "CV PR-AUC", "test PR-AUC", "test F1", "test FPR"]}
            rows={f.ablation_domain_only.rows.map((r: any) => [r.config, r.n_features, `${r.cv_pr_auc_mean} ± ${r.cv_pr_auc_std}`, r.test.pr_auc, r.test.f1, r.test.fpr])} />
        </>}
      </Card>
      <Card title="Adversarial mutations (flag recall vs model evasion)">
        {f.adversarial ? <Table head={["operator", "expected flag", "applied", "flag recall", "evasion rate", "Δscore"]}
          rows={f.adversarial.rows.map((r: any) => [r.operator, r.expected_flag, r.applied, r.flag_recall, r.evasion_rate, r.mean_score_delta])} />
          : <Missing what="adversarial results" cmd="python -m adversarial.evaluate" />}
      </Card>
      <div className="grid lg:grid-cols-2 gap-4">
        <Card title="Latency per URL">
          {f.latency ? <Table head={["stage", "mean ms", "p50 ms", "p95 ms"]}
            rows={["lexing", "features", "inference", "total"].map((k) => [k, f.latency[k].mean_ms, f.latency[k].p50_ms, f.latency[k].p95_ms])} />
            : <Missing what="latency results" cmd="python -m bench.latency" />}
          {f.latency && <div className="text-xs mt-2">Scanner time vs length, linear fit R² = {f.latency.linear_fit_r2}</div>}
        </Card>
        <Card title="Automata statistics per lexer mode">
          {f.automata_stats ? <Table head={["mode", "NFA", "DFA", "min", "Moore", "H=M", "k", "conflicts"]}
            rows={f.automata_stats.modes.map((m: any) => [m.mode, m.nfa, m.dfa, m.min, m.moore, m.hopcroft_eq_moore ? "yes" : "NO", `${m.k_before}→${m.k_after}`, m.conflicts_resolved])} />
            : <Missing what="automata stats" cmd="python -m lexer.build_automata" />}
        </Card>
      </div>
      {res.figures.length > 0 && (
        <Card title="Figures">
          <div className="grid md:grid-cols-2 gap-4">
            {res.figures.map((name) => (
              <figure key={name} className="min-w-0"><img src={`/api/results/figures/${name}`} alt={`Figure ${name.replace(/\.png$/, "").replace(/_/g, " ")}`} className="w-full h-auto rounded-lg outline outline-1 -outline-offset-1 outline-black/10" />
                <figcaption className="text-xs text-slate-500 mt-1">{name}</figcaption></figure>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
