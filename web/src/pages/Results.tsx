import { useEffect, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import { Card, ErrorBox } from "../components/common";

function Table({ head, rows }: { head: string[]; rows: (string | number | null | undefined)[][] }) {
  return (
    <div className="overflow-auto">
      <table className="w-full text-xs">
        <thead className="text-slate-500"><tr>{head.map((h) => <th key={h} className="text-left px-1 py-1">{h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-t">{r.map((c, j) => <td key={j} className="px-1 py-1 font-mono">{c ?? "—"}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

function Missing({ what, cmd }: { what: string; cmd: string }) {
  return <div className="text-sm text-slate-500">No {what} yet. Run <code className="bg-slate-100 px-1">{cmd}</code></div>;
}

export default function Results() {
  const [res, setRes] = useState<{ files: Record<string, any>; figures: string[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.results().then(setRes).catch((e) => setError(e.message)); }, []);
  if (error) return <ErrorBox error={error} />;
  if (!res) return <div className="text-sm text-slate-500">Loading…</div>;
  const f = res.files;
  const mc = f.model_comparison;
  const mcd = f.model_comparison_domain_only;
  const roc = mc?.best?.curves_test?.roc?.map(([x, y]: number[]) => ({ fpr: x, tpr: y }));

  const modelRows = (m: any) => Object.entries(m.models).map(([name, r]: [string, any]) => [
    name, `${r.cv_grouped_5fold.mean_pr_auc} ± ${r.cv_grouped_5fold.std_pr_auc}`, r.test.precision, r.test.recall,
    r.test.f1, r.test.fpr, r.test.roc_auc, r.test.pr_auc]);

  return (
    <div className="space-y-4">
      <div className="text-sm text-slate-600">Every number on this page is read from <code>artifacts/results/*.json</code>, produced by the experiment scripts. Nothing is typed in by hand.</div>
      <Card title="Model comparison (time-based test split, threshold 0.5)">
        {mc ? <Table head={["model", "CV PR-AUC (grouped 5-fold)", "precision", "recall", "F1", "FPR", "ROC-AUC", "PR-AUC"]} rows={modelRows(mc)} />
          : <Missing what="model results" cmd="python -m ml.train" />}
        {mcd && <>
          <div className="text-sm font-semibold mt-4 mb-1">Domain-only control (path and query removed: no path shortcut possible)</div>
          <Table head={["model", "CV PR-AUC (grouped 5-fold)", "precision", "recall", "F1", "FPR", "ROC-AUC", "PR-AUC"]} rows={modelRows(mcd)} />
        </>}
      </Card>
      {mc && (
        <div className="grid lg:grid-cols-2 gap-4">
          <Card title={`ROC curve: ${mc.best.model} (calibrated)`}>
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={roc}><CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="fpr" type="number" domain={[0, 1]} tickFormatter={(v) => v.toFixed(1)} label={{ value: "FPR", position: "insideBottom", offset: -2 }} />
                <YAxis domain={[0, 1]} /><Tooltip /><Legend />
                <Line type="monotone" dataKey="tpr" stroke="#4f46e5" dot={false} name="TPR" />
              </LineChart>
            </ResponsiveContainer>
          </Card>
          <Card title="Policy on the test split (calibrated thresholds)">
            <div className="text-xs text-slate-500 mb-2">Thresholds: suspicious ≥ {mc.best.thresholds.suspicious.toFixed(3)}, malicious ≥ {mc.best.thresholds.malicious.toFixed(3)} ({mc.best.thresholds.source})</div>
            <Table head={["true class", "Safe", "Suspicious", "Malicious"]}
              rows={Object.entries(mc.best.test_policy).map(([k, v]: [string, any]) => [k, v.Safe, v.Suspicious, v.Malicious])} />
            <div className="text-xs mt-3">Binary at the malicious threshold: P {mc.best.test_at_malicious_threshold.precision} · R {mc.best.test_at_malicious_threshold.recall} · FPR {mc.best.test_at_malicious_threshold.fpr}</div>
            {(() => { const c = mc.best.test_at_malicious_threshold.confusion; return (
              <div className="grid grid-cols-2 gap-1 mt-3 text-center text-xs max-w-xs">
                <div className="bg-emerald-100 p-2">TN {c.tn}</div><div className="bg-rose-100 p-2">FP {c.fp}</div>
                <div className="bg-amber-100 p-2">FN {c.fn}</div><div className="bg-emerald-200 p-2">TP {c.tp}</div>
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
      <div className="grid lg:grid-cols-2 gap-4">
        <Card title="Adversarial mutations (flag recall vs model evasion)">
          {f.adversarial ? <Table head={["operator", "expected flag", "applied", "flag recall", "evasion rate", "Δscore"]}
            rows={f.adversarial.rows.map((r: any) => [r.operator, r.expected_flag, r.applied, r.flag_recall, r.evasion_rate, r.mean_score_delta])} />
            : <Missing what="adversarial results" cmd="python -m adversarial.evaluate" />}
        </Card>
        <Card title="Latency per URL">
          {f.latency ? <Table head={["stage", "mean ms", "p50 ms", "p95 ms"]}
            rows={["lexing", "features", "inference", "total"].map((k) => [k, f.latency[k].mean_ms, f.latency[k].p50_ms, f.latency[k].p95_ms])} />
            : <Missing what="latency results" cmd="python -m bench.latency" />}
          {f.latency && <div className="text-xs mt-2">Scanner time vs length, linear fit R² = {f.latency.linear_fit_r2}</div>}
        </Card>
      </div>
      <Card title="Automata statistics per lexer mode">
        {f.automata_stats ? <Table head={["mode", "NFA", "DFA", "min", "Moore", "H=M", "k", "conflicts"]}
          rows={f.automata_stats.modes.map((m: any) => [m.mode, m.nfa, m.dfa, m.min, m.moore, m.hopcroft_eq_moore ? "yes" : "NO", `${m.k_before}→${m.k_after}`, m.conflicts_resolved])} />
          : <Missing what="automata stats" cmd="python -m lexer.build_automata" />}
      </Card>
      {res.figures.length > 0 && (
        <Card title="Figures">
          <div className="grid md:grid-cols-2 gap-4">
            {res.figures.map((name) => (
              <figure key={name}><img src={`/api/results/figures/${name}`} alt={name} className="border rounded" />
                <figcaption className="text-xs text-slate-500 mt-1">{name}</figcaption></figure>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
