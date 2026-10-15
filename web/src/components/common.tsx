import { useState, type ReactNode } from "react";
import { TOKEN_COLORS, VERDICT_STYLE, type Analysis, type Flag, type Span, type Token } from "../api";

export function Card({ title, children, right }: { title?: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section className="bg-white rounded-xl border border-slate-200 shadow-sm p-4">
      {(title || right) && (
        <div className="flex items-center justify-between mb-3">
          {title && <h2 className="font-semibold text-slate-700">{title}</h2>}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="rounded-lg border border-rose-300 bg-rose-50 text-rose-800 px-3 py-2 text-sm">{error}</div>;
}

/** URL shown as plain text only: never a link, never fetched. */
export function SafeText({ text, className = "" }: { text: string; className?: string }) {
  return <span className={`font-mono break-all select-all ${className}`}>{text}</span>;
}

export function VerdictCard({ a }: { a: Analysis }) {
  const pct = Math.round(a.score * 100);
  const t = a.thresholds;
  return (
    <div className="flex flex-col md:flex-row gap-4 items-stretch">
      <div className={`${VERDICT_STYLE[a.verdict]} text-white rounded-xl px-6 py-4 min-w-[180px] flex flex-col justify-center`}>
        <div className="text-sm opacity-90">Verdict</div>
        <div className="text-3xl font-bold">{a.verdict}</div>
        <div className="text-sm opacity-90">score {a.score.toFixed(3)}</div>
      </div>
      <div className="flex-1">
        <div className="text-xs text-slate-500 mb-1">Calibrated probability (thresholds: {t.source})</div>
        <div className="relative h-6 rounded-full overflow-hidden flex">
          <div className="bg-emerald-200" style={{ width: `${t.suspicious * 100}%` }} />
          <div className="bg-amber-200" style={{ width: `${(t.malicious - t.suspicious) * 100}%` }} />
          <div className="bg-rose-200 flex-1" />
          <div className="absolute top-0 h-6 w-1 bg-slate-900" style={{ left: `calc(${pct}% - 2px)` }} title={`${pct}%`} />
        </div>
        <div className="flex justify-between text-[11px] text-slate-500 mt-1">
          <span>Safe &lt; {t.suspicious.toFixed(2)}</span>
          <span>Suspicious</span>
          <span>Malicious ≥ {t.malicious.toFixed(2)}</span>
        </div>
        <div className="mt-3 text-sm text-slate-600 space-y-1">
          <div>Defanged: <SafeText text={a.url_defanged} /></div>
          <div>Registered domain: <span className="font-mono">{a.registered_domain || "—"}</span></div>
          <div className="text-xs text-slate-500">
            Model: {a.model} · lex {a.timing_ms.lex} ms · features {a.timing_ms.features} ms · model {a.timing_ms.model} ms
            · {a.scan_stats.transitions} DFA transitions
          </div>
        </div>
      </div>
    </div>
  );
}

export function TokenChips({ tokens }: { tokens: Token[] }) {
  return (
    <div className="flex flex-wrap gap-2">
      {tokens.map((t, i) => (
        <span key={i} title={`${t.type}  [${t.start}, ${t.end})`}
          className={`border rounded-md px-2 py-1 text-sm font-mono ${TOKEN_COLORS[t.type] ?? "bg-slate-100"}`}>
          <span className="text-[10px] uppercase opacity-70 mr-1">{t.type}</span>{t.value || "∅"}
        </span>
      ))}
    </div>
  );
}

/** Render the input with highlighted spans (flags or explanation evidence). */
export function HighlightedUrl({ text, spans, tone = "flag" }: { text: string; spans: Span[] | Flag[]; tone?: "flag" | "focus" }) {
  const marks = new Array(text.length).fill(false);
  spans.forEach((s) => { for (let i = s.start; i < Math.min(s.end, text.length); i++) marks[i] = true; });
  const parts: { s: string; on: boolean }[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = visible(text[i]);
    if (parts.length && parts[parts.length - 1].on === marks[i]) parts[parts.length - 1].s += ch;
    else parts.push({ s: ch, on: marks[i] });
  }
  const on = tone === "flag" ? "bg-rose-200 text-rose-900 rounded" : "bg-yellow-200 text-slate-900 rounded";
  return (
    <div className="font-mono text-sm break-all bg-slate-50 border rounded-lg p-3">
      {parts.map((p, i) => <span key={i} className={p.on ? on : ""}>{p.s}</span>)}
    </div>
  );
}

export function visible(ch: string): string {
  const c = ch.charCodeAt(0);
  if (c < 32) return `\\x${c.toString(16).padStart(2, "0")}`;
  if (c === 127) return "\\x7f";
  return ch;
}

export function FlagList({ flags }: { flags: Flag[] }) {
  if (!flags.length) return <div className="text-sm text-slate-500">No lexical anomaly flags.</div>;
  return (
    <ul className="space-y-2">
      {flags.map((f, i) => (
        <li key={i} className="flex gap-2 items-start text-sm">
          <span className={`px-2 py-0.5 rounded font-mono text-xs ${f.severity >= 3 ? "bg-rose-600 text-white" : f.severity === 2 ? "bg-amber-400" : "bg-slate-200"}`}>
            {f.code}
          </span>
          <span className="text-[10px] uppercase mt-1 px-1 rounded border text-slate-500">
            {f.source === "dfa" ? "DFA state" : "attribute"}
          </span>
          <span className="text-slate-600">{f.description} <span className="font-mono text-slate-800">“{f.evidence}”</span></span>
        </li>
      ))}
    </ul>
  );
}

export function UrlInput({ onSubmit, busy, initial = "" }: { onSubmit: (u: string) => void; busy: boolean; initial?: string }) {
  const [u, setU] = useState(initial);
  const examples = [
    "https://www.wikipedia.org/wiki/Finite-state_machine",
    "http://3232235777/login",
    "https://paypal.com@evil.example/verify",
    "https://xn--pypal-4ve.com/signin",
    "http://paypal.com.verify.login-auth.example:8443/a//b?next=https%3A%2F%2Fevil.example",
  ];
  return (
    <div className="space-y-2">
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); if (u.trim()) onSubmit(u.trim()); }}>
        <input value={u} onChange={(e) => setU(e.target.value)} maxLength={2048} spellCheck={false}
          placeholder="Paste a URL (it is never opened or fetched)"
          className="flex-1 font-mono text-sm border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
        <button disabled={busy} className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg px-4 py-2 text-sm">
          {busy ? "Analysing…" : "Analyse"}
        </button>
      </form>
      <div className="flex flex-wrap gap-2 text-xs">
        <span className="text-slate-500">Demo:</span>
        {examples.map((e) => (
          <button key={e} type="button" onClick={() => { setU(e); onSubmit(e); }}
            className="font-mono px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 truncate max-w-[260px]" title={e}>
            {e.replace("://", "[://]").replace(/\./g, "[.]")}
          </button>
        ))}
      </div>
    </div>
  );
}
