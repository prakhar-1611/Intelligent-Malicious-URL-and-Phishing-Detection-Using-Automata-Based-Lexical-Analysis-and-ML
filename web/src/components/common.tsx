import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, TOKEN_COLORS, VERDICT_STYLE, type Analysis, type Flag, type Span, type Token } from "../api";
import { DEMOS } from "../demos";

export function Card({ title, children, right, className = "" }: { title?: string; children: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <section className={`min-w-0 bg-white rounded-xl border border-slate-200 p-4 sm:p-5 ${className}`}>
      {(title || right) && (
        <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 mb-4">
          {title && <h2 className="font-semibold text-slate-900 min-w-0">{title}</h2>}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

/** Page title block: what this page is for, in one line. */
export function PageHeader({ title, subtitle, right }: { title: string; subtitle: string; right?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 mb-5">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 text-balance">{title}</h1>
        <p className="text-sm text-slate-600 mt-1 max-w-3xl text-pretty">{subtitle}</p>
      </div>
      {right}
    </div>
  );
}

// Colour carries meaning only (safe / suspicious / malicious); every other tile stays neutral.
const TONE: Record<string, string> = {
  indigo: "text-slate-900",
  emerald: "text-emerald-700",
  amber: "text-amber-700",
  rose: "text-rose-700",
  slate: "text-slate-900",
  violet: "text-slate-900",
};

/** Small number tile used in stat strips. */
export function Stat({ label, value, hint, tone = "slate" }: { label: string; value: ReactNode; hint?: string; tone?: keyof typeof TONE }) {
  return (
    <div className="min-w-0 bg-white px-4 py-3">
      <div className="text-[13px] text-slate-600 truncate">{label}</div>
      <div className={`text-2xl font-semibold leading-tight mt-1 tabular-nums tracking-tight ${TONE[tone]}`}>{value}</div>
      {hint && <div className="text-xs text-slate-500 mt-0.5 truncate" title={hint}>{hint}</div>}
    </div>
  );
}

/** A row of Stat cells in one container split by 1px hairlines; `cols` sets the grid columns. */
export function StatStrip({ cols, children }: { cols: string; children: ReactNode }) {
  return <div className={`grid gap-px bg-slate-200 border border-slate-200 rounded-xl overflow-hidden ${cols}`}>{children}</div>;
}

/** The four steps of the system, shown on empty pages. */
export function HowItWorks() {
  // counts come from /health, so the copy never drifts from the running system
  const [h, setH] = useState<{ rules?: number; url_flags?: number; features?: number; model?: string }>({});
  useEffect(() => { api.health().then(setH).catch(() => {}); }, []);
  const n = (v: number | undefined, word: string) => (v ? `${v} ${word}` : word);
  const steps = [
    { t: "Read", d: `A lexer built from ${n(h.rules, "regex rules")} (Thompson → subset → Hopcroft) splits the link into tokens.` },
    { t: "Flag", d: `Suspicious patterns light up as the DFA reaches anomaly states or an attribute check fires${h.url_flags ? `: ${h.url_flags} kinds` : ""}.` },
    { t: "Score", d: `${h.model ?? "A gradient-boosted model"} turns ${n(h.features, "features")}, including DFA state visits, into a calibrated risk score.` },
    { t: "Explain", d: "SHAP shows which features, characters and DFA states drove the verdict." },
  ];
  return (
    <ol className="grid sm:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-5">
      {steps.map((s, i) => (
        <li key={s.t} className="border-t-2 border-slate-200 pt-3 first:border-indigo-600">
          <div className="flex items-baseline gap-2">
            <span className="text-sm font-semibold text-indigo-700 tabular-nums">{i + 1}</span>
            <span className="font-semibold text-slate-900">{s.t}</span>
          </div>
          <p className="text-sm text-slate-600 mt-1.5 leading-relaxed text-pretty">{s.d}</p>
        </li>
      ))}
    </ol>
  );
}

/** Clickable demo links: one click analyses the URL. Shown as plain text, never as links. */
export function DemoGrid({ onPick }: { onPick: (u: string) => void }) {
  return (
    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
      {DEMOS.map((d) => (
        <button key={d.url} onClick={() => onPick(d.url)}
          className="flex flex-col justify-start text-left rounded-lg border border-slate-200 bg-white hover:border-indigo-300 hover:bg-indigo-50/30 transition-colors p-4 group min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className="font-semibold text-slate-800 group-hover:text-indigo-700">{d.title}</span>
            <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${d.kind === "benign" ? "bg-emerald-50 text-emerald-800" : "bg-rose-50 text-rose-800"}`}>
              {d.kind}
            </span>
          </div>
          <div className="font-mono text-[13px] text-slate-600 mt-2 break-all">{defangText(d.url)}</div>
          <div className="text-[13px] text-slate-700 mt-2">{d.trick}</div>
        </button>
      ))}
    </div>
  );
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return <div role="alert" className="rounded-lg border border-rose-300 bg-rose-50 text-rose-800 px-3 py-2 text-sm break-words">{error}</div>;
}

/** URL shown as plain text only: never a link, never fetched. */
export function SafeText({ text, className = "" }: { text: string; className?: string }) {
  return <span className={`font-mono break-all select-all ${className}`}>{text}</span>;
}

export const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Re-play a short settle on each new result so a re-analysis visibly lands (opacity only under reduced motion). */
export function useReveal<T extends HTMLElement>(dep: unknown) {
  const ref = useRef<T>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || !el.animate) return;
    el.animate(reducedMotion() ? [{ opacity: 0 }, { opacity: 1 }]
      : [{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }],
      { duration: reducedMotion() ? 150 : 200, easing: "cubic-bezier(0.23, 1, 0.32, 1)" });
  }, [dep]);
  return ref;
}

export function VerdictCard({ a }: { a: Analysis }) {
  const pct = Math.round(a.score * 100);
  const t = a.thresholds;
  const ref = useReveal<HTMLDivElement>(a);
  return (
    <div ref={ref} className="flex flex-col md:flex-row gap-4 items-stretch">
      <div className={`${VERDICT_STYLE[a.verdict]} rounded-lg px-6 py-4 md:min-w-[180px] flex flex-col justify-center`}>
        <div className="text-sm">Verdict</div>
        <div className="text-3xl font-bold tracking-tight">{a.verdict}</div>
        <div className="text-sm tabular-nums">score {a.score.toFixed(3)}</div>
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-xs text-slate-500 mb-1">Calibrated probability (thresholds: {t.source})</div>
        <div className="relative h-6 rounded-full overflow-hidden flex" role="img"
          aria-label={`Score ${a.score.toFixed(3)}; suspicious from ${t.suspicious.toFixed(2)}, malicious from ${t.malicious.toFixed(2)}`}>
          <div className="bg-emerald-200" style={{ width: `${t.suspicious * 100}%` }} />
          <div className="bg-amber-200" style={{ width: `${(t.malicious - t.suspicious) * 100}%` }} />
          <div className="bg-rose-200 flex-1" />
          {/* full-width track moved by transform, so the marker glides from the previous score */}
          <div className="absolute inset-0 transition-transform duration-300 ease-[cubic-bezier(0.23,1,0.32,1)] motion-reduce:transition-none"
            style={{ transform: `translateX(${a.score * 100}%)` }}>
            <div className="h-6 w-1 -ml-0.5 bg-slate-900" title={`${pct}%`} />
          </div>
        </div>
        <div className="flex justify-between text-xs text-slate-600 mt-1 tabular-nums">
          <span>Safe &lt; {t.suspicious.toFixed(2)}</span>
          <span>Suspicious</span>
          <span>Malicious ≥ {t.malicious.toFixed(2)}</span>
        </div>
        <div className="mt-3 text-sm text-slate-600 space-y-1">
          <div>Defanged: <SafeText text={a.url_defanged} /></div>
          <div>Registered domain: <span className="font-mono">{a.registered_domain || "—"}</span></div>
          <div className="text-xs text-slate-500 tabular-nums">
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
          className={`border rounded-md px-2 py-1 text-sm font-mono break-all min-w-0 max-w-full ${TOKEN_COLORS[t.type] ?? "bg-slate-100"}`}>
          <span className="text-[11px] mr-1.5">{t.type}</span>{t.value || "∅"}
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

/** Display-only defang for the static demo strings (API results are already defanged by security/defang.py). */
export function defangText(url: string): string {
  return url.replace(/^http/i, (m) => (m[0] === "H" ? "HXXP" : "hxxp")).replace(/\./g, "[.]");
}

export function visible(ch: string): string {
  const c = ch.charCodeAt(0);
  if (c < 32) return `\\x${c.toString(16).padStart(2, "0")}`;
  if (c === 127) return "\\x7f";
  return ch;
}

export function FlagList({ flags, empty = "No lexical anomaly flags." }: { flags: Flag[]; empty?: string }) {
  if (!flags.length) return <div className="text-sm text-slate-600">{empty}</div>;
  return (
    <ul className="space-y-2">
      {flags.map((f, i) => (
        <li key={i} className="flex flex-wrap sm:flex-nowrap gap-x-2 gap-y-1 items-start text-sm">
          <span className={`px-2 py-0.5 rounded font-mono text-xs shrink-0 ${f.severity >= 3 ? "bg-rose-100 text-rose-800" : f.severity === 2 ? "bg-amber-100 text-amber-900" : "bg-slate-100 text-slate-700"}`}>
            {f.code}
          </span>
          <span className="text-xs mt-0.5 text-slate-500 whitespace-nowrap shrink-0">
            {f.source === "dfa" ? "DFA state" : "attribute"}
          </span>
          <span className="text-slate-600 min-w-0 break-words">{f.description} <span className="font-mono text-slate-800 break-all">“{f.evidence}”</span></span>
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
        <input value={u} onChange={(e) => setU(e.target.value)} maxLength={2048} spellCheck={false} autoComplete="off"
          aria-label="URL to analyse" placeholder="Paste a URL (it is never opened or fetched)"
          className="flex-1 min-w-0 font-mono text-sm border border-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400" />
        <button disabled={busy || !u.trim()} className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg px-4 py-2 text-sm font-medium shrink-0 active:scale-[0.96] motion-reduce:active:scale-100 transition-[transform,background-color] duration-150">
          {busy ? "Analysing…" : "Analyse"}
        </button>
      </form>
      <div className="flex flex-wrap gap-2 text-[13px]">
        <span className="text-slate-600 py-0.5">Demo:</span>
        {examples.map((e) => (
          <button key={e} type="button" onClick={() => { setU(e); onSubmit(e); }}
            className="font-mono px-2 py-2 sm:py-0.5 rounded bg-slate-100 text-slate-700 hover:bg-slate-200 transition-colors truncate max-w-full sm:max-w-[260px]" title={defangText(e)}>
            {defangText(e)}
          </button>
        ))}
      </div>
    </div>
  );
}
