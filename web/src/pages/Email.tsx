import { useState } from "react";
import { api, VERDICT_STYLE, type EmailAnalysis, type MimePart } from "../api";
import { Card, ErrorBox, FlagList, PageHeader, SafeText, useReveal } from "../components/common";

const MAX_BYTES = 1_000_000; // same cap as the API (api/security.py MAX_EMAIL_BYTES)

// Which header rows each email flag points at, so the table can highlight them.
const FLAG_HEADERS: Record<string, string[]> = {
  S_FROM_REPLYTO_MISMATCH: ["from", "reply-to"],
  S_RETURNPATH_MISMATCH: ["from", "return-path"],
  S_DISPLAYNAME_SPOOF: ["from"],
  S_LOOKALIKE_SENDER: ["from"],
  S_AUTH_FAIL: ["authentication-results"],
};

const SAMPLES = [
  { key: "benign_folded", title: "Team planning note", kind: "benign", d: "Folded headers, matching sender domains, SPF/DKIM/DMARC pass." },
  { key: "spoofed_paypal", title: "Spoofed PayPal alert", kind: "phishing", d: "Look-alike sender, failed DMARC, a lying HTML link and an .exe attachment." },
];

export default function Email() {
  const [raw, setRaw] = useState("");
  const [res, setRes] = useState<EmailAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(text: string) {
    if (!text.trim()) return;
    if (new Blob([text]).size > MAX_BYTES) { setError("Email is larger than 1 MB, the API limit."); return; }
    setBusy(true); setError(null);
    try { setRes(await api.email(text)); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  async function loadSample(key: string) {
    setBusy(true); setError(null);
    try {
      const text = (await api.emailSamples())[key];
      if (!text) throw new Error(`sample ${key} not found in data/samples/emails`);
      setRaw(text);
      setRes(await api.email(text));
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  return (
    <div className="space-y-5">
      <PageHeader title="Check an email"
        subtitle="Paste a raw email or upload a .eml file. Headers are lexed, the MIME parts are parsed, every link is scored by the URL model, and the result is combined into one verdict. Nothing in the email is opened." />
      <Card title="Raw email" right={<span className="text-xs text-slate-500 tabular-nums">{raw ? `${new Blob([raw]).size.toLocaleString()} / 100,000 bytes` : "headers, blank line, body"}</span>}>
        <textarea value={raw} onChange={(e) => setRaw(e.target.value)} rows={10} spellCheck={false}
          aria-label="Raw email source"
          className="w-full font-mono text-xs leading-5 border border-slate-200 rounded-lg p-3 bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-indigo-400"
          placeholder={"From: \"Sender\" <someone@example.com>\nSubject: ...\n\nBody text"} />
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <button onClick={() => run(raw)} disabled={busy || !raw.trim()}
            className="bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg px-5 py-2 text-sm font-medium disabled:opacity-50 active:scale-[0.96] motion-reduce:active:scale-100 transition-[transform,background-color] duration-150">
            {busy ? "Analysing…" : "Analyse email"}
          </button>
          <label className="border border-slate-200 hover:bg-slate-50 rounded-lg px-4 py-2 text-sm cursor-pointer focus-within:ring-2 focus-within:ring-indigo-400">
            Upload .eml
            <input type="file" accept=".eml,.txt,message/rfc822" className="sr-only" onChange={async (e) => {
              const f = e.target.files?.[0];
              e.target.value = "";
              if (!f) return;
              if (f.size > MAX_BYTES) { setError(`${f.name} is larger than 1 MB, the API limit.`); return; }
              const text = await f.text();
              setRaw(text);
              run(text);
            }} />
          </label>
          {raw && <button onClick={() => { setRaw(""); setRes(null); setError(null); }} className="text-sm text-slate-500 hover:text-slate-800 px-2">Clear</button>}
        </div>
      </Card>
      <ErrorBox error={error} />
      {!res && (
        <Card title="Try a sample" right={<span className="text-xs text-slate-500">one click loads and analyses it</span>}>
          <div className="grid sm:grid-cols-2 gap-3">
            {SAMPLES.map((s) => (
              <button key={s.key} onClick={() => loadSample(s.key)} disabled={busy}
                className="flex flex-col justify-start text-left rounded-lg border border-slate-200 bg-white hover:border-indigo-300 hover:bg-indigo-50/30 transition-colors p-4 group disabled:opacity-60 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-slate-800 group-hover:text-indigo-700">{s.title}</span>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${s.kind === "benign" ? "bg-emerald-50 text-emerald-800" : "bg-rose-50 text-rose-800"}`}>{s.kind}</span>
                </div>
                <div className="font-mono text-xs text-slate-600 mt-2 break-all">data/samples/emails/{s.key}.eml</div>
                <div className="text-xs text-slate-600 mt-2">{s.d}</div>
              </button>
            ))}
          </div>
        </Card>
      )}
      {res && <EmailResult r={res} />}
    </div>
  );
}

function EmailResult({ r }: { r: EmailAnalysis }) {
  const s = r.summary;
  const reveal = useReveal<HTMLDivElement>(r);
  const hot = new Map<string, string[]>();
  r.flags.forEach((f) => (FLAG_HEADERS[f.code] ?? []).forEach((k) => hot.set(k, [...(hot.get(k) ?? []), f.code])));
  return (
    <>
      <Card>
        <div ref={reveal} className="flex flex-col md:flex-row gap-4 items-stretch">
          <div className={`${VERDICT_STYLE[s.verdict]} rounded-lg px-6 py-4 md:min-w-[180px] flex flex-col justify-center`}>
            <div className="text-sm">Email verdict</div>
            <div className="text-3xl font-bold tracking-tight">{s.verdict}</div>
            <div className="text-sm tabular-nums">{s.evidence_points} points · worst link {s.max_url_score.toFixed(3)}</div>
          </div>
          <div className="flex-1 min-w-0 text-sm text-slate-600 space-y-2">
            <div><span className="font-semibold text-slate-800">Decided by: </span>{s.deciding_rule}</div>
            <div className="text-[13px] text-slate-600">{s.rule}</div>
            {s.reasons.length > 0 && (
              <ul className="text-[13px] space-y-1 pt-1">
                {s.reasons.map((x, i) => (
                  <li key={i} className="flex flex-wrap gap-x-2 min-w-0">
                    <span className="font-mono tabular-nums text-slate-500 shrink-0">+{x.points}</span>
                    <span className="font-mono text-slate-800 shrink-0">{x.code}</span>
                    <span className="break-words min-w-0">{x.evidence}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </Card>
      <div className="grid lg:grid-cols-2 gap-4 items-start">
        <Card title="Headers" right={<span className="text-xs text-slate-500">{r.headers.length} fields · {r.folds} folded lines joined</span>}>
          <AuthChips auth={r.auth_results} />
          <div className="overflow-auto mt-3">
            <table className="w-full text-[13px]">
              <thead className="text-slate-500 border-b border-slate-200"><tr><th className="text-left font-normal px-2 py-1.5 w-32">field</th><th className="text-left font-normal px-2 py-1.5">value</th></tr></thead>
              <tbody>
                {r.headers.map((h, i) => {
                  const codes = hot.get(h.key.toLowerCase());
                  return (
                    <tr key={i} className={`border-t border-slate-100 align-top ${codes ? "bg-rose-50" : ""}`}>
                      <td className={`px-2 py-1.5 font-mono ${codes ? "text-rose-700 font-semibold" : h.known ? "text-slate-800" : "text-slate-500"}`}>{h.key}</td>
                      <td className="px-2 py-1.5">
                        <span className="font-mono break-all">{h.value}</span>
                        {codes && <div className="mt-1 flex flex-wrap gap-1">{codes.map((c) => <span key={c} className="font-mono text-[11px] px-1.5 rounded bg-rose-100 text-rose-800">{c}</span>)}</div>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Flags (evidence, not verdicts)">
          <FlagList flags={r.flags} empty="No header or body flags raised." />
        </Card>
      </div>
      <div className="grid lg:grid-cols-2 gap-4 items-start">
        <Card title="MIME structure" right={r.mime_truncated ? <span className="text-xs text-amber-700">stopped after 100 parts</span> : undefined}>
          <ul className="text-sm"><PartNode p={r.mime} /></ul>
        </Card>
        <Card title="HTML links" right={<span className="text-xs text-slate-500">shown text vs real destination</span>}>
          {r.links.length === 0 ? <div className="text-sm text-slate-500">No HTML part with links.</div> : (
            <ul className="space-y-2">
              {r.links.map((l, i) => (
                <li key={i} className={`rounded-lg border p-2 text-[13px] ${l.mismatch ? "border-rose-300 bg-rose-50" : "border-slate-200"}`}>
                  <div className="flex gap-2"><span className="text-slate-500 w-12 shrink-0">shows</span><SafeText text={l.text || "(no text)"} /></div>
                  <div className="flex gap-2 mt-1"><span className="text-slate-500 w-12 shrink-0">goes to</span><SafeText text={l.href || "(no href)"} /></div>
                  {l.mismatch && <div className="mt-1 text-rose-700 font-semibold">Mismatch: {l.text_domain} ≠ {l.href_domain}</div>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      <Card title={`Links found in the body (${r.urls.length})`} right={<span className="text-xs text-slate-500">scored by the URL model, defanged</span>}>
        {r.urls.length === 0 ? <div className="text-sm text-slate-500">No http(s) or www. links in the body.</div> : (
          <div className="overflow-auto">
            <table className="w-full min-w-[560px] text-[13px]">
              <thead className="text-slate-500 border-b border-slate-200"><tr><th className="text-left font-normal px-2 py-1.5">URL (defanged)</th><th className="font-normal px-2">verdict</th><th className="font-normal px-2 text-right">score</th><th className="text-left font-normal px-2">flags</th></tr></thead>
              <tbody>
                {r.urls.map((u, i) => (
                  <tr key={i} className="border-t border-slate-100 align-top">
                    <td className="px-2 py-1.5"><SafeText text={u.url_defanged} /></td>
                    <td className={`px-2 py-1.5 text-center font-semibold ${u.verdict === "Malicious" ? "text-rose-700" : u.verdict === "Suspicious" ? "text-amber-700" : "text-emerald-700"}`}>{u.verdict}</td>
                    <td className="px-2 py-1.5 text-right tabular-nums">{u.score.toFixed(3)}</td>
                    <td className="px-2 py-1.5 font-mono text-[11px] text-slate-700 break-words">{u.flags.map((f) => f.code).join(" ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}

function AuthChips({ auth }: { auth: Record<string, string> }) {
  const keys = ["spf", "dkim", "dmarc"];
  return (
    <div className="flex flex-wrap gap-2 text-xs">
      {keys.map((k) => {
        const v = auth[k];
        const tone = !v ? "bg-slate-100 text-slate-500" : v === "pass" ? "bg-emerald-100 text-emerald-800"
          : ["fail", "softfail", "permerror", "temperror"].includes(v) ? "bg-rose-100 text-rose-800" : "bg-amber-100 text-amber-800";
        return <span key={k} className={`px-2 py-1 rounded-md font-mono ${tone}`}>{k.toUpperCase()}: {v ?? "not reported"}</span>;
      })}
    </div>
  );
}

function PartNode({ p }: { p: MimePart }) {
  return (
    <li className="mt-1">
      <div className={`flex flex-wrap items-baseline gap-x-2 rounded-md px-2 py-1 ${p.risky ? "bg-rose-50 ring-1 ring-rose-200" : ""}`}>
        <span className="font-mono text-slate-800">{p.content_type}</span>
        {p.filename && <span className="font-mono text-xs break-all">“{p.filename}”</span>}
        {p.risky && <span className="text-xs font-medium px-1.5 rounded bg-rose-100 text-rose-800">risky extension</span>}
        <span className="text-xs text-slate-500 tabular-nums">
          {p.children.length ? `${p.children.length} part${p.children.length === 1 ? "" : "s"}` : `${p.size.toLocaleString()} bytes`}
          {p.encoding !== "7bit" && ` · ${p.encoding}`}{p.charset && ` · ${p.charset}`}
        </span>
      </div>
      {p.children.length > 0 && <ul className="ml-4 pl-2 border-l border-slate-200">{p.children.map((c, i) => <PartNode key={i} p={c} />)}</ul>}
    </li>
  );
}
