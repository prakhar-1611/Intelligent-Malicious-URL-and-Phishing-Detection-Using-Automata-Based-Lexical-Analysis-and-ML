// Typed client for the FastAPI service (proxied at /api by Vite).

export type Token = { type: string; value: string; start: number; end: number };
export type Flag = {
  code: string; start: number; end: number; evidence: string; severity: number;
  source: "dfa" | "attr"; description: string;
};
export type Step = {
  i: number; ch: string; mode: string; state: number; g: number;
  accept: string | null; lexeme: number; anomaly: boolean;
};
export type Span = { start: number; end: number; text: string };
export type Explanation = {
  feature: string; group: string; description: string; value: number;
  contribution: number | null; direction: string; spans: Span[]; states: number[]; flags: string[];
};
export type Analysis = {
  input: string; url_defanged: string; verdict: "Safe" | "Suspicious" | "Malicious"; score: number;
  thresholds: { suspicious: number; malicious: number; source: string }; model: string;
  registered_domain: string; tokens: Token[]; flags: Flag[]; trace: number[]; steps: Step[];
  lexemes: { type: string; value: string; start: number; end: number; mode: string }[];
  symtab: { size: number; buckets: number; max_chain: number; symbols: any[] };
  explanation: Explanation[]; timing_ms: Record<string, number>;
  scan_stats: { transitions: number; backtracked: number; errors: number };
};
export type GraphNode = {
  id: string; label: string; start: boolean; accept: boolean; tag: string | null;
  dead?: boolean; anomaly?: boolean; nfa_states?: number[]; g?: number;
};
export type GraphEdge = { source: string; target: string; label: string; eps?: boolean };
export type Graph = { nodes: GraphNode[]; edges: GraphEdge[] };
export type MimePart = {
  content_type: string; charset: string; encoding: string; disposition: string; filename: string;
  size: number; risky: boolean; children: MimePart[];
};
export type EmailAnalysis = {
  headers: { key: string; value: string; known: boolean }[];
  flags: Flag[]; auth_results: Record<string, string>; folds: number; malformed_lines: number;
  mime: MimePart; mime_truncated: boolean;
  links: { text: string; href: string; text_domain: string; href_domain: string; mismatch: boolean }[];
  urls: { url_defanged: string; verdict: Analysis["verdict"]; score: number; registered_domain: string; flags: Flag[] }[];
  summary: {
    verdict: "Safe" | "Suspicious" | "Phishing"; evidence_points: number; max_url_score: number;
    deciding_rule: string; rule: string; header_flags: string[]; body_flags: string[];
    reasons: { code: string; points: number; evidence: string }[];
  };
};

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!r.ok) {
    let detail = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail ?? j);
    } catch { /* not JSON */ }
    throw new Error(detail);
  }
  return r.json() as Promise<T>;
}

export const api = {
  health: () => call<any>("/health"),
  analyze: (url: string) => call<Analysis>("/analyze", { method: "POST", body: JSON.stringify({ url }) }),
  batch: (urls: string[]) => call<any>("/analyze/batch", { method: "POST", body: JSON.stringify({ urls }) }),
  email: (raw: string) => call<EmailAnalysis>("/analyze/email", { method: "POST", body: JSON.stringify({ raw }) }),
  emailSamples: () => call<Record<string, string>>("/samples/emails"),
  automataList: () => call<{ rules: string[]; examples: string[]; modes: string[] }>("/automata"),
  automaton: (name: string, stage: string) =>
    call<any>(`/automata/${encodeURIComponent(name)}?stage=${stage}`),
  custom: (pattern: string, stage: string) =>
    call<any>("/automata/custom", { method: "POST", body: JSON.stringify({ pattern, stage }) }),
  scannerStates: () => call<{ modes: Record<string, { graph: Graph; offset: number; n_states: number }>; order: string[] }>("/scanner/states"),
  results: () => call<{ files: Record<string, any>; figures: string[] }>("/results"),
};

export const TOKEN_COLORS: Record<string, string> = {
  SCHEME: "bg-violet-100 text-violet-800 border-violet-300",
  USERINFO: "bg-red-100 text-red-800 border-red-300",
  SUBDOMAIN: "bg-sky-100 text-sky-800 border-sky-300",
  BASE_DOMAIN: "bg-blue-200 text-blue-900 border-blue-400",
  TLD: "bg-indigo-100 text-indigo-800 border-indigo-300",
  IP_HOST: "bg-orange-100 text-orange-800 border-orange-300",
  PORT: "bg-amber-100 text-amber-800 border-amber-300",
  PATH: "bg-emerald-100 text-emerald-800 border-emerald-300",
  QUERY_PARAM: "bg-teal-100 text-teal-800 border-teal-300",
  FRAGMENT: "bg-lime-100 text-lime-800 border-lime-300",
  ERROR: "bg-rose-200 text-rose-900 border-rose-500",
};

export const VERDICT_STYLE: Record<string, string> = {
  Safe: "bg-emerald-700 text-white",
  Suspicious: "bg-amber-400 text-amber-950",
  Malicious: "bg-rose-600 text-white",
  Phishing: "bg-rose-600 text-white",
};
