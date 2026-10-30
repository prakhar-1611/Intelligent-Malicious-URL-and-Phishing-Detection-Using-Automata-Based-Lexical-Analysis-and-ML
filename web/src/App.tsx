import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { api } from "./api";
import Analyze from "./pages/Analyze";
import AutomataLab from "./pages/AutomataLab";
import Batch from "./pages/Batch";
import Email from "./pages/Email";
import Explain from "./pages/Explain";
import LiveTrace from "./pages/LiveTrace";
import Results from "./pages/Results";

const PAGES = [
  { to: "/", label: "Analyze", el: <Analyze /> },
  { to: "/explain", label: "Explain", el: <Explain /> },
  { to: "/automata", label: "Automata Lab", el: <AutomataLab /> },
  { to: "/trace", label: "Live Trace", el: <LiveTrace /> },
  { to: "/batch", label: "Batch", el: <Batch /> },
  { to: "/email", label: "Email", el: <Email /> },
  { to: "/results", label: "Results", el: <Results /> },
];

export default function App() {
  const [health, setHealth] = useState<any>(null);
  useEffect(() => { api.health().then(setHealth).catch(() => setHealth({ status: "down" })); }, []);
  const up = health?.status === "ok";
  return (
    <div className="min-h-screen flex flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 bg-white text-slate-900 px-3 py-2 rounded-lg shadow">Skip to content</a>
      <header className="md:sticky top-0 z-30 bg-slate-950 text-white border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center gap-x-4 gap-y-3">
          <div className="flex items-center gap-3 min-w-0">
            <Logo />
            <div className="min-w-0">
              <div className="font-bold tracking-tight">Automata Phishing Detector</div>
              <div className="hidden sm:block text-xs text-indigo-200">Regex → Thompson NFA → subset DFA → Hopcroft min-DFA → scanner → model</div>
            </div>
            <StatusDot up={up} health={health} className="md:hidden ml-auto" />
          </div>
          <nav aria-label="Pages" className="w-full md:w-auto md:ml-auto -mx-1 md:mx-0 overflow-x-auto no-scrollbar">
            <div className="flex gap-1 w-max">
              {PAGES.map((p) => (
                <NavLink key={p.to} to={p.to} end
                  className={({ isActive }) => `px-3 py-1.5 rounded-lg text-sm whitespace-nowrap transition-colors ${isActive ? "bg-white/15 text-white font-medium" : "text-slate-300 hover:text-white hover:bg-white/10"}`}>
                  {p.label}
                </NavLink>
              ))}
            </div>
          </nav>
          <StatusDot up={up} health={health} className="hidden md:flex" />
        </div>
      </header>
      {health?.status === "down" && (
        <div role="alert" className="bg-rose-600 text-white text-sm text-center px-4 py-1.5">API unreachable: start it with <code className="bg-white/20 px-1 rounded">start.bat</code> or <code className="bg-white/20 px-1 rounded">.venv\Scripts\python -m uvicorn api.main:app --port 8000</code></div>
      )}
      <main id="main" className="flex-1 w-full max-w-7xl mx-auto px-4 py-6 sm:py-7">
        <Routes>{PAGES.map((p) => <Route key={p.to} path={p.to} element={p.el} />)}</Routes>
      </main>
      <footer className="border-t border-slate-200 bg-white">
        <div className="max-w-7xl mx-auto px-4 py-4 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-500">
          {health?.model && <span>Model: <b className="text-slate-700">{health.model}</b></span>}
          {health?.dfa_states && <span className="tabular-nums"><b className="text-slate-700">{health.dfa_states}</b> min-DFA states · {health.modes?.length} lexer modes · {health.features} features</span>}
          <span>URLs are never fetched, resolved or rendered as links.</span>
          <span className="md:ml-auto">BCSE307P Compiler Design Lab · VIT Vellore</span>
        </div>
      </footer>
    </div>
  );
}

function StatusDot({ up, health, className }: { up: boolean; health: any; className: string }) {
  return (
    <span role="status" className={`${className} items-center gap-1.5 text-xs px-2.5 py-1 rounded-full whitespace-nowrap ${up ? "bg-emerald-500/15 text-emerald-300" : "bg-rose-500/15 text-rose-300"}`}>
      <span className={`w-2 h-2 rounded-full ${up ? "bg-emerald-400" : "bg-rose-400"}`} aria-hidden="true" />
      {up ? "API online" : health ? "API offline" : "connecting…"}
    </span>
  );
}

/** Small automaton mark: two states and a transition inside a shield. */
function Logo() {
  return (
    <svg width="34" height="34" viewBox="0 0 34 34" aria-hidden="true">
      <path d="M17 2 L30 7 V16 C30 24 24 30 17 32 C10 30 4 24 4 16 V7 Z" fill="#4f46e5" />
      <circle cx="11.5" cy="17" r="4" fill="none" stroke="#fff" strokeWidth="1.8" />
      <circle cx="22.5" cy="17" r="4" fill="none" stroke="#fff" strokeWidth="1.8" />
      <circle cx="22.5" cy="17" r="2.2" fill="none" stroke="#fff" strokeWidth="1.2" />
      <path d="M15.5 17 H17.8" stroke="#fff" strokeWidth="1.8" />
      <path d="M17.6 15.3 L19.6 17 L17.6 18.7 Z" fill="#fff" />
    </svg>
  );
}
