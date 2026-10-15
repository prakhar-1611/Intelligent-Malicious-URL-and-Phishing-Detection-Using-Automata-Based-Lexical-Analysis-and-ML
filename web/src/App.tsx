import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { api } from "./api";
import Analyze from "./pages/Analyze";
import AutomataLab from "./pages/AutomataLab";
import Batch from "./pages/Batch";
import Explain from "./pages/Explain";
import LiveTrace from "./pages/LiveTrace";
import Results from "./pages/Results";

const PAGES = [
  { to: "/", label: "Analyze", el: <Analyze /> },
  { to: "/explain", label: "Explain", el: <Explain /> },
  { to: "/automata", label: "Automata Lab", el: <AutomataLab /> },
  { to: "/trace", label: "Live Trace", el: <LiveTrace /> },
  { to: "/batch", label: "Batch", el: <Batch /> },
  { to: "/results", label: "Results", el: <Results /> },
];

export default function App() {
  const [health, setHealth] = useState<any>(null);
  useEffect(() => { api.health().then(setHealth).catch(() => setHealth({ status: "down" })); }, []);
  return (
    <div className="min-h-screen">
      <header className="bg-slate-900 text-white">
        <div className="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center gap-4">
          <div>
            <div className="font-bold">Automata-based Phishing URL Detector</div>
            <div className="text-xs text-slate-400">Regex → Thompson NFA → subset DFA → Hopcroft min-DFA → scanner → features → model</div>
          </div>
          <nav className="flex flex-wrap gap-1 ml-auto">
            {PAGES.map((p) => (
              <NavLink key={p.to} to={p.to} end
                className={({ isActive }) => `px-3 py-1.5 rounded-lg text-sm ${isActive ? "bg-indigo-600" : "hover:bg-slate-700"}`}>
                {p.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      {health?.status === "down" && (
        <div className="bg-rose-600 text-white text-sm text-center py-1">API unreachable: start it with <code>uvicorn api.main:app --port 8000</code></div>
      )}
      <main className="max-w-7xl mx-auto px-4 py-6">
        <Routes>{PAGES.map((p) => <Route key={p.to} path={p.to} element={p.el} />)}</Routes>
      </main>
      <footer className="max-w-7xl mx-auto px-4 pb-6 text-xs text-slate-500">
        {health?.model && <>Model: {health.model} · {health.dfa_states} min-DFA states across {health.modes?.length} lexer modes · {health.features} features · </>}
        URLs are never fetched, resolved or rendered as links. BCSE307P Compiler Design Lab, VIT Vellore.
      </footer>
    </div>
  );
}
