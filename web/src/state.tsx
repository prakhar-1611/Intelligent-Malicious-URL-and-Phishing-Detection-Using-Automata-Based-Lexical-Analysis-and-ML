import { createContext, useContext, useState, type ReactNode } from "react";
import type { Analysis } from "./api";

// The last analysis is shared so Explain and Live Trace show the URL analysed on Analyze.
type Ctx = {
  analysis: Analysis | null;
  setAnalysis: (a: Analysis | null) => void;
  focusStates: number[];
  setFocusStates: (s: number[]) => void;
};

const AnalysisContext = createContext<Ctx | null>(null);

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [focusStates, setFocusStates] = useState<number[]>([]);
  return (
    <AnalysisContext.Provider value={{ analysis, setAnalysis, focusStates, setFocusStates }}>
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis(): Ctx {
  const c = useContext(AnalysisContext);
  if (!c) throw new Error("useAnalysis outside provider");
  return c;
}
