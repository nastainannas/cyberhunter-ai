import type { Finding, ScanResult } from "./pages/Scan";

// Module-level scan state. Lives outside the React component tree so an
// in-progress scan (logs, live findings, results, queue) survives navigation
// away from the Scan page and back.
export interface ScanSnapshot {
  logs: string[];
  liveFindings: Finding[];
  results: ScanResult[];
  queue: string[];
  scanning: boolean;
  error: string | null;
}

let state: ScanSnapshot = {
  logs: [],
  liveFindings: [],
  results: [],
  queue: [],
  scanning: false,
  error: null,
};

const listeners = new Set<() => void>();

export function getScanState(): ScanSnapshot {
  return state;
}

export function setScanState(patch: Partial<ScanSnapshot>) {
  state = { ...state, ...patch };
  listeners.forEach((l) => l());
}

export function subscribeScan(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function resetScanView() {
  state = {
    ...state,
    logs: [],
    liveFindings: [],
    results: [],
    queue: [],
    scanning: false,
    error: null,
  };
}

export function appendLog(msg: string) {
  setScanState({ logs: [...state.logs, msg] });
}

export function appendLiveFinding(f: Finding) {
  setScanState({ liveFindings: [...state.liveFindings, f] });
}

export function appendResult(r: ScanResult) {
  setScanState({ results: [...state.results, r] });
}

export function shiftQueue() {
  setScanState({ queue: state.queue.slice(1) });
}
