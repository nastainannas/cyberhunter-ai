import { useRef, useState } from "react";
import { api } from "../api";

export default function Tools() {
  const [tab, setTab] = useState<"ports" | "dns" | "robots" | "methods">("ports");
  const [target, setTarget] = useState("");
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  function addLog(m: string) { setLogs((p) => [...p, m]); }

  async function run() {
    if (!target.trim() || busy) return;
    setBusy(true); setError(null); setResult(null); setLogs([]);
    try {
      if (tab === "ports") {
        // host only
        const host = target.trim().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
        addLog(`Starting port scan on ${host}…`);
        const res = await fetch("/api/tools/portscan/stream", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ host }),
        });
        const reader = res.body!.getReader();
        const dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const lines = buf.split("\n"); buf = lines.pop() ?? "";
          for (const l of lines) {
            const t = l.trim(); if (!t.startsWith("data:")) continue;
            try {
              const ev = JSON.parse(t.slice(5));
              if (ev.type === "log") addLog(ev.message);
              else if (ev.type === "result") { setResult(ev); addLog(`[done] ${ev.open.length} open port(s) of ${ev.scanned} scanned`); }
              else if (ev.type === "error") { setError(ev.error); addLog(`[error] ${ev.error}`); }
            } catch {}
          }
        }
      } else if (tab === "dns") {
        const host = target.trim().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
        const r = await api.dnsLookup(host);
        setResult(r);
      } else if (tab === "robots") {
        const r = await api.robots(target.trim());
        setResult(r);
      } else if (tab === "methods") {
        const r = await api.httpMethods(target.trim());
        setResult(r);
      }
    } catch (e: any) {
      setError(e.message); addLog(`[error] ${e.message}`);
    } finally {
      setBusy(false);
      logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
    }
  }

  return (
    <>
      <h1>Recon Tools</h1>
      <p className="subtitle">Port scanner, DNS lookup, robots.txt parser, HTTP method probe — authorized testing only.</p>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="btn-row" style={{ marginTop: 0 }}>
          {([["ports", "Port Scanner"], ["dns", "DNS Lookup"], ["robots", "Robots.txt"], ["methods", "HTTP Methods"]] as const).map(([k, label]) => (
            <button key={k} className={`btn ${tab === k ? "primary" : ""}`} onClick={() => { setTab(k); setResult(null); setLogs([]); setError(null); }}>{label}</button>
          ))}
        </div>
        <div className="field" style={{ marginTop: 14 }}>
          <label>{tab === "ports" || tab === "dns" ? "Host" : "URL"}</label>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={tab === "ports" || tab === "dns" ? "example.com" : "https://example.com"} />
        </div>
        <button className="btn primary" onClick={run} disabled={busy || !target.trim()}>{busy ? "Running…" : "Run"}</button>
      </div>

      {error && <div className="alert">{error}</div>}

      {logs.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h2>Log</h2>
          <div ref={logRef} style={{ background: "#060a10", border: "1px solid var(--border)", borderRadius: 8, padding: 12, fontFamily: "Consolas, monospace", fontSize: 12, maxHeight: 200, overflowY: "auto", whiteSpace: "pre-wrap" }}>
            {logs.map((l, i) => <div key={i} style={{ color: l.includes("error") ? "var(--danger)" : "var(--text-dim)" }}>{l}</div>)}
          </div>
        </div>
      )}

      {result && (
        <div className="card">
          <h2>Result</h2>
          {tab === "ports" && result.open && (
            <table>
              <thead><tr><th>Port</th><th>Service</th><th>State</th></tr></thead>
              <tbody>
                {result.open.map((p: any) => (
                  <tr key={p.port}><td>{p.port}</td><td>{p.service}</td><td style={{ color: "var(--danger)" }}>OPEN</td></tr>
                ))}
                {result.open.length === 0 && <tr><td colSpan={3} className="status-text">No open ports found among {result.scanned} scanned.</td></tr>}
              </tbody>
            </table>
          )}
          {tab === "dns" && (
            <table>
              <tbody>
                {Object.entries(result).filter(([k]) => k !== "ok" && k !== "host").map(([k, v]: any) => (
                  <tr key={k}><td style={{ width: 80, color: "var(--text-dim)" }}>{k.toUpperCase()}</td>
                    <td>{v ? JSON.stringify(v) : <span className="status-text">none</span>}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          {tab === "robots" && (
            <>
              <p className="status-text">{result.found ? `Found — ${result.url}` : "robots.txt not found"}</p>
              {result.disallow?.length > 0 && <><h2>Disallow ({result.disallow.length})</h2><ul>{result.disallow.map((d: string, i: number) => <li key={i}><code>{d}</code></li>)}</ul></>}
              {result.allow?.length > 0 && <><h2>Allow ({result.allow.length})</h2><ul>{result.allow.map((d: string, i: number) => <li key={i}><code>{d}</code></li>)}</ul></>}
              {result.sitemap?.length > 0 && <><h2>Sitemaps</h2><ul>{result.sitemap.map((d: string, i: number) => <li key={i}><code>{d}</code></li>)}</ul></>}
            </>
          )}
          {tab === "methods" && result.methods && (
            <table>
              <thead><tr><th>Method</th><th>Status</th></tr></thead>
              <tbody>
                {result.methods.map((m: any) => (
                  <tr key={m.method}><td>{m.method}</td><td style={{ color: m.method === "TRACE" ? "var(--danger)" : "var(--text)" }}>{m.status}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </>
  );
}
