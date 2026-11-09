import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { exportReport, ScanResult } from "./Scan";

const SEV_COLOR: Record<string, string> = {
  critical: "var(--danger)", high: "#ff8c42", medium: "var(--warn)", low: "var(--info)", info: "var(--text-dim)",
};

export default function Findings() {
  const [scans, setScans] = useState<any[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [closed, setClosed] = useState<Set<string>>(new Set());

  const [searchParams, setSearchParams] = useSearchParams();
  const sevFilter = searchParams.get("sev");
  const hasSev = (s: any) => !sevFilter || (s.findings ?? []).some((f: any) => f.severity === sevFilter);
  const isOpen = (s: any) => (sevFilter ? hasSev(s) && !closed.has(s.id) : expanded === s.id);
  function toggle(s: any) {
    if (sevFilter) {
      setClosed((prev) => {
        const n = new Set(prev);
        n.has(s.id) ? n.delete(s.id) : n.add(s.id);
        return n;
      });
    } else {
      setExpanded(expanded === s.id ? null : s.id);
    }
  }

  async function load() {
    const r = await api.findings();
    setScans(r.findings);
  }
  useEffect(() => { load().catch(() => {}); }, []);

  async function remove(id: string) {
    if (!confirm("Delete this scan record?")) return;
    await api.deleteFinding(id);
    load();
  }

  async function clearAll() {
    if (!confirm(`Delete ALL ${scans.length} scan record(s) from the findings database? This cannot be undone.`)) return;
    await api.clearFindings();
    load();
  }

  return (
    <>
      <h1>Findings Database</h1>
      <p className="subtitle">Stored scan results — target, timestamp, severity summary, and all findings.</p>
      <div className="card">
        {sevFilter && (
          <div className="notice" style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span>Filtered: <strong style={{ textTransform: "capitalize" }}>{sevFilter}</strong> findings only</span>
            <button className="btn" style={{ marginLeft: "auto", fontSize: 11, padding: "3px 10px" }}
              onClick={() => setSearchParams({})}>Clear filter</button>
          </div>
        )}
        {scans.length === 0 && <p className="status-text">No scans saved yet. Run a scan from Scan Target — results are saved automatically.</p>}
        {scans.length > 0 && (
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 10 }}>
            <button className="btn danger" style={{ fontSize: 11, padding: "4px 12px" }} onClick={clearAll}>
              🗑 Clear Database ({scans.length})
            </button>
          </div>
        )}
        {scans.map((s) => (
          <div key={s.id} className="card" style={{ marginBottom: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <strong>{s.target}</strong>
              <span className="tag">{new Date(s.created_at).toLocaleString()}</span>
              <span className="tag">HTTP {s.status}</span>
              {s.pages_crawled && <span className="tag">{s.pages_crawled} pages</span>}
              <span className="tag" style={{ color: "var(--danger)" }}>{s.summary?.critical ?? 0} critical</span>
              <span className="tag" style={{ color: "#ff8c42" }}>{s.summary?.high ?? 0} high</span>
              <span className="tag" style={{ color: "var(--warn)" }}>{s.summary?.medium ?? 0} medium</span>
              <button className="btn" style={{ marginLeft: "auto", fontSize: 11, padding: "3px 8px" }} onClick={() => toggle(s)}>
                {isOpen(s) ? "Hide" : `Details (${s.findings?.length ?? 0})`}
              </button>
              <button className="btn" style={{ fontSize: 11, padding: "3px 8px" }}
                onClick={() => exportReport({ ...s, params_tested: s.params_tested ?? [] } as ScanResult)}>Export</button>
              <button className="btn danger" style={{ fontSize: 11, padding: "3px 8px" }} onClick={() => remove(s.id)}>Delete</button>
            </div>
            {isOpen(s) && (
              <div style={{ marginTop: 12 }}>
                {(() => {
                  const list = sevFilter ? (s.findings ?? []).filter((f: any) => f.severity === sevFilter) : (s.findings ?? []);
                  if (list.length === 0) return <p className="status-text">No {sevFilter} findings in this scan.</p>;
                  return list.map((f: any, i: number) => (
                  <div key={f.id ?? i} className="card" style={{ marginBottom: 6, borderLeft: `3px solid ${SEV_COLOR[f.severity] ?? "var(--border)"}`, padding: "10px 12px" }}>
                    <strong>{f.title}</strong>
                    <span className="tag" style={{ marginLeft: 8 }}>{f.severity}</span>
                    {f.parameter && <span className="tag">{f.parameter}</span>}
                    {f.vector && <span className="tag">via {f.vector}</span>}
                    {f.payload && <div style={{ fontSize: 12, marginTop: 4 }}><strong>Payload:</strong> <code>{f.payload}</code></div>}
                    <p className="status-text" style={{ margin: "4px 0 0" }}>{f.evidence}</p>
                  </div>
                  ));
                })()}
              </div>
            )}
          </div>
        ))}
      </div>
    </>
  );
}
