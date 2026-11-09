import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, Provider } from "../api";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "#ff5c5c",
  high: "#ff8c42",
  medium: "#ffc857",
  low: "#58a6ff",
  info: "#8b98ab",
};

// SVG donut slice path between two angles (degrees, 0 = up, clockwise)
function slicePath(cx: number, cy: number, r0: number, r1: number, a0: number, a1: number) {
  const rad = (d: number) => ((d - 90) * Math.PI) / 180;
  const x0 = cx + r1 * Math.cos(rad(a0)), y0 = cy + r1 * Math.sin(rad(a0));
  const x1 = cx + r1 * Math.cos(rad(a1)), y1 = cy + r1 * Math.sin(rad(a1));
  const x2 = cx + r0 * Math.cos(rad(a1)), y2 = cy + r0 * Math.sin(rad(a1));
  const x3 = cx + r0 * Math.cos(rad(a0)), y3 = cy + r0 * Math.sin(rad(a0));
  const large = a1 - a0 > 180 ? 1 : 0;
  return `M${x0},${y0} A${r1},${r1} 0 ${large} 1 ${x1},${y1} L${x2},${y2} A${r0},${r0} 0 ${large} 0 ${x3},${y3} Z`;
}

function SeverityDonut({ counts, total, onSelect }: { counts: Record<string, number>; total: number; onSelect: (sev: string) => void }) {
  const size = 220, cx = size / 2, cy = size / 2, r1 = 95, r0 = 62;
  let angle = 0;
  const slices = SEV_ORDER.filter((s) => counts[s] > 0).map((s) => {
    const frac = counts[s] / total;
    const a0 = angle, a1 = angle + frac * 360;
    angle = a1;
    return { sev: s, path: slicePath(cx, cy, r0, r1, a0, a1), pct: frac * 100 };
  });
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ display: "block", margin: "0 auto" }}>
      {slices.map(({ sev, path }) => (
        <path
          key={sev}
          d={path}
          fill={SEV_COLOR[sev]}
          style={{ cursor: "pointer", opacity: 0.9, transition: "opacity .15s" }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = "1")}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = "0.75")}
          onClick={() => onSelect(sev)}
        >
          <title>{`${sev}: ${counts[sev]} (${counts[sev] / total * 100 | 0}%) — click to view`}</title>
        </path>
      ))}
      <text x={cx} y={cy - 4} textAnchor="middle" fill="var(--text)" fontSize="26" fontWeight="700">{total}</text>
      <text x={cx} y={cy + 16} textAnchor="middle" fill="var(--text-dim)" fontSize="11">findings</text>
    </svg>
  );
}

export default function Dashboard() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    api.providers().then((r) => setProviders(r.providers)).catch(() => {});
    api.findings().then((r) => setFindings(r.findings)).catch(() => {});
  }, []);

  const connected = providers.filter((p) => p.status === "connected").length;

  // Aggregate severity counts across every stored scan's findings
  const sevCounts = useMemo(() => {
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const scan of findings) {
      for (const f of scan.findings ?? []) {
        const s = f.severity ?? "info";
        if (s in c) c[s]++;
      }
    }
    return c;
  }, [findings]);
  const totalFindings = SEV_ORDER.reduce((n, s) => n + sevCounts[s], 0);

  return (
    <>
      <h1>Dashboard</h1>
      <p className="subtitle">CYBERHUNTER AI — Multi-Model Security Analysis Platform</p>
      <div className="grid">
        <div className="card">
          <h2>AI Providers</h2>
          <p>{connected} of {providers.length} configured provider(s) connected.</p>
          <div className="btn-row">
            <Link to="/ai-config"><button className="btn primary">Manage AI Providers</button></Link>
          </div>
        </div>
        <div className="card">
          <h2>Vulnerability Scanner</h2>
          <p>Run target scans and analyze findings with AI.</p>
          <div className="btn-row">
            <Link to="/scan"><button className="btn">Open Scanner</button></Link>
          </div>
        </div>
        <div className="card">
          <h2>AI Playground</h2>
          <p>Test any connected model before using it in analysis.</p>
          <div className="btn-row">
            <Link to="/ai-playground"><button className="btn">Open Playground</button></Link>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h2>Findings Overview</h2>
        {totalFindings === 0 ? (
          <p className="status-text">No findings yet — run a scan from Scan Target.</p>
        ) : (
          <div style={{ display: "flex", gap: 32, alignItems: "center", flexWrap: "wrap" }}>
            <SeverityDonut counts={sevCounts} total={totalFindings} onSelect={(sev) => navigate(`/findings?sev=${sev}`)} />
            <div style={{ flex: 1, minWidth: 220 }}>
              {SEV_ORDER.map((sev) => (
                <div
                  key={sev}
                  onClick={() => navigate(`/findings?sev=${sev}`)}
                  style={{
                    display: "flex", alignItems: "center", gap: 10,
                    padding: "7px 10px", borderRadius: 8, cursor: "pointer",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <span style={{ width: 12, height: 12, borderRadius: 3, background: SEV_COLOR[sev], flex: "none" }} />
                  <span style={{ textTransform: "capitalize", width: 80 }}>{sev}</span>
                  <strong>{sevCounts[sev]}</strong>
                  <span className="status-text">({totalFindings ? Math.round((sevCounts[sev] / totalFindings) * 100) : 0}%)</span>
                </div>
              ))}
              <div className="status-text" style={{ marginTop: 10 }}>Klik segmen grafik atau baris di atas untuk melihat detail di Findings.</div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
