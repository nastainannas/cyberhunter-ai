import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export default function BugBounty() {
  const [platform, setPlatform] = useState<"hackerone" | "yeswehack">("hackerone");
  const [status, setStatus] = useState({ hackerone: false, yeswehack: false });
  const [creds, setCreds] = useState<any>({ username: "", token: "", clientId: "", clientSecret: "" });
  const [credMsg, setCredMsg] = useState("");
  const [q, setQ] = useState("");
  const [programs, setPrograms] = useState<any[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [scopes, setScopes] = useState<Record<string, any[]>>({});
  const [scopeLoading, setScopeLoading] = useState<Record<string, boolean>>({});
  const [hunt, setHunt] = useState<any>(null);
  const [huntCfg, setHuntCfg] = useState({ maxPrograms: 5, mode: "passive" as "passive" | "active", programType: "bounty" as "bounty" | "vdp" | "all" });
  const [huntMsg, setHuntMsg] = useState("");

  async function loadStatus() {
    const s = await api.bountyStatus();
    setStatus(s);
  }
  useEffect(() => { loadStatus().catch(() => {}); }, []);

  async function saveCreds() {
    setCredMsg("");
    try {
      await api.saveBountyCreds({ platform, ...creds });
      setCredMsg("Credentials saved (encrypted).");
      setCreds({ username: "", token: "", clientId: "", clientSecret: "" });
      loadStatus();
      loadPrograms(1);
    } catch (e: any) { setCredMsg(e.message); }
  }

  async function loadPrograms(p = page) {
    setLoading(true); setErr("");
    try {
      const r = await api.bountyPrograms(platform, q, p);
      if (r.error) { setErr(r.error); setPrograms([]); }
      else setPrograms(r.programs ?? []);
      setPage(p);
    } catch (e: any) { setErr(e.message); setPrograms([]); }
    setLoading(false);
  }

  async function loadScope(handle: string) {
    if (scopes[handle] || scopeLoading[handle]) return;
    setScopeLoading((s) => ({ ...s, [handle]: true }));
    try {
      const r = await api.bountyScope(platform, handle);
      setScopes((s) => ({ ...s, [handle]: r.scopes ?? [] }));
    } catch { setScopes((s) => ({ ...s, [handle]: [] })); }
    setScopeLoading((s) => ({ ...s, [handle]: false }));
  }

  async function huntStatus() {
    try {
      const r = await api.autoHuntStatus();
      setHunt(r);
      if (r.running || r.job?.status === "discovering" || r.job?.status === "scanning") {
        setTimeout(huntStatus, 3000);
      }
    } catch { /* ignore */ }
  }

  useEffect(() => { huntStatus(); }, []);

  async function startHunt() {
    setHuntMsg("");
    try {
      const r = await api.startAutoHunt({ platform, ...huntCfg });
      if (r.error) setHuntMsg(r.error);
      else { setHuntMsg("Hunt started — discovering programs…"); huntStatus(); }
    } catch (e: any) { setHuntMsg(e.message); }
  }

  async function stopHunt() {
    await api.stopAutoHunt();
    huntStatus();
  }

  function assetToTarget(asset: string): string | null {
    // Scope assets can be domains, URLs, wildcards, IPs, APIs — only URL-ish ones are scannable
    const a = asset.trim();
    if (/^\*?\.?[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(a) && !/^\*/.test(a)) {
      return "https://" + a.replace(/^\*\./, "");
    }
    if (/^https?:\/\//i.test(a)) return a;
    return null;
  }

  const configured = platform === "hackerone" ? status.hackerone : status.yeswehack;

  return (
    <>
      <h1>Bug Bounty Hunter</h1>
      <p className="subtitle">
        Browse public bug bounty programs and their official scopes, then scan in-scope targets directly.
        Only scan assets listed in the program's policy — unauthorized scanning is illegal.
      </p>

      <div className="card">
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          {(["hackerone", "yeswehack"] as const).map((p) => (
            <button key={p} className={platform === p ? "btn primary" : "btn"} onClick={() => { setPlatform(p); setPrograms([]); setScopes({}); setErr(""); }}>
              {p === "hackerone" ? "HackerOne" : "YesWeHack"} {status[p] ? "●" : "○"}
            </button>
          ))}
        </div>

        {!configured && (
          <div>
            <p className="status-text">
              {platform === "hackerone"
                ? "HackerOne API needs your API username + API token (Settings → API Token di hackerone.com)."
                : "YesWeHack API needs OAuth client_id + client_secret (developer.yeswehack.com)."}
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, maxWidth: 640 }}>
              {platform === "hackerone" ? (
                <>
                  <input placeholder="API Username" value={creds.username} onChange={(e) => setCreds({ ...creds, username: e.target.value })} />
                  <input placeholder="API Token" type="password" value={creds.token} onChange={(e) => setCreds({ ...creds, token: e.target.value })} />
                </>
              ) : (
                <>
                  <input placeholder="Client ID" value={creds.clientId} onChange={(e) => setCreds({ ...creds, clientId: e.target.value })} />
                  <input placeholder="Client Secret" type="password" value={creds.clientSecret} onChange={(e) => setCreds({ ...creds, clientSecret: e.target.value })} />
                </>
              )}
            </div>
            <div style={{ marginTop: 8, display: "flex", gap: 8, alignItems: "center" }}>
              <button className="btn primary" onClick={saveCreds}>Save Credentials</button>
              {credMsg && <span className="status-text">{credMsg}</span>}
            </div>
          </div>
        )}

        {configured && (
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <input placeholder="Search programs…" value={q} onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && loadPrograms(1)} style={{ flex: 1 }} />
            <button className="btn primary" onClick={() => loadPrograms(1)} disabled={loading}>Search</button>
          </div>
        )}

        {err && <div className="notice" style={{ color: "var(--danger)" }}>{err}</div>}
        {loading && <p className="status-text">Loading programs…</p>}

        {configured && (
          <div className="card" style={{ borderLeft: "3px solid var(--warn)", marginBottom: 14 }}>
            <h3 style={{ marginTop: 0 }}>Auto Hunt</h3>
            <p className="status-text" style={{ marginTop: -6 }}>
              Automatically discover public {platform === "hackerone" ? "HackerOne" : "YesWeHack"} programs,
              collect their in-scope URL assets, and scan them one by one. Findings are saved to Findings Database.
            </p>
            <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
              <label style={{ fontSize: 13 }}>Programs:
                <input type="number" min={1} max={50} value={huntCfg.maxPrograms}
                  onChange={(e) => setHuntCfg({ ...huntCfg, maxPrograms: parseInt(e.target.value, 10) || 1 })}
                  style={{ width: 60, marginLeft: 6 }} />
              </label>
              <label style={{ fontSize: 13 }}>Program type:
                <select value={huntCfg.programType} onChange={(e) => setHuntCfg({ ...huntCfg, programType: e.target.value as any })} style={{ marginLeft: 6 }}>
                  <option value="bounty">Bounty (paid)</option>
                  <option value="vdp">VDP (no bounty — no ID verification needed)</option>
                  <option value="all">All programs</option>
                </select>
              </label>
              <label style={{ fontSize: 13 }}>Mode:
                <select value={huntCfg.mode} onChange={(e) => setHuntCfg({ ...huntCfg, mode: e.target.value as any })} style={{ marginLeft: 6 }}>
                  <option value="passive">Passive (recon only)</option>
                  <option value="active">Active (send probes)</option>
                </select>
              </label>
              {hunt?.running || hunt?.status === "discovering" || hunt?.status === "scanning" ? (
                <button className="btn danger" onClick={stopHunt}>Stop Hunt</button>
              ) : (
                <button className="btn primary" onClick={startHunt}>Start Auto Hunt</button>
              )}
              {huntMsg && <span className="status-text">{huntMsg}</span>}
            </div>
            {hunt?.job && (
              <div style={{ marginTop: 10, fontSize: 13 }}>
                <div className="status-text">
                  Status: <strong>{hunt.job.status}</strong> · programs seen: {hunt.job.programs_seen}
                  {hunt.job.targets_total != null && ` · targets: ${hunt.job.done}/${hunt.job.targets_total}`}
                  {hunt.job.current && ` · now: ${hunt.job.current}`}
                </div>
                {(hunt.job.targets ?? []).length > 0 && (
                  <div style={{ marginTop: 8, maxHeight: 220, overflowY: "auto" }}>
                    {hunt.job.targets.map((t: any, i: number) => (
                      <div key={i} style={{ display: "flex", gap: 8, padding: "4px 0", borderBottom: "1px solid var(--border)", fontSize: 12 }}>
                        <span className="tag" style={{
                          color: t.status === "done" ? "var(--info)" : t.status === "error" ? "var(--danger)" : "var(--warn)",
                        }}>{t.status}</span>
                        <code style={{ flex: 1 }}>{t.target}</code>
                        {t.wildcard && <span className="tag" style={{ color: "var(--warn)" }}>+subdomains</span>}
                        <span className="tag">{t.program}</span>
                        {t.findings != null && <span className="tag">{t.findings} findings</span>}
                        {t.error && <span style={{ color: "var(--danger)" }}>{t.error}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {programs.map((p) => (
          <div key={p.handle} className="card" style={{ marginBottom: 8, borderLeft: "3px solid var(--info)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <strong>{p.name}</strong>
              <span className="tag">{p.handle}</span>
              {p.bounty && <span className="tag" style={{ color: "var(--warn)" }}>bounty</span>}
              <span className="tag" style={{ color: p.state === "public_mode" || p.submission_state === "open" ? "var(--info)" : "var(--text-dim)" }}>{p.state}/{p.submission_state}</span>
              <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
                <a className="btn" style={{ fontSize: 11, padding: "3px 10px", textDecoration: "none" }} href={p.url} target="_blank" rel="noreferrer">Program page</a>
                <button className="btn" style={{ fontSize: 11, padding: "3px 10px" }} onClick={() => loadScope(p.handle)}>
                  {scopeLoading[p.handle] ? "Loading…" : scopes[p.handle] ? `Scope (${scopes[p.handle].length})` : "Scope"}
                </button>
              </span>
            </div>
            {scopes[p.handle] && (
              <div style={{ marginTop: 10 }}>
                {scopes[p.handle].length === 0 && <p className="status-text">No in-scope assets returned by API.</p>}
                {scopes[p.handle].map((s, i) => {
                  const target = assetToTarget(s.asset_identifier);
                  return (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0", borderBottom: "1px solid var(--border)", fontSize: 13 }}>
                      <code style={{ flex: 1 }}>{s.asset_identifier}</code>
                      <span className="tag">{s.asset_type}</span>
                      {s.eligible_for_bounty && <span className="tag" style={{ color: "var(--warn)" }}>bounty-eligible</span>}
                      {target
                        ? <Link className="btn primary" style={{ fontSize: 11, padding: "2px 8px", textDecoration: "none" }} to={`/scan?target=${encodeURIComponent(target)}`}>Scan</Link>
                        : <span className="tag" style={{ color: "var(--text-dim)" }}>manual</span>}
                    </div>
                  );
                })}
                <p className="status-text" style={{ marginTop: 8, fontSize: 11 }}>
                  Scanning a "Scan" target jumps to Scan Target prefilled — verify it is in scope and check the program policy first.
                </p>
              </div>
            )}
          </div>
        ))}

        {configured && programs.length > 0 && (
          <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
            <button className="btn" disabled={page <= 1} onClick={() => loadPrograms(page - 1)}>← Prev</button>
            <span className="status-text" style={{ alignSelf: "center" }}>Page {page}</span>
            <button className="btn" onClick={() => loadPrograms(page + 1)}>Next →</button>
          </div>
        )}
      </div>
    </>
  );
}
