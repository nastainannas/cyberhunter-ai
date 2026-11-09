import { useEffect, useState } from "react";
import { api } from "../api";

const SEV_COLOR: Record<string, string> = {
  critical: "var(--danger)", high: "#ff8c42", medium: "var(--warn)", low: "var(--info)", info: "var(--text-dim)",
};
const SEVS = ["critical", "high", "medium", "low", "info"];
const STATUS_COLOR: Record<string, string> = {
  open: "var(--danger)", acknowledged: "var(--warn)", resolved: "var(--info)",
};

const emptyRule = { name: "", minSeverity: "high", webhookType: "generic", webhookUrl: "", enabled: true };

export default function IncidentResponse() {
  const [rules, setRules] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [form, setForm] = useState<any>(emptyRule);
  const [msg, setMsg] = useState("");
  const [testMsg, setTestMsg] = useState<Record<string, string>>({});

  async function load() {
    const r = await api.incidents();
    setRules(r.rules ?? []);
    setIncidents(r.incidents ?? []);
  }
  useEffect(() => { load().catch(() => {}); }, []);

  async function addRule() {
    setMsg("");
    try {
      await api.createIncidentRule(form);
      setForm(emptyRule);
      await load();
    } catch (e: any) { setMsg(e.message); }
  }

  async function toggleRule(r: any) {
    await api.updateIncidentRule(r.id, { enabled: !r.enabled });
    load();
  }

  async function removeRule(id: string) {
    if (!confirm("Delete this incident rule?")) return;
    await api.deleteIncidentRule(id);
    load();
  }

  async function testRule(r: any) {
    setTestMsg((m) => ({ ...m, [r.id]: "sending…" }));
    try {
      const res = await api.testIncidentWebhook({ webhookType: r.webhookType, webhookUrl: r.webhookUrl });
      setTestMsg((m) => ({ ...m, [r.id]: res.ok ? `OK (${res.status})` : `Failed: ${res.error ?? res.status}` }));
    } catch (e: any) {
      setTestMsg((m) => ({ ...m, [r.id]: `Failed: ${e.message}` }));
    }
  }

  async function setStatus(id: string, status: string) {
    await api.setIncidentStatus(id, status);
    load();
  }

  async function clearAll() {
    if (!confirm("Clear ALL incident records?")) return;
    await api.clearIncidents();
    load();
  }

  const open = incidents.filter((i) => i.status !== "resolved").length;

  return (
    <>
      <h1>Incident Response</h1>
      <p className="subtitle">
        Automated response rules — when a scan finding meets the severity threshold, an incident ticket is created
        and notifications are sent to your webhook (Discord / Slack / generic).
      </p>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Response Rules</h3>
        {msg && <div className="notice" style={{ color: "var(--danger)" }}>{msg}</div>}
        {rules.length === 0 && <p className="status-text">No rules yet — add one below to start automated incident response.</p>}
        {rules.map((r) => (
          <div key={r.id} className="card" style={{ marginBottom: 8, borderLeft: `3px solid ${r.enabled ? "var(--info)" : "var(--border)"}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <strong>{r.name}</strong>
              <span className="tag">min: {r.minSeverity}</span>
              <span className="tag">{r.webhookType}</span>
              {r.webhookUrl
                ? <span className="tag" style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.webhookUrl}</span>
                : <span className="tag" style={{ color: "var(--text-dim)" }}>no webhook — ticket only</span>}
              <span className="tag" style={{ color: r.enabled ? "var(--info)" : "var(--text-dim)" }}>{r.enabled ? "enabled" : "disabled"}</span>
              <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
                {r.webhookUrl && (
                  <button className="btn" style={{ fontSize: 11, padding: "3px 8px" }} onClick={() => testRule(r)}>Test</button>
                )}
                <button className="btn" style={{ fontSize: 11, padding: "3px 8px" }} onClick={() => toggleRule(r)}>{r.enabled ? "Disable" : "Enable"}</button>
                <button className="btn danger" style={{ fontSize: 11, padding: "3px 8px" }} onClick={() => removeRule(r.id)}>Delete</button>
              </span>
            </div>
            {testMsg[r.id] && <div className="status-text" style={{ marginTop: 6, fontSize: 12 }}>{testMsg[r.id]}</div>}
          </div>
        ))}

        <div className="card" style={{ marginTop: 12, borderLeft: "3px solid var(--info)" }}>
          <h3 style={{ marginTop: 0 }}>New Rule</h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <input placeholder="Rule name (e.g. Critical vulns → Discord)" value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <select value={form.minSeverity} onChange={(e) => setForm({ ...form, minSeverity: e.target.value })}>
              {SEVS.map((s) => <option key={s} value={s}>Severity ≥ {s}</option>)}
            </select>
            <select value={form.webhookType} onChange={(e) => setForm({ ...form, webhookType: e.target.value })}>
              <option value="generic">Generic webhook (JSON POST)</option>
              <option value="discord">Discord webhook</option>
              <option value="slack">Slack webhook</option>
            </select>
            <input placeholder="Webhook URL (optional — blank = ticket only)" value={form.webhookUrl}
              onChange={(e) => setForm({ ...form, webhookUrl: e.target.value })} />
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10, fontSize: 13 }}>
            <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
            Enabled
          </label>
          <div style={{ marginTop: 10 }}>
            <button className="btn primary" onClick={addRule} disabled={!form.name.trim()}>Add Rule</button>
          </div>
        </div>
      </div>

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <h3 style={{ margin: 0 }}>Incidents ({open} open / {incidents.length} total)</h3>
          <button className="btn danger" style={{ marginLeft: "auto", fontSize: 11, padding: "4px 12px" }} onClick={clearAll}>Clear All</button>
        </div>
        {incidents.length === 0 && <p className="status-text">No incidents yet. They are created automatically when a scan finding matches an enabled rule.</p>}
        {incidents.map((i) => (
          <div key={i.id} className="card" style={{ marginTop: 8, borderLeft: `3px solid ${SEV_COLOR[i.severity] ?? "var(--border)"}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span className="tag" style={{ color: SEV_COLOR[i.severity] }}>{i.severity}</span>
              <strong>{i.name}</strong>
              <span className="tag" style={{ color: STATUS_COLOR[i.status] }}>{i.status}</span>
              <span className="tag">{i.rule_name}</span>
              <span className="tag">{new Date(i.created_at).toLocaleString()}</span>
              <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
                {i.status !== "acknowledged" && <button className="btn" style={{ fontSize: 11, padding: "3px 8px" }} onClick={() => setStatus(i.id, "acknowledged")}>Ack</button>}
                {i.status !== "resolved" && <button className="btn" style={{ fontSize: 11, padding: "3px 8px" }} onClick={() => setStatus(i.id, "resolved")}>Resolve</button>}
              </span>
            </div>
            <div className="status-text" style={{ marginTop: 6, fontSize: 12 }}>
              {i.target} · {i.url || "-"} · param: {i.param || "-"}
              {i.actions?.length > 0 && (
                <span> · actions: {i.actions.map((a: any) => `${a.type}${a.ok ? "✓" : "✗"}`).join(", ")}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
