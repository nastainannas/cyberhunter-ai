// Automated Incident Response — rules engine.
// When a finding meets a rule's severity threshold, an incident is created
// and configured actions run (webhook notification + incident ticket).
import crypto from "node:crypto";
import { getDb, saveDbNow } from "./db.js";

const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const DEDUPE_MS = 24 * 60 * 60 * 1000;

export function initIncidentStore() {
  const db = getDb();
  db.incidentRules ??= [];
  db.incidents ??= [];
  return db;
}

function incidentText(inc) {
  return [
    `[CYBERHUNTER AI] ${String(inc.severity).toUpperCase()} — ${inc.name}`,
    `Target: ${inc.target}`,
    `URL: ${inc.url || "-"}`,
    `Parameter: ${inc.param || "-"}`,
    `Payload: ${inc.payload || "-"}`,
    `OWASP: ${inc.owasp || "-"}`,
    `Recommendation: ${inc.recommendation || "-"}`,
  ].join("\n");
}

export async function sendWebhook(webhookType, webhookUrl, inc) {
  const text = incidentText(inc);
  let body;
  if (webhookType === "discord") body = { content: text.slice(0, 1900) };
  else if (webhookType === "slack") body = { text };
  else body = { source: "cyberhunter-ai", incident: { ...inc, actions: undefined }, text };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
      redirect: "follow",
    });
    return { ok: r.ok, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    clearTimeout(timer);
  }
}

// Called (fire-and-forget) for every confirmed finding during a scan.
export async function handleFinding(f, target) {
  try {
    const db = initIncidentStore();
    for (const rule of db.incidentRules) {
      if (!rule.enabled) continue;
      if ((SEV[f.severity] ?? 0) < (SEV[rule.minSeverity] ?? SEV.high)) continue;
      const sig = `${rule.id}|${target}|${f.name}|${f.param ?? ""}|${f.url ?? ""}`;
      const dup = db.incidents.find((i) =>
        i.sig === sig && i.status !== "resolved" &&
        Date.now() - new Date(i.created_at).getTime() < DEDUPE_MS);
      if (dup) continue;

      const inc = {
        id: crypto.randomUUID(),
        sig,
        created_at: new Date().toISOString(),
        rule_id: rule.id,
        rule_name: rule.name,
        target,
        status: "open",
        severity: f.severity,
        name: f.name,
        category: f.category ?? "",
        owasp: f.owasp ?? "",
        url: f.url ?? "",
        param: f.param ?? "",
        payload: f.payload ?? "",
        recommendation: f.recommendation ?? "",
        actions: [],
      };
      db.incidents.unshift(inc);
      if (db.incidents.length > 500) db.incidents.length = 500;

      if (rule.webhookUrl) {
        const res = await sendWebhook(rule.webhookType || "generic", rule.webhookUrl, inc);
        inc.actions.push({ type: "webhook", ok: !!res.ok, detail: res.status ?? res.error, at: new Date().toISOString() });
      }
      inc.actions.push({
        type: "ticket",
        ok: true,
        detail: "Incident ticket recorded — assign owner & apply remediation",
        at: new Date().toISOString(),
      });
      saveDbNow();
    }
  } catch { /* incident response must never break a scan */ }
}

// ---------- CRUD ----------
export function listIncidents() {
  const db = initIncidentStore();
  return { rules: db.incidentRules, incidents: db.incidents };
}

export function createRule(body) {
  const db = initIncidentStore();
  const rule = {
    id: crypto.randomUUID(),
    name: String(body.name || "Untitled rule").slice(0, 120),
    enabled: body.enabled !== false,
    minSeverity: ["critical", "high", "medium", "low", "info"].includes(body.minSeverity) ? body.minSeverity : "high",
    webhookType: ["generic", "discord", "slack"].includes(body.webhookType) ? body.webhookType : "generic",
    webhookUrl: String(body.webhookUrl || "").slice(0, 500),
    created_at: new Date().toISOString(),
  };
  if (rule.webhookUrl && !/^https?:\/\//i.test(rule.webhookUrl)) {
    return { error: "Webhook URL must start with http(s)://" };
  }
  db.incidentRules.push(rule);
  saveDbNow();
  return { rule };
}

export function updateRule(id, body) {
  const db = initIncidentStore();
  const r = db.incidentRules.find((x) => x.id === id);
  if (!r) return { error: "Rule not found" };
  if (body.name !== undefined) r.name = String(body.name).slice(0, 120);
  if (body.enabled !== undefined) r.enabled = !!body.enabled;
  if (body.minSeverity !== undefined && SEV[body.minSeverity] !== undefined) r.minSeverity = body.minSeverity;
  if (body.webhookType !== undefined && ["generic", "discord", "slack"].includes(body.webhookType)) r.webhookType = body.webhookType;
  if (body.webhookUrl !== undefined) {
    const u = String(body.webhookUrl).slice(0, 500);
    if (u && !/^https?:\/\//i.test(u)) return { error: "Webhook URL must start with http(s)://" };
    r.webhookUrl = u;
  }
  saveDbNow();
  return { rule: r };
}

export function deleteRule(id) {
  const db = initIncidentStore();
  const i = db.incidentRules.findIndex((x) => x.id === id);
  if (i < 0) return { error: "Rule not found" };
  db.incidentRules.splice(i, 1);
  saveDbNow();
  return { ok: true };
}

export function setIncidentStatus(id, status) {
  const db = initIncidentStore();
  const inc = db.incidents.find((x) => x.id === id);
  if (!inc) return { error: "Incident not found" };
  if (!["open", "acknowledged", "resolved"].includes(status)) return { error: "Invalid status" };
  inc.status = status;
  inc.status_at = new Date().toISOString();
  saveDbNow();
  return { incident: inc };
}

export function clearIncidents() {
  const db = initIncidentStore();
  db.incidents = [];
  saveDbNow();
  return { ok: true };
}

export async function testWebhook(body) {
  const fake = {
    id: "test", severity: "high", name: "Test Incident — webhook verification",
    target: "https://example.com", url: "https://example.com/?id=1",
    param: "id", payload: "test' OR '1'='1", owasp: "A03:2021 Injection",
    recommendation: "This is a test notification from CYBERHUNTER AI.",
  };
  return sendWebhook(body.webhookType || "generic", String(body.webhookUrl || ""), fake);
}
