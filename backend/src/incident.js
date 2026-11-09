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
  db.quarantined ??= [];
  db.quarantineWhitelist ??= [];
  return db;
}

export function targetOrigin(target) {
  try {
    const u = new URL(/^https?:\/\//i.test(target) ? target : "https://" + target);
    return u.origin;
  } catch { return null; }
}

export function quarantineStatus(target) {
  const db = initIncidentStore();
  const origin = targetOrigin(target);
  if (!origin) return null;
  if (db.quarantineWhitelist.includes(origin)) return null;
  return db.quarantined.find((q) => q.origin === origin) ?? null;
}

export function isWhitelisted(origin) {
  return initIncidentStore().quarantineWhitelist.includes(origin);
}

function quarantineWebhook(origin, action, reason, rule) {
  const url = rule?.webhookUrl && rule?.quarantineWebhook === true ? rule.webhookUrl : null;
  if (!url) return;
  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source: "cyberhunter-ai", action, origin, reason }),
    signal: AbortSignal.timeout(8000),
    redirect: "follow",
  }).catch(() => {});
}

export function releaseQuarantine(origin, opts = {}) {
  const db = initIncidentStore();
  const i = db.quarantined.findIndex((q) => q.origin === origin);
  if (i < 0) return { error: "Not quarantined" };
  const [q] = db.quarantined.splice(i, 1);
  saveDbNow();
  if (!opts.silent) quarantineWebhook(origin, "release", q.reason, db.incidentRules.find((r) => r.id === q.rule_id));
  return { ok: true };
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
      const fname = f.title || f.name || f.category || "Finding";
      const furl = f.url || f.endpoint || "";
      const fparam = f.param || f.parameter || "";
      const sig = `${rule.id}|${target}|${fname}|${fparam}|${furl}`;
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
        name: fname,
        category: f.category ?? "",
        owasp: f.owasp ?? "",
        url: furl,
        param: fparam,
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

      // auto-containment: quarantine the target origin so future scans are
      // blocked until an operator releases it manually
      if (rule.quarantine) {
        const origin = targetOrigin(target);
        if (origin && !isWhitelisted(origin) && !db.quarantined.some((q) => q.origin === origin)) {
          db.quarantined.push({
            origin,
            reason: `${inc.severity}: ${inc.name}`,
            incident_id: inc.id,
            rule_id: rule.id,
            quarantined_at: new Date().toISOString(),
          });
          inc.actions.push({ type: "quarantine", ok: true, detail: `Target ${origin} quarantined`, at: new Date().toISOString() });
          quarantineWebhook(origin, "quarantine", `${inc.severity}: ${inc.name}`, rule);
        }
      }
      saveDbNow();
    }
  } catch { /* incident response must never break a scan */ }
}

// ---------- CRUD ----------
export function listIncidents() {
  const db = initIncidentStore();
  return { rules: db.incidentRules, incidents: db.incidents, quarantined: db.quarantined, whitelist: db.quarantineWhitelist };
}

export function addWhitelist(origin) {
  const o = targetOrigin(origin) ?? String(origin).trim();
  if (!o) return { error: "Invalid origin" };
  const db = initIncidentStore();
  if (!db.quarantineWhitelist.includes(o)) db.quarantineWhitelist.push(o);
  saveDbNow();
  return { ok: true, whitelist: db.quarantineWhitelist };
}

export function removeWhitelist(origin) {
  const db = initIncidentStore();
  const i = db.quarantineWhitelist.indexOf(origin);
  if (i < 0) return { error: "Not whitelisted" };
  db.quarantineWhitelist.splice(i, 1);
  saveDbNow();
  return { ok: true, whitelist: db.quarantineWhitelist };
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
    quarantine: body.quarantine === true,
    quarantineWebhook: body.quarantineWebhook === true,
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
  if (body.quarantine !== undefined) r.quarantine = !!body.quarantine;
  if (body.quarantineWebhook !== undefined) r.quarantineWebhook = !!body.quarantineWebhook;
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
  // auto-release: resolving the incident lifts quarantine entries it created
  if (status === "resolved") {
    for (const q of [...db.quarantined]) {
      if (q.incident_id === id) releaseQuarantine(q.origin);
    }
  }
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
