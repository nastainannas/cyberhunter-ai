import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { getDb, saveDbNow, encryptSecret, decryptSecret, addUsageLog } from "./db.js";
import { listProviderTypes, getAdapter, isKnownProvider } from "./providers/index.js";
import { ProviderError } from "./providers/base.js";
import { scanTarget } from "./scanner.js";
import { portScan, dnsLookup, fetchRobots, httpMethodsProbe } from "./tools.js";
import { handleFinding, listIncidents, createRule, updateRule, deleteRule, setIncidentStatus, clearIncidents, testWebhook, quarantineStatus, releaseQuarantine, initIncidentStore, addWhitelist, removeWhitelist } from "./incident.js";
import { saveCreds, hasCreds, listPrograms, programScope, autoHunt, huntStatus, stopHunt } from "./bugbounty.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 8787;

app.use(cors());
app.use(express.json({ limit: "2mb" }));

const db = getDb();
db.findings ??= [];
initIncidentStore();

// ---------- helpers ----------

function publicProvider(p) {
  return {
    id: p.id,
    provider_key: p.provider_key,
    name: p.name,
    base_url: p.base_url,
    type: p.type,
    has_api_key: !!p.encrypted_api_key,
    enabled: p.enabled,
    status: p.status ?? "not_configured",
    status_message: p.status_message ?? null,
    options: p.options ?? {},
    default_model: p.default_model ?? null,
    created_at: p.created_at,
    updated_at: p.updated_at,
  };
}

function runtimeConfig(p) {
  return {
    baseUrl: p.base_url,
    apiKey: p.encrypted_api_key ? decryptSecret(p.encrypted_api_key) : null,
    defaultModel: p.default_model,
    options: p.options ?? {},
  };
}

function findProvider(id) {
  return db.providers.find((p) => p.id === id);
}

function setStatus(p, status, message) {
  p.status = status;
  p.status_message = message ?? null;
  p.updated_at = new Date().toISOString();
  saveDbNow();
}

function handleError(res, err) {
  if (err instanceof ProviderError) {
    return res.status(err.status || 502).json({ ok: false, error: err.message, code: err.code });
  }
  if (err?.name === "AbortError" || /abort/i.test(err?.message ?? "")) {
    return res.status(504).json({ ok: false, error: "Request timed out. Check that the provider is reachable.", code: "TIMEOUT" });
  }
  if (/ECONNREFUSED|fetch failed|ENOTFOUND/i.test(err?.message ?? "")) {
    return res.status(502).json({ ok: false, error: "Cannot reach provider. For local providers, make sure Ollama/LM Studio is running.", code: "UNREACHABLE" });
  }
  return res.status(500).json({ ok: false, error: err.message || "Internal error", code: "INTERNAL" });
}

// ---------- provider types ----------

app.get("/api/provider-types", (_req, res) => {
  res.json({ ok: true, providers: listProviderTypes() });
});

// ---------- providers CRUD ----------

app.get("/api/providers", (_req, res) => {
  res.json({ ok: true, providers: db.providers.map(publicProvider) });
});

app.post("/api/providers", (req, res) => {
  const { id, provider_key, name, base_url, api_key, enabled, options, default_model } = req.body ?? {};
  if (!provider_key || !isKnownProvider(provider_key)) {
    return res.status(400).json({ ok: false, error: "Unknown provider_key" });
  }
  const adapter = getAdapter(provider_key);
  const now = new Date().toISOString();

  let p = id ? findProvider(id) : null;
  if (p) {
    p.name = name ?? p.name;
    p.base_url = base_url ?? p.base_url;
    p.enabled = enabled ?? p.enabled;
    p.options = { ...(p.options ?? {}), ...(options ?? {}) };
    p.default_model = default_model ?? p.default_model;
    if (api_key && api_key.trim()) p.encrypted_api_key = encryptSecret(api_key.trim());
    // If explicitly clearing key
    if (api_key === "") p.encrypted_api_key = null;
    p.updated_at = now;
  } else {
    p = {
      id: crypto.randomUUID(),
      provider_key,
      name: name || adapter.meta.name,
      type: adapter.meta.type,
      base_url: base_url || adapter.meta.defaultBaseUrl,
      encrypted_api_key: api_key && api_key.trim() ? encryptSecret(api_key.trim()) : null,
      enabled: enabled ?? true,
      status: "not_configured",
      options: options ?? {},
      default_model: default_model ?? null,
      created_at: now,
      updated_at: now,
    };
    db.providers.push(p);
  }
  saveDbNow();
  res.json({ ok: true, provider: publicProvider(p) });
});

app.delete("/api/providers/:id", (req, res) => {
  const idx = db.providers.findIndex((p) => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ ok: false, error: "Provider not found" });
  const removed = db.providers.splice(idx, 1)[0];
  db.models = db.models.filter((m) => m.provider_id !== removed.id);
  saveDbNow();
  res.json({ ok: true });
});

// ---------- test / models ----------

app.post("/api/providers/:id/test", async (req, res) => {
  const p = findProvider(req.params.id);
  if (!p) return res.status(404).json({ ok: false, error: "Provider not found" });
  const adapter = getAdapter(p.provider_key);
  try {
    setStatus(p, "connecting");
    const result = await adapter.testConnection(runtimeConfig(p));
    setStatus(p, "connected", result.message);
    // persist discovered models
    if (result.models?.length) {
      for (const name of result.models) {
        if (!db.models.find((m) => m.provider_id === p.id && m.model_name === name)) {
          db.models.push({
            id: crypto.randomUUID(),
            provider_id: p.id,
            model_name: name,
            model_display_name: name,
            is_available: true,
            capabilities: {},
            created_at: new Date().toISOString(),
          });
        }
      }
      saveDbNow();
    }
    res.json({ ok: true, message: result.message, models: result.models ?? [] });
  } catch (err) {
    setStatus(p, "error", err.message);
    handleError(res, err);
  }
});

app.post("/api/providers/:id/models", async (req, res) => {
  const p = findProvider(req.params.id);
  if (!p) return res.status(404).json({ ok: false, error: "Provider not found" });
  const adapter = getAdapter(p.provider_key);
  try {
    const models = await adapter.listModels(runtimeConfig(p));
    // upsert
    for (const m of models) {
      const existing = db.models.find((x) => x.provider_id === p.id && x.model_name === m.model_name);
      if (existing) {
        existing.is_available = true;
        existing.capabilities = m.capabilities ?? {};
        existing.model_display_name = m.model_display_name ?? m.model_name;
      } else {
        db.models.push({
          id: crypto.randomUUID(),
          provider_id: p.id,
          model_name: m.model_name,
          model_display_name: m.model_display_name ?? m.model_name,
          is_available: true,
          capabilities: m.capabilities ?? {},
          created_at: new Date().toISOString(),
        });
      }
    }
    // mark missing as unavailable
    const names = new Set(models.map((m) => m.model_name));
    for (const m of db.models.filter((x) => x.provider_id === p.id)) {
      if (!names.has(m.model_name)) m.is_available = false;
    }
    saveDbNow();
    res.json({ ok: true, models: db.models.filter((m) => m.provider_id === p.id && m.is_available) });
  } catch (err) {
    handleError(res, err);
  }
});

app.get("/api/models", (req, res) => {
  const providerId = req.query.provider_id;
  let models = db.models.filter((m) => m.is_available);
  if (providerId) models = models.filter((m) => m.provider_id === providerId);
  res.json({ ok: true, models });
});

// ---------- chat ----------

app.post("/api/chat", async (req, res) => {
  const { provider_id, model, messages, temperature, max_tokens, stream, task_type } = req.body ?? {};
  const p = provider_id ? findProvider(provider_id) : db.providers.find((x) => x.enabled);
  if (!p) return res.status(400).json({ ok: false, error: "No provider configured. Add one in AI Configuration." });
  if (!p.enabled) return res.status(400).json({ ok: false, error: "Provider is disabled." });
  const adapter = getAdapter(p.provider_key);
  const config = runtimeConfig(p);
  const request = {
    model: model || p.default_model,
    messages,
    temperature,
    maxTokens: max_tokens,
    stream: !!stream,
  };
  const started = Date.now();

  if (stream) {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    try {
      let full = "";
      for await (const chunk of adapter.chatStream(config, request)) {
        if (chunk.type === "delta") full += chunk.content;
        res.write(`data: ${JSON.stringify(chunk)}\n\n`);
      }
      res.write(`data: ${JSON.stringify({ type: "meta", provider: p.provider_key, model: request.model, elapsed_ms: Date.now() - started })}\n\n`);
      res.end();
      addUsageLog({
        provider_name: adapter.meta.name,
        model_name: request.model,
        task_type: task_type ?? "chat",
        response_time: Date.now() - started,
        request_status: "success",
      });
    } catch (err) {
      res.write(`data: ${JSON.stringify({ type: "error", error: err.message, code: err.code })}\n\n`);
      res.end();
      addUsageLog({
        provider_name: adapter.meta.name,
        model_name: request.model,
        task_type: task_type ?? "chat",
        response_time: Date.now() - started,
        request_status: "error",
      });
    }
    return;
  }

  try {
    const result = await adapter.chat(config, request);
    const elapsed = Date.now() - started;
    addUsageLog({
      provider_name: adapter.meta.name,
      model_name: result.model ?? request.model,
      task_type: task_type ?? "chat",
      response_time: elapsed,
      token_usage: result.usage ?? null,
      request_status: "success",
    });
    res.json({ ok: true, provider: p.provider_key, provider_name: adapter.meta.name, model: result.model ?? request.model, content: result.content, usage: result.usage, elapsed_ms: elapsed });
  } catch (err) {
    addUsageLog({
      provider_name: adapter.meta.name,
      model_name: request.model,
      task_type: task_type ?? "chat",
      response_time: Date.now() - started,
      request_status: "error",
    });
    handleError(res, err);
  }
});

// ---------- vulnerability scanner ----------

app.post("/api/scan", async (req, res) => {
  const { target } = req.body ?? {};
  if (!target || typeof target !== "string") {
    return res.status(400).json({ ok: false, error: "Target URL is required." });
  }
  const q = quarantineStatus(target);
  if (q && !req.body?.force) {
    return res.status(423).json({ ok: false, quarantined: true, error: `Target ${q.origin} is quarantined by incident response (${q.reason}). Release it in Incident Response page or pass force:true.`, quarantine: q });
  }
  try {
    const result = await scanTarget(target, {
      mode: req.body?.mode, auth: req.body?.auth,
      maxPages: req.body?.maxPages, maxDepth: req.body?.maxDepth,
      maxProbeRequests: req.body?.maxProbeRequests, requestDelayMs: req.body?.requestDelayMs,
      includeSubdomains: req.body?.includeSubdomains,
    });
    if (!result.ok) return res.status(400).json(result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// SSE streaming scan — emits live progress logs, then final result
app.post("/api/scan/stream", async (req, res) => {
  const { target } = req.body ?? {};
  if (!target || typeof target !== "string") {
    return res.status(400).json({ ok: false, error: "Target URL is required." });
  }
  const q = quarantineStatus(target);
  if (q && !req.body?.force) {
    return res.status(423).json({ ok: false, quarantined: true, error: `Target ${q.origin} is quarantined by incident response (${q.reason}).`, quarantine: q });
  }
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  const send = (data) => { try { res.write(`data: ${JSON.stringify(data)}\n\n`); } catch { /* client gone */ } };
  // if the client disconnects mid-scan, tell the scanner to stop at the next request
  let cancelled = false;
  res.on("close", () => { if (!res.writableEnded) cancelled = true; });

  // Live persistence: a findings record is created up-front and updated on
  // every confirmed vulnerability, so even a stopped/crashed scan leaves a
  // complete, exportable report in the database.
  const entry = {
    id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    target: String(target),
    mode: req.body?.mode === "passive" ? "passive" : "active",
    status: 0, elapsed_ms: 0, pages_crawled: 0,
    authenticated: false, cancelled: false, live: true,
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findings: [],
  };
  const recount = () => {
    const c = { total: entry.findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of entry.findings) c[f.severity in c ? f.severity : "info"]++;
    entry.summary = c;
  };
  db.findings.unshift(entry);
  if (db.findings.length > 200) db.findings.length = 200;
  saveDbNow();

  try {
    const result = await scanTarget(target, {
      mode: req.body?.mode, auth: req.body?.auth,
      maxPages: req.body?.maxPages, maxDepth: req.body?.maxDepth,
      maxProbeRequests: req.body?.maxProbeRequests, requestDelayMs: req.body?.requestDelayMs,
      includeSubdomains: req.body?.includeSubdomains,
      isCancelled: () => cancelled,
      out: { findings: [], testedParams: new Set() },
      onFinding: (f) => {
        entry.findings.push(f);
        recount();
        saveDbNow();
        send({ type: "finding", finding: f });
        handleFinding(f, entry.target).catch(() => {});
      },
    }, (msg) => send({ type: "log", message: msg }));
    // finalize the record with the official result (covers any findings the
    // live feed may have missed, plus status/pages/params)
    Object.assign(entry, {
      status: result.status ?? 0,
      elapsed_ms: result.elapsed_ms ?? 0,
      pages_crawled: result.pages_crawled ?? 0,
      authenticated: !!result.authenticated,
      cancelled: !!result.cancelled,
      findings: result.findings ?? entry.findings,
      summary: result.summary ?? entry.summary,
      live: false,
    });
    saveDbNow();
    send({ type: result.ok ? (result.cancelled ? "cancelled" : "result") : "error", ...result });
  } catch (err) {
    entry.live = false;
    entry.error = err.message;
    saveDbNow();
    send({ type: "error", ok: false, error: err.message });
  }
  try { res.end(); } catch { /* ignore */ }
});

// ---------- recon tools ----------

function validHost(h) {
  return typeof h === "string" && /^[a-zA-Z0-9.-]+$/.test(h) && !h.includes("..") && h.length < 255;
}

// SSE port scan with live logs
app.post("/api/tools/portscan/stream", async (req, res) => {
  const { host, ports } = req.body ?? {};
  if (!validHost(host)) return res.status(400).json({ ok: false, error: "Invalid host." });
  const portList = Array.isArray(ports) && ports.length ? ports.filter((p) => p > 0 && p < 65536).slice(0, 200) : undefined;
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  const send = (d) => res.write(`data: ${JSON.stringify(d)}\n\n`);
  try {
    send({ type: "log", message: `Port scanning ${host} — ${portList?.length ?? 26} ports, concurrency 20` });
    const result = await portScan(host, { ports: portList, log: (m) => send({ type: "log", message: m }) });
    send({ type: "result", ...result });
  } catch (e) {
    send({ type: "error", ok: false, error: e.message });
  }
  res.end();
});

app.get("/api/tools/dns", async (req, res) => {
  const host = req.query.host;
  if (!validHost(host)) return res.status(400).json({ ok: false, error: "Invalid host." });
  try { res.json({ ok: true, ...(await dnsLookup(host)) }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/api/tools/robots", async (req, res) => {
  const { url } = req.body ?? {};
  let u;
  try { u = new URL(url?.startsWith("http") ? url : "https://" + url); } catch { return res.status(400).json({ ok: false, error: "Invalid URL." }); }
  try { res.json({ ok: true, ...(await fetchRobots(u.origin)) }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/api/tools/httpmethods", async (req, res) => {
  const { url } = req.body ?? {};
  let u;
  try { u = new URL(url?.startsWith("http") ? url : "https://" + url); } catch { return res.status(400).json({ ok: false, error: "Invalid URL." }); }
  try { res.json({ ok: true, methods: await httpMethodsProbe(u.toString()) }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ---------- findings database ----------

app.get("/api/findings", (_req, res) => {
  res.json({ ok: true, findings: db.findings });
});

app.post("/api/findings", (req, res) => {
  const { scan } = req.body ?? {};
  if (!scan?.target) return res.status(400).json({ ok: false, error: "scan.target required" });
  const entry = {
    id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    target: scan.target,
    status: scan.status,
    elapsed_ms: scan.elapsed_ms,
    pages_crawled: scan.pages_crawled,
    summary: scan.summary,
    findings: scan.findings ?? [],
  };
  db.findings.unshift(entry);
  if (db.findings.length > 200) db.findings.length = 200;
  saveDbNow();
  res.json({ ok: true, finding: entry });
});

app.delete("/api/findings", (_req, res) => {
  db.findings = [];
  saveDbNow();
  res.json({ ok: true });
});

app.delete("/api/findings/:id", (req, res) => {
  const idx = db.findings.findIndex((f) => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ ok: false, error: "Not found" });
  db.findings.splice(idx, 1);
  saveDbNow();
  res.json({ ok: true });
});

// ---------- incident response ----------

app.get("/api/incidents", (_req, res) => {
  res.json({ ok: true, ...listIncidents() });
});

app.post("/api/incidents/rules", (req, res) => {
  const r = createRule(req.body ?? {});
  if (r.error) return res.status(400).json({ ok: false, error: r.error });
  res.json({ ok: true, rule: r.rule });
});

app.put("/api/incidents/rules/:id", (req, res) => {
  const r = updateRule(req.params.id, req.body ?? {});
  if (r.error) return res.status(404).json({ ok: false, error: r.error });
  res.json({ ok: true, rule: r.rule });
});

app.delete("/api/incidents/rules/:id", (req, res) => {
  const r = deleteRule(req.params.id);
  if (r.error) return res.status(404).json({ ok: false, error: r.error });
  res.json(r);
});

app.post("/api/incidents/:id/status", (req, res) => {
  const r = setIncidentStatus(req.params.id, req.body?.status);
  if (r.error) return res.status(400).json({ ok: false, error: r.error });
  res.json({ ok: true, incident: r.incident });
});

app.delete("/api/incidents", (_req, res) => {
  res.json(clearIncidents());
});

app.post("/api/incidents/test-webhook", async (req, res) => {
  const url = String(req.body?.webhookUrl || "");
  if (!/^https?:\/\//i.test(url)) return res.status(400).json({ ok: false, error: "Invalid webhook URL" });
  const r = await testWebhook(req.body ?? {});
  res.json({ ok: r.ok, status: r.status, error: r.error });
});

// ---------- Bug Bounty platform integration ----------

app.post("/api/bounty/credentials", (req, res) => {
  const platform = String(req.body?.platform ?? "");
  if (!["hackerone", "yeswehack"].includes(platform)) {
    return res.status(400).json({ ok: false, error: "platform must be hackerone or yeswehack" });
  }
  res.json(saveCreds(platform, req.body ?? {}));
});

app.get("/api/bounty/status", (req, res) => {
  // YesWeHack works via public scraping without credentials
  res.json({ hackerone: hasCreds("hackerone"), yeswehack: true });
});

app.get("/api/bounty/programs", async (req, res) => {
  const platform = String(req.query.platform ?? "hackerone");
  const r = await listPrograms(platform, {
    pageSize: Math.min(parseInt(req.query.size, 10) || 25, 100),
    page: parseInt(req.query.page, 10) || 1,
    query: String(req.query.q ?? ""),
  });
  if (r.error) return res.status(r.needCreds ? 428 : 502).json({ ok: false, ...r });
  res.json({ ok: true, ...r });
});

app.get("/api/bounty/programs/:platform/:handle/scope", async (req, res) => {
  const r = await programScope(req.params.platform, req.params.handle);
  if (r.error) return res.status(r.needCreds ? 428 : 502).json({ ok: false, ...r });
  res.json({ ok: true, ...r });
});

app.post("/api/bounty/auto-hunt", (req, res) => {
  const r = autoHunt({
    platform: String(req.body?.platform ?? "hackerone"),
    maxPrograms: Math.min(parseInt(req.body?.maxPrograms, 10) || 5, 50),
    mode: req.body?.mode === "active" ? "active" : "passive",
    maxPages: Math.min(parseInt(req.body?.maxPages, 10) || 25, 100),
    requestDelayMs: Math.min(parseInt(req.body?.requestDelayMs, 10) || 300, 5000),
    perTargetTimeoutMs: Math.min(parseInt(req.body?.perTargetTimeoutMs, 10) || 8 * 60 * 1000, 30 * 60 * 1000),
    programType: ["bounty", "vdp", "all"].includes(req.body?.programType) ? req.body.programType : "bounty",
  });
  if (r.error) return res.status(r.needCreds ? 428 : 409).json({ ok: false, ...r });
  res.json(r);
});

app.get("/api/bounty/auto-hunt/status", (req, res) => {
  res.json({ ok: true, ...huntStatus() });
});

app.post("/api/bounty/auto-hunt/stop", (req, res) => {
  res.json(stopHunt());
});

app.delete("/api/quarantine/:origin", (req, res) => {
  const origin = decodeURIComponent(req.params.origin);
  const r = releaseQuarantine(origin);
  if (r.error) return res.status(404).json({ ok: false, error: r.error });
  res.json(r);
});

app.post("/api/quarantine-whitelist", (req, res) => {
  const r = addWhitelist(req.body?.origin ?? "");
  if (r.error) return res.status(400).json({ ok: false, error: r.error });
  res.json(r);
});

app.delete("/api/quarantine-whitelist/:origin", (req, res) => {
  const r = removeWhitelist(decodeURIComponent(req.params.origin));
  if (r.error) return res.status(404).json({ ok: false, error: r.error });
  res.json(r);
});

// ---------- usage logs ----------

app.get("/api/usage-logs", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit ?? "100", 10), 500);
  res.json({ ok: true, logs: db.usageLogs.slice(0, limit) });
});

// ---------- settings (router config etc.) ----------

app.get("/api/settings", (_req, res) => {
  res.json({ ok: true, settings: db.settings });
});

app.put("/api/settings", (req, res) => {
  db.settings = { ...db.settings, ...(req.body ?? {}) };
  saveDbNow();
  res.json({ ok: true, settings: db.settings });
});

// ---------- static frontend (production build) ----------

const distDir = path.join(__dirname, "..", "..", "frontend", "dist");
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir));
  app.get("*", (_req, res) => res.sendFile(path.join(distDir, "index.html")));
}

app.listen(PORT, () => {
  console.log(`CYBERHUNTER backend listening on http://localhost:${PORT}`);
});
