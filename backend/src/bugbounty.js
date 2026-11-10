// Bug Bounty platform integration — fetch public program lists and their
// official scopes from HackerOne / YesWeHack so users can pick in-scope
// targets to scan. Credentials are stored encrypted in settings.
import crypto from "node:crypto";
import { getDb, saveDbNow, encryptSecret, decryptSecret } from "./db.js";

const H1_API = "https://api.hackerone.com";
const YWH_API = "https://api.yeswehack.com";

function creds(platform) {
  const db = getDb();
  const c = db.settings?.bountyCreds?.[platform];
  if (!c) return null;
  return {
    username: c.username,
    token: decryptSecret(c.token_enc) ?? "",
    clientId: c.client_id ?? "",
    clientSecret: decryptSecret(c.client_secret_enc) ?? "",
  };
}

export function saveCreds(platform, body) {
  const db = getDb();
  db.settings ??= {};
  db.settings.bountyCreds ??= {};
  const prev = db.settings.bountyCreds[platform] ?? {};
  db.settings.bountyCreds[platform] = {
    username: String(body.username ?? prev.username ?? "").slice(0, 120),
    token_enc: body.token ? encryptSecret(String(body.token)) : prev.token_enc ?? null,
    client_id: String(body.clientId ?? prev.client_id ?? "").slice(0, 200),
    client_secret_enc: body.clientSecret ? encryptSecret(String(body.clientSecret)) : prev.client_secret_enc ?? null,
    updated_at: new Date().toISOString(),
  };
  saveDbNow();
  return { ok: true };
}

export function hasCreds(platform) {
  return !!creds(platform)?.token || !!creds(platform)?.clientSecret;
}

async function h1Fetch(path, c) {
  try {
    // HackerOne API uses HTTP Basic: username:api_token
    const basic = Buffer.from(`${c.username}:${c.token}`).toString("base64");
    const r = await fetch(`${H1_API}${path}`, {
      headers: { Accept: "application/json", Authorization: `Basic ${basic}` },
      signal: AbortSignal.timeout(20000),
    });
    if (!r.ok) return { error: `HackerOne API ${r.status}`, status: r.status };
    return await r.json();
  } catch (e) {
    return { error: e.message };
  }
}

// ---------- HackerOne ----------

export async function h1Programs(c, { pageSize = 25, page = 1, query = "" } = {}) {
  let path = `/v1/hackers/programs?page%5Bsize%5D=${pageSize}&page%5Bnumber%5D=${page}`;
  if (query) path += `&filter%5Bquery%5D=${encodeURIComponent(query)}`;
  const j = await h1Fetch(path, c);
  if (j.error) return j;
  return {
    programs: (j.data ?? []).map((p) => ({
      platform: "hackerone",
      handle: p.attributes?.handle ?? p.id,
      name: p.attributes?.name ?? p.id,
      url: `https://hackerone.com/${p.attributes?.handle ?? p.id}`,
      bounty: !!p.attributes?.offers_bounties,
      state: p.attributes?.state ?? "unknown",
      submission_state: p.attributes?.submission_state ?? "unknown",
    })),
    total: j.links?.next ? undefined : (j.data ?? []).length,
  };
}

export async function h1Scope(c, handle) {
  const j = await h1Fetch(`/v1/hackers/programs/${encodeURIComponent(handle)}/structured_scopes?page%5Bsize%5D=100`, c);
  if (j.error) return j;
  const scopes = (j.data ?? []).map((s) => ({
    asset_identifier: s.attributes?.asset_identifier ?? "",
    asset_type: s.attributes?.asset_type ?? "",
    eligible_for_bounty: !!s.attributes?.eligible_for_bounty,
    eligible_for_submission: s.attributes?.eligible_for_submission !== false,
    instruction: s.attributes?.instruction ?? "",
    max_severity: s.attributes?.max_severity ?? "",
  })).filter((s) => s.eligible_for_submission);
  return { handle, scopes };
}

// ---------- YesWeHack ----------

async function ywhToken(c) {
  const r = await fetch(`${YWH_API}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: c.clientId,
      client_secret: c.clientSecret,
      scope: "api",
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!r.ok) return { error: `YesWeHack auth ${r.status}` };
  return r.json();
}

export async function ywhPrograms(c, { pageSize = 25, page = 1 } = {}) {
  const tok = await ywhToken(c);
  if (tok.error) return tok;
  const r = await fetch(`${YWH_API}/programs?page=${page}&items_per_page=${pageSize}`, {
    headers: { Authorization: `Bearer ${tok.access_token}`, Accept: "application/json" },
    signal: AbortSignal.timeout(20000),
  });
  if (!r.ok) return { error: `YesWeHack API ${r.status}` };
  const j = await r.json();
  const list = j.items ?? j.data ?? [];
  return {
    programs: list.map((p) => ({
      platform: "yeswehack",
      handle: String(p.id ?? p.slug ?? ""),
      name: p.title ?? p.name ?? String(p.id),
      url: p.url ?? `https://yeswehack.com/programs/${p.slug ?? p.id}`,
      bounty: true,
      state: p.status ?? "unknown",
      submission_state: "open",
    })),
  };
}

// ---------- Dispatcher ----------

export async function listPrograms(platform, opts = {}) {
  const c = creds(platform);
  if (!c) return { error: `No ${platform} credentials configured`, needCreds: true };
  if (platform === "hackerone") return h1Programs(c, opts);
  if (platform === "yeswehack") return ywhPrograms(c, opts);
  return { error: "Unknown platform" };
}

export async function programScope(platform, handle) {
  const c = creds(platform);
  if (!c) return { error: `No ${platform} credentials configured`, needCreds: true };
  if (platform === "hackerone") return h1Scope(c, handle);
  return { error: "Scope fetch not yet supported for this platform" };
}

// ---------- Auto Hunt ----------
// Automatically discover in-scope web assets from public bug bounty programs
// and scan them sequentially. Conservative by design: public programs only,
// URL-type assets only, one target at a time with a delay between scans.

import { scanTarget } from "./scanner.js";
import { handleFinding, quarantineStatus, isWhitelisted } from "./incident.js";

const huntState = {
  running: false,
  job: null, // {id, platform, started_at, status, programs_seen, targets: [{target, program, status, findings, error}], done, current}
};

export function huntStatus() {
  return huntState.job ? { ...huntState.job, running: huntState.running } : { running: false, job: null };
}

const SCOPED_TYPES = new Set(["url", "domain", "wildcard"]);

function scopeToTarget(asset) {
  const a = String(asset.asset_identifier ?? "").trim();
  if (!a) return null;
  // explicit URL
  if (/^https?:\/\//i.test(a)) {
    try { return new URL(a).origin; } catch { return null; }
  }
  // wildcard/domain — use apex-ish base (strip leading *.)
  const host = a.replace(/^\*\./, "").replace(/^\./, "").replace(/\/.*$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return null;
  if (/\s/.test(host) || host.includes("@")) return null;
  return "https://" + host;
}

export async function autoHunt({ platform = "hackerone", maxPrograms = 5, mode = "passive", maxPages = 25, requestDelayMs = 300 } = {}) {
  if (huntState.running) return { error: "A hunt is already running" };
  const c = creds(platform);
  if (!c) return { error: `No ${platform} credentials configured`, needCreds: true };

  huntState.running = true;
  const job = {
    id: crypto.randomUUID(),
    platform,
    mode,
    started_at: new Date().toISOString(),
    status: "discovering",
    programs_seen: 0,
    targets: [],
    done: 0,
    current: null,
  };
  huntState.job = job;

  (async () => {
    try {
      // 1) discover programs — public_mode only, bounty-paying preferred
      const seen = new Set();
      const candidates = [];
      for (let page = 1; page <= 10 && candidates.length < maxPrograms; page++) {
        const r = await h1Programs(c, { pageSize: 25, page });
        if (r.error || !r.programs?.length) break;
        for (const p of r.programs) {
          job.programs_seen++;
          if (p.state !== "public_mode" || p.submission_state !== "open") continue;
          if (seen.has(p.handle)) continue;
          seen.add(p.handle);
          candidates.push(p);
          if (candidates.length >= maxPrograms) break;
        }
        if (!r.programs.length || r.programs.length < 25) break;
      }

      // 2) collect in-scope URL assets
      const targets = [];
      for (const p of candidates) {
        const sc = await h1Scope(c, p.handle);
        if (sc.error || !sc.scopes) continue;
        for (const s of sc.scopes) {
          if (!SCOPED_TYPES.has((s.asset_type ?? "").toLowerCase())) continue;
          const t = scopeToTarget(s);
          if (!t) continue;
          const origin = (() => { try { return new URL(t).origin; } catch { return t; } })();
          if (isWhitelisted(origin)) continue;
          if (quarantineStatus(t)) continue;
          if (targets.some((x) => x.target === t)) continue;
          targets.push({ target: t, program: p.name, program_url: p.url, asset: s.asset_identifier });
        }
      }
      job.status = "scanning";
      job.targets_total = targets.length;

      // 3) scan sequentially — never parallel, delay between targets
      for (const t of targets) {
        if (huntState.job !== job) break; // superseded
        job.current = t.target;
        const rec = { ...t, status: "scanning", findings: 0, started_at: new Date().toISOString() };
        job.targets.push(rec);
        try {
          const res = await scanTarget(t.target, {
            mode,
            maxPages,
            requestDelayMs,
            onFinding: (f) => { handleFinding(f, t.target).catch(() => {}); },
          });
          rec.status = res.ok ? "done" : "error";
          rec.findings = res.findings?.length ?? res.summary?.total ?? 0;
          rec.error = res.ok ? undefined : res.error;
          rec.summary = res.summary;
          // persist the full scan record so it appears in Findings Database
          if (res.ok) {
            const db = getDb();
            db.findings ??= [];
            db.findings.unshift({
              id: crypto.randomUUID(),
              created_at: new Date().toISOString(),
              target: res.target ?? t.target,
              mode: res.mode ?? mode,
              status: res.status ?? 0,
              elapsed_ms: res.elapsed_ms ?? 0,
              pages_crawled: res.pages_crawled ?? 0,
              params_tested: res.params_tested ?? [],
              authenticated: !!res.authenticated,
              cancelled: !!res.cancelled,
              live: false,
              program: t.program,
              program_url: t.program_url,
              summary: res.summary,
              findings: res.findings ?? [],
            });
            if (db.findings.length > 200) db.findings.length = 200;
            saveDbNow();
          }
        } catch (e) {
          rec.status = "error";
          rec.error = e.message;
        }
        rec.finished_at = new Date().toISOString();
        job.done++;
        job.current = null;
        await new Promise((r) => setTimeout(r, Math.max(requestDelayMs, 1000)));
      }
      job.status = "done";
    } catch (e) {
      job.status = "error";
      job.error = e.message;
    } finally {
      huntState.running = false;
      job.finished_at = new Date().toISOString();
    }
  })();

  return { ok: true, job: { id: job.id } };
}

export function stopHunt() {
  if (!huntState.running) return { error: "No hunt running" };
  huntState.job.status = "stopped";
  huntState.job.current = null;
  huntState.running = false;
  return { ok: true };
}
