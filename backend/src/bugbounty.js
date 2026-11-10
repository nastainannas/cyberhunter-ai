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

export async function h1Programs(c, { pageSize = 25, page = 1, query = "", bounty } = {}) {
  let path = `/v1/hackers/programs?page%5Bsize%5D=${pageSize}&page%5Bnumber%5D=${page}`;
  if (query) path += `&filter%5Bquery%5D=${encodeURIComponent(query)}`;
  if (bounty === true || bounty === false) path += `&filter%5Boffers_bounties%5D=${bounty}`;
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

// ---------- YesWeHack public scraping (no credentials needed) ----------
// The official API requires an approved OAuth app; the public program pages
// are server-rendered HTML, so we parse them directly.

const YWH_WEB = "https://yeswehack.com";
const YWH_UA = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
  Accept: "text/html,application/xhtml+xml",
};

async function ywhFetchHtml(path) {
  try {
    const r = await fetch(`${YWH_WEB}${path}`, { headers: YWH_UA, signal: AbortSignal.timeout(25000), redirect: "follow" });
    if (!r.ok) return { error: `yeswehack.com ${r.status}` };
    return { html: await r.text() };
  } catch (e) {
    return { error: e.message };
  }
}

function decodeHtml(s) {
  return String(s)
    .replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
}

export async function ywhProgramsPublic({ page = 1 } = {}) {
  const p = Math.max(1, page | 0);
  const r = await ywhFetchHtml(`/programs?page=${p}`);
  if (r.error) return r;
  const seen = new Map();
  const re = /<a[^>]+href="(\/programs\/[a-z0-9][a-z0-9-]*)"[^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(r.html))) {
    const slug = m[1].split("/").pop();
    if (seen.has(slug)) continue;
    const txt = decodeHtml(m[2].replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
    if (!txt || /^view program$/i.test(txt)) continue;
    seen.set(slug, {
      platform: "yeswehack",
      handle: slug,
      name: txt,
      url: `${YWH_WEB}${m[1]}`,
      bounty: true,
      state: "public",
      submission_state: "open",
      via: "scrape",
    });
  }
  const programs = [...seen.values()];
  return { programs, total: programs.length, page: p, via: "scrape" };
}

export async function ywhScopePublic(slug) {
  const r = await ywhFetchHtml(`/programs/${encodeURIComponent(slug)}`);
  if (r.error) return r;
  const scopes = [];
  const re = /<tr[^>]*>([\s\S]*?)<\/tr>/g;
  let m;
  while ((m = re.exec(r.html))) {
    const row = m[1];
    if (!/mat-column-scope|cdk-column-scope/.test(row)) continue;
    const cells = [...row.matchAll(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/g)]
      .map((c) => decodeHtml(c[1].replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim());
    if (cells.length < 2) continue;
    const [asset, type = "", value = ""] = cells;
    if (!asset || /^(scope|asset)$/i.test(asset)) continue;
    const t = type.toLowerCase();
    // web-addressable assets only become scannable targets; mobile/hardware etc are kept but filtered downstream
    const isWeb = /web|domain|url|api|application|site|service/i.test(t) && !/mobile|ios|android|hardware|iot/i.test(t);
    scopes.push({
      asset_identifier: asset,
      asset_type: isWeb ? "url" : t || "other",
      eligible_for_bounty: true,
      eligible_for_submission: true,
      instruction: `${type}${value ? ` · value: ${value}` : ""}`,
      max_severity: "",
    });
  }
  const uniq = [...new Map(scopes.map((s) => [s.asset_identifier + "|" + s.asset_type, s])).values()];
  return { handle: slug, scopes: uniq, via: "scrape" };
}

// ---------- Dispatcher ----------

export async function listPrograms(platform, opts = {}) {
  if (platform === "yeswehack") return ywhProgramsPublic(opts); // public scrape — no creds needed
  const c = creds(platform);
  if (!c) return { error: `No ${platform} credentials configured`, needCreds: true };
  if (platform === "hackerone") return h1Programs(c, opts);
  return { error: "Unknown platform" };
}

export async function programScope(platform, handle) {
  if (platform === "yeswehack") return ywhScopePublic(handle);
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
  // explicit URL — may itself contain a wildcard host
  if (/^https?:\/\//i.test(a)) {
    try {
      const u = new URL(a);
      const wild = u.hostname.startsWith("*.");
      if (wild) u.hostname = u.hostname.slice(2);
      return { target: u.origin, wildcard: wild };
    } catch { return null; }
  }
  // wildcard/domain — *.example.com means "example.com + all subdomains"
  const wild = /^\*\./.test(a);
  const host = a.replace(/^\*\./, "").replace(/^\./, "").replace(/\/.*$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return null;
  if (/\s/.test(host) || host.includes("@")) return null;
  return { target: "https://" + host, wildcard: wild };
}

function persistScan(t, res, mode) {
  if (!res?.ok) return;
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

export async function autoHunt({ platform = "hackerone", maxPrograms = 5, mode = "passive", maxPages = 25, requestDelayMs = 300, perTargetTimeoutMs = 8 * 60 * 1000, programType = "bounty" } = {}) {
  if (huntState.running) return { error: "A hunt is already running" };
  const c = creds(platform);
  // HackerOne needs API creds; YesWeHack works via public-page scraping without them
  if (platform === "hackerone" && !c) return { error: `No ${platform} credentials configured`, needCreds: true };

  huntState.running = true;
  const job = {
    id: crypto.randomUUID(),
    platform,
    mode,
    programType,
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
      // 1) discover programs — public_mode only; programType: bounty | vdp | all
      const bountyFilter = programType === "vdp" ? false : programType === "bounty" ? true : undefined;
      const seen = new Set();
      const candidates = [];
      for (let page = 1; page <= 10 && candidates.length < maxPrograms; page++) {
        const r = await listPrograms(platform, { pageSize: 25, page, bounty: bountyFilter });
        if (r.error || !r.programs?.length) break;
        for (const p of r.programs) {
          job.programs_seen++;
          // hackerone: public_mode+open; scraped yeswehack: state "public", submission_state "open"
          if (!["public_mode", "public", "unknown"].includes(p.state)) continue;
          if (p.submission_state && p.submission_state !== "open") continue;
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
        const sc = await programScope(platform, p.handle);
        if (sc.error || !sc.scopes) continue;
        for (const s of sc.scopes) {
          if (!SCOPED_TYPES.has((s.asset_type ?? "").toLowerCase())) continue;
          const st = scopeToTarget(s);
          if (!st) continue;
          const t = st.target;
          const origin = (() => { try { return new URL(t).origin; } catch { return t; } })();
          if (isWhitelisted(origin)) continue;
          if (quarantineStatus(t)) continue;
          const dup = targets.find((x) => x.target === t);
          if (dup) { dup.wildcard = dup.wildcard || st.wildcard; continue; }
          targets.push({ target: t, wildcard: st.wildcard, program: p.name, program_url: p.url, asset: s.asset_identifier });
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
        let scanP = null;
        try {
          let cancelled = false;
          scanP = scanTarget(t.target, {
            mode,
            maxPages,
            requestDelayMs,
            includeSubdomains: !!t.wildcard,
            isCancelled: () => cancelled,
            onFinding: (f) => { handleFinding(f, t.target).catch(() => {}); },
          });
          // per-target timeout — a stuck/huge target must not block the queue
          const res = await Promise.race([
            scanP,
            new Promise((_, rej) => setTimeout(() => { cancelled = true; rej(new Error(`timeout after ${Math.round(perTargetTimeoutMs / 60000)}min`)); }, perTargetTimeoutMs)),
          ]);
          rec.status = res.ok ? "done" : "error";
          rec.findings = res.findings?.length ?? res.summary?.total ?? 0;
          rec.error = res.ok ? undefined : res.error;
          rec.summary = res.summary;
          persistScan(t, res, mode);
        } catch (e) {
          rec.status = "error";
          rec.error = e.message;
          // if the scan resolves later (e.g. after timeout cancel), still persist partial results
          scanP?.then((res2) => { if (res2?.ok) persistScan(t, res2, mode); }).catch(() => {});
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
