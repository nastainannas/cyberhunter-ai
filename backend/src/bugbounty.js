// Bug Bounty platform integration — fetch public program lists and their
// official scopes from HackerOne / YesWeHack so users can pick in-scope
// targets to scan. Credentials are stored encrypted in settings.
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
