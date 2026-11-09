// CVE / known-vulnerability surface checks.
// - Technology fingerprinting (CMS/framework + version) from HTML meta tags,
//   response headers, session cookies and well-known fingerprint files.
// - PHP2Shell (CVE-2026-109618 / CVE-2026-109619): PHP-core RCE fixed in
//   8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 — detected via version fingerprint,
//   plus a conservative multipart OOM behavioral probe when the version is
//   hidden. The probe can briefly exhaust PHP memory on the target — it is
//   only sent in active mode and is capped at ~1 MiB.
// - A curated ruleset mapping product+version ranges to public CVEs.
// All checks are GET-based except the single php2shell probe.

const UA_FETCH = { "User-Agent": "CYBERHUNTER-Scanner/0.1 (authorized security audit)" };

// ---------- helpers ----------

function parseVersion(s) {
  const m = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(s ?? "");
  return m ? [+m[1], +m[2], +(m[3] ?? 0)] : null;
}
function vcmp(a, b) {
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
}
function inRange(v, min, maxExclusive) {
  return vcmp(v, min) >= 0 && (!maxExclusive || vcmp(v, maxExclusive) < 0);
}

// ---------- fingerprints ----------

const PRODUCT_SIGNATURES = [
  {
    name: "wordpress", label: "WordPress",
    detect(html, headers) {
      const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([\d.]+)/i.exec(html ?? "")
        ?? /content=["']WordPress\s+([\d.]+)["'][^>]+name=["']generator/i.exec(html ?? "");
      if (gen) return { version: gen[1], via: "generator meta" };
      if (/wp-content|wp-includes|wp-json/i.test(html ?? "")) return { version: null, via: "wp-* assets" };
      return null;
    },
  },
  {
    name: "joomla", label: "Joomla",
    detect(html, headers) {
      const gen = /Joomla!?\s*(!)?\s*([\d.]+)/i.exec(/<meta[^>]+generator[^>]+>/i.exec(html ?? "")?.[0] ?? "");
      if (gen) return { version: gen[2], via: "generator meta" };
      if (/content=["']Joomla/i.test(html ?? "") || /\/media\/jui|\/administrator\/manifests/i.test(html ?? "")) {
        const v = /Joomla!?\s*([\d.]+)/i.exec(html ?? "");
        return { version: v?.[1] ?? null, via: "joomla assets" };
      }
      return null;
    },
  },
  {
    name: "drupal", label: "Drupal",
    detect(html, headers) {
      const xg = headers?.get?.("x-generator");
      const m = /Drupal\s+([\d.]+)/i.exec(xg ?? "");
      if (m) return { version: m[1], via: "X-Generator header" };
      if (/Drupal\.settings|\/sites\/default\/files|misc\/drupal\.js/i.test(html ?? "")) {
        const v = /Drupal\s+([\d.]+)/i.exec(html ?? "");
        return { version: v?.[1] ?? null, via: "drupal assets" };
      }
      return null;
    },
  },
  {
    name: "laravel", label: "Laravel",
    detect(html, headers, cookies) {
      const ck = (cookies ?? []).join(";");
      if (/laravel_session|XSRF-TOKEN/i.test(ck)) return { version: null, via: "session cookie" };
      if (/_ignition|laravel\.|Symfony/i.test(html ?? "")) return { version: null, via: "framework markers" };
      return null;
    },
  },
  {
    name: "phpmyadmin", label: "phpMyAdmin",
    detect(html, headers) {
      const v = /phpMyAdmin\s+([\d.]+)/i.exec(html ?? "");
      if (v) return { version: v[1], via: "page footer" };
      if (/pmahomme|phpmyadmin\.css|index\.php\?route=/i.test(html ?? "")) return { version: null, via: "pma assets" };
      return null;
    },
  },
  {
    name: "thinkphp", label: "ThinkPHP",
    detect(html, headers) {
      if (/thinkphp|ThinkPHP/i.test(html ?? "")) {
        const v = /ThinkPHP[ /]([\d.]+)/i.exec(html ?? "");
        return { version: v?.[1] ?? null, via: "framework marker" };
      }
      return null;
    },
  },
  {
    name: "yii", label: "Yii",
    detect(html, headers, cookies) {
      const ck = (cookies ?? []).join(";");
      if (/YII_CSRF_TOKEN|_csrf/i.test(ck) && /yii/i.test(html ?? "")) return { version: null, via: "csrf cookie" };
      return null;
    },
  },
  {
    name: "codeigniter", label: "CodeIgniter",
    detect(html, headers, cookies) {
      const ck = (cookies ?? []).join(";");
      if (/ci_session/i.test(ck)) return { version: null, via: "ci_session cookie" };
      return null;
    },
  },
  {
    name: "magento", label: "Magento",
    detect(html, headers, cookies) {
      const ck = (cookies ?? []).join(";");
      if (/mage-cache-storage|frontend/i.test(ck) || /Magento/i.test(html ?? "")) return { version: null, via: "magento markers" };
      return null;
    },
  },
];

// ---------- PHP version → php2shell verdict ----------

// Fixed releases: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. PHP ≤8.1 is EOL and
// unpatched; 5.x–8.1 all affected per advisory.
function php2shellVerdict(version) {
  const v = parseVersion(version);
  if (!v) return null;
  const [maj, min, pat] = v;
  if (maj < 8) return { vulnerable: true, reason: `PHP ${maj}.${min}.${pat} — branch is EOL/unpatched (php2shell affects PHP 5.4–8.5 pre-fix)` };
  // 8.0/8.1 are EOL — no fixed release exists for these branches
  if (maj === 8 && min < 2) return { vulnerable: true, reason: `PHP 8.${min}.${pat} — branch is EOL, no php2shell fix released` };
  if (maj === 8 && min === 2) return pat >= 35 ? { vulnerable: false } : { vulnerable: true, reason: `PHP 8.2.${pat} < 8.2.35` };
  if (maj === 8 && min === 3) return pat >= 36 ? { vulnerable: false } : { vulnerable: true, reason: `PHP 8.3.${pat} < 8.3.36` };
  if (maj === 8 && min === 4) return pat >= 27 ? { vulnerable: false } : { vulnerable: true, reason: `PHP 8.4.${pat} < 8.4.27` };
  if (maj === 8 && min === 5) return pat >= 12 ? { vulnerable: false } : { vulnerable: true, reason: `PHP 8.5.${pat} < 8.5.12` };
  if (maj === 8 && min > 5) return { vulnerable: false };
  return null;
}

function extractPhpVersion(text, headers) {
  const xp = headers?.get?.("x-powered-by") ?? "";
  let m = /PHP\/([\d.]+)/i.exec(xp) ?? /PHP\s*([\d.]+)/i.exec(headers?.get?.("server") ?? "");
  if (m) return { version: m[1], via: "HTTP header" };
  m = /PHP Version\s+([\d.]+)/i.exec(text ?? "") ?? /phpversion\(\)[^\n]*?([\d]+\.[\d]+\.[\d]+)/i.exec(text ?? "");
  if (m) return { version: m[1], via: "response body" };
  m = /<meta[^>]+name=["']generator["'][^>]+content=["']PHP\s*([\d.]+)/i.exec(text ?? "");
  if (m) return { version: m[1], via: "generator meta" };
  return null;
}

// ---------- CVE ruleset ----------
// Each rule: product name (matches fingerprint), optional version predicate,
// cve id, severity, title, description. Version null = any version of product.
const CVE_RULES = [
  // ---- PHP core ----
  { product: "php", cve: "CVE-2024-4577", sev: "critical", title: "PHP-CGI Windows argument injection (CVE-2024-4577)",
    match: (v) => { const p = parseVersion(v); return p && p[0] >= 8 ? inRange(p, [8, 0, 0], [8, 1, 30]) || inRange(p, [8, 2, 0], [8, 2, 21]) || inRange(p, [8, 3, 0], [8, 3, 9]) : p && p[0] === 7; },
    desc: "PHP-CGI on Windows passes command-line arguments to the CGI process unsafely — unauthenticated RCE when the app runs under IIS/CGI.",
    requires: "Windows + PHP-CGI deployment" },
  { product: "php", cve: "CVE-2019-11043", sev: "critical", title: "PHP-FPM env_path_info underflow (CVE-2019-11043)",
    match: (v) => { const p = parseVersion(v); return p && inRange(p, [7, 1, 0], [7, 4, 0]); },
    desc: "env_path_info underflow in PHP-FPM + nginx allows remote code execution via crafted URLs (phuip-fpizdam).",
    requires: "nginx + PHP-FPM, unpatched 7.x" },

  // ---- WordPress core ----
  { product: "wordpress", cve: "CVE-2022-21662", sev: "high", title: "WordPress SQLi via WP_Query tax_query (CVE-2022-21662)",
    match: (v) => { const p = parseVersion(v); return p && inRange(p, [5, 0, 0], [5, 9, 7]); },
    desc: "Insufficient escaping in tax_query allows SQL injection by authenticated users." },
  { product: "wordpress", cve: "CVE-2023-2745", sev: "medium", title: "WordPress stored XSS in HTML API (CVE-2023-2745)",
    match: (v) => { const p = parseVersion(v); return p && inRange(p, [5, 9, 0], [6, 2, 4]); },
    desc: "Stored XSS via wp_kses_post in the HTML API affects WordPress 5.9–6.2.3." },
  { product: "wordpress", cve: "CVE-2024-31210", sev: "high", title: "WordPress CSRF leading to RCE via plugin upload (CVE-2024-31210)",
    match: (v) => { const p = parseVersion(v); return p && inRange(p, [4, 7, 0], [6, 4, 4]); },
    desc: "CSRF in plugin/theme installation flow can lead to arbitrary plugin upload → RCE." },

  // ---- Joomla ----
  { product: "joomla", cve: "CVE-2023-23752", sev: "critical", title: "Joomla! API information disclosure (CVE-2023-23752)",
    match: (v) => { const p = parseVersion(v); return !p || inRange(p, [4, 0, 0], [4, 2, 8]); },
    desc: "Improper access check in webservice endpoints exposes configuration incl. DB credentials (api/index.php/v1/config/application)." },
  { product: "joomla", cve: "CVE-2023-30547", sev: "high", title: "Joomla! XSS in mail output (CVE-2023-30547)",
    match: (v) => { const p = parseVersion(v); return p && inRange(p, [4, 0, 0], [4, 3, 4]); },
    desc: "XSS via crafted mail addresses in com_users." },

  // ---- Drupal ----
  { product: "drupal", cve: "CVE-2018-7600", sev: "critical", title: "Drupalgeddon2 — Drupal RCE (CVE-2018-7600)",
    match: (v) => { const p = parseVersion(v); if (!p) return true; return (p[0] === 7 && p[1] < 58) || (p[0] === 8 && p[1] <= 5 && !(p[1] === 5 && p[2] >= 1)); },
    desc: "Unrestricted file upload / remote code execution via Form API rendering — mass-exploited in the wild." },
  { product: "drupal", cve: "CVE-2019-6339", sev: "critical", title: "Drupal REST RCE (CVE-2019-6339)",
    match: (v) => { const p = parseVersion(v); if (!p) return true; return (p[0] === 8 && p[1] < 6) || (p[0] === 7 && p[1] >= 50 && p[1] < 60); },
    desc: "REST module deserialization allows remote code execution." },
  { product: "drupal", cve: "CVE-2024-55636", sev: "high", title: "Drupal core XSS / access bypass (CVE-2024-55636)",
    match: (v) => { const p = parseVersion(v); return p && inRange(p, [10, 0, 0], [10, 3, 7]); },
    desc: "Multiple core issues incl. access bypass; affects Drupal 10.0–10.3.6." },

  // ---- Laravel ----
  { product: "laravel", cve: "CVE-2021-3129", sev: "critical", title: "Laravel Ignition RCE (CVE-2021-3129)",
    match: () => true, // version rarely disclosed; debug-mode check below confirms
    desc: "Ignition ≤2.5.1 in debug mode allows unauthenticated RCE via /_ignition/execute-solution." },
  { product: "laravel", cve: "CVE-2024-52301", sev: "high", title: "Laravel environment file exposure (CVE-2024-52301)",
    match: () => true,
    desc: "Framework ships a .env handling flaw; combined with exposed env files leaks APP_KEY → RCE via unserialize." },

  // ---- phpMyAdmin ----
  { product: "phpmyadmin", cve: "CVE-2020-26935", sev: "high", title: "phpMyAdmin SQL injection (CVE-2020-26935)",
    match: (v) => { const p = parseVersion(v); return p && (inRange(p, [4, 9, 0], [4, 9, 6]) || inRange(p, [5, 0, 0], [5, 0, 3])); },
    desc: "Search feature SQL injection in phpMyAdmin 4.9.x <4.9.6 / 5.0.x <5.0.3." },
  { product: "phpmyadmin", cve: "CVE-2018-19968", sev: "critical", title: "phpMyAdmin LFI (CVE-2018-19968)",
    match: (v) => { const p = parseVersion(v); return p && (inRange(p, [4, 8, 0], [4, 9, 0]) || inRange(p, [5, 0, 0], [5, 0, 0])); },
    desc: "Local file inclusion via index.php?target= allows reading arbitrary files / RCE with session upload." },

  // ---- ThinkPHP ----
  { product: "thinkphp", cve: "CVE-2018-20062", sev: "critical", title: "ThinkPHP 5.x RCE (CVE-2018-20062)",
    match: (v) => { const p = parseVersion(v); return !p || inRange(p, [5, 0, 0], [5, 1, 31]); },
    desc: "invokefunction call chain allows unauthenticated RCE on ThinkPHP 5.0.x–5.1.30." },
  { product: "thinkphp", cve: "CVE-2019-9082", sev: "critical", title: "ThinkPHP 5.0/5.1 RCE (CVE-2019-9082)",
    match: (v) => { const p = parseVersion(v); return !p || inRange(p, [5, 0, 0], [5, 1, 0]); },
    desc: "update() method param injection → RCE on ThinkPHP ≤5.1." },

  // ---- Yii ----
  { product: "yii", cve: "CVE-2020-15148", sev: "high", title: "Yii2 debug module RCE (CVE-2020-15148)",
    match: () => true,
    desc: "yii\debug module allows remote code execution when debug mode is enabled in production." },
];

// ---------- php2shell behavioral probe ----------
// Conservative multipart OOM probe (~1 MiB). Vulnerable PHP builds return an
// empty HTTP 500 / memory-exhaustion fatal / dead worker; patched builds
// usually return a normal 200 or a non-empty error page. A positive result is
// reported as "probable" — version-based verdicts are authoritative.
function php2shellProbe() {
  const boundary = `----CYBERHUNTER${Date.now().toString(36)}`;
  // 62-level nested array key — the trigger shape used by public scanners
  const key = "a" + "[a]".repeat(62);
  const padLen = Math.max(0, (1 << 20) - 4096);
  const pad = "A".repeat(padLen);
  const body =
    `--${boundary}\r\nContent-Disposition: form-data; name="${key}"\r\n\r\n${pad}\r\n--${boundary}--\r\n`;
  return {
    headers: {
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
      "Content-Length": String(Buffer.byteLength(body)),
    },
    body,
  };
}

// ---------- main ----------

export async function scanCveSurface({ pages, origin, ftF, log, t0, findings, finding, active }) {
  const allHtml = (pages ?? []).map((p) => p.html ?? "").join("\n").slice(0, 400000);
  const headers = pages?.[0]?.res?.headers ?? null;
  const cookieStr = (pages ?? []).flatMap((p) => {
    try { return [...(p.res?.headers?.getSetCookie?.() ?? [])]; } catch { return []; }
  }).join(";");

  // 1) PHP version fingerprint → php2shell verdict
  let php = extractPhpVersion(allHtml, headers);
  if (!php) {
    // probe common phpinfo paths for a disclosed version
    for (const p of ["/phpinfo.php", "/info.php", "/test.php", "/pi.php", "/p.php", "/phpversion.php"]) {
      try {
        const r = await ftF(new URL(p, origin).toString(), {}, 8000);
        const ctype = r.headers.get("content-type") ?? "";
        if (!r.ok || !/html|text/i.test(ctype)) continue;
        const text = await r.text();
        if (!/php\s*version|phpinfo\(\)/i.test(text)) continue;
        php = extractPhpVersion(text, r.headers);
        if (php) { php.via += ` (${p})`; break; }
      } catch { /* next */ }
    }
  }

  if (php) {
    const verdict = php2shellVerdict(php.version);
    log(`[${t0()}s] [CVE] PHP ${php.version} detected (${php.via})${verdict ? (verdict.vulnerable ? " — PHP2Shell VULNERABLE range" : " — patched for php2shell") : ""}`);
    if (verdict?.vulnerable) {
      findings.push(finding({
        title: `PHP2Shell — PHP ${php.version} vulnerable to CVE-2026-109618 & CVE-2026-109619`,
        severity: "critical", category: "cve", owasp: "A06:2021 Vulnerable and Outdated Components",
        description: `Server discloses PHP ${php.version} (${php.via}). ${verdict.reason}. PHP2Shell is unauthenticated RCE / memory disclosure in PHP core — application code cannot mitigate it.`,
        endpoint: origin + "/", parameter: "PHP runtime version", vector: "version-fingerprint",
        payload: "N/A — version-based detection",
        evidence: `PHP version ${php.version} disclosed via ${php.via}; fixed releases are 8.2.35/8.3.36/8.4.27/8.5.12`,
        exploit: "Unauthenticated remote attacker triggers memory corruption during request startup/shutdown → arbitrary code execution as the web-server user, or disclosure of other requests' memory (sessions, credentials).",
        recommendation: "Upgrade PHP to the fixed release for your branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) and restart Apache/PHP-FPM. Patching app code alone does NOT fix this.",
      }));
    }
  } else if (active) {
    // version hidden — conservative behavioral probe on the target root
    try {
      log(`[${t0()}s] [CVE] PHP version hidden — running php2shell behavioral probe (1 MiB multipart)`);
      const ctrl = await ftF(origin + "/", {}, 12000);
      await ctrl.text();
      const probe = php2shellProbe();
      const r = await ftF(origin + "/", { method: "POST", headers: { ...UA_FETCH, ...probe.headers }, body: probe.body }, 20000);
      const text = await r.text();
      const memErr = /allowed memory size|out of memory|memory exhausted/i.test(text);
      const empty500 = r.status === 500 && text.trim().length === 0;
      if (memErr || empty500) {
        findings.push(finding({
          title: "Possible PHP2Shell exposure (CVE-2026-109618/109619) — behavioral probe",
          severity: "high", category: "cve", owasp: "A06:2021 Vulnerable and Outdated Components",
          description: `PHP version is not disclosed, but a ~1 MiB nested-multipart probe produced ${memErr ? "a PHP memory-exhaustion error" : "an empty HTTP 500"} — consistent with the pre-patch OOM handling flaw. Verify against the installed PHP version (fixed: 8.2.35/8.3.36/8.4.27/8.5.12).`,
          endpoint: origin + "/", parameter: "PHP runtime", vector: "behavioral-probe",
          payload: "POST / multipart/form-data, array key nested 62 levels, ~1 MiB",
          evidence: `Probe → HTTP ${r.status}, body ${text.length}b${memErr ? ` containing '${text.match(/allowed memory size[^<\n]*/i)?.[0] ?? "memory error"}'` : " (empty)"}`,
          exploit: "If vulnerable: unauthenticated RCE / cross-request memory disclosure in PHP core.",
          recommendation: "Confirm the PHP version and patch level; upgrade to the fixed release. Note: post-patch builds with very low memory_limit can rarely produce a similar empty 500 — verify before treating as confirmed.",
        }));
      } else {
        log(`[${t0()}s] [CVE] php2shell probe inconclusive (HTTP ${r.status}, ${text.length}b) — no crash signature`);
      }
    } catch (e) {
      log(`[${t0()}s] [CVE] php2shell probe failed: ${e.message}`);
    }
  }

  // 2) product fingerprints → CVE rules
  const detected = [];
  for (const sig of PRODUCT_SIGNATURES) {
    try {
      const hit = sig.detect(allHtml, headers, (pages ?? []).flatMap((p) => {
        try { return [...(p.res?.headers?.getSetCookie?.() ?? [])]; } catch { return []; }
      }));
      if (hit) detected.push({ ...hit, name: sig.name, label: sig.label });
    } catch { /* ignore */ }
  }
  // PHP itself counts as a "product" so core-CVE rules (CVE-2024-4577,
  // CVE-2019-11043) can match the disclosed version
  if (php?.version) detected.push({ name: "php", label: "PHP", version: php.version, via: php.via });
  for (const d of detected) {
    log(`[${t0()}s] [CVE] ${d.label} detected${d.version ? ` ${d.version}` : ""} (${d.via})`);
    for (const rule of CVE_RULES.filter((r) => r.product === d.name)) {
      const v = d.version ? parseVersion(d.version) : null;
      const matched = rule.match(d.version ?? "");
      if (!matched) continue;
      // Laravel Ignition: only report when debug endpoint actually answers
      if (rule.cve === "CVE-2021-3129") {
        try {
          const ig = await ftF(`${origin}/_ignition/health-check`, {}, 8000);
          if (ig.status === 404) continue; // ignition not routed → not exploitable
        } catch { /* still report as potential */ }
      }
      findings.push(finding({
        title: `${d.label} — ${rule.title}`,
        severity: rule.sev === "critical" ? "critical" : rule.sev === "high" ? "high" : "medium",
        category: "cve", owasp: "A06:2021 Vulnerable and Outdated Components",
        description: `${d.label} ${d.version ?? "(version undisclosed)"} detected via ${d.via}. ${rule.desc}${rule.requires ? ` Applies when: ${rule.requires}.` : ""}`,
        endpoint: origin + "/", parameter: `${d.label} version`, vector: "version-fingerprint",
        payload: "N/A — version/rule-based detection",
        evidence: `${d.label} fingerprint: version=${d.version ?? "hidden"}, via=${d.via}`,
        exploit: "Known CVE — see advisory for exploit details; outdated components are a leading breach vector.",
        recommendation: `Upgrade ${d.label} to a patched release; check the CVE advisory for fixed versions. Remove version disclosure where possible.`,
      }));
    }
  }

  // 3) active verification for CVEs that can be confirmed read-only
  if (active) {
    // Joomla CVE-2023-23752 — API config disclosure (GET, read-only)
    if (detected.some((d) => d.name === "joomla")) {
      try {
        const r = await ftF(`${origin}/api/index.php/v1/config/application?public=true`, {}, 10000);
        const text = await r.text();
        if (r.ok && /"dbtype"|"db\s*"|"password"|"secret"/i.test(text) && /json/i.test(r.headers.get("content-type") ?? "")) {
          findings.push(finding({
            title: "Joomla! CVE-2023-23752 CONFIRMED — API exposes configuration/DB credentials",
            severity: "critical", category: "cve", owasp: "A01:2021 Broken Access Control",
            description: "The Joomla webservice endpoint returned application configuration including database settings without authentication.",
            endpoint: `${origin}/api/index.php/v1/config/application?public=true`, parameter: "public API endpoint", vector: "active-verification",
            payload: "GET /api/index.php/v1/config/application?public=true",
            evidence: `HTTP ${r.status}, JSON body contains config keys (dbtype/credentials fields)`,
            exploit: "Unauthenticated attacker extracts DB credentials → full database compromise.",
            recommendation: "Update Joomla to ≥4.2.8 / apply the vendor patch; restrict /api/ access.",
          }));
        }
      } catch { /* ignore */ }
    }
    // Laravel debug / Ignition exposure
    if (detected.some((d) => d.name === "laravel")) {
      try {
        const r = await ftF(`${origin}/_ignition/execute-solution`, { method: "OPTIONS" }, 8000);
        if (r.status !== 404 && r.status !== 405) {
          findings.push(finding({
            title: "Laravel Ignition endpoint reachable (CVE-2021-3129 exposure)",
            severity: "high", category: "cve", owasp: "A05:2021 Security Misconfiguration",
            description: "/_ignition/ endpoint responds — if debug mode is on with Ignition ≤2.5.1, unauthenticated RCE is possible.",
            endpoint: `${origin}/_ignition/execute-solution`, parameter: "N/A", vector: "active-verification",
            payload: "OPTIONS /_ignition/execute-solution",
            evidence: `HTTP ${r.status} — endpoint exists`,
            exploit: "Crafted solution payload → file write → RCE (CVE-2021-3129).",
            recommendation: "Set APP_DEBUG=false in production; upgrade Ignition; block /_ignition routes.",
          }));
        }
      } catch { /* ignore */ }
    }
  }
}
