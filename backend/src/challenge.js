// CYBERHUNTER AI — anti-bot JS challenge solver.
// Some targets sit behind JS-interstitial WAFs (BitNinja-style "One moment,
// please..." / "being verified" pages). They serve an interstitial to
// non-browser clients; a real browser executes the obfuscated check, gets a
// clearance cookie, and reloads into real content. This module drives headless
// Chromium through that flow and returns the issued cookies so the scanner's
// normal fetch layer can reuse the cleared session.

import puppeteer from "puppeteer";

export const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Heuristic: interstitial pages are small, titled "moment/verify/wait/attention"
// and typically auto-reload. Real app pages rarely match all signals.
export function isJsChallengePage(html) {
  if (!html || html.length > 120000) return false;
  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? "").trim();
  if (/moment|just a moment|attention required|checking your browser|please wait|being verified/i.test(title)) return true;
  return /being verified|request is being verified|one moment, please/i.test(html)
    && /window\.location\.reload|location\.reload\(\)/i.test(html);
}

// Merge "a=1; b=2" cookie strings; later pairs win on name conflicts.
export function mergeCookieStrings(...parts) {
  const map = new Map();
  for (const part of parts) {
    for (const pair of String(part ?? "").split(";")) {
      const i = pair.indexOf("=");
      if (i <= 0) continue;
      const name = pair.slice(0, i).trim();
      if (name) map.set(name, pair.slice(i + 1).trim());
    }
  }
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

// Returns "k=v; k2=v2" for cookies the browser obtained, or null on failure.
export async function solveJsChallenge(startUrl, log = () => {}) {
  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: [
        "--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage",
        "--window-size=1280,800", "--disable-blink-features=AutomationControlled",
      ],
    });
  } catch (e) {
    log(`[CHALLENGE] headless browser unavailable: ${e.message}`);
    return null;
  }
  try {
    const page = await browser.newPage();
    await page.setUserAgent(CHROME_UA);
    await page.setViewport({ width: 1280, height: 800 });
    // hide the most common automation tells before any page script runs
    await page.evaluateOnNewDocument(() => {
      try { Object.defineProperty(navigator, "webdriver", { get: () => undefined }); } catch { /* ignore */ }
      try { Object.defineProperty(navigator, "languages", { get: () => ["en-US", "en"] }); } catch { /* ignore */ }
      try { window.chrome = window.chrome || { runtime: {} }; } catch { /* ignore */ }
    });

    await page.goto(startUrl, { waitUntil: "domcontentloaded", timeout: 30000 }).catch(() => {});

    // Poll until the interstitial clears (JS check → reload → clearance cookie).
    // Cap ~30s so a stuck challenge doesn't stall the whole scan.
    let cleared = false;
    for (let i = 0; i < 30; i++) {
      await sleep(1000);
      const state = await page.evaluate(() => ({
        title: document.title || "",
        text: (document.body?.innerText || "").slice(0, 300),
      })).catch(() => null);
      if (state && !isJsChallengePage(`<title>${state.title}</title>${state.text}`)) { cleared = true; break; }
      // mid-wait: nudge a reload once the first JS check has had time to run
      if (i === 7) await page.reload({ waitUntil: "domcontentloaded", timeout: 15000 }).catch(() => {});
    }
    if (!cleared) log("[CHALLENGE] interstitial did not clear within timeout");

    const cookies = await page.cookies(startUrl).catch(() => []);
    if (!cookies.length) { log("[CHALLENGE] no cookies issued by challenge"); return null; }
    log(`[CHALLENGE] clearance cookies obtained (${cookies.map((c) => c.name).join(", ")})`);
    return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
  } catch (e) {
    log(`[CHALLENGE] solver error: ${e.message}`);
    return null;
  } finally {
    await browser.close().catch(() => {});
  }
}
