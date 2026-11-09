// One-off asset generator for hackathon submission — screenshots the running
// app via Puppeteer. Run from backend/: node scripts/shot-assets.js
import puppeteer from "puppeteer";
import { mkdirSync } from "node:fs";

const OUT = new URL("../../submission-assets/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
mkdirSync(OUT, { recursive: true });

const BASE = "http://localhost:5173";
const pages = [
  ["dashboard", "/"],
  ["scan", "/scan"],
  ["findings", "/findings"],
  ["ai-config", "/ai-config"],
  ["tools", "/tools"],
];

const browser = await puppeteer.launch({ headless: "new", args: ["--no-sandbox", "--disable-dev-shm-usage"] });

// full-page screenshots at desktop size
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });
for (const [name, path] of pages) {
  await page.goto(BASE + path, { waitUntil: "networkidle0", timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1200));
  await page.screenshot({ path: `${OUT}${name}.png` });
  console.log("shot:", name);
}

// thumbnail 1200x630 — dashboard, cropped composition
await page.setViewport({ width: 1200, height: 630, deviceScaleFactor: 1 });
await page.goto(BASE + "/", { waitUntil: "networkidle0", timeout: 30000 });
await new Promise((r) => setTimeout(r, 1200));
await page.screenshot({ path: `${OUT}thumbnail.png` });
console.log("shot: thumbnail");

await browser.close();
console.log("done →", OUT);
