// Capture video assets: slide PNGs + app page screenshots + live-scan frames
import puppeteer from 'puppeteer';
import path from 'node:path';
import fs from 'node:fs';

const ROOT = path.resolve('..');
const ASSETS = path.join(ROOT, 'submission-assets');
const VID = path.join(ASSETS, 'video');
fs.mkdirSync(path.join(VID, 'slides'), { recursive: true });
fs.mkdirSync(path.join(VID, 'app'), { recursive: true });
fs.mkdirSync(path.join(VID, 'live'), { recursive: true });

const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });

// ---- 1. slides ----
await page.setViewport({ width: 1280, height: 760, deviceScaleFactor: 1 });
await page.goto('file:///' + path.join(ASSETS, 'slides-v4.html').replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
await page.evaluate(() => document.fonts.ready);
const slides = await page.$$('.slide');
for (let i = 0; i < slides.length; i++) {
  await slides[i].screenshot({ path: path.join(VID, 'slides', `s${String(i + 1).padStart(2, '0')}.png`) });
}
console.log('slides captured:', slides.length);

// ---- 2. app pages ----
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });
const routes = [
  ['dashboard', 'http://localhost:5173/'],
  ['scan', 'http://localhost:5173/scan'],
  ['findings', 'http://localhost:5173/findings'],
  ['ai-config', 'http://localhost:5173/ai-config'],
  ['tools', 'http://localhost:5173/tools'],
];
for (const [name, url] of routes) {
  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 });
    await new Promise(r => setTimeout(r, 1200));
    await page.screenshot({ path: path.join(VID, 'app', `${name}.png`) });
    console.log('app shot:', name);
  } catch (e) { console.log('skip', name, e.message); }
}

// ---- 3. live scan frames (scan own frontend - authorized local target) ----
try {
  // start a scan via API (passive = fast, safe)
  const res = await fetch('http://localhost:8787/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: 'http://localhost:5173', mode: 'passive' }),
  });
  console.log('scan start:', res.status);
  await page.goto('http://localhost:5173/scan', { waitUntil: 'networkidle2', timeout: 20000 });
  for (let i = 0; i < 40; i++) {
    await page.screenshot({ path: path.join(VID, 'live', `f${String(i).padStart(3, '0')}.png`) });
    await new Promise(r => setTimeout(r, 1500));
  }
  console.log('live frames: 40');
} catch (e) { console.log('live capture failed:', e.message); }

await browser.close();
console.log('DONE');
