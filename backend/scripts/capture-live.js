// Drive the real Scan UI: fill form, start passive scan on localhost:5173,
// capture frames while the live log streams.
import puppeteer from 'puppeteer';
import path from 'node:path';
import fs from 'node:fs';

const VID = path.resolve('..', 'submission-assets', 'video');
const OUT = path.join(VID, 'live');
fs.mkdirSync(OUT, { recursive: true });
for (const f of fs.readdirSync(OUT)) fs.unlinkSync(path.join(OUT, f));

const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });
await page.goto('http://localhost:5173/scan', { waitUntil: 'networkidle2', timeout: 30000 });
await new Promise(r => setTimeout(r, 1500));

// fill target
const ta = await page.$('textarea');
if (ta) await ta.type('http://localhost:5173', { delay: 15 });
// passive mode (faster, safe)
const btns = await page.$$('button');
for (const b of btns) {
  const t = await b.evaluate(el => el.textContent.trim());
  if (t === 'Passive') { await b.click(); break; }
}
// authorize checkbox
await page.evaluate(() => { const c = document.getElementById('auth'); if (c && !c.checked) c.click(); });
await new Promise(r => setTimeout(r, 400));
// start scan
for (const b of await page.$$('button')) {
  const t = await b.evaluate(el => el.textContent.trim());
  if (t === 'Start Scan') { await b.click(); break; }
}
console.log('scan started, capturing frames...');

for (let i = 0; i < 60; i++) {
  await page.screenshot({ path: path.join(OUT, `f${String(i).padStart(3, '0')}.png`) });
  await new Promise(r => setTimeout(r, 1500));
}
console.log('done');
await browser.close();
