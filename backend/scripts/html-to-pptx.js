// Render slides-v4.html -> PPTX: screenshot each .slide section, one image per slide.
import puppeteer from 'puppeteer';
import PptxGenJS from 'pptxgenjs';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

const ASSETS = path.resolve('..', 'submission-assets');
const HTML = path.join(ASSETS, 'slides-v4.html');
const OUT = path.join(ASSETS, 'cyberhunter-ai-platform-v4.pptx');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'slides-'));

const browser = await puppeteer.launch({ headless: 'new' });
const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 860, deviceScaleFactor: 2 });
await page.goto('file:///' + HTML.replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
await page.evaluate(() => document.fonts.ready);

const slides = await page.$$('.slide');
console.log('slides found:', slides.length);

const pptx = new PptxGenJS();
pptx.defineLayout({ name: 'W', width: 13.333, height: 7.5 });
pptx.layout = 'W';

for (let i = 0; i < slides.length; i++) {
  const imgPath = path.join(TMP, `slide-${String(i + 1).padStart(2, '0')}.png`);
  await slides[i].screenshot({ path: imgPath });
  const s = pptx.addSlide();
  s.addImage({ path: imgPath, x: 0, y: 0, w: 13.333, h: 7.5 });
  console.log('slide', i + 1, 'captured');
}

await pptx.writeFile({ fileName: OUT });
await browser.close();
fs.rmSync(TMP, { recursive: true, force: true });
console.log('saved ->', OUT);
