// Render slides-v4.html -> PDF (one 16:9 page per slide, exact size)
import puppeteer from 'puppeteer';
import path from 'node:path';

const ASSETS = path.resolve('..', 'submission-assets');
const HTML = path.join(ASSETS, 'slides-v4.html');
const OUT = path.join(ASSETS, 'cyberhunter-ai-platform.pdf');

const browser = await puppeteer.launch({ headless: 'new' });
const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 860, deviceScaleFactor: 2 });
await page.goto('file:///' + HTML.replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
await page.evaluate(() => document.fonts.ready);
await page.addStyleTag({ content: '.slide{margin:0!important}' });
await page.pdf({
  path: OUT,
  width: '13.333in',
  height: '7.5in',
  printBackground: true,
  margin: { top: 0, bottom: 0, left: 0, right: 0 },
  pageRanges: '',
});
await browser.close();
console.log('saved ->', OUT);
