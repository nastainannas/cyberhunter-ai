// Render slides.html → cyberhunter-slides.pdf (16:9 pages) via Puppeteer.
import puppeteer from "puppeteer";
import { pathToFileURL } from "node:url";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const html = pathToFileURL(resolve(here, "../../submission-assets/slides.html")).href;
const out = resolve(here, "../../submission-assets/cyberhunter-slides.pdf");

const browser = await puppeteer.launch({ headless: "new", args: ["--no-sandbox", "--disable-dev-shm-usage"] });
const page = await browser.newPage();
await page.goto(html, { waitUntil: "load" });
await page.pdf({
  path: out,
  width: "13.333in",
  height: "7.5in",
  printBackground: true,
  margin: { top: 0, bottom: 0, left: 0, right: 0 },
  pageRanges: "1-10",
});
await browser.close();
console.log("done →", out);
