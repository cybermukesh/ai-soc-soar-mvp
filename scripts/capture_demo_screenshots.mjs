import { chromium } from "playwright";
import fs from "node:fs/promises";

const outDir = new URL("../demo/screenshots/", import.meta.url);
const demoUrl = new URL("../demo/video/demo-flow.html", import.meta.url).href;
const slides = [
  "01-demo-overview.png",
  "02-noise-reduction.png",
  "03-local-enrichment.png",
  "04-case-soar.png",
  "05-admin-rbac.png",
];

await fs.mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });

await page.goto(demoUrl, { waitUntil: "networkidle" });
await page.screenshot({ path: new URL(slides[0], outDir), fullPage: true });

for (const fileName of slides.slice(1)) {
  await page.getByRole("button", { name: "Next" }).click();
  await page.waitForTimeout(250);
  await page.screenshot({ path: new URL(fileName, outDir), fullPage: true });
}

await browser.close();
console.log(`Sanitized screenshots written to ${outDir.pathname}`);
