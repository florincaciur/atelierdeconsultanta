import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { chromium } from "playwright";

const ROOT = path.resolve(import.meta.dirname, "..");
const MIME = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webp": "image/webp"
};

const server = http.createServer((request, response) => {
  let pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  if (pathname === "/investitii-modernizarea-microintreprinderilor-apel-2") {
    pathname = "/investitii-modernizarea-microintreprinderilor-apel-2/index.html";
  }
  let file = path.resolve(ROOT, pathname.replace(/^\/+/, ""));
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
  if (!file.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(file)) {
    response.writeHead(404);
    response.end("Not found");
    return;
  }
  response.writeHead(200, {
    "Cache-Control": "no-store",
    "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream"
  });
  fs.createReadStream(file).pipe(response);
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true });
const screenshotDirectory = path.join(os.tmpdir(), "faber-micro-apel-2-visual");
fs.mkdirSync(screenshotDirectory, { recursive: true });

try {
  for (const viewport of [{ width: 320, height: 720, name: "mobile-320" }, { width: 390, height: 844, name: "mobile" }, { width: 1440, height: 1000, name: "desktop" }]) {
    const page = await browser.newPage({ viewport });
    const consoleErrors = [];
    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    page.on("pageerror", (error) => consoleErrors.push(error.message));

    const response = await page.goto(`${baseUrl}/investitii-modernizarea-microintreprinderilor-apel-2`, { waitUntil: "domcontentloaded" });
    assert.equal(response?.status(), 200, `${viewport.name}: pagina nu răspunde cu 200`);
    await page.locator("[data-micro-apel-2-form]").waitFor({ state: "visible" });

    const layout = await page.evaluate(() => {
      const form = document.querySelector("[data-micro-apel-2-form]");
      const results = document.querySelector(".micro2-results");
      const simulator = document.querySelector(".micro2-simulator");
      const panel = document.querySelector("main .panel");
      const overview = document.querySelector(".program-reading-overview");
      const overviewHeading = overview?.querySelector("h2");
      const formRect = form?.getBoundingClientRect();
      const resultsRect = results?.getBoundingClientRect();
      const bounds = (node) => {
        const rect = node?.getBoundingClientRect();
        return rect ? { left: rect.left, right: rect.right, width: rect.width, minWidth: getComputedStyle(node).minWidth } : null;
      };
      return {
        h1Count: document.querySelectorAll("h1").length,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        formBounds: bounds(form),
        resultsBounds: bounds(results),
        simulatorBounds: bounds(simulator),
        panelBounds: bounds(panel),
        overviewBackground: overview ? getComputedStyle(overview).backgroundImage : "",
        overviewHeadingColor: overviewHeading ? getComputedStyle(overviewHeading).color : "",
        formWithinViewport: Boolean(formRect && formRect.left >= -1 && formRect.right <= window.innerWidth + 1),
        resultsWithinViewport: Boolean(resultsRect && resultsRect.left >= -1 && resultsRect.right <= window.innerWidth + 1)
      };
    });

    await page.locator("#simulator-punctaj-apel-2").screenshot({ path: path.join(screenshotDirectory, `${viewport.name}.png`) });
    assert.equal(layout.h1Count, 1, `${viewport.name}: pagina trebuie să aibă un singur H1`);
    assert.ok(layout.overflow <= 1, `${viewport.name}: pagina are scroll orizontal de ${layout.overflow}px`);
    assert.equal(layout.formWithinViewport, true, `${viewport.name}: formularul depășește viewport-ul (${JSON.stringify(layout)})`);
    assert.equal(layout.resultsWithinViewport, true, `${viewport.name}: rezultatul depășește viewport-ul (${JSON.stringify(layout.resultsBounds)})`);
    assert.match(layout.overviewBackground, /rgb\(16, 40, 70\).*rgb\(23, 61, 98\)/u, `${viewport.name}: fundalul închis al hărții de parcurgere a fost suprascris (${layout.overviewBackground})`);
    assert.equal(layout.overviewHeadingColor, "rgb(255, 255, 255)", `${viewport.name}: titlul hărții nu mai folosește text alb pe fundalul închis`);

    await page.evaluate(() => {
      const form = document.querySelector("[data-micro-apel-2-form]");
      const values = {
        caen: "2110", newJobs: "3", headquartersCounty: "bt", implementationCounty: "vs",
        ownContribution: "30", grant: "100000", turnover2023: "250000", turnover2024: "300000",
        turnover2025: "350000", netProfit2025: "25000", assets2025: "500000", debts2025: "200000",
        establishedAt: "2020-01-01", employees2025: "7", disadvantagedHire: "yes", microenterprise: "yes",
        activityHistory: "yes", fixedAssets: "yes", deMinimis: "yes", siteRights: "yes", annexes: "yes", cashFlow: "yes"
      };
      for (const [name, value] of Object.entries(values)) form.elements.namedItem(name).value = value;
      form.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await page.waitForFunction(() => document.querySelector("[data-score-total]")?.textContent.trim() === "100");
    assert.equal((await page.locator("[data-score-total]").textContent()).trim(), "100", `${viewport.name}: simulatorul nu ajunge la punctajul maxim`);
    assert.equal(await page.locator("[data-score-meter]").getAttribute("aria-valuenow"), "100", `${viewport.name}: meter-ul nu reflectă scorul`);
    assert.deepEqual(consoleErrors, [], `${viewport.name}: erori în consolă`);

    await page.locator("#simulator-punctaj-apel-2").screenshot({ path: path.join(screenshotDirectory, `${viewport.name}-complete.png`) });
    await page.close();
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

console.log(`PASS micro-apel-2 visual: 320px, 390px și 1440px; capturi în ${screenshotDirectory}`);
