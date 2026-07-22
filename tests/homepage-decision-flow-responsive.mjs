import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright";

const ROOT = path.resolve(import.meta.dirname, "..");
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".json": "application/json", ".svg": "image/svg+xml", ".webp": "image/webp", ".png": "image/png" };
const server = http.createServer((request, response) => {
  let pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  if (pathname === "/") pathname = "/index.html";
  let file = path.join(ROOT, pathname.replace(/^\//, ""));
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
  if (!file.startsWith(ROOT) || !fs.existsSync(file)) { response.writeHead(404); response.end("Not found"); return; }
  response.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream", "Cache-Control": "no-store" });
  fs.createReadStream(file).pipe(response);
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true });

try {
  for (const viewport of [{ width: 320, height: 720 }, { width: 390, height: 844 }, { width: 768, height: 900 }, { width: 1366, height: 768 }]) {
    const page = await browser.newPage({ viewport });
    const consoleErrors = [];
    page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
    await page.goto(baseUrl, { waitUntil: "networkidle" });
    const metrics = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      forms: document.querySelectorAll("main form").length,
      carousels: document.querySelectorAll("main [data-priority-carousel]").length,
      sections: document.querySelectorAll("main > section").length,
      ctaBottom: document.querySelector("#hero .btn-primary")?.getBoundingClientRect().bottom,
      tocOpen: document.querySelector(".long-form-toc details")?.open
    }));
    assert(metrics.overflow <= 0, `${viewport.width}px: scroll orizontal`);
    assert.equal(metrics.forms, 0);
    assert.equal(metrics.carousels, 1);
    assert.equal(metrics.sections, 8);
    assert.equal(metrics.tocOpen, false);
    if (viewport.width === 390 || viewport.width === 1366) assert(metrics.ctaBottom <= viewport.height, `${viewport.width}px: CTA-ul principal este sub fold`);
    await page.locator("[data-priority-next]").click();
    assert.equal((await page.locator("[data-priority-counter]").textContent()).trim(), "2 din 6");
    assert.deepEqual(consoleErrors, [], `${viewport.width}px: erori console`);
    await page.close();
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

console.log("Homepage responsive PASS: 320, 390, 768 și 1366 px, fără overflow și cu carusel funcțional.");
