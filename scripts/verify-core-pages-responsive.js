#!/usr/bin/env node
"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const OUTPUT = path.join(ROOT, "reports", "core-pages-responsive-2026-07-20");
const REPORT = path.join(ROOT, "reports", "core-pages-responsive-2026-07-20.json");
const VIEWPORTS = [
  { width: 320, height: 844 },
  { width: 390, height: 844 },
  { width: 1440, height: 1000 }
];
const PAGES = [
  ["consultanta", "/consultanta-fonduri-europene.html"],
  ["despre-faber", "/despre-faber.html"],
  ["fonduri-europene", "/fonduri-europene.html"],
  ["contact", "/contact.html"]
];

function contentType(file) {
  const extension = path.extname(file).toLowerCase();
  if (extension === ".html") return "text/html; charset=utf-8";
  if (extension === ".css") return "text/css; charset=utf-8";
  if (extension === ".js") return "application/javascript; charset=utf-8";
  if (extension === ".svg") return "image/svg+xml";
  if (extension === ".png") return "image/png";
  if (extension === ".webp") return "image/webp";
  return "application/octet-stream";
}

function createServer() {
  return http.createServer((request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, "http://127.0.0.1").pathname).replace(/^\/+/, "");
    const file = path.resolve(DIST, pathname || "index.html");
    if (!file.startsWith(DIST + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }
    response.writeHead(200, { "Content-Type": contentType(file) });
    response.end(fs.readFileSync(file));
  });
}

async function main() {
  if (!fs.existsSync(DIST)) throw new Error("dist is missing; run npm run build first.");
  fs.mkdirSync(OUTPUT, { recursive: true });
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const results = [];

  try {
    for (const viewport of VIEWPORTS) {
      await page.setViewportSize(viewport);
      for (const [slug, pathname] of PAGES) {
        const response = await page.goto(`${base}${pathname}`, { waitUntil: "networkidle" });
        const metrics = await page.evaluate(() => {
          const root = document.documentElement;
          const h1 = document.querySelector("h1");
          const h1Rect = h1?.getBoundingClientRect();
          const support = document.querySelector(".core-search-support");
          const details = support?.querySelector(".core-search-details");
          const pageHeight = root.scrollHeight;
          return {
            viewportWidth: innerWidth,
            scrollWidth: root.scrollWidth,
            pageHeight,
            h1Count: document.querySelectorAll("h1").length,
            h1WithinViewport: Boolean(h1Rect && h1Rect.left >= -2 && h1Rect.right <= innerWidth + 2),
            corePageCount: document.querySelectorAll("body.core-page").length,
            supportCount: document.querySelectorAll(".core-search-support").length,
            supportRatio: support ? (support.getBoundingClientRect().top + scrollY) / pageHeight : 0,
            detailsOpen: Boolean(details?.open),
            faqCount: support?.querySelectorAll(".faq-item").length || 0,
            contactFormCount: document.querySelectorAll("form.contact-form").length,
            cssLoaded: [...document.styleSheets].some((sheet) => sheet.href?.includes("core-pages.css"))
          };
        });

        const errors = [];
        if (!response || response.status() !== 200) errors.push(`HTTP ${response?.status() || "missing"}`);
        if (metrics.scrollWidth > metrics.viewportWidth + 1) errors.push(`horizontal overflow ${metrics.scrollWidth}/${metrics.viewportWidth}`);
        if (metrics.h1Count !== 1 || !metrics.h1WithinViewport) errors.push("H1 missing or clipped");
        if (metrics.corePageCount !== 1 || !metrics.cssLoaded) errors.push("core page stylesheet missing");
        if (metrics.supportCount !== 1 || metrics.detailsOpen || metrics.faqCount !== 6) errors.push("footer documentation structure invalid");
        if (metrics.supportRatio < .68) errors.push(`documentation starts too early (${metrics.supportRatio.toFixed(2)})`);
        if (slug === "contact" && metrics.contactFormCount !== 1) errors.push("contact form missing");

        await page.locator(".core-search-details > summary").click();
        const expanded = await page.evaluate(() => ({
          open: document.querySelector(".core-search-details")?.open,
          allFaqVisible: [...document.querySelectorAll(".core-search-support .faq-item")].every((item) => item.getBoundingClientRect().height > 0),
          overflow: document.documentElement.scrollWidth > innerWidth
        }));
        if (!expanded.open || !expanded.allFaqVisible || expanded.overflow) errors.push("expanded documentation is inaccessible or causes overflow");
        await page.locator(".core-search-details > summary").click();

        const screenshot = path.join(OUTPUT, `${slug}-${viewport.width}.png`);
        await page.screenshot({ path: screenshot, fullPage: false });
        results.push({ slug, viewport, metrics, expanded, screenshot: path.relative(ROOT, screenshot), errors });
      }
    }
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }

  fs.writeFileSync(REPORT, `${JSON.stringify({ generatedAt: "2026-07-20", results }, null, 2)}\n`, "utf8");
  const failed = results.filter((result) => result.errors.length);
  results.forEach((result) => console.log(`${result.errors.length ? "FAIL" : "PASS"} ${result.slug.padEnd(18)} ${result.viewport.width}px${result.errors.length ? ` (${result.errors.join("; ")})` : ""}`));
  if (failed.length) process.exit(1);
  console.log(`Core responsive validation passed: ${results.length} captures.`);
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
