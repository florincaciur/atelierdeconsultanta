#!/usr/bin/env node
"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const OUTPUT = path.join(ROOT, "reports", "priority-responsive-2026-07-20");
const REPORT = path.join(ROOT, "reports", "priority-responsive-2026-07-20.json");
const VIEWPORTS = [
  { width: 320, height: 844 },
  { width: 390, height: 844 },
  { width: 1440, height: 1000 }
];
const PAGES = [
  { slug: "home", path: "/index.html", programPage: false },
  { slug: "afir-autoconsum", path: "/afir-autoconsum-agroalimentar.html", programPage: true },
  { slug: "dr12", path: "/dr12-afir.html", programPage: true },
  { slug: "dr14", path: "/dr14.html", programPage: true },
  { slug: "dr18", path: "/dr18/index.html", programPage: true },
  { slug: "microintreprinderi-ne", path: "/investitii-modernizarea-microintreprinderilor-apel-2.html", programPage: true }
];

function contentType(file) {
  const extension = path.extname(file).toLowerCase();
  if (extension === ".html") return "text/html; charset=utf-8";
  if (extension === ".css") return "text/css; charset=utf-8";
  if (extension === ".js") return "application/javascript; charset=utf-8";
  if (extension === ".svg") return "image/svg+xml";
  if (extension === ".png") return "image/png";
  if (extension === ".webp") return "image/webp";
  if (extension === ".jpg" || extension === ".jpeg") return "image/jpeg";
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
      for (const spec of PAGES) {
        const consoleErrors = [];
        const listener = (message) => {
          if (message.type() === "error") consoleErrors.push(message.text());
        };
        page.on("console", listener);
        const response = await page.goto(`${base}${spec.path}`, { waitUntil: "networkidle" });
        const metrics = await page.evaluate(({ expectProgram }) => {
          const root = document.documentElement;
          const h1 = document.querySelector("h1");
          const h1Rect = h1?.getBoundingClientRect();
          const serviceTargets = new Set([...document.querySelectorAll("main a[href]")].map((link) => link.getAttribute("href")));
          return {
            viewportWidth: window.innerWidth,
            scrollWidth: root.scrollWidth,
            pageHeight: root.scrollHeight,
            h1Count: document.querySelectorAll("h1").length,
            h1WithinViewport: Boolean(h1Rect && h1Rect.left >= -2 && h1Rect.right <= window.innerWidth + 2),
            h1Overflow: h1 ? getComputedStyle(h1).overflow : "missing",
            programSurface: expectProgram ? {
              visualCount: document.querySelectorAll("[data-program-visual='immersive-verification']").length,
              stepCount: document.querySelectorAll("[data-program-visual='immersive-verification'] [data-program-step]").length,
              pressedCount: document.querySelectorAll("[data-program-visual='immersive-verification'] [data-program-step][aria-pressed='true']").length,
              officialSourceCount: document.querySelectorAll("[data-program-visual='immersive-verification'] .program-visual__footer a[href^='https://']").length,
              contextualCount: document.querySelectorAll("[data-program-contextual-links]").length,
              conversionCount: document.querySelectorAll("[data-program-contextual-links] a[data-link-relation='conversion'][href^='/contact']").length
            } : null,
            homepageFlow: !expectProgram ? {
              heroCount: document.querySelectorAll(".homepage-decision-hero").length,
              methodCount: document.querySelectorAll("[data-homepage-method]").length,
              methodTabs: document.querySelectorAll("[data-homepage-method-tab]").length,
              explorerCount: document.querySelectorAll("[data-homepage-explorer]").length,
              explorerTabs: document.querySelectorAll("[data-homepage-explorer-tab]").length,
              contactCount: document.querySelectorAll("#homepage-contact").length
            } : null,
            homepageServicePaths: !expectProgram ? {
              consulting: serviceTargets.has("/consultanta-fonduri-europene"),
              projectDesign: serviceTargets.has("/proiectare-fonduri-europene")
            } : null
          };
        }, { expectProgram: spec.programPage });
        page.off("console", listener);

        const screenshot = path.join(OUTPUT, `${spec.slug}-${viewport.width}.png`);
        await page.screenshot({ path: screenshot, fullPage: false });
        if (spec.slug === "home") {
          await page.locator(".homepage-decision-hero").screenshot({
            path: path.join(OUTPUT, `home-decision-hero-${viewport.width}.png`)
          });
        }
        const errors = [];
        if (!response || response.status() !== 200) errors.push(`HTTP ${response?.status() || "missing"}`);
        if (metrics.scrollWidth > metrics.viewportWidth + 1) errors.push(`horizontal overflow ${metrics.scrollWidth}/${metrics.viewportWidth}`);
        if (metrics.h1Count !== 1 || !metrics.h1WithinViewport || metrics.h1Overflow === "hidden") errors.push("H1 missing, clipped or outside viewport");
        if (spec.programPage) {
          const surface = metrics.programSurface;
          if (!surface || surface.visualCount !== 1 || surface.stepCount !== 4 || surface.pressedCount !== 1) errors.push("program visual is missing, duplicated or not initialized");
          if (!surface || surface.officialSourceCount !== 1) errors.push("official source is missing from the program visual");
          if (!surface || surface.contextualCount !== 1 || surface.conversionCount !== 1) errors.push("contextual route or its contact action is missing");
        } else {
          if (!metrics.homepageServicePaths?.consulting || !metrics.homepageServicePaths?.projectDesign) {
            errors.push("homepage does not expose both consulting and project-design paths");
          }
          const flow = metrics.homepageFlow;
          if (!flow || flow.heroCount !== 1 || flow.methodCount !== 1 || flow.methodTabs !== 5 || flow.explorerCount !== 1 || flow.explorerTabs !== 4 || flow.contactCount !== 1) {
            errors.push("homepage decision flow is incomplete or duplicated");
          }
        }
        if (consoleErrors.length) errors.push(`console errors: ${consoleErrors.join(" | ")}`);
        results.push({ page: spec.slug, viewport, screenshot: path.relative(ROOT, screenshot), metrics, errors });
      }
    }
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }

  fs.writeFileSync(REPORT, `${JSON.stringify({ generatedAt: "2026-09-02", results }, null, 2)}\n`, "utf8");
  const failed = results.filter((result) => result.errors.length);
  for (const result of results) {
    console.log(`${result.errors.length ? "FAIL" : "PASS"} ${result.page.padEnd(18)} ${result.viewport.width}px -> ${result.screenshot}${result.errors.length ? ` (${result.errors.join("; ")})` : ""}`);
  }
  if (failed.length) process.exit(1);
  console.log(`Responsive validation passed: ${results.length} captures at 320, 390 and 1440 px.`);
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
