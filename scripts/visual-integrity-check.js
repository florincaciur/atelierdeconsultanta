#!/usr/bin/env node
"use strict";

const fs = require("fs");
const fsp = require("fs/promises");
const http = require("http");
const path = require("path");
const { chromium } = require("playwright");
const { fileForRoute } = require("../tools/structured-data-utils");
const { sitemapUrls } = require("../tools/sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DIR = path.join(ROOT, "reports");
const SCREENSHOT_DIR = path.join(REPORT_DIR, "visual-screenshots");
const REPORT_PATH = path.join(REPORT_DIR, "visual-integrity-report.json");
const MARKDOWN_PATH = path.join(REPORT_DIR, "visual-integrity-report.md");
const SITE = "https://atelierdeconsultanta.ro";
const VIEWPORTS = [
  { name: "mobile-320", width: 320, height: 844 },
  { name: "mobile-390", width: 390, height: 844 },
  { name: "tablet-768", width: 768, height: 1024 },
  { name: "desktop-1365", width: 1365, height: 900 }
];
const REPRESENTATIVE = new Set(["/", "/contact", "/consultanta-fonduri-europene", "/afir", "/dr14", "/dr18", "/blog"]);
const MIME_TYPES = {
  ".css": "text/css; charset=utf-8", ".html": "text/html; charset=utf-8", ".ico": "image/x-icon",
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8", ".png": "image/png", ".svg": "image/svg+xml",
  ".webmanifest": "application/manifest+json; charset=utf-8", ".webp": "image/webp", ".xml": "application/xml; charset=utf-8"
};

function routes() {
  return sitemapUrls(ROOT).map((value) => {
    const pathname = new URL(value).pathname;
    return pathname === "/" ? "/" : pathname.replace(/\/$/, "");
  });
}

function routeLabel(route) {
  return (route === "/" ? "home" : route.slice(1)).replace(/[^a-z0-9-]+/gi, "-");
}

function requestedFile(requestUrl) {
  const pathname = decodeURIComponent(new URL(requestUrl, "http://127.0.0.1").pathname);
  if (path.extname(pathname)) return path.resolve(ROOT, pathname.replace(/^\/+/, ""));
  return fileForRoute(ROOT, pathname === "/" ? "/" : pathname.replace(/\/$/, ""));
}

function createServer() {
  const server = http.createServer((request, response) => {
    try {
      const file = requestedFile(request.url);
      if (!file.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
        response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        response.end("Not found");
        return;
      }
      response.writeHead(200, { "content-type": MIME_TYPES[path.extname(file).toLowerCase()] || "application/octet-stream" });
      fs.createReadStream(file).pipe(response);
    } catch (error) {
      response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      response.end(String(error.stack || error));
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port })));
}

async function inspect(page, route, viewport, responseStatus, consoleErrors) {
  return page.evaluate(({ canonicalUrl, pageRoute, size, status, runtimeErrors }) => {
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0;
    };
    const text = (element) => (element.innerText || element.textContent || element.value || element.getAttribute("aria-label") || "").replace(/\s+/g, " ").trim();
    const intentionalScroller = (element) => Boolean(element.closest("[data-carousel], [data-slider], [role='tablist'], .carousel, .slider, .homepage-method-tabs, .homepage-explorer-tabs, .program-menu-grid, .calc-section[role='region'], .table-wrap, .table-responsive, .responsive-table, [class*='table-wrap'], [class*='table-region'], [class*='table-scroll'], .long-form-table-region"));
    const clippedText = [];
    for (const element of document.querySelectorAll("h1,h2,h3,h4,p,li,a,button,label,summary,dt,dd,.card,.service-card,.program-card,.homepage-card,.design-card")) {
      if (!visible(element) || element.matches(".skip-link") || element.closest("[aria-hidden='true']") || intentionalScroller(element)) continue;
      const style = getComputedStyle(element);
      if (!text(element) || Number.parseInt(style.webkitLineClamp || "0", 10) > 0) continue;
      const widthClipped = element.scrollWidth > element.clientWidth + 2 && ["hidden", "clip"].includes(style.overflowX);
      const heightClipped = element.scrollHeight > element.clientHeight + 2 && ["hidden", "clip"].includes(style.overflowY);
      if (widthClipped || heightClipped) clippedText.push({ tag: element.tagName.toLowerCase(), className: String(element.className || "").slice(0, 100), text: text(element).slice(0, 120), widthClipped, heightClipped });
    }

    const viewportOffenders = [];
    for (const element of document.querySelectorAll("main h1,main h2,main h3,main p,main a,main button,main article,main section,main figure,main form,main table")) {
      if (!visible(element) || intentionalScroller(element) || element.closest("[aria-hidden='true']")) continue;
      const rect = element.getBoundingClientRect();
      if (rect.width > 0 && (rect.left < -2 || rect.right > innerWidth + 2)) viewportOffenders.push({ tag: element.tagName.toLowerCase(), className: String(element.className || "").slice(0, 100), text: text(element).slice(0, 100), left: Math.round(rect.left), right: Math.round(rect.right) });
      if (viewportOffenders.length >= 12) break;
    }

    const duplicateIds = [...document.querySelectorAll("[id]")].map((item) => item.id).filter((id, index, all) => all.indexOf(id) !== index);
    const unlabeledControls = [...document.querySelectorAll("input:not([type='hidden']),select,textarea")].filter((control) => {
      if (!visible(control)) return false;
      const id = control.id;
      return !control.getAttribute("aria-label") && !control.getAttribute("aria-labelledby") && !control.closest("label") && !(id && document.querySelector(`label[for="${CSS.escape(id)}"]`));
    }).map((control) => `${control.tagName.toLowerCase()}#${control.id || "fără-id"}`);
    const unnamedActions = [...document.querySelectorAll("a[href],button")].filter((element) => visible(element) && !text(element) && !element.querySelector("img[alt]")).map((element) => `${element.tagName.toLowerCase()}.${String(element.className || "").slice(0, 60)}`);
    const missingAlt = [...document.querySelectorAll("img:not([alt])")].map((image) => image.getAttribute("src") || "img-fără-src");
    const skip = document.querySelector("a.skip-link[href^='#']");
    const skipTarget = skip ? document.querySelector(skip.getAttribute("href")) : null;
    const canonical = document.querySelector("link[rel='canonical']")?.href || "";
    const description = document.querySelector("meta[name='description']")?.content.trim() || "";
    const visibleBodyText = document.body.innerText || "";
    const watermarkMatches = [...new Set((visibleBodyText.match(/\b(?:as an ai|chatgpt|generated by ai|generated by openai|lorem ipsum|todo_[a-z_]*|de_validat_uman)\b/giu) || []).map((value) => value.toLowerCase()))];
    const mojibakeMatches = [...new Set(visibleBodyText.match(/(?:Ã.|â€|â€“|â€”|�|È.|Ä.)/gu) || [])].slice(0, 12);
    const horizontalOverflow = Math.max(0, document.documentElement.scrollWidth - innerWidth);
    const documentOverflowOffenders = [];
    if (horizontalOverflow > 1) {
      for (const element of document.querySelectorAll("body *")) {
        if (!visible(element) || intentionalScroller(element) || element.closest("[aria-hidden='true']")) continue;
        const rect = element.getBoundingClientRect();
        if (rect.left < -2 || rect.right > innerWidth + 2) {
          const style = getComputedStyle(element);
          documentOverflowOffenders.push({ tag: element.tagName.toLowerCase(), className: String(element.className || "").slice(0, 100), left: Math.round(rect.left), right: Math.round(rect.right), width: Math.round(rect.width), position: style.position });
        }
        if (documentOverflowOffenders.length >= 16) break;
      }
    }
    const checks = {
      http: status === 200,
      metadata: Boolean(document.title.trim() && description.length >= 50 && canonical === canonicalUrl && document.querySelector("meta[name='viewport']")),
      landmarks: document.querySelectorAll("main").length === 1 && document.querySelectorAll("h1").length === 1,
      language: /^ro(?:-|$)/i.test(document.documentElement.lang),
      skipLink: Boolean(skip && skipTarget),
      imageAlternatives: missingAlt.length === 0,
      controlsNamed: unlabeledControls.length === 0 && unnamedActions.length === 0,
      uniqueIds: duplicateIds.length === 0,
      noHorizontalOverflow: horizontalOverflow <= 1 && viewportOffenders.length === 0,
      noClippedText: clippedText.length === 0,
      noWatermarks: watermarkMatches.length === 0 && mojibakeMatches.length === 0,
      noConsoleErrors: runtimeErrors.length === 0
    };
    return {
      route: pageRoute, viewport: size, title: document.title, canonical, descriptionLength: description.length,
      horizontalOverflow, viewportOffenders, documentOverflowOffenders, clippedText, duplicateIds: [...new Set(duplicateIds)], missingAlt,
      unlabeledControls, unnamedActions, watermarkMatches, mojibakeMatches, consoleErrors: runtimeErrors,
      checks, pass: Object.values(checks).every(Boolean)
    };
  }, { canonicalUrl: `${SITE}${route === "/" ? "/" : route}`, pageRoute: route, size: viewport, status: responseStatus, runtimeErrors: consoleErrors });
}

async function auditViewport(browser, baseUrl, viewport, allRoutes) {
  const page = await browser.newPage({ viewport: { width: viewport.width, height: viewport.height }, reducedMotion: "reduce" });
  const results = [];
  try {
    for (const route of allRoutes) {
      const consoleErrors = [];
      const onConsole = (message) => { if (message.type() === "error" && !/favicon\.ico/i.test(message.text())) consoleErrors.push(message.text()); };
      const onPageError = (error) => consoleErrors.push(error.message);
      page.on("console", onConsole);
      page.on("pageerror", onPageError);
      const response = await page.goto(`${baseUrl}${route}`, { waitUntil: "domcontentloaded", timeout: 20000 });
      await page.waitForTimeout(40);
      const result = await inspect(page, route, viewport, response?.status() || 0, consoleErrors);
      const shouldCapture = !result.pass || (REPRESENTATIVE.has(route) && ["mobile-390", "desktop-1365"].includes(viewport.name));
      if (shouldCapture) {
        const screenshot = path.join(SCREENSHOT_DIR, `${routeLabel(route)}-${viewport.name}.png`);
        await page.screenshot({ path: screenshot, fullPage: true });
        result.screenshot = path.relative(ROOT, screenshot).split(path.sep).join("/");
      }
      results.push(result);
      page.off("console", onConsole);
      page.off("pageerror", onPageError);
    }
  } finally {
    await page.close();
  }
  return results;
}

function markdown(report) {
  const failed = report.results.filter((result) => !result.pass);
  const checks = Object.entries(report.summary.checks).map(([name, values]) => `| ${name} | ${values.pass} | ${values.fail} |`).join("\n");
  const failures = failed.length ? failed.map((result) => `- \`${result.route}\` la ${result.viewport.name}: ${Object.entries(result.checks).filter(([, pass]) => !pass).map(([name]) => name).join(", ")}`).join("\n") : "- Nicio abatere detectată.";
  return `# Audit integral de integritate vizuală și accesibilitate\n\nGenerat: ${report.generatedAt}\n\n- URL-uri canonice: **${report.summary.routes}**\n- Viewport-uri: **${VIEWPORTS.length}** (320, 390, 768 și 1365 px)\n- Verificări de pagină: **${report.summary.totalChecks}**\n- Verificări trecute: **${report.summary.passedChecks}**\n- Verificări eșuate: **${report.summary.failedChecks}**\n\n| Control | Trecut | Eșuat |\n|---|---:|---:|\n${checks}\n\n## Abateri\n\n${failures}\n`;
}

async function main() {
  await fsp.rm(SCREENSHOT_DIR, { recursive: true, force: true });
  await fsp.mkdir(SCREENSHOT_DIR, { recursive: true });
  const allRoutes = routes();
  const { server, port } = await createServer();
  const browser = await chromium.launch({ headless: true });
  let results;
  try {
    const groups = await Promise.all(VIEWPORTS.map((viewport) => auditViewport(browser, `http://127.0.0.1:${port}`, viewport, allRoutes)));
    results = groups.flat();
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
  const checkNames = Object.keys(results[0]?.checks || {});
  const summary = {
    routes: allRoutes.length,
    totalChecks: results.length,
    passedChecks: results.filter((result) => result.pass).length,
    failedChecks: results.filter((result) => !result.pass).length,
    checks: Object.fromEntries(checkNames.map((name) => [name, { pass: results.filter((result) => result.checks[name]).length, fail: results.filter((result) => !result.checks[name]).length }]))
  };
  const report = { generatedAt: new Date().toISOString(), summary, results };
  await fsp.writeFile(REPORT_PATH, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await fsp.writeFile(MARKDOWN_PATH, markdown(report), "utf8");
  console.log(`Audit vizual integral: ${summary.routes} rute × ${VIEWPORTS.length} viewport-uri = ${summary.totalChecks}; eșecuri: ${summary.failedChecks}.`);
  for (const result of results.filter((item) => !item.pass).slice(0, 80)) console.log(`- ${result.route} @ ${result.viewport.name}: ${Object.entries(result.checks).filter(([, pass]) => !pass).map(([name]) => name).join(", ")}`);
  if (summary.failedChecks) process.exitCode = 1;
}

main().catch((error) => { console.error(error.stack || error); process.exitCode = 1; });
