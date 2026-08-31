import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { fileForRoute } = require("../tools/structured-data-utils");
const { routes } = require("../tools/sync-site-immersive");
const { routes: programRoutes } = require("../tools/sync-program-visuals");
const programSet = new Set(programRoutes());
const VIEWPORTS = [
  { width: 320, height: 844, reducedMotion: "reduce" },
  { width: 1440, height: 960, reducedMotion: "no-preference" }
];
const MIME = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webp": "image/webp"
};

function requestedFile(requestUrl) {
  const pathname = decodeURIComponent(new URL(requestUrl, "http://127.0.0.1").pathname);
  if (path.extname(pathname)) return path.resolve(ROOT, pathname.replace(/^\/+/, ""));
  return fileForRoute(ROOT, pathname.replace(/\/$/, "") || "/");
}

function localServer() {
  const server = http.createServer((request, response) => {
    try {
      const file = requestedFile(request.url || "/");
      const insideRoot = file === ROOT || file.startsWith(`${ROOT}${path.sep}`);
      if (!insideRoot || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
        response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        response.end("Not found");
        return;
      }
      response.writeHead(200, { "content-type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream" });
      fs.createReadStream(file).pipe(response);
    } catch (error) {
      response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      response.end(String(error));
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port })));
}

const { server, port } = await localServer();
const browser = await chromium.launch({ headless: true });
const failures = [];
let checks = 0;

try {
  await Promise.all(VIEWPORTS.map(async (viewport) => {
    const context = await browser.newContext({ viewport, reducedMotion: viewport.reducedMotion });
    await context.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.hostname === "127.0.0.1") await route.continue();
      else await route.abort("blockedbyclient");
    });
    const page = await context.newPage();
    try {
      for (const pageRoute of routes()) {
        const runtimeErrors = [];
        const onPageError = (error) => runtimeErrors.push(error.message);
        page.on("pageerror", onPageError);
        const response = await page.goto(`http://127.0.0.1:${port}${pageRoute}`, { waitUntil: "domcontentloaded", timeout: 25000 });
        await page.waitForFunction(() => document.body?.getAttribute("data-immersive-ready") === "true", null, { timeout: 5000 });
        const result = await page.evaluate(({ isProgram, viewportWidth, motion }) => {
          const visible = (element) => {
            if (!element) return false;
            const style = getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
          };
          const outside = [];
          for (const element of document.querySelectorAll("main :is(section,article,aside,figure,form,fieldset,h1,h2,h3,p,button,svg,img)")) {
            if (!visible(element) || element.closest("[aria-hidden='true'],.table-wrap,.table-responsive,[class*='table-scroll'],[role='tablist'],.homepage-method-tabs,.homepage-explorer-tabs,.priority-program-track,.priority-program-viewport")) continue;
            const rect = element.getBoundingClientRect();
            if (rect.left < -2 || rect.right > innerWidth + 2) outside.push(`${element.tagName.toLowerCase()}.${String(element.className || "").split(/\s+/u).slice(0, 2).join(".")}:${Math.round(rect.left)}..${Math.round(rect.right)}`);
            if (outside.length === 6) break;
          }
          const visual = document.querySelector("[data-program-visual='immersive-verification']");
          const desktop = visual?.querySelector(".program-visual__svg--desktop");
          const mobile = visual?.querySelector(".program-visual__svg--mobile");
          const pressed = visual ? visual.querySelectorAll("[data-program-step][aria-pressed='true']").length : 0;
          const expectedScene = viewportWidth <= 640 ? mobile : desktop;
          const labelsFit = visual ? [...visual.querySelectorAll("[data-program-step]")].every((button) => button.scrollWidth <= button.clientWidth + 2 && button.scrollHeight <= button.clientHeight + 2) : true;
          return {
            ready: document.body.getAttribute("data-immersive-ready"),
            progress: Boolean(document.querySelector(".site-immersive-progress")),
            overflow: Math.max(0, document.documentElement.scrollWidth - innerWidth),
            outside,
            h1: document.querySelectorAll("h1").length,
            programReady: !isProgram || visual?.getAttribute("data-immersive-ready") === "true",
            sceneVisible: !isProgram || visible(expectedScene),
            pressed,
            labelsFit,
            motionDisabled: !isProgram || motion !== "reduce" || Number.parseFloat(getComputedStyle(visual.querySelector(".program-visual__track")).animationDuration) <= .001
          };
        }, { isProgram: programSet.has(pageRoute), viewportWidth: viewport.width, motion: viewport.reducedMotion });
        const errors = [];
        if (!response || response.status() !== 200) errors.push(`HTTP ${response?.status() || "absent"}`);
        if (runtimeErrors.length) errors.push(`runtime: ${runtimeErrors.join(" | ")}`);
        if (result.ready !== "true" || !result.progress) errors.push("stratul imersiv nu s-a inițializat");
        if (result.overflow > 1) errors.push(`overflow orizontal ${result.overflow}px`);
        if (result.outside.length) errors.push(`elemente în afara viewportului: ${result.outside.join(", ")}`);
        if (result.h1 !== 1) errors.push(`număr H1 în main/body: ${result.h1}`);
        if (!result.programReady || !result.sceneVisible || (programSet.has(pageRoute) && result.pressed !== 1)) errors.push("banner de program neinițializat sau scena potrivită nu este vizibilă");
        if (!result.labelsFit) errors.push("etichete de program tăiate");
        if (!result.motionDisabled) errors.push("prefers-reduced-motion nu oprește animația programului");
        if (errors.length) failures.push({ route: pageRoute, viewport: viewport.width, errors });
        checks += 1;
        page.off("pageerror", onPageError);
      }
    } finally {
      await context.close();
    }
  }));
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

for (const failure of failures) console.error(`FAIL ${failure.route} @ ${failure.viewport}px\n  ${failure.errors.join("\n  ")}`);
assert.equal(failures.length, 0, `${failures.length} din ${checks} verificări responsive au eșuat`);
console.log(`Integritate vizuală site: ${routes().length} rute × ${VIEWPORTS.length} viewport-uri = ${checks} verificări trecute.`);
