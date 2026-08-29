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
const { routes } = require("../tools/sync-program-visuals");
const VIEWPORTS = [
  { width: 320, height: 844 },
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1440, height: 960 }
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

async function inspect(page, route, viewport) {
  return page.evaluate(({ pageRoute, size }) => {
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0;
    };
    const intentionalScroller = (element) => Boolean(element.closest(".micro2-table-wrap,.table-wrap,.table-responsive,.responsive-table,.long-form-table-region,.dr14-tabs__list,.dr14-score__switcher,[role='tablist'],[class*='table-scroll'],[class*='table-region']"));
    const label = (element) => (element.innerText || element.textContent || element.getAttribute("aria-label") || "").replace(/\s+/gu, " ").trim().slice(0, 110);
    const parseColor = (value) => {
      const match = String(value || "").match(/rgba?\((?:\s*)([\d.]+)[, ]+([\d.]+)[, ]+([\d.]+)(?:\s*[,/]\s*([\d.]+))?\s*\)/iu);
      return match ? { r: Number(match[1]), g: Number(match[2]), b: Number(match[3]), a: match[4] === undefined ? 1 : Number(match[4]) } : null;
    };
    const luminance = ({ r, g, b }) => [r, g, b].map((channel) => {
      const normalized = channel / 255;
      return normalized <= .04045 ? normalized / 12.92 : ((normalized + .055) / 1.055) ** 2.4;
    }).reduce((sum, channel, index) => sum + channel * [.2126, .7152, .0722][index], 0);
    const contrastRatio = (left, right) => {
      const values = [luminance(left), luminance(right)].sort((a, b) => b - a);
      return (values[0] + .05) / (values[1] + .05);
    };
    const solidBackground = (element) => {
      let current = element;
      while (current) {
        const style = getComputedStyle(current);
        if (style.backgroundImage && style.backgroundImage !== "none") return null;
        const color = parseColor(style.backgroundColor);
        if (color && color.a >= .98) return { color, source: `${current.tagName.toLowerCase()}.${String(current.className || "").trim().replace(/\s+/gu, ".")}` };
        current = current.parentElement;
      }
      return { color: { r: 255, g: 255, b: 255, a: 1 }, source: "canvas alb implicit" };
    };

    const contextual = document.querySelector("[data-program-contextual-links] details");
    const contextualDefaultClosed = contextual ? !contextual.open : true;
    const microAlertBeforeOpen = document.querySelector("[data-score-alert-disclosure]");
    const microAlertDefaultClosed = microAlertBeforeOpen ? !microAlertBeforeOpen.open : true;
    document.querySelectorAll("main details").forEach((detail) => { detail.open = true; });

    const clippedText = [];
    for (const element of document.querySelectorAll("main h1,main h2,main h3,main h4,main p,main li,main a,main button,main label,main summary,main dt,main dd,main strong,main small")) {
      if (!visible(element) || intentionalScroller(element) || element.closest("[aria-hidden='true']")) continue;
      const style = getComputedStyle(element);
      const widthClipped = element.scrollWidth > element.clientWidth + 2 && ["hidden", "clip"].includes(style.overflowX);
      const heightClipped = element.scrollHeight > element.clientHeight + 2 && ["hidden", "clip"].includes(style.overflowY);
      if (widthClipped || heightClipped) clippedText.push({ tag: element.tagName.toLowerCase(), className: String(element.className || "").slice(0, 90), text: label(element), widthClipped, heightClipped });
      if (clippedText.length >= 12) break;
    }

    const outsideViewport = [];
    for (const element of document.querySelectorAll("main :where(section,article,aside,figure,form,fieldset,h1,h2,h3,p,a,button,svg,img)")) {
      if (!visible(element) || intentionalScroller(element) || element.closest("[aria-hidden='true']")) continue;
      const rect = element.getBoundingClientRect();
      if (rect.left < -2 || rect.right > innerWidth + 2) outsideViewport.push({ tag: element.tagName.toLowerCase(), className: String(element.className || "").slice(0, 90), text: label(element), left: Math.round(rect.left), right: Math.round(rect.right) });
      if (outsideViewport.length >= 12) break;
    }

    const svgIssues = [];
    const visibleSvgs = [...document.querySelectorAll("main svg")].filter(visible);
    for (const svg of visibleSvgs) {
      const rect = svg.getBoundingClientRect();
      const viewBox = (svg.getAttribute("viewBox") || "").trim().split(/\s+/u).map(Number);
      if (viewBox.length !== 4 || !viewBox.every(Number.isFinite) || viewBox[2] <= 0 || viewBox[3] <= 0) svgIssues.push("viewBox invalid");
      if (rect.width < 16 || rect.height < 16) svgIssues.push(`dimensiune randată ${Math.round(rect.width)}×${Math.round(rect.height)}`);
      if (!intentionalScroller(svg) && (rect.left < -2 || rect.right > innerWidth + 2)) svgIssues.push(`SVG în afara viewportului ${Math.round(rect.left)}..${Math.round(rect.right)}`);
      if (svg.getAttribute("preserveAspectRatio") === "none") svgIssues.push("preserveAspectRatio=none");
      for (const textNode of svg.querySelectorAll("text")) {
        if (!visible(textNode)) continue;
        const textRect = textNode.getBoundingClientRect();
        if (textRect.left < rect.left - 4 || textRect.right > rect.right + 4 || textRect.top < rect.top - 4 || textRect.bottom > rect.bottom + 4) {
          svgIssues.push(`text SVG tăiat: ${(textNode.textContent || "").trim()}`);
        }
      }
    }

    const contrastIssues = [];
    let contrastChecks = 0;
    for (const element of document.querySelectorAll("main h1,main h2,main h3,main h4,main p,main li,main a,main button,main label,main summary,main dt,main dd,main span,main strong,main small,main .program-card__number")) {
      if (!visible(element) || element.closest("svg,[aria-hidden='true']") || intentionalScroller(element)) continue;
      const directText = [...element.childNodes].filter((node) => node.nodeType === Node.TEXT_NODE).map((node) => node.textContent || "").join(" ").trim();
      if (!directText) continue;
      const style = getComputedStyle(element);
      const foreground = parseColor(style.color);
      const background = solidBackground(element);
      if (!foreground || foreground.a < .98 || !background) continue;
      contrastChecks += 1;
      const fontSize = Number.parseFloat(style.fontSize);
      const weight = Number.parseInt(style.fontWeight, 10) || (style.fontWeight === "bold" ? 700 : 400);
      const large = fontSize >= 24 || (fontSize >= 18.66 && weight >= 700);
      const minimum = large ? 3 : 4.5;
      const ratio = contrastRatio(foreground, background.color);
      if (ratio + .02 < minimum) contrastIssues.push({ text: directText.replace(/\s+/gu, " ").slice(0, 100), className: String(element.className || "").slice(0, 90), ratio: Number(ratio.toFixed(2)), minimum, color: style.color, backgroundSource: background.source });
      if (contrastIssues.length >= 12) break;
    }

    const contextualBody = document.querySelector(".program-contextual-links__body");
    const contextualList = document.querySelector(".program-contextual-links__list");
    const contextualBodyStyle = contextualBody ? getComputedStyle(contextualBody) : null;
    const contextualContentWidth = contextualBody && contextualBodyStyle
      ? contextualBody.clientWidth - Number.parseFloat(contextualBodyStyle.paddingLeft) - Number.parseFloat(contextualBodyStyle.paddingRight)
      : 0;
    const contextualWidthIntegrity = !contextualBody || !contextualList || Math.abs(contextualContentWidth - contextualList.getBoundingClientRect().width) <= 2;
    const microAlert = document.querySelector("[data-score-alert-disclosure]");
    const microAlertIntegrity = pageRoute !== "/investitii-modernizarea-microintreprinderilor-apel-2" || Boolean(microAlert && microAlert.querySelector("summary") && microAlert.querySelector("[data-score-alert-count]") && microAlert.querySelectorAll("[data-score-alerts] li").length);

    return {
      route: pageRoute,
      viewport: size.width,
      horizontalOverflow: Math.max(0, document.documentElement.scrollWidth - innerWidth),
      clippedText,
      outsideViewport,
      visibleSvgCount: visibleSvgs.length,
      svgIssues: [...new Set(svgIssues)],
      contrastChecks,
      contrastIssues,
      contextualDefaultClosed,
      contextualWidthIntegrity,
      microAlertIntegrity,
      microAlertDefaultClosed
    };
  }, { pageRoute: route, size: viewport });
}

const { server, port } = await localServer();
const browser = await chromium.launch({ headless: true });
const failures = [];
let checks = 0;

try {
  await Promise.all(VIEWPORTS.map(async (viewport) => {
    const page = await browser.newPage({ viewport, reducedMotion: "reduce" });
    try {
      for (const route of routes()) {
        const errors = [];
        const runtimeErrors = [];
        const onPageError = (error) => runtimeErrors.push(error.message);
        const onConsole = (message) => {
          const text = message.text();
          const googlePreferredSourceReportOnly = /Framing 'https:\/\/news\.google\.com\/'.*report-only Content Security Policy directive: "frame-ancestors 'self'"/iu.test(text);
          if (message.type() === "error" && !/favicon\.ico/iu.test(text) && !googlePreferredSourceReportOnly) runtimeErrors.push(text);
        };
        page.on("pageerror", onPageError);
        page.on("console", onConsole);
        const response = await page.goto(`http://127.0.0.1:${port}${route}`, { waitUntil: "domcontentloaded", timeout: 25000 });
        await page.waitForTimeout(60);
        const result = await inspect(page, route, viewport);
        if (!response || response.status() !== 200) errors.push(`HTTP ${response?.status() || "absent"}`);
        if (runtimeErrors.length) errors.push(`erori runtime: ${runtimeErrors.join(" | ")}`);
        if (result.horizontalOverflow > 1) errors.push(`overflow orizontal ${result.horizontalOverflow}px`);
        if (result.clippedText.length) errors.push(`text tăiat: ${JSON.stringify(result.clippedText.slice(0, 3))}`);
        if (result.outsideViewport.length) errors.push(`elemente în afara viewportului: ${JSON.stringify(result.outsideViewport.slice(0, 3))}`);
        if (!result.visibleSvgCount) errors.push("niciun SVG vizibil");
        if (result.svgIssues.length) errors.push(`SVG: ${result.svgIssues.join(", ")}`);
        if (result.contrastChecks < 20) errors.push(`acoperire contrast insuficientă: ${result.contrastChecks}`);
        if (result.contrastIssues.length) errors.push(`contrast: ${JSON.stringify(result.contrastIssues.slice(0, 4))}`);
        if (!result.contextualDefaultClosed) errors.push("secțiunea contextuală nu este restrânsă implicit");
        if (!result.contextualWidthIntegrity) errors.push("lista contextuală nu folosește lățimea corpului secțiunii");
        if (!result.microAlertIntegrity) errors.push("dropdown-ul de avertismente nu este funcțional");
        if (!result.microAlertDefaultClosed) errors.push("dropdown-ul de avertismente nu este restrâns implicit");
        checks += 1;
        if (errors.length) failures.push({ route, viewport: viewport.width, errors });
        page.off("pageerror", onPageError);
        page.off("console", onConsole);
      }
    } finally {
      await page.close();
    }
  }));
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

for (const failure of failures) console.error(`FAIL ${failure.route} @ ${failure.viewport}px\n  ${failure.errors.join("\n  ")}`);
assert.equal(failures.length, 0, `${failures.length} din ${checks} verificări vizuale de program au eșuat`);
console.log(`Integritate vizuală programe: ${routes().length} rute × ${VIEWPORTS.length} viewport-uri = ${checks} verificări trecute (text, contrast, încadrare și SVG).`);
