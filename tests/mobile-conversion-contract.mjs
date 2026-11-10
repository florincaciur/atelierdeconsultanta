import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { chromium, devices } from "playwright";
import sharp from "sharp";
import structuredData from "../tools/structured-data-utils.js";

const require = createRequire(import.meta.url);
const root = path.resolve(import.meta.dirname, "..");
const { fileForRoute } = structuredData;
const option = name => process.argv.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
const live = option("origin");
const out = option("output");
const adr = "/digitalizare-imm-regiunea-centru-apel-2";
const routes = ["/", "/e-drive", adr, "/calculator-soc", "/contact"];
const mime = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml", ".json": "application/json", ".png": "image/png", ".webp": "image/webp"
};
const server = http.createServer(async (req, res) => {
  if (req.method !== "GET") return res.writeHead(405).end();
  const route = new URL(req.url, "http://localhost").pathname;
  const file = path.extname(route) ? path.resolve(root, `.${route}`) : fileForRoute(root, route);
  if (!file.startsWith(root + path.sep)) return res.writeHead(404).end();
  try {
    res.setHeader("Content-Type", mime[path.extname(file)] || "application/octet-stream");
    res.end(await fs.readFile(file));
  } catch { res.writeHead(404).end(); }
});

if (!live) await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const origin = live ? new URL(live).origin : `http://127.0.0.1:${server.address().port}`;
const { defaultBrowserType, ...device } = devices["Pixel 7"];
const report = { origin, intercepted: 0, otherWritesBlocked: 0, flows: [], accessibility: [], noJs: [] };

async function open(page, route) {
  const response = await page.goto(origin + route, { waitUntil: "load" });
  assert.equal(response.status(), 200, route);
}

async function safeContext(browser, options = {}, mock = async route => route.abort()) {
  const context = await browser.newContext({ ...device, serviceWorkers: "block", reducedMotion: "reduce", ...options });
  await context.route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin === origin && url.pathname === "/api/contact-triage" && request.method() === "POST") {
      report.intercepted++;
      return mock(route);
    }
    if (url.origin === origin && request.method() === "GET") return route.continue();
    if (url.origin === origin && !["GET", "HEAD"].includes(request.method())) report.otherWritesBlocked++;
    return route.abort();
  });
  return context;
}

async function checkFlow(browser, { source, selector, program = "unknown", phone = false, retry = false, so }) {
  let submissions = 0;
  const payloads = [];
  const context = await safeContext(browser, {}, async route => {
    const request = route.request();
    const body = new Response(request.postDataBuffer(), { headers: { "content-type": request.headers()["content-type"] } });
    payloads.push(await body.formData());
    submissions++;
    const failed = retry && submissions === 1;
    if (retry) await new Promise(resolve => setTimeout(resolve, 600));
    await route.fulfill({ status: failed ? 503 : 200, json: failed ? { success: false, message: "Serviciu indisponibil temporar." } : { success: true, leadId: "intercepted-audit" } });
  });
  try {
    const page = await context.newPage();
    await open(page, source);
    if (so) {
      await page.getByRole("button", { name: /adaugă cultură/iu }).first().click();
      await page.locator("#culturi-body .area-input").last().fill("2.5");
    }
    if (selector) {
      const link = page.locator(selector).first();
      // Drop the referrer to check that the CTA itself carries the source.
      await link.evaluate(node => { node.rel = "noreferrer"; });
      await Promise.all([page.waitForURL(url => url.pathname === "/contact"), link.click()]);
    }
    const form = page.locator("#contact-triage-form");
    await form.locator("[data-action=review-short]").waitFor();
    const value = name => form.locator(`[name="${name}"]`).inputValue();
    assert.equal(await value("source_page"), selector ? source : "/");
    assert.equal(await value("program_slug"), program);
    if (so) assert.equal(await value("calculator_so_result"), String(so));
    if (source === "/contact") {
      await form.locator("[data-action=review-short]").click();
      assert.equal(submissions, 0);
      assert.equal(await form.locator("#contact-applicant-type").getAttribute("aria-invalid"), "true");
    }
    await form.locator("#contact-applicant-type").selectOption("societate");
    await form.locator("#contact-location").fill("Brașov");
    await form.locator("#contact-investment").fill("Verificare formular în mediu interceptat");
    await form.locator(phone ? "#contact-phone" : "#contact-email").fill(phone ? "0700000000" : "audit@example.invalid");
    await form.locator("#privacy-notice-acknowledged").check();
    await form.locator("[data-action=review-short]").click();
    await form.locator("[data-final-submit]").click();
    if (retry) {
      const button = form.locator("[data-retry-submit]");
      await button.waitFor();
      assert.equal(await value("investment"), "Verificare formular în mediu interceptat");
      await button.click();
    }
    await page.locator("[data-form-success]").waitFor();
    assert.equal(submissions, retry ? 2 : 1);
    for (const payload of payloads) {
      assert.equal(payload.get("source_page"), selector ? source : "/");
      assert.equal(payload.get("program_slug") || "", program);
      if (so) assert.equal(payload.get("calculator_so_result"), String(so));
      assert.equal(payload.get("privacy_notice_acknowledged"), "true");
    }
    report.flows.push({ source, program, so: so || null, contactMethod: phone ? "telefon" : "email", intercepted: submissions, retry });
  } finally { await context.close(); }
}

function luminance(rgb) {
  return rgb.reduce((sum, channel, index) => {
    const s = channel / 255;
    return sum + [0.2126, 0.7152, 0.0722][index] * (s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4);
  }, 0);
}

async function checkCtaContrast(page, selector) {
  const cta = page.locator(selector).first();
  await cta.scrollIntoViewIfNeeded();
  const foreground = await cta.evaluate(node => {
    const color = getComputedStyle(node).color.match(/[\d.]+/g).map(Number).slice(0, 3);
    node.style.setProperty("-webkit-text-fill-color", "transparent", "important");
    return color;
  });
  let pixels;
  try {
    pixels = await sharp(await cta.screenshot({ scale: "css" })).removeAlpha().raw().toBuffer({ resolveWithObject: true });
  } finally {
    await cta.evaluate(node => node.style.removeProperty("-webkit-text-fill-color"));
  }
  const { width, height, channels } = pixels.info;
  const contrast = [0.25, 0.5, 0.75].map(x => {
    const start = (Math.floor(height / 2) * width + Math.floor(width * x)) * channels;
    const a = luminance(foreground);
    const b = luminance([...pixels.data.subarray(start, start + 3)]);
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  });
  const minRatio = Number(Math.min(...contrast).toFixed(2));
  assert(minRatio >= 4.5, `${selector}: contrast ${minRatio}:1`);
  return { selector, minRatio };
}

async function checkAccessibility(browser) {
  const context = await safeContext(browser);
  try {
    const page = await context.newPage();
    for (const route of routes) {
      await open(page, route);
      await page.keyboard.press("Tab");
      assert.equal(await page.locator(":focus").getAttribute("href"), "#main-content", route + " skip link");
      const menu = page.locator("#hamburgerBtn");
      await menu.focus();
      await page.keyboard.press("Enter");
      assert.equal(await menu.getAttribute("aria-expanded"), "true");
      await page.keyboard.press("Escape");
      assert.equal(await menu.getAttribute("aria-expanded"), "false");
      if (route === "/") {
        await page.locator("[data-hero-program-next]").focus();
        await page.keyboard.press("Enter");
        assert.equal(await page.locator("[data-hero-program-page-count]").textContent(), "Grupul 2 din 2");
      }
      await page.addScriptTag({ path: require.resolve("axe-core/axe.min.js") });
      const data = await page.evaluate(async () => {
        const axe = await window.axe.run(document, { runOnly: ["color-contrast"] });
        return {
          scrollOverflow: document.documentElement.scrollWidth - innerWidth,
          runningAnimations: document.getAnimations().filter(animation => animation.playState === "running" && animation.effect?.target?.closest("main")).map(animation => ({
            id: animation.animationName || animation.transitionProperty || animation.id, element: animation.effect.target.className.toString()
          })),
          contrast: axe.violations.flatMap(rule => rule.nodes.map(node => ({ target: node.target.join(" "), detail: node.failureSummary }))),
          contrastNeedsManual: axe.incomplete.flatMap(rule => rule.nodes.map(node => node.target.join(" ")))
        };
      });
      assert(data.scrollOverflow <= 1, `${route}: overflow ${data.scrollOverflow}px`);
      assert.equal(data.contrast.length, 0, `${route}: ${JSON.stringify(data.contrast)}`);
      assert.equal(data.runningAnimations.length, 0, route + " mișcare redusă");
      const selector = {
        "/": "#hero [data-contextual-hero-cta]", "/e-drive": ".program-hero__actions .program-button--primary",
        [adr]: ".program-hero__actions .program-button--primary", "/calculator-soc": "[data-calculator-context-cta]",
        "/contact": "#contact-triage-form [data-action=review-short]"
      }[route];
      const primaryContrast = await checkCtaContrast(page, selector);
      report.accessibility.push({ route, keyboard: true, primaryContrast, ...data });
    }
  } finally { await context.close(); }
}

async function checkNoJs(browser) {
  const context = await safeContext(browser, { javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    const selectors = {
      "/": ["#hero [data-hero-program-item][href='/e-drive']", "#hero [data-hero-program-item][href='" + adr + "']", "#hero noscript a[href='/calendar-fonduri-europene']"],
      "/e-drive": [".program-factual-status", "#masura-1", "#masura-2"],
      [adr]: [".program-factual-status", "#exemplu-plan-erp", "#documente summary"],
      "/calculator-soc": ["#exemple-calcul-so [data-so-example]", "#coeficienti-soc-2020 > summary"],
      "/contact": ["#contact-triage-form", "#contact-triage-form .contact-no-js-submit button"]
    };
    for (const route of routes) {
      await open(page, route);
      for (const selector of selectors[route]) {
        const element = page.locator(selector).first();
        assert(await element.isVisible(), `${route}: ${selector} ascuns fără JavaScript`);
      }
      const sourceLink = page.locator(".preferred-source-cta a[href^='https://www.google.com/preferences/source']");
      assert(await sourceLink.isVisible(), `${route}: preferință Google fără JavaScript`);
      report.noJs.push({ route, visible: selectors[route] });
    }
  } finally { await context.close(); }
}

let browser;
try {
  browser = await chromium.launch();
  await checkAccessibility(browser);
  await checkNoJs(browser);
  await checkFlow(browser, { source: "/", selector: "#hero [data-contextual-hero-cta]" });
  await checkFlow(browser, { source: "/e-drive", selector: ".program-hero__actions a[href^='/contact']", program: "e-drive", phone: true });
  await checkFlow(browser, { source: adr, selector: ".program-hero__actions a[href^='/contact']", program: adr.slice(1), retry: true });
  await checkFlow(browser, { source: "/calculator-soc", selector: "[data-calculator-context-cta]", so: 1945 });
  await checkFlow(browser, { source: "/contact", phone: true });
  assert.equal(report.otherWritesBlocked, 0);
  console.log(JSON.stringify({ flows: report.flows, noJs: report.noJs.length, accessibility: report.accessibility.map(({ route, contrast, contrastNeedsManual, runningAnimations }) => ({ route, contrast: contrast.length, contrastNeedsManual: contrastNeedsManual.length, runningAnimations: runningAnimations.length })), intercepted: report.intercepted }));
} finally {
  if (out) await fs.writeFile(out, JSON.stringify(report, null, 2) + "\n");
  if (browser) await browser.close();
  if (!live) await new Promise(resolve => server.close(resolve));
}
