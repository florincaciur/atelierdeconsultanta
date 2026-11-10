#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const { chromium, devices } = require("playwright");

const scenarios = {
  "/": ["[data-hero-program-next]", "[data-hero-program-prev]", "[data-hero-program-next]"],
  "/e-drive": ["#documente summary", "#documente summary", "#documente summary"],
  "/digitalizare-imm-regiunea-centru-apel-2": ["#documente summary", "#documente summary", "#documente summary"],
  "/calculator-soc": ["#calculator button.btn-add", "#calculator button.calc-remove", "#calculator button.btn-add"],
  "/contact": ["#contact-optional-summary", "#contact-optional-summary", "#contact-optional-summary"]
};
const profiles = {
  mobile: { latency: 150, downloadKbps: 1600, uploadKbps: 750, cpu: 4 },
  constrained: { latency: 400, downloadKbps: 400, uploadKbps: 400, cpu: 4 }
};
const option = (name, fallback) => process.argv.find(arg => arg.startsWith(`--${name}=`))?.split("=").slice(1).join("=") || fallback;
const origin = new URL(option("origin", "https://atelierdeconsultanta.ro")).origin;
const profile = option("profile", "mobile");
const conditions = profiles[profile];
const runs = Number(option("runs", profile === "mobile" ? 3 : 1));
const output = option("output");
const routes = option("routes")?.split(",") || Object.keys(scenarios);
if (!conditions || !Number.isInteger(runs) || runs < 1 || !routes.every(route => scenarios[route])) throw new Error("Profil, număr de rulari sau rute invalide.");

function installObservers() {
  const data = window.mobileAudit = { lcp: [], shifts: [], events: [], tasks: [] };
  const observe = (type, output, convert, options = {}) => {
    new PerformanceObserver(list => {
      for (const entry of list.getEntries()) output.push(convert(entry));
    }).observe({ type, buffered: true, ...options });
  };
  observe("largest-contentful-paint", data.lcp, entry => ({
    ms: entry.startTime, renderMs: entry.renderTime, loadMs: entry.loadTime, size: entry.size,
    url: entry.url, element: entry.element && (entry.element.id ? "#" + entry.element.id : entry.element.tagName.toLowerCase() + "." + [...entry.element.classList].join("."))
  }));
  observe("layout-shift", data.shifts, entry => ({
    ms: entry.startTime, value: entry.value, recentInput: entry.hadRecentInput,
    elements: entry.sources.map(source => source.node?.id || source.node?.className || source.node?.nodeName).map(String)
  }));
  observe("event", data.events, entry => ({
    id: entry.interactionId, name: entry.name, start: entry.startTime, duration: entry.duration,
    delay: entry.processingStart - entry.startTime, processing: entry.processingEnd - entry.processingStart
  }), { durationThreshold: 16 });
  observe("longtask", data.tasks, entry => ({ ms: entry.startTime, duration: entry.duration }));
}

function summarizeVitals(data) {
  let maxCls = 0;
  let current = 0;
  let first = -Infinity;
  let previous = -Infinity;
  for (const shift of data.shifts.filter(item => !item.recentInput)) {
    if (shift.ms - previous >= 1000 || shift.ms - first >= 5000) {
      current = 0;
      first = shift.ms;
    }
    current += shift.value;
    previous = shift.ms;
    maxCls = Math.max(maxCls, current);
  }
  const slowest = data.events.filter(event => event.id).sort((a, b) => b.duration - a.duration)[0];
  return {
    lcpMs: Math.round(data.lcp.at(-1)?.ms) || null,
    cls: Number(maxCls.toFixed(5)),
    interactionMs: slowest?.duration ?? null,
    interactionBelow16Ms: !slowest && data.interactionCount > 0,
    interactionCount: data.interactionCount,
    slowest,
    blockingMs: Math.round(data.tasks.filter(task => task.ms >= data.fcpMs && task.ms <= data.loadSampleMs)
      .reduce((sum, task) => sum + Math.max(0, task.duration - 50), 0))
  };
}

async function measure(browser, route, run) {
  const { defaultBrowserType, ...device } = devices["Pixel 7"];
  const context = await browser.newContext({ ...device, serviceWorkers: "block", locale: "ro-RO" });
  // The audit never forwards writes, including accidental submits.
  await context.route("**/*", request => ["GET", "HEAD"].includes(request.request().method()) ? request.continue() : request.abort());
  try {
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("Network.enable");
    await cdp.send("Network.setCacheDisabled", { cacheDisabled: true });
    await cdp.send("Network.emulateNetworkConditions", {
      offline: false, latency: conditions.latency,
      downloadThroughput: conditions.downloadKbps * 125, uploadThroughput: conditions.uploadKbps * 125,
      connectionType: "cellular4g"
    });
    await cdp.send("Emulation.setCPUThrottlingRate", { rate: conditions.cpu });
    const resources = new Map();
    cdp.on("Network.requestWillBeSent", ({ requestId, request, type, initiator }) => {
      if (!request.url.startsWith("http")) return;
      const url = new URL(request.url);
      resources.set(requestId, { path: url.pathname, host: url.hostname, type: type || "Other", initiator: initiator.type, bytes: null });
    });
    cdp.on("Network.responseReceived", ({ requestId, response, type }) => {
      const entry = resources.get(requestId);
      if (entry) Object.assign(entry, { status: response.status, type, mime: response.mimeType });
    });
    cdp.on("Network.loadingFinished", ({ requestId, encodedDataLength }) => {
      const entry = resources.get(requestId);
      if (entry) entry.bytes = encodedDataLength;
    });
    cdp.on("Network.loadingFailed", ({ requestId, errorText }) => {
      const entry = resources.get(requestId);
      if (entry) entry.error = errorText;
    });
    await page.addInitScript(installObservers);
    const response = await page.goto(origin + route, { waitUntil: "domcontentloaded", timeout: 60000 });
    if (response.status() !== 200) throw new Error(`${route} HTTP ${response.status()}`);
    await page.waitForLoadState("load", { timeout: 35000 }).catch(() => {});
    await page.waitForTimeout(1100);
    const start = await page.evaluate(() => {
      const navigation = performance.getEntriesByType("navigation")[0];
      return {
        fcpMs: performance.getEntriesByName("first-contentful-paint")[0]?.startTime,
        ttfbMs: navigation.responseStart, domMs: navigation.domContentLoadedEventEnd, loadMs: navigation.loadEventEnd,
        loadSampleMs: performance.now(),
        aboveFold: document.querySelector("h1")?.getBoundingClientRect().height > 0
      };
    });
    const initialResources = [...resources.values()].map(entry => ({ ...entry }));
    for (const selector of scenarios[route]) {
      await page.locator(selector).first().tap({ timeout: 12000 });
      await page.waitForTimeout(180);
    }
    await page.waitForTimeout(500);
    const data = await page.evaluate(() => ({ ...window.mobileAudit, interactionCount: performance.interactionCount }));
    return { route, run, ...start, ...summarizeVitals({ ...start, ...data }), lcp: data.lcp, shifts: data.shifts, resources: initialResources };
  } finally {
    await context.close();
  }
}

async function main() {
  const browser = await chromium.launch();
  const report = { origin, profile, conditions, device: devices["Pixel 7"], chromium: browser.version(), recordedAt: new Date().toISOString(), rows: [] };
  try {
    for (let run = 1; run <= runs; run++) {
      for (const route of routes) {
        const row = await measure(browser, route, run);
        report.rows.push(row);
        if (output) fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
        console.log(`${run} ${route} LCP=${row.lcpMs}ms CLS=${row.cls} interacțiune=${row.interactionMs ?? (row.interactionBelow16Ms ? "<16" : "n/d")}ms cereri=${row.resources.length}`);
      }
    }
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
