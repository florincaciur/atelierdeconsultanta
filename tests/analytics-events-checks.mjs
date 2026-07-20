import assert from "node:assert/strict";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ALLOWED_TAGS = new Set([
  "faber_event_route",
  "faber_event_component_type",
  "faber_event_cta_id",
  "faber_event_destination_route",
  "faber_event_program_category",
  "faber_event_status"
]);
const DELEGATED_CLICK_EVENTS = [
  "nav_click",
  "program_menu_click",
  "eligibility_cta_click",
  "whatsapp_number_click",
  "contact_page_click",
  "calculator_result_to_dr12",
  "calculator_result_to_dr14",
  "source_document_click",
  "next_step_click",
  "phone_click",
  "email_click"
];

function analyticsFixture() {
  const controls = DELEGATED_CLICK_EVENTS.map((eventName) => (
    `<button type="button" id="event-${eventName}" data-analytics-event="${eventName}" data-analytics-component="playwright_fixture" data-analytics-cta-id="${eventName}" data-analytics-target="/fixture-target">${eventName}</button>`
  )).join("\n");
  return `<!doctype html><html lang="ro"><head><meta charset="utf-8"><script src="/assets/analytics-events.js" defer></script></head><body>${controls}</body></html>`;
}

function contentType(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  if (extension === ".html") return "text/html; charset=utf-8";
  if (extension === ".js") return "application/javascript; charset=utf-8";
  if (extension === ".css") return "text/css; charset=utf-8";
  if (extension === ".json") return "application/json; charset=utf-8";
  if (extension === ".svg") return "image/svg+xml";
  if (extension === ".png") return "image/png";
  if (extension === ".jpg" || extension === ".jpeg") return "image/jpeg";
  if (extension === ".webp") return "image/webp";
  return "application/octet-stream";
}

async function isFile(filePath) {
  try {
    return (await fsp.stat(filePath)).isFile();
  } catch {
    return false;
  }
}

async function resolveFile(pathname) {
  if (pathname === "/") return path.join(ROOT, "index.html");
  const clean = decodeURIComponent(pathname).replace(/^\/+/, "");
  const candidates = [
    path.join(ROOT, clean),
    path.join(ROOT, clean, "index.html"),
    path.join(ROOT, `${clean}.html`)
  ];
  for (const candidate of candidates) {
    if (await isFile(candidate)) return candidate;
  }
  return path.join(ROOT, "404.html");
}

async function createServer() {
  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", "http://127.0.0.1");
      if (url.pathname === "/__analytics-fixture") {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(analyticsFixture());
        return;
      }
      const filePath = await resolveFile(url.pathname);
      const status = filePath.endsWith(`${path.sep}404.html`) && url.pathname !== "/404.html" ? 404 : 200;
      response.writeHead(status, { "content-type": contentType(filePath) });
      const source = await fsp.readFile(filePath);
      const body = path.extname(filePath).toLowerCase() === ".html"
        ? source.toString("utf8").replace(/\s*<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">/i, "")
        : source;
      response.end(body);
    } catch (error) {
      response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      response.end(String(error.stack || error));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

async function installClarityRecorder(context) {
  await context.addInitScript(() => {
    window.clarity = function (...args) {
      let calls = [];
      try { calls = JSON.parse(sessionStorage.getItem("__clarityTestCalls") || "[]"); } catch {}
      calls.push(args);
      sessionStorage.setItem("__clarityTestCalls", JSON.stringify(calls));
    };
  });
}

async function calls(page) {
  return page.evaluate(() => JSON.parse(sessionStorage.getItem("__clarityTestCalls") || "[]"));
}

async function clearCalls(page) {
  await page.evaluate(() => sessionStorage.setItem("__clarityTestCalls", "[]"));
}

function eventCount(recordedCalls, name) {
  return recordedCalls.filter((entry) => entry[0] === "event" && entry[1] === name).length;
}

function assertAllowedPayload(recordedCalls, forbiddenValues = []) {
  for (const entry of recordedCalls) {
    if (entry[0] !== "set") continue;
    assert(ALLOWED_TAGS.has(entry[1]), `unexpected Clarity tag: ${entry[1]}`);
  }
  const serialized = JSON.stringify(recordedCalls).toLowerCase();
  for (const value of forbiddenValues) {
    assert(!serialized.includes(value.toLowerCase()), `field value leaked into Clarity calls: ${value}`);
  }
}

function collectErrors(page, label) {
  const errors = [];
  page.on("pageerror", (error) => errors.push(`${label}: ${error.message}`));
  return errors;
}

async function blockUnneededExternalRequests(page) {
  await page.route(/^https?:\/\/(?!127\.0\.0\.1)/, async (route) => {
    if (/formsubmit\.co\/ajax\//.test(route.request().url())) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true })
      });
      return;
    }
    await route.abort();
  });
}

async function verifyDelegatedClickTaxonomy(browser, baseUrl) {
  const context = await browser.newContext();
  await installClarityRecorder(context);
  const page = await context.newPage();
  const errors = collectErrors(page, "delegated-click-taxonomy");
  await page.goto(`${baseUrl}/__analytics-fixture`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => Boolean(window.FaberAnalytics));
  await clearCalls(page);

  for (const eventName of DELEGATED_CLICK_EVENTS) {
    await page.click(`#event-${eventName}`);
  }

  const recorded = await calls(page);
  for (const eventName of DELEGATED_CLICK_EVENTS) {
    assert.equal(eventCount(recorded, eventName), 1, `${eventName} must fire exactly once per delegated click`);
  }
  assertAllowedPayload(recorded);
  assert.deepEqual(errors, [], `JavaScript errors in delegated taxonomy fixture: ${errors.join("; ")}`);
  await context.close();
}

async function verifyDialogAndForms(browser, baseUrl) {
  const context = await browser.newContext();
  await installClarityRecorder(context);
  const page = await context.newPage();
  const errors = collectErrors(page, "homepage");
  await blockUnneededExternalRequests(page);
  await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => Boolean(window.FaberAnalytics));
  await clearCalls(page);

  await page.click("#navbar [data-whatsapp-dialog-open]");
  assert.equal(await page.$eval("#eligibility-whatsapp-dialog", (element) => element.hidden), false, "WhatsApp dialog did not open");
  let recorded = await calls(page);
  assert.equal(eventCount(recorded, "eligibility_cta_click"), 1, "eligibility CTA event duplicated");
  assert.equal(eventCount(recorded, "whatsapp_dialog_open"), 1, "dialog open event duplicated");
  await page.click("[data-whatsapp-dialog-close]");

  await clearCalls(page);
  await page.focus("#contact-name");
  await page.focus("#contact-email");
  await page.click("#contactForm [type='submit']");
  recorded = await calls(page);
  assert.equal(eventCount(recorded, "form_start"), 1, "form_start must fire once per form");
  assert.equal(eventCount(recorded, "form_submit_attempt"), 1, "invalid submit attempt duplicated");
  assert.equal(eventCount(recorded, "form_validation_error"), 1, `multiple invalid fields generated duplicate errors: ${JSON.stringify(recorded)}`);

  const privateName = "Ana PII Sentinel";
  const privateEmail = "pii-sentinel@example.com";
  const privateMessage = "Mesaj privat sentinel pentru documentația proiectului";
  const privatePhone = "0712345678";
  const privateCaen = "6201";
  await page.fill("#contact-name", privateName);
  await page.fill("#contact-email", privateEmail);
  await page.fill("#contact-phone", privatePhone);
  await page.fill("#contact-caen", privateCaen);
  await page.fill("#contact-message", privateMessage);
  await page.check("#gdpr-consent");

  const attemptsBeforeSuccess = eventCount(await calls(page), "form_submit_attempt");
  await page.click("#contactForm [type='submit']");
  await page.waitForFunction(() => document.querySelector("#formSuccess")?.classList.contains("show"));
  recorded = await calls(page);
  assert.equal(eventCount(recorded, "form_submit_attempt") - attemptsBeforeSuccess, 1, "valid submit attempt duplicated");
  assert.equal(eventCount(recorded, "form_submit_success"), 1, "confirmed form success must fire exactly once");
  assertAllowedPayload(recorded, [privateName, privateEmail, privateMessage, privatePhone, privateCaen]);

  await page.evaluate(() => {
    window.FaberAnalytics.track("contact_page_click", {
      component_type: "privacy_test",
      destination_route: "/contact",
      name: "Never Send This Name",
      email: "never-send@example.com",
      field_value: "secret"
    });
  });
  recorded = await calls(page);
  assertAllowedPayload(recorded, ["Never Send This Name", "never-send@example.com", "secret"]);
  assert.deepEqual(errors, [], `JavaScript errors on homepage: ${errors.join("; ")}`);
  await context.close();
}

async function verifyNavigation(browser, baseUrl) {
  const context = await browser.newContext();
  await installClarityRecorder(context);
  const page = await context.newPage();
  const errors = collectErrors(page, "navigation");
  await blockUnneededExternalRequests(page);
  await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => Boolean(window.FaberAnalytics));
  await clearCalls(page);

  await Promise.all([
    page.waitForURL(`${baseUrl}/consultanta-fonduri-europene`),
    page.click('#navbar a[href="/consultanta-fonduri-europene"]')
  ]);
  const recorded = await calls(page);
  assert.equal(eventCount(recorded, "nav_click"), 1, "nav click event duplicated");
  assert.equal(new URL(page.url()).pathname, "/consultanta-fonduri-europene", "analytics blocked navigation");
  assert.deepEqual(errors, [], `JavaScript errors during navigation: ${errors.join("; ")}`);
  await context.close();
}

async function verifyCalculator(browser, baseUrl) {
  const context = await browser.newContext();
  await installClarityRecorder(context);
  const page = await context.newPage();
  const errors = collectErrors(page, "calculator");
  await blockUnneededExternalRequests(page);

  await page.goto(`${baseUrl}/calculator-soc`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => Boolean(window.FaberAnalytics));
  await clearCalls(page);
  await page.click("#culturi-table + .calc-buttons .btn-add");
  await page.fill("#culturi-body .area-input", "10");
  let recorded = await calls(page);
  assert.equal(eventCount(recorded, "calculator_start"), 1, "calculator_start duplicated");
  assert.equal(eventCount(recorded, "calculator_complete"), 1, "calculator_complete duplicated by recalculation");
  assert(!JSON.stringify(recorded).includes("4900"), "individual SO result leaked into analytics");
  const dr14Link = await page.$eval('#status-badges [data-analytics-event="calculator_result_to_dr14"]', (element) => ({
    href: element.getAttribute("href"),
    outerHTML: element.outerHTML
  }));
  await page.evaluate(() => {
    window.__calculatorClickPrevented = null;
    document.addEventListener("click", (event) => {
      if (event.target.closest?.('[data-analytics-event="calculator_result_to_dr14"]')) {
        window.__calculatorClickPrevented = event.defaultPrevented;
      }
    });
  });
  await page.click('#status-badges [data-analytics-event="calculator_result_to_dr14"]');
  await page.waitForTimeout(300);
  const clickPrevented = await page.evaluate(() => window.__calculatorClickPrevented);
  assert.equal(new URL(page.url()).pathname, "/dr14", `DR14 result navigation was blocked: ${page.url()}; prevented=${clickPrevented}; link=${JSON.stringify(dr14Link)}`);
  recorded = await calls(page);
  assert.equal(eventCount(recorded, "calculator_result_to_dr14"), 1, "DR14 result event duplicated");

  await page.goto(`${baseUrl}/calculator-soc`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => Boolean(window.FaberAnalytics));
  await clearCalls(page);
  await page.click("#culturi-table + .calc-buttons .btn-add");
  await page.fill("#culturi-body .area-input", "30");
  await page.click('#status-badges [data-analytics-event="calculator_result_to_dr12"]');
  await page.waitForTimeout(300);
  assert.equal(new URL(page.url()).pathname, "/dr12-afir", `DR12 result navigation was blocked: ${page.url()}`);
  recorded = await calls(page);
  assert.equal(eventCount(recorded, "calculator_start"), 1, "calculator_start duplicated on DR12 path");
  assert.equal(eventCount(recorded, "calculator_complete"), 1, "calculator_complete duplicated on DR12 path");
  assert.equal(eventCount(recorded, "calculator_result_to_dr12"), 1, "DR12 result event duplicated");
  assert(!JSON.stringify(recorded).includes("14700"), "individual SO result leaked into analytics");
  assertAllowedPayload(recorded);
  assert.deepEqual(errors, [], `JavaScript errors in calculator: ${errors.join("; ")}`);
  await context.close();
}

async function verifyWithoutClarity(browser, baseUrl) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = collectErrors(page, "clarity-unavailable");
  await page.route("**://www.clarity.ms/**", (route) => route.abort());
  await page.route(/^https?:\/\/(?!127\.0\.0\.1|www\.clarity\.ms)/, (route) => route.abort());
  await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => Boolean(window.FaberAnalytics));
  await page.click("#navbar [data-whatsapp-dialog-open]");
  assert.equal(await page.$eval("#eligibility-whatsapp-dialog", (element) => element.hidden), false, "dialog failed without Clarity");
  await page.click("[data-whatsapp-dialog-close]");
  await Promise.all([
    page.waitForURL(`${baseUrl}/blog`),
    page.click('#navbar a[href="/blog"]')
  ]);
  assert.equal(new URL(page.url()).pathname, "/blog", "navigation failed without Clarity");
  assert.deepEqual(errors, [], `JavaScript errors without Clarity: ${errors.join("; ")}`);
  await context.close();
}

const { server, baseUrl } = await createServer();
const browser = await chromium.launch({ headless: true });
try {
  await verifyDelegatedClickTaxonomy(browser, baseUrl);
  console.log("Analytics Playwright: taxonomie click delegată PASS");
  await verifyDialogAndForms(browser, baseUrl);
  console.log("Analytics Playwright: dialog și formulare PASS");
  await verifyNavigation(browser, baseUrl);
  console.log("Analytics Playwright: navigare PASS");
  await verifyCalculator(browser, baseUrl);
  console.log("Analytics Playwright: calculator PASS");
  await verifyWithoutClarity(browser, baseUrl);
  console.log("Analytics Playwright PASS: evenimente deduplicate, payload fără valori de câmp, navigare intactă, calculator anonim și funcționare fără Clarity.");
} finally {
  await browser.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
