import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const config = JSON.parse(await fs.readFile(path.join(ROOT, "config", "funnel-analytics.json"), "utf8"));

function fixture() {
  return `<!doctype html>
<html lang="ro"><head><meta charset="utf-8"><style>
html,body{margin:0;min-height:1600px}#primary{position:absolute;top:781px;left:20px;width:220px;height:40px}
#fixture-form{position:absolute;top:900px;left:20px}a{display:inline-block;min-width:80px;min-height:30px}
</style><script src="/assets/lead-attribution.js" defer></script><script src="/assets/analytics-events.js" defer></script></head>
<body data-analytics-page-type="program" data-analytics-program-slug="dr12-afir" data-analytics-program-family="afir-agricultura">
  <a id="primary" href="#form" data-analytics-event="cta_click" data-analytics-cta-view="true" data-analytics-cta-id="dr12_primary" data-analytics-copy-variant="a">Verifică</a>
  <form id="fixture-form" data-analytics-form="contact_triage" data-analytics-form-version="short_v1" data-clarity-mask="true">
    <label for="email">Email</label><input id="email" name="email" type="email" value="pii@example.com">
    <label for="investment">Investiție</label><input id="investment" name="investment" value="Descriere secretă">
    <button type="submit">Trimite</button>
  </form>
  <a id="phone" href="tel:+40123456789" data-analytics-event="contact_phone" data-analytics-cta-id="phone_contact">Telefon</a>
  <a id="email-link" href="mailto:pii@example.com" data-analytics-event="contact_email" data-analytics-cta-id="email_contact">Email</a>
  <a id="whatsapp" href="https://wa.me/40123456789" data-analytics-event="contact_whatsapp" data-analytics-cta-id="whatsapp_contact">WhatsApp</a>
</body></html>`;
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, "http://127.0.0.1");
  if (url.pathname === "/assets/analytics-events.js") {
    response.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
    response.end(await fs.readFile(path.join(ROOT, "assets", "analytics-events.js")));
    return;
  }
  if (url.pathname === "/assets/lead-attribution.js") {
    response.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
    response.end(await fs.readFile(path.join(ROOT, "assets", "lead-attribution.js")));
    return;
  }
  if (url.pathname === "/fixture") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(fixture());
    return;
  }
  response.writeHead(404).end();
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();
const browser = await chromium.launch({ headless: true });

try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 800 } });
  page.on("pageerror", (error) => console.error("analytics fixture pageerror:", error.message));
  await page.route("https://www.clarity.ms/**", (route) => route.abort());
  await page.goto(`http://127.0.0.1:${port}/fixture?utm_source=chatgpt.com&utm_medium=referral&utm_campaign=private-email-test&analytics_debug=1`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => window.FaberAnalytics && Array.isArray(window.dataLayer));

  let events = await page.evaluate(() => window.dataLayer.slice());
  assert.equal(events.some((entry) => entry.event === "cta_view"), false, "CTA under 50% visibility must not emit cta_view");
  assert.equal(events.some((entry) => entry.event === "form_start"), false, "form_start must not emit at page load");

  await page.evaluate(() => window.scrollTo(0, 3));
  await page.waitForFunction(() => window.dataLayer.some((entry) => entry.event === "cta_view"));
  await page.evaluate(() => { window.scrollTo(0, 0); window.scrollTo(0, 3); });
  await page.waitForTimeout(100);
  events = await page.evaluate(() => window.dataLayer.slice());
  assert.equal(events.filter((entry) => entry.event === "cta_view").length, 1, "cta_view must emit once per CTA and page");

  await page.locator("#primary").click();
  await page.locator("#email").evaluate((element) => element.focus());
  events = await page.evaluate(() => window.dataLayer.slice());
  assert.equal(events.some((entry) => entry.event === "form_start"), false, "programmatic focus is not a real form interaction");
  await page.locator("#email").press("End");
  await page.waitForFunction(() => window.dataLayer.some((entry) => entry.event === "form_start"));

  await page.evaluate(() => {
    const form = document.querySelector("#fixture-form");
    const email = document.querySelector("#email");
    window.FaberAnalytics.fieldError(form, email, "format");
    window.FaberAnalytics.stepOneComplete(form);
    window.FaberAnalytics.stepOneComplete(form);
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  events = await page.evaluate(() => window.dataLayer.slice());
  assert.equal(events.some((entry) => entry.event === "form_submit"), false, "client submit attempt must not emit form_submit");

  await page.evaluate(() => {
    window.FaberAnalytics.formSubmitSuccess(document.querySelector("#fixture-form"), { leadCorrelationId: "test-lead-001" });
  });
  for (const selector of ["#phone", "#email-link", "#whatsapp"]) {
    await page.locator(selector).evaluate((element) => element.addEventListener("click", (event) => event.preventDefault(), { once: true }));
    await page.locator(selector).click();
  }

  events = await page.evaluate(() => window.dataLayer.slice());
  for (const required of ["cta_view", "cta_click", "form_start", "step_1_complete", "field_error", "form_submit", "contact_phone", "contact_email", "contact_whatsapp"]) {
    assert(events.some((entry) => entry.event === required), `missing ${required}`);
  }
  assert.equal(events.filter((entry) => entry.event === "step_1_complete").length, 1, "step_1_complete must be idempotent");
  const fieldError = events.find((entry) => entry.event === "field_error");
  assert.equal(fieldError.field_name_generic, "email");
  assert.equal(fieldError.error_type, "format");
  const submitted = events.find((entry) => entry.event === "form_submit");
  assert.equal(submitted.lead_correlation_id, "test-lead-001");
  assert.equal(submitted.program_slug, "dr12-afir");
  assert.equal(submitted.program_family, "afir-agricultura");
  assert.equal(submitted.source_channel, "chatgpt");

  const allowed = new Set(["event", ...config.payloadKeys]);
  for (const entry of events) {
    for (const key of Object.keys(entry)) assert(allowed.has(key), `${entry.event} contains unapproved key ${key}`);
  }
  const serialized = JSON.stringify(events);
  for (const forbidden of ["pii@example.com", "Descriere secretă", "private-email-test", "chatgpt.com", "+40123456789"]) {
    assert.equal(serialized.includes(forbidden), false, `analytics leaked ${forbidden}`);
  }

  const attribution = await page.evaluate(() => window.FaberAnalytics.getCrmAttribution());
  assert.equal(attribution.utm_source, "chatgpt.com", "raw UTM must remain available only for CRM");
  assert.equal(attribution.utm_campaign, "private-email-test");
  assert.equal(attribution.source_channel, "chatgpt");
  const debugEvents = await page.evaluate(() => window.__faberAnalyticsDebug || []);
  assert.equal(debugEvents.length, events.length, "debug mode must mirror the sanitized event stream");

  console.log(`Analytics browser checks passed: ${events.length} sanitized events, 50% CTA threshold and server-confirmed submit.`);
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
