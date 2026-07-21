import assert from "node:assert/strict";
import fsp from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";
import { chromium } from "playwright";
import canonicalContact from "../tools/canonical-contact.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTACT_FILE = path.join(ROOT, "contact", "index.html");
const { renderContactChannels, renderFooterContact } = canonicalContact;

function approvedContactFixture(base) {
  const config = structuredClone(base);
  Object.assign(config.fields.publicPhone, {
    status: "approved",
    approvedValue: "+40769828338",
    internalSource: "Registru intern aprobat",
    approvedBy: "Decident test",
    approvedAt: "2026-07-21"
  });
  Object.assign(config.fields.publicEmail, {
    status: "approved",
    approvedValue: "atelier.consultanta@gmail.com",
    internalSource: "Registru intern aprobat",
    approvedBy: "Decident test",
    approvedAt: "2026-07-21"
  });
  Object.assign(config.approvals.operationalEmailOwnerConfirmation, {
    state: "approved",
    approvedBy: "Proprietar test",
    approvedAt: "2026-07-21",
    internalSource: "Confirmare internă test"
  });
  Object.assign(config.approvals.businessDecision, {
    state: "approved",
    approvedBy: "Decident test",
    approvedAt: "2026-07-21",
    internalSource: "Decizie internă test"
  });
  return config;
}

async function verifyStaticAccessibility() {
  const html = await fsp.readFile(CONTACT_FILE, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const form = $("#contact-triage-form");
  assert.equal(form.length, 1);

  form.find("input:not([type='hidden']), select, textarea").each((_, control) => {
    const id = $(control).attr("id");
    assert(id, `${control.tagName} without id`);
    assert.equal(form.find(`label[for='${id}']`).length, 1, `${id} must have one explicit label`);
  });

  for (const id of [
    "contact-applicant-type",
    "contact-location",
    "contact-investment",
    "contact-email",
    "contact-phone",
    "privacy-notice-acknowledged"
  ]) {
    const describedBy = form.find(`#${id}`).attr("aria-describedby") || "";
    assert(describedBy, `${id} must reference instructions/errors`);
    for (const reference of describedBy.split(/\s+/u).filter(Boolean)) {
      assert.equal(form.find(`#${reference}`).length, 1, `${id} references missing #${reference}`);
    }
  }

  assert.equal(form.find("[data-error-summary][role='alert']").length, 1);
  assert.equal(form.find("[data-retry-submit]").text().trim(), "Încearcă din nou");
  assert.equal($("[data-form-success][aria-live='polite'][aria-atomic='true']").length, 1);
  assert.equal(form.find("[data-final-submit] [data-submit-spinner]").length, 1);

  const legal = JSON.parse(await fsp.readFile(path.join(ROOT, "config", "legal-identity.json"), "utf8"));
  const publicMain = $("main").html() || "";
  const publicFooter = renderFooterContact(legal);
  assert.match(publicMain, /href="tel:\+40769828338"/u, "approved direct contact must render in main");
  assert.match(publicFooter, /mailto:atelier\.consultanta@gmail\.com/iu, "approved direct contact must render in footer");

  const pending = structuredClone(legal);
  Object.assign(pending.approvals.businessDecision, { state: "pending", approvedBy: "DE_VALIDAT_UMAN", approvedAt: "DE_VALIDAT_UMAN", internalSource: "DE_VALIDAT_UMAN" });
  for (const id of ["publicPhone", "publicEmail"]) Object.assign(pending.fields[id], { status: "pending", approvedValue: "DE_VALIDAT_UMAN", approvedBy: "DE_VALIDAT_UMAN", approvedAt: "DE_VALIDAT_UMAN" });
  assert.doesNotMatch(renderContactChannels(pending), /tel:|mailto:/iu, "pending direct contact must not render in main");
  assert.doesNotMatch(renderFooterContact(pending), /tel:|mailto:/iu, "pending direct contact must not render in footer");

  const approved = approvedContactFixture(legal);
  const approvedMain = renderContactChannels(approved);
  const approvedFooter = renderFooterContact(approved);
  for (const output of [approvedMain, approvedFooter]) {
    assert.match(output, /href="tel:\+40769828338"/u);
    assert.match(output, /0769 828 338/u);
    assert.match(output, /href="mailto:atelier\.consultanta@gmail\.com"/u);
    assert.match(output, /atelier\.consultanta@gmail\.com/u);
  }

  const jsonLd = $("script[type='application/ld+json']").text();
  assert.match(jsonLd, /atelier\.consultanta@gmail\.com|\+40769828338/u, "approved contact must be present in contact-page JSON-LD");
}

function contentType(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  if (extension === ".html") return "text/html; charset=utf-8";
  if (extension === ".js") return "application/javascript; charset=utf-8";
  if (extension === ".css") return "text/css; charset=utf-8";
  if (extension === ".svg") return "image/svg+xml";
  if (extension === ".png") return "image/png";
  if ([".jpg", ".jpeg", ".webp"].includes(extension)) return `image/${extension.slice(1).replace("jpg", "jpeg")}`;
  return "application/octet-stream";
}

async function createServer() {
  let failuresRemaining = 0;
  let responseDelay = 0;
  const submissions = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    if (url.pathname === "/api/contact-triage" && request.method === "POST") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      submissions.push(Buffer.concat(chunks).toString("utf8"));
      if (responseDelay) await new Promise((resolve) => setTimeout(resolve, responseDelay));
      const fail = failuresRemaining > 0;
      if (fail) failuresRemaining -= 1;
      response.writeHead(fail ? 503 : 200, { "content-type": "application/json; charset=utf-8" });
      response.end(JSON.stringify(fail
        ? { success: false, message: "Rețeaua nu a confirmat trimiterea. Încearcă din nou." }
        : { success: true, leadId: "accessibility-test" }));
      return;
    }

    let filePath;
    if (url.pathname === "/contact") filePath = CONTACT_FILE;
    else filePath = path.join(ROOT, decodeURIComponent(url.pathname).replace(/^\/+/, ""));
    try {
      if (!(await fsp.stat(filePath)).isFile()) throw new Error("not_file");
    } catch {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("Not found");
      return;
    }

    let body = await fsp.readFile(filePath);
    if (filePath.endsWith(".html")) {
      body = Buffer.from(body.toString("utf8").replace(/\s*<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">/iu, ""));
    }
    response.writeHead(200, { "content-type": contentType(filePath) });
    response.end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    server,
    submissions,
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    failNext(count = 1) { failuresRemaining = count; },
    delay(ms) { responseDelay = ms; }
  };
}

async function preparePage(browser, baseUrl, viewport = { width: 1280, height: 900 }) {
  const page = await browser.newPage({ viewport });
  await page.route(/^https?:\/\/(?!127\.0\.0\.1)/u, (route) => route.abort());
  await page.goto(`${baseUrl}/contact`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.querySelector("#contact-triage-form")?.classList.contains("contact-triage--enhanced"));
  return page;
}

async function fillValidStepOne(page, channel = "email") {
  await page.selectOption("#contact-applicant-type", "societate");
  await page.fill("#contact-location", "Iași");
  await page.fill("#contact-investment", "Echipamente pentru atelier");
  if (channel === "email") await page.fill("#contact-email", "accesibilitate@example.com");
  else await page.fill("#contact-phone", "0769828338");
  await page.check("#privacy-notice-acknowledged");
}

async function verifyInvalidSummaryAndKeyboard(browser, baseUrl) {
  const page = await preparePage(browser, baseUrl);
  await page.click('[data-action="review-short"]');
  await page.waitForSelector("[data-error-summary]:not([hidden])");
  await page.waitForFunction(() => document.activeElement?.id === "contact-applicant-type");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "contact-applicant-type", "focus must move to first invalid field");
  assert.equal(await page.locator("[data-error-summary] li").count(), 5);
  assert.equal(await page.getAttribute("#contact-applicant-type", "aria-invalid"), "true");
  assert.equal(await page.isVisible("#contact-applicant-type-error"), true);
  assert.match(await page.textContent("#contact-applicant-type-error"), /Alege tipul solicitantului/u);

  const firstTop = await page.locator("#contact-applicant-type").evaluate((element) => element.getBoundingClientRect().top);
  const headerBottom = await page.locator("#navbar").evaluate((element) => element.getBoundingClientRect().bottom);
  assert(firstTop >= headerBottom, `focused error is covered by header (${firstTop} < ${headerBottom})`);

  await page.selectOption("#contact-applicant-type", "societate");
  await page.locator("#contact-applicant-type").focus();
  const expected = ["contact-location", "contact-investment", "contact-email", "contact-phone", "contact-optional-summary", "privacy-notice-acknowledged"];
  for (const id of expected) {
    await page.keyboard.press("Tab");
    assert.equal(await page.evaluate(() => document.activeElement?.id), id, `unexpected keyboard order before ${id}`);
  }

  const aria = await page.locator("#contact-triage-form").ariaSnapshot();
  assert.match(aria, /Tip solicitant/u);
  assert.match(aria, /Email sau telefon/u);
  assert.match(aria, /Politica de confidențialitate/u);
  await page.close();
}

async function verifyDoubleSubmit(browser, fixture) {
  fixture.delay(450);
  const page = await preparePage(browser, fixture.baseUrl);
  await fillValidStepOne(page, "email");
  await page.click('[data-action="review-short"]');
  const before = fixture.submissions.length;
  await page.locator("[data-final-submit]").evaluate((button) => {
    button.click();
    button.click();
  });
  await page.waitForFunction(() => document.querySelector("#contact-triage-form")?.getAttribute("aria-busy") === "true");
  assert.equal(await page.isDisabled("[data-final-submit]"), true);
  assert.match(await page.textContent("[data-submit-status]"), /se trimite/iu);
  await page.waitForSelector("[data-form-success]:not([hidden])");
  assert.equal(fixture.submissions.length - before, 1, "double click must create one request");
  fixture.delay(0);
  await page.close();
}

async function verifyRetryAndPreservedValues(browser, fixture) {
  fixture.failNext(1);
  const page = await preparePage(browser, fixture.baseUrl);
  await fillValidStepOne(page, "phone");
  await page.click('[data-action="review-short"]');
  const before = fixture.submissions.length;
  await page.click("[data-final-submit]");
  await page.waitForSelector("[data-retry-submit]:not([hidden])");
  assert.equal(await page.evaluate(() => document.activeElement?.hasAttribute("data-form-alert")), true, "network error must be focused and announced");
  assert.equal(await page.inputValue("#contact-phone"), "0769828338", "network error must preserve values");
  assert.equal(await page.isDisabled("[data-final-submit]"), false);
  await page.click("[data-retry-submit]");
  await page.waitForSelector("[data-form-success]:not([hidden])");
  assert.equal(fixture.submissions.length - before, 2, "retry must issue exactly one additional request");
  await page.close();
}

async function verifyReflowAndTargets(browser, baseUrl) {
  const page = await preparePage(browser, baseUrl, { width: 320, height: 900 });
  const noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1);
  assert.equal(noOverflow, true, "320px viewport must not have horizontal page scrolling");

  const smallTargets = await page.locator("#contact-triage-form button, #contact-triage-form input:not([type='hidden']), #contact-triage-form select, #contact-triage-form textarea, #contact-triage-form summary").evaluateAll((elements) => (
    elements.filter((element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      if (style.display === "none" || style.visibility === "hidden" || rect.width === 0 || rect.height === 0 || element.closest(".contact-honeypot")) return false;
      return rect.width < 24 || rect.height < 24;
    }).map((element) => ({ id: element.id, tag: element.tagName, rect: element.getBoundingClientRect().toJSON() }))
  ));
  assert.deepEqual(smallTargets, [], `targets below 24px: ${JSON.stringify(smallTargets)}`);

  const mobileButtonHeights = await page.locator("#contact-triage-form button:visible, #contact-triage-form summary:visible").evaluateAll((elements) => elements.map((element) => element.getBoundingClientRect().height));
  assert(mobileButtonHeights.every((height) => height >= 44), `mobile actions below 44px: ${mobileButtonHeights.join(", ")}`);

  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  const zoomReflow = await page.evaluate(() => ({
    fits: document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1,
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
    offenders: Array.from(document.querySelectorAll("body *")).map((element) => {
      const rect = element.getBoundingClientRect();
      return { tag: element.tagName, id: element.id, className: String(element.className || ""), left: rect.left, right: rect.right, width: rect.width };
    }).filter((item) => item.width > 0 && (item.right > document.documentElement.clientWidth + 1 || item.left < -1)).slice(0, 12)
  }));
  assert.equal(zoomReflow.fits, true, `200% text zoom at 320px must reflow without horizontal page scrolling: ${JSON.stringify(zoomReflow)}`);
  await page.close();
}

await verifyStaticAccessibility();
console.log("Contact accessibility static and canonical-contact contract PASS");
const fixture = await createServer();
const browser = await chromium.launch({ headless: true });
try {
  await verifyInvalidSummaryAndKeyboard(browser, fixture.baseUrl);
  console.log("Contact accessibility error summary, focus, ARIA and keyboard order PASS");
  await verifyDoubleSubmit(browser, fixture);
  console.log("Contact accessibility loading and double-submit prevention PASS");
  await verifyRetryAndPreservedValues(browser, fixture);
  console.log("Contact accessibility network retry and value preservation PASS");
  await verifyReflowAndTargets(browser, fixture.baseUrl);
  console.log("Contact accessibility 320px reflow, 200% text zoom and target sizes PASS");
} finally {
  await browser.close();
  await new Promise((resolve, reject) => fixture.server.close((error) => error ? reject(error) : resolve()));
}
