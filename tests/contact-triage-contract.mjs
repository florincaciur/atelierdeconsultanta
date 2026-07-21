import assert from "node:assert/strict";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";
import { chromium } from "playwright";
import { handleRequest, validateContactPayload } from "../cloudflare/domain-seo-redirects.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTACT_FILE = path.join(ROOT, "contact", "index.html");
const NOW = Date.parse("2026-07-21T12:00:00.000Z");

function basePayload(overrides = {}) {
  return {
    schema_version: "1.0.0",
    lead_id: "test-lead-001",
    applicant_type: "societate",
    location: "Iași, Pașcani",
    investment: "Achiziție de utilaje pentru producție",
    email: "test@example.com",
    phone: "",
    privacy_notice_acknowledged: true,
    program_slug: "unknown",
    caen_or_so: "Nu știu încă",
    budget_estimate: "Nu știu încă",
    extended_description: "",
    documents_summary: "",
    expenses_summary: "",
    contact_preference: "no_preference",
    page_url: "/contact",
    referrer_path: "",
    program_context: "",
    program_family: "afir-agricultura",
    source_channel: "chatgpt",
    utm_source: "chatgpt.com",
    utm_medium: "referral",
    utm_campaign: "dr12_qa",
    utm_term: "",
    utm_content: "primary_cta",
    landing_referrer: "https://chatgpt.com/",
    landing_page_path: "/dr12-afir",
    form_started_at: String(NOW - 5000),
    website: "",
    ...overrides
  };
}

function requestFor(payload, headers = {}) {
  return new Request("https://atelierdeconsultanta.ro/api/contact-triage", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      origin: "https://atelierdeconsultanta.ro",
      ...headers
    },
    body: JSON.stringify(payload)
  });
}

async function verifyStaticContract() {
  const html = await fsp.readFile(CONTACT_FILE, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const form = $("#contact-triage-form");
  assert.equal(form.length, 1, "canonical contact page must contain one triage form");
  assert.equal(form.attr("action"), "/api/contact-triage");
  assert.equal(form.attr("method"), "post");
  assert.equal(form.attr("data-clarity-mask"), "true");
  assert.equal(form.attr("data-legal-copy-state"), "pending_validation");
  assert.match($("[data-form-step='1']").text(), /Pasul 1 din 2/u);
  assert.match($("[data-form-step='1']").text(), /60–90 secunde/u);
  assert.match($("[data-form-step='2']").text(), /Pasul 2 din 2/u);
  assert.equal($("[name='applicant_type'][required]").length, 1);
  assert.equal($("[name='location'][required]").length, 1);
  assert.equal($("[name='investment'][required]").length, 1);
  assert.equal($("[name='privacy_notice_acknowledged'][required]").length, 1);
  assert.equal(form.find("[required]").length, 4, "only three direct answers plus the notice acknowledgment use native required");
  assert.equal($("[name='email'][required]").length, 0, "email must not be required individually");
  assert.equal($("[name='phone'][required]").length, 0, "phone must not be required individually");
  assert.equal($("[name='name']").length, 0, "name is not part of initial triage");
  assert.match($("[name='program_slug'] option").first().text(), /Nu știu încă/u);
  assert.equal($("[name='caen_or_so']").attr("value"), "Nu știu încă");
  assert.equal($("[name='budget_estimate']").attr("value"), "Nu știu încă");
  assert.match($("[name='program_slug'] option[value='dr12-afir']").attr("data-page-aliases") || "", /dr-12-afir-instalarea-tinerilor-fermieri/u);
  assert.match($("[data-form-summary]").text(), /Rezumat înainte de trimitere/u);
  assert.match($("[data-form-success]").text(), /nu promite un termen de răspuns/iu);
  assert.doesNotMatch($(".consent-label").text(), /marketing|sunt de acord/iu);
  assert.equal($('script[src^="/assets/contact-triage.js"]').length, 1);
  assert.equal($('link[href^="/assets/contact-triage.css"]').length, 1);

  const schema = JSON.parse(await fsp.readFile(path.join(ROOT, "config", "contact-triage-payload.schema.json"), "utf8"));
  assert.equal(schema.properties.schema_version.const, "1.0.0");
  assert.equal(schema.anyOf.length, 2, "schema must express email OR phone");
  assert(!schema.required.includes("email") && !schema.required.includes("phone"));
  const packageJson = JSON.parse(await fsp.readFile(path.join(ROOT, "package.json"), "utf8"));
  assert.match(packageJson.scripts["deploy:cloudflare-domain-worker"], /validate:contact-triage:publish/u);
  assert.match(packageJson.scripts["deploy:contact-triage"], /wrangler deploy --config wrangler\.redirects\.jsonc/u);
}

async function verifyServerContract() {
  let result = validateContactPayload(basePayload(), NOW);
  assert.equal(result.valid, true, "email-only payload must be valid");
  assert.equal(result.spam, false);

  result = validateContactPayload(basePayload({ email: "", phone: "0769828338" }), NOW);
  assert.equal(result.valid, true, "phone-only payload must be valid");

  result = validateContactPayload(basePayload({ email: "", phone: "" }), NOW);
  assert.equal(result.valid, false, "payload without email and phone must fail");
  assert(result.errors.some((error) => error.code === "one_required"));

  result = validateContactPayload(basePayload({ email: "", phone: "123" }), NOW);
  assert.equal(result.valid, false, "invalid phone must fail");
  assert(result.errors.some((error) => error.code === "invalid_phone"));

  result = validateContactPayload(basePayload({ website: "spam.example" }), NOW);
  assert.equal(result.spam, true, "honeypot must flag spam");

  result = validateContactPayload(basePayload({ form_started_at: String(NOW - 200) }), NOW);
  assert.equal(result.spam, true, "implausibly fast submission must flag spam");

  result = validateContactPayload(basePayload({ schema_version: "2.0.0" }), NOW);
  assert.equal(result.valid, false, "unsupported schema versions must fail server validation");
  assert(result.errors.some((error) => error.code === "unsupported_version"));

  const forwarded = [];
  const validResponse = await handleRequest(
    requestFor(basePayload({ email: "", phone: "0769828338" })),
    async () => { throw new Error("origin should not receive contact API requests"); },
    {
      CONTACT_FORM_FORWARD_URL: "https://formsubmit.co/ajax/approved-destination",
      forwardFetch: async (url, options) => {
        forwarded.push({ url, options, body: JSON.parse(options.body) });
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      },
      now: NOW,
      submittedAt: new Date(NOW)
    }
  );
  assert.equal(validResponse.status, 200);
  assert.deepEqual(await validResponse.json(), { success: true, leadId: "test-lead-001" });
  assert.equal(forwarded.length, 1);
  assert.equal(forwarded[0].body.email, "—");
  assert.equal(forwarded[0].body.phone, "0769828338");
  assert.equal(forwarded[0].body.privacy_notice_version, "approved_2026-07-22");
  assert.equal(forwarded[0].body.utm_source, "chatgpt.com", "raw ChatGPT UTM must be preserved in CRM payload");
  assert.equal(forwarded[0].body.landing_referrer, "https://chatgpt.com/");
  assert.equal(forwarded[0].body.program_family, "afir-agricultura");
  assert.equal(forwarded[0].body.website, undefined, "honeypot must never be forwarded");

  const missingContact = await handleRequest(
    requestFor(basePayload({ email: "", phone: "" })),
    async () => new Response(null, { status: 500 }),
    { CONTACT_FORM_FORWARD_URL: "https://formsubmit.co/ajax/approved-destination", forwardFetch: async () => new Response(null, { status: 200 }), now: NOW }
  );
  assert.equal(missingContact.status, 422);

  const missingDestination = await handleRequest(
    requestFor(basePayload()),
    async () => new Response(null, { status: 500 }),
    { now: NOW }
  );
  assert.equal(missingDestination.status, 503, "unapproved/unconfigured destination must block delivery");

  let spamForwarded = false;
  const spamResponse = await handleRequest(
    requestFor(basePayload({ website: "bot" })),
    async () => new Response(null, { status: 500 }),
    {
      CONTACT_FORM_FORWARD_URL: "https://formsubmit.co/ajax/approved-destination",
      forwardFetch: async () => { spamForwarded = true; return new Response(null, { status: 200 }); },
      now: NOW
    }
  );
  assert.equal(spamResponse.status, 200);
  assert.equal(spamForwarded, false, "honeypot submissions must not be forwarded");

  const crossOrigin = await handleRequest(
    requestFor(basePayload(), { origin: "https://malicious.example" }),
    async () => new Response(null, { status: 500 }),
    { CONTACT_FORM_FORWARD_URL: "https://formsubmit.co/ajax/approved-destination", now: NOW }
  );
  assert.equal(crossOrigin.status, 403);

  const nativeBody = new URLSearchParams(basePayload({ email: "", phone: "0769828338", form_started_at: "" }));
  const nativeResponse = await handleRequest(
    new Request("https://atelierdeconsultanta.ro/api/contact-triage", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "text/html" },
      body: nativeBody
    }),
    async () => new Response(null, { status: 500 }),
    {
      CONTACT_FORM_FORWARD_URL: "https://formsubmit.co/ajax/approved-destination",
      forwardFetch: async () => new Response("{}", { status: 200 }),
      now: NOW,
      submittedAt: new Date(NOW)
    }
  );
  assert.equal(nativeResponse.status, 200);
  assert.match(await nativeResponse.text(), /Solicitarea a fost trimisă/u, "no-JS submission must receive an HTML confirmation");
}

function contentType(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  if (extension === ".html") return "text/html; charset=utf-8";
  if (extension === ".js") return "application/javascript; charset=utf-8";
  if (extension === ".css") return "text/css; charset=utf-8";
  if (extension === ".json") return "application/json; charset=utf-8";
  if (extension === ".svg") return "image/svg+xml";
  if ([".png", ".jpg", ".jpeg", ".webp"].includes(extension)) return `image/${extension.replace(".", "").replace("jpg", "jpeg")}`;
  return "application/octet-stream";
}

async function resolveStatic(pathname) {
  if (pathname === "/contact") return CONTACT_FILE;
  const clean = decodeURIComponent(pathname).replace(/^\/+/, "");
  const candidate = path.join(ROOT, clean);
  try {
    if ((await fsp.stat(candidate)).isFile()) return candidate;
  } catch {}
  return null;
}

async function createBrowserServer() {
  const submissions = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    if (url.pathname === "/dr-12-afir-instalarea-tinerilor-fermieri") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end('<!doctype html><html><body><a id="to-contact" href="/contact">Contact</a></body></html>');
      return;
    }
    if (url.pathname === "/api/contact-triage" && request.method === "POST") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      submissions.push({ headers: request.headers, body: Buffer.concat(chunks).toString("utf8") });
      response.writeHead(200, { "content-type": "application/json; charset=utf-8" });
      response.end(JSON.stringify({ success: true, leadId: "browser-test" }));
      return;
    }
    const filePath = await resolveStatic(url.pathname);
    if (!filePath) {
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
  return { server, submissions, baseUrl: `http://127.0.0.1:${server.address().port}` };
}

async function verifyBrowserFlow() {
  const { server, submissions, baseUrl } = await createBrowserServer();
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.route(/^https?:\/\/(?!127\.0\.0\.1)/u, (route) => route.abort());
    await page.goto(`${baseUrl}/contact?program=dr12-afir&utm_source=chatgpt.com&utm_medium=referral&utm_campaign=dr12_browser`, { waitUntil: "domcontentloaded" });
    await page.waitForFunction(() => document.querySelector("#contact-triage-form")?.classList.contains("contact-triage--enhanced"));
    assert.equal(await page.isVisible('[data-form-step="1"]'), true);
    assert.equal(await page.isVisible('[data-form-step="2"]'), false);
    assert.equal(await page.inputValue("#contact-program"), "dr12-afir", "program query must prefill registry option");
    assert.equal(await page.inputValue('[name="utm_source"]'), "chatgpt.com", "raw ChatGPT UTM must be retained for CRM");
    assert.equal(await page.inputValue('[name="source_channel"]'), "chatgpt", "analytics channel must be normalized");
    assert.equal(await page.inputValue('[name="program_family"]'), "afir-agricultura");

    await page.selectOption("#contact-applicant-type", "societate");
    await page.fill("#contact-location", "Iași, Pașcani");
    await page.fill("#contact-investment", "Utilaje noi pentru producție");
    await page.fill("#contact-email", "browser@example.com");
    await page.check("#privacy-notice-acknowledged");
    assert.equal(await page.inputValue("#contact-phone"), "");

    await page.click('[data-action="add-details"]');
    assert.equal(await page.isVisible('[data-form-step="2"]'), true);
    await page.fill("#contact-description", "Context păstrat între etape");
    await page.click('[data-action="back-to-step-1"]');
    assert.equal(await page.inputValue("#contact-email"), "browser@example.com");
    await page.click('[data-action="add-details"]');
    assert.equal(await page.inputValue("#contact-description"), "Context păstrat între etape");
    await page.click('[data-action="review-full"]');
    assert.equal(await page.isVisible("[data-form-summary]"), true);
    const summaryText = await page.textContent("[data-summary-list]");
    assert.match(summaryText, /browser@example\.com/u);
    assert.match(summaryText, /Context păstrat între etape/u);

    await page.click("[data-final-submit]");
    await page.waitForSelector("[data-form-success]:not([hidden])");
    assert.equal(submissions.length, 1);
    assert.match(submissions[0].body, /name="email"\r?\n\r?\nbrowser@example\.com/u);
    assert.match(submissions[0].body, /name="phone"\r?\n\r?\n\r?\n/u, "email-only browser flow must submit an empty phone");
    assert.match(submissions[0].body, /name="utm_source"\r?\n\r?\nchatgpt\.com/u);
    assert.match(submissions[0].body, /name="source_channel"\r?\n\r?\nchatgpt/u);

    const missing = await browser.newPage();
    await missing.route(/^https?:\/\/(?!127\.0\.0\.1)/u, (route) => route.abort());
    await missing.goto(`${baseUrl}/contact`, { waitUntil: "domcontentloaded" });
    await missing.selectOption("#contact-applicant-type", "societate");
    await missing.fill("#contact-location", "Bacău");
    await missing.fill("#contact-investment", "Echipamente pentru atelier");
    await missing.check("#privacy-notice-acknowledged");
    await missing.click('[data-action="review-short"]');
    assert.equal(await missing.isVisible("[data-contact-method-error]"), true);
    assert.equal(await missing.isVisible("[data-form-summary]"), false);

    const aliasReferrer = await browser.newPage();
    await aliasReferrer.route(/^https?:\/\/(?!127\.0\.0\.1)/u, (route) => route.abort());
    await aliasReferrer.goto(`${baseUrl}/dr-12-afir-instalarea-tinerilor-fermieri`, { waitUntil: "domcontentloaded" });
    await Promise.all([
      aliasReferrer.waitForURL(`${baseUrl}/contact`),
      aliasReferrer.click("#to-contact")
    ]);
    await aliasReferrer.waitForFunction(() => document.querySelector("#contact-triage-form")?.classList.contains("contact-triage--enhanced"));
    assert.equal(await aliasReferrer.inputValue("#contact-program"), "dr12-afir", "program aliases must prefill from same-origin referrer");

    const noJs = await browser.newContext({ javaScriptEnabled: false });
    const noJsPage = await noJs.newPage();
    await noJsPage.goto(`${baseUrl}/contact`, { waitUntil: "domcontentloaded" });
    assert.equal(await noJsPage.isVisible('[data-form-step="1"]'), true);
    assert.equal(await noJsPage.isVisible('[data-form-step="2"]'), true);
    assert.equal(await noJsPage.isVisible(".contact-no-js-submit"), true);
    await noJs.close();
  } finally {
    await browser.close();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

await verifyStaticContract();
console.log("Contact triage static contract PASS");
await verifyServerContract();
console.log("Contact triage server contract PASS");
await verifyBrowserFlow();
console.log("Contact triage browser and no-JS flow PASS");
