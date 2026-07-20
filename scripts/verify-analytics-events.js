#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { ROOT, findPublicHtmlFiles } = require("../tools/sync-global-header");
const { listHtmlFiles, synchronizePublicHtml } = require("../tools/sync-analytics-events");

const EVENTS = new Set([
  "nav_click",
  "program_menu_click",
  "eligibility_cta_click",
  "whatsapp_dialog_open",
  "whatsapp_number_click",
  "contact_page_click",
  "form_start",
  "form_submit_attempt",
  "form_submit_success",
  "form_validation_error",
  "calculator_start",
  "calculator_complete",
  "calculator_result_to_dr12",
  "calculator_result_to_dr14",
  "source_document_click",
  "next_step_click",
  "phone_click",
  "email_click"
]);
const ALLOWED_TAG_KEYS = [
  "route",
  "component_type",
  "cta_id",
  "destination_route",
  "program_category",
  "status"
];
const GENERATORS = [
  "tools/generate-program-pages.js",
  "tools/generate-programmatic-seo.js",
  "tools/generate-project-design-pages.js",
  "tools/generate-seo-hubs.js",
  "tools/generate-seo-blog-article.js",
  "tools/generate-redirect-fallbacks.js"
];

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, ...relativePath.split("/")), "utf8");
}

function count(text, pattern) {
  return [...text.matchAll(pattern)].length;
}

function main() {
  const errors = [];
  const publicFiles = findPublicHtmlFiles();
  let forms = 0;
  let annotatedClicks = 0;

  for (const relativePath of publicFiles) {
    const html = read(relativePath);
    const $ = cheerio.load(html, { decodeEntities: false });
    const analyticsScripts = $('script[src^="/assets/analytics-events.js"]');
    if (analyticsScripts.length !== 1) errors.push(`${relativePath}: analytics-events.js apare de ${analyticsScripts.length} ori`);
    if (/https:\/\/www\.clarity\.ms\/tag\//i.test(html)) errors.push(`${relativePath}: loader Clarity inline rămas`);
    if (synchronizePublicHtml(html, relativePath) !== html) errors.push(`${relativePath}: sincronizarea analytics nu este idempotentă`);

    $("[data-analytics-event]").each((_, element) => {
      annotatedClicks += 1;
      const names = ($(element).attr("data-analytics-event") || "").trim().split(/\s+/).filter(Boolean);
      for (const name of names) {
        if (!EVENTS.has(name)) errors.push(`${relativePath}: eveniment necunoscut ${name}`);
      }
      const target = $(element).attr("data-analytics-target") || "";
      if (/^(?:mailto:|tel:|https:\/\/(?:api\.)?wa\.me\/)/i.test(target)) {
        errors.push(`${relativePath}: destinație sensibilă transmisibilă în data-analytics-target`);
      }
    });

    $("form").each((_, form) => {
      forms += 1;
      if (!$(form).attr("data-analytics-form")) errors.push(`${relativePath}: formular fără ID analytics generic`);
      if ($(form).attr("data-clarity-mask") !== "true") errors.push(`${relativePath}: formular fără data-clarity-mask=true`);
    });
  }

  for (const relativePath of listHtmlFiles()) {
    if (/https:\/\/www\.clarity\.ms\/tag\//i.test(read(relativePath))) {
      errors.push(`${relativePath}: implementare Clarity inline rămasă în repository`);
    }
  }

  const analyticsSource = read("assets/analytics-events.js");
  for (const name of EVENTS) {
    if (!analyticsSource.includes(`"${name}"`)) errors.push(`assets/analytics-events.js: lipsește ${name}`);
  }
  for (const key of ALLOWED_TAG_KEYS) {
    if (!analyticsSource.includes(`"${key}"`)) errors.push(`assets/analytics-events.js: lipsește cheia permisă ${key}`);
  }
  for (const forbidden of [
    { pattern: /\.value\b/, label: "citire .value" },
    { pattern: /\bFormData\b/, label: "FormData" },
    { pattern: /\bidentify\b/i, label: "Clarity identify" },
    { pattern: /\binnerText\b|\btextContent\b/, label: "citire text vizibil" },
    { pattern: /googletagmanager|google-analytics|connect\.facebook\.net|fbq\s*\(/i, label: "tracker terț nepermis" }
  ]) {
    if (forbidden.pattern.test(analyticsSource)) errors.push(`assets/analytics-events.js: ${forbidden.label} nu este permisă`);
  }
  if (count(analyticsSource, /CLARITY_PROJECT_ID\s*=/g) !== 1) errors.push("ID-ul proiectului Clarity nu are o singură sursă de adevăr");
  if (!/document\.addEventListener\("click"/.test(analyticsSource)) errors.push("lipsește delegarea globală pentru clickuri");

  const partial = read("partials/global-header.html");
  for (const eventName of ["nav_click", "program_menu_click", "eligibility_cta_click", "whatsapp_number_click"]) {
    if (!partial.includes(`data-analytics-event="${eventName}"`)) errors.push(`header: lipsește ${eventName}`);
  }
  const $partial = cheerio.load(partial, { decodeEntities: false });
  if ($partial("#navbar [data-whatsapp-dialog-open][data-analytics-event='eligibility_cta_click']").length !== 1) {
    errors.push("header: CTA eligibilitate desktop neinstrumentat");
  }
  if ($partial("#mobileMenu [data-whatsapp-dialog-open][data-analytics-event='eligibility_cta_click']").length !== 1) {
    errors.push("header: CTA eligibilitate mobil neinstrumentat");
  }

  const headerBehavior = read("assets/global-header.js");
  if (!headerBehavior.includes("faber:whatsapp-dialog-open")) errors.push("global-header.js: deschiderea efectivă a dialogului nu este raportată");

  const home = read("index.html");
  if (count(home, /FaberAnalytics\.formSubmitSuccess\(form\)/g) !== 2) errors.push("homepage: succesul confirmat al celor două formulare nu este instrumentat exact o dată");
  if (count(home, /FaberAnalytics\.formValidationError\(form\)/g) !== 2) errors.push("homepage: erorile de validare ale celor două formulare nu sunt instrumentate exact o dată");
  if (count(home, /fetch\('https:\/\/formsubmit\.co\/ajax\/atelier\.consultanta@gmail\.com'/g) !== 2) {
    errors.push("homepage: endpointurile AJAX ale formularelor au fost modificate");
  }
  const $contact = cheerio.load(read("contact/index.html"), { decodeEntities: false });
  if ($contact("form.contact-form").attr("action") !== "mailto:atelier.consultanta@gmail.com") {
    errors.push("contact: endpointul formularului mailto a fost modificat");
  }
  const $ideas = cheerio.load(read("idei-afaceri-fonduri-europene.html"), { decodeEntities: false });
  if ($ideas("form.contact-form").attr("action") !== "https://formsubmit.co/atelier.consultanta@gmail.com") {
    errors.push("idei-afaceri: endpointul FormSubmit a fost modificat");
  }

  const calculator = read("calculator-soc.html");
  for (const required of [
    'data-analytics-calculator="calculator_soc"',
    "FaberAnalytics.calculatorComplete()",
    'data-analytics-event="calculator_result_to_dr12"',
    'data-analytics-event="calculator_result_to_dr14"'
  ]) {
    if (!calculator.includes(required)) errors.push(`calculator-soc.html: lipsește ${required}`);
  }

  for (const generator of GENERATORS) {
    const source = read(generator);
    if (!source.includes("/assets/analytics-events.js")) errors.push(`${generator}: nu încarcă stratul comun de analytics`);
    if (/clarity\.ms\/tag|wnvzyco6rq/.test(source)) errors.push(`${generator}: păstrează un loader Clarity propriu`);
  }

  if (errors.length) {
    console.error(`Analytics verification FAILED (${errors.length}):`);
    errors.forEach((error) => console.error(` - ${error}`));
    process.exitCode = 1;
    return;
  }

  console.log(`Analytics verification PASS: ${publicFiles.length} pagini publice cu un singur loader, ${forms} formulare mascate și ${annotatedClicks} controale delegate; ${EVENTS.size} evenimente și ${ALLOWED_TAG_KEYS.length} chei de payload aprobate.`);
}

main();
