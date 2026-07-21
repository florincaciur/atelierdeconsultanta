#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { ROOT, findPublicHtmlFiles } = require("../tools/sync-global-header");
const { listHtmlFiles, synchronizePublicHtml } = require("../tools/sync-analytics-events");

const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "funnel-analytics.json"), "utf8"));
const EVENTS = new Set([
  ...config.events,
  "nav_click",
  "program_menu_click",
  "whatsapp_dialog_open",
  "calculator_start",
  "calculator_complete",
  "calculator_result_to_dr12",
  "calculator_result_to_dr14",
  "source_document_click",
  "next_step_click",
  "carousel_interaction",
  "program_card_click"
]);
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
  let observedCtas = 0;

  for (const relativePath of publicFiles) {
    const html = read(relativePath);
    const $ = cheerio.load(html, { decodeEntities: false });
    const analyticsScripts = $('script[src^="/assets/analytics-events.js"]');
    const attributionScripts = $('script[src^="/assets/lead-attribution.js"]');
    if (analyticsScripts.length !== 1) errors.push(`${relativePath}: analytics-events.js apare de ${analyticsScripts.length} ori`);
    if (attributionScripts.length !== 1) errors.push(`${relativePath}: lead-attribution.js apare de ${attributionScripts.length} ori`);
    if (/https:\/\/www\.clarity\.ms\/tag\//i.test(html)) errors.push(`${relativePath}: loader Clarity inline rămas`);
    if (synchronizePublicHtml(html, relativePath) !== html) errors.push(`${relativePath}: sincronizarea analytics nu este idempotentă`);
    if (!$('body').attr("data-analytics-page-type")) errors.push(`${relativePath}: lipsește page_type controlat pe body`);

    const pageCtaIds = new Set();
    $("[data-analytics-event]").each((_, element) => {
      annotatedClicks += 1;
      const names = ($(element).attr("data-analytics-event") || "").trim().split(/\s+/).filter(Boolean);
      for (const name of names) if (!EVENTS.has(name)) errors.push(`${relativePath}: eveniment necunoscut ${name}`);
      if (names.includes("cta_click")) {
        observedCtas += 1;
        if ($(element).attr("data-analytics-cta-view") !== "true") errors.push(`${relativePath}: CTA click fără cta_view`);
        const ctaId = $(element).attr("data-analytics-cta-id") || "";
        if (!ctaId) errors.push(`${relativePath}: CTA fără cta_id stabil`);
        if (ctaId !== "eligibility_whatsapp" && pageCtaIds.has(ctaId)) errors.push(`${relativePath}: cta_id duplicat ${ctaId}`);
        pageCtaIds.add(ctaId);
      }
      const target = $(element).attr("data-analytics-target") || "";
      if (/^(?:mailto:|tel:|https:\/\/(?:api\.)?wa\.me\/)/i.test(target)) {
        errors.push(`${relativePath}: destinație sensibilă transmisibilă în data-analytics-target`);
      }
    });

    $("form").each((_, form) => {
      forms += 1;
      if (!$(form).attr("data-analytics-form")) errors.push(`${relativePath}: formular fără ID analytics generic`);
      if (!$(form).attr("data-analytics-form-version")) errors.push(`${relativePath}: formular fără versiune analytics`);
      if ($(form).attr("data-clarity-mask") !== "true") errors.push(`${relativePath}: formular fără data-clarity-mask=true`);
    });
  }

  for (const relativePath of listHtmlFiles()) {
    if (/https:\/\/www\.clarity\.ms\/tag\//i.test(read(relativePath))) errors.push(`${relativePath}: implementare Clarity inline rămasă`);
  }

  const analyticsSource = read("assets/analytics-events.js");
  const attributionSource = read("assets/lead-attribution.js");
  for (const name of EVENTS) if (!analyticsSource.includes(`"${name}"`)) errors.push(`assets/analytics-events.js: lipsește ${name}`);
  for (const key of config.payloadKeys) if (!analyticsSource.includes(`"${key}"`)) errors.push(`assets/analytics-events.js: lipsește cheia ${key}`);
  for (const forbidden of [
    { pattern: /\.value\b/, label: "citire .value" },
    { pattern: /\bFormData\b/, label: "FormData" },
    { pattern: /\bidentify\b/i, label: "Clarity identify" },
    { pattern: /\binnerText\b|\btextContent\b/, label: "citire text vizibil" },
    { pattern: /googletagmanager|google-analytics|connect\.facebook\.net|fbq\s*\(/i, label: "tracker terț nepermis" }
  ]) if (forbidden.pattern.test(analyticsSource)) errors.push(`assets/analytics-events.js: ${forbidden.label} nu este permisă`);
  if (count(analyticsSource, /CLARITY_PROJECT_ID\s*=/g) !== 1) errors.push("ID-ul Clarity nu are o singură sursă de adevăr");
  if (!/intersectionRatio\s*<\s*0\.5/.test(analyticsSource)) errors.push("cta_view nu impune pragul de 50%");
  if (!/window\.dataLayer\.push\(snapshot\)/.test(analyticsSource)) errors.push("payload-ul filtrat nu ajunge în dataLayer");
  if (!/\["pointerdown", "keydown", "input", "change"\]/.test(analyticsSource)) errors.push("form_start nu este legat de interacțiuni reale");
  if (/utm_|document\.referrer|sessionStorage/.test(analyticsSource)) errors.push("analytics-events.js nu trebuie să citească atribuirea brută");
  if (/dataLayer|clarity|sendBeacon|\bfetch\s*\(/i.test(attributionSource)) errors.push("lead-attribution.js trebuie să rămână first-party, fără transport analytics");

  const partial = read("partials/global-header.html");
  for (const eventName of ["nav_click", "program_menu_click", "cta_click", "contact_whatsapp"]) {
    if (!partial.includes(`data-analytics-event="${eventName}"`)) errors.push(`header: lipsește ${eventName}`);
  }
  const $partial = cheerio.load(partial, { decodeEntities: false });
  if ($partial("#navbar .nav-cta[data-analytics-event='cta_click'][data-analytics-cta-view='true']").length !== 1) errors.push("header: CTA desktop neinstrumentat");
  if ($partial("#mobileMenu .mobile-cta[data-analytics-event='cta_click'][data-analytics-cta-view='true']").length !== 1) errors.push("header: CTA mobil neinstrumentat");

  const home = read("index.html");
  if (count(home, /FaberAnalytics\.formSubmitSuccess\(form\)/g) !== 2) errors.push("homepage: succesul server al formularelor nu este instrumentat exact o dată");
  if (count(home, /FaberAnalytics\.formValidationError\(form\)/g) !== 2) errors.push("homepage: erorile formularelor nu sunt instrumentate exact o dată");

  const $contact = cheerio.load(read("contact/index.html"), { decodeEntities: false });
  const contactForm = $contact("#contact-triage-form");
  if (contactForm.attr("action") !== "/api/contact-triage") errors.push("contact: endpoint server-side incorect");
  if (contactForm.attr("data-analytics-form-version") !== "short_v1") errors.push("contact: form_version diferit de short_v1");

  for (const generator of GENERATORS) {
    const source = read(generator);
    if (!source.includes("/assets/analytics-events.js")) errors.push(`${generator}: nu încarcă stratul comun`);
    if (/clarity\.ms\/tag|wnvzyco6rq/.test(source)) errors.push(`${generator}: loader Clarity propriu`);
  }

  if (errors.length) {
    console.error(`Analytics verification FAILED (${errors.length}):`);
    errors.forEach((error) => console.error(` - ${error}`));
    process.exitCode = 1;
    return;
  }

  console.log(`Analytics verification PASS: ${publicFiles.length} pagini, ${forms} formulare mascate, ${observedCtas} CTA-uri observate; ${config.events.length} evenimente funnel și ${config.payloadKeys.length} chei non-PII.`);
}

main();
