#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForPage, loadPriorityConfig } = require("../tools/priority-aeo");
const {
  ORGANIZATION_ID,
  organizationSchema,
  serializeJsonLd,
  websiteSchema
} = require("../tools/schema-helpers");
const { normalizeJsonLdValue } = require("../tools/normalize-copy-ro");
const {
  SITE,
  cleanText,
  comparableText,
  loadPageHints,
  parseJsonLd,
  typesOf,
  visibleFaqItems
} = require("../tools/structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const LIVE = process.argv.includes("--live");
const officialUrls = new Set();
const STRUCTURED_DATA_PROGRAMS = new Set([
  "dr12-afir",
  "dr14",
  "por-adr-nord-est",
  "afir-autoconsum-agroalimentar",
  "pro-infra",
  "pocidif-21"
]);

function words(value) {
  return cleanText(value).split(/\s+/u).filter(Boolean).length;
}

function hasType(node, type) {
  return typesOf(node).includes(type);
}

function validatePage(slug, page, config, hints, errors) {
  const file = fileForPage(slug, page);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  const canonical = `${SITE}${page.route}`;
  const pageErrors = [];
  const exactHeading = (label) => $("main h2").filter((_, element) => cleanText($(element).text()) === label);

  const direct = $("main [data-answer-readiness-direct]");
  if (direct.length !== 1) pageErrors.push(`trebuie exact un răspuns direct, găsite ${direct.length}`);
  const directWords = words(direct.text());
  if (directWords < 45 || directWords > 80) pageErrors.push(`răspunsul direct are ${directWords} cuvinte, necesar 45–80`);
  if (exactHeading(page.sectionTitle).length !== 1) pageErrors.push(`lipsește H2-ul de intenție „${page.sectionTitle}”`);
  const facts = $("main .answer-readiness__facts > div");
  if (facts.length !== 8) pageErrors.push(`secțiunea operațională are ${facts.length} răspunsuri, necesar 8`);
  const nearbySource = $("main .answer-readiness__source");
  if (nearbySource.length !== 1 || nearbySource.find("a[href^='https://']").length !== 1) pageErrors.push("lipsește sursa oficială apropiată de răspunsul direct");
  const reviewed = page.lastReviewed || config.lastReviewed || config.lastVerified;
  if (!$(`main time[datetime='${reviewed}']`).length) pageErrors.push(`lipsește data vizibilă de revizuire ${reviewed}`);

  const sourceSections = $("main section").filter((_, element) => /Surse oficiale/iu.test(cleanText($(element).find("h2").first().text())));
  const officialLinks = sourceSections.find("a[href^='https://']");
  if (!sourceSections.length || !officialLinks.length) pageErrors.push("lipsește secțiunea vizibilă cu surse oficiale HTTPS");
  officialLinks.each((_, element) => {
    try {
      const url = new URL($(element).attr("href"));
      if (!url.hostname || /example\.(?:com|org)$/iu.test(url.hostname)) pageErrors.push(`sursă oficială invalidă: ${url}`);
      officialUrls.add(url.toString());
    } catch {
      pageErrors.push(`link de sursă invalid: ${$(element).attr("href")}`);
    }
  });

  const blocks = parseJsonLd($);
  for (const block of blocks) if (block.error) pageErrors.push(`JSON-LD invalid (${block.error})`);
  if (blocks.length !== 1) pageErrors.push(`trebuie exact un bloc JSON-LD determinist, găsite ${blocks.length}`);
  const nodes = blocks.flatMap((block) => block.nodes);
  for (const required of ["WebPage", "WebSite", "BreadcrumbList", "FAQPage", "Organization", "Article"]) {
    if (!nodes.some((node) => hasType(node, required))) pageErrors.push(`lipsește tipul schema ${required}`);
  }
  for (const forbidden of ["GovernmentService", "Service", "WebApplication", "BlogPosting", "AggregateRating", "Review"]) {
    if (nodes.some((node) => hasType(node, forbidden))) pageErrors.push(`tip schema nejustificat pe pagina editorială: ${forbidden}`);
  }

  const org = nodes.find((node) => node["@id"] === ORGANIZATION_ID);
  if (!org || serializeJsonLd(org) !== serializeJsonLd(organizationSchema())) pageErrors.push("Organization FABER nu este identică sursei canonice");
  const website = nodes.find((node) => hasType(node, "WebSite"));
  if (!website || serializeJsonLd(website) !== serializeJsonLd(websiteSchema())) pageErrors.push("WebSite nu este identic sursei canonice");

  const webPage = nodes.find((node) => hasType(node, "WebPage"));
  const article = nodes.find((node) => hasType(node, "Article"));
  const editorialDate = hints?.updatedAt;
  if (!webPage || webPage.dateModified !== editorialDate) pageErrors.push(`WebPage.dateModified trebuie să fie data editorială ${editorialDate}`);
  if (!article?.author || !article?.publisher || !article?.mainEntityOfPage) pageErrors.push("Article trebuie să aibă author, publisher și mainEntityOfPage");
  if (article && article.dateModified !== editorialDate) pageErrors.push(`Article.dateModified trebuie să fie data editorială ${editorialDate}`);

  const visibleFaq = new Map(visibleFaqItems($).map((item) => [comparableText(item.question), comparableText(item.answer)]));
  const faq = nodes.find((node) => hasType(node, "FAQPage"));
  const schemaFaq = Array.isArray(faq?.mainEntity) ? faq.mainEntity : [];
  if (!schemaFaq.length) pageErrors.push("FAQPage nu conține întrebări");
  for (const item of schemaFaq) {
    const question = cleanText(item.name);
    const answer = cleanText(item.acceptedAnswer?.text);
    const key = comparableText(question);
    if (!visibleFaq.has(key)) pageErrors.push(`FAQ schema fără întrebare vizibilă: ${question}`);
    else if (visibleFaq.get(key) !== comparableText(answer)) pageErrors.push(`FAQ schema cu răspuns diferit de cel vizibil: ${question}`);
  }

  const breadcrumb = nodes.find((node) => hasType(node, "BreadcrumbList"));
  const breadcrumbItems = breadcrumb?.itemListElement || [];
  if (breadcrumbItems.length < 2 || breadcrumbItems.length > 4) pageErrors.push(`breadcrumb cu ${breadcrumbItems.length} niveluri, necesar 2–4`);
  for (const item of breadcrumbItems) {
    try {
      const target = new URL(item.item);
      if (target.origin !== SITE || target.hash || target.search || target.pathname.endsWith(".html")) pageErrors.push(`breadcrumb necanonic: ${item.item}`);
    } catch {
      pageErrors.push(`breadcrumb URL invalid: ${item.item}`);
    }
  }
  if (breadcrumbItems.at(-1)?.item !== canonical) pageErrors.push("breadcrumb nu se încheie cu ruta canonică");

  const normalized = normalizeJsonLdValue({ "@graph": nodes });
  if (serializeJsonLd(normalized) !== serializeJsonLd({ "@graph": nodes })) pageErrors.push("există valori JSON-LD românești nenormalizate");
  if ($("link[rel='canonical']").attr("href") !== canonical) pageErrors.push(`canonical diferit: ${$("link[rel='canonical']").attr("href")}`);
  if ($("h1").length !== 1) pageErrors.push(`număr H1 invalid: ${$("h1").length}`);

  if (pageErrors.length) errors.push(...pageErrors.map((error) => `${slug}: ${error}`));
  else console.log(`${slug}: structură semantică și date structurate valide`);
}

async function verifyLiveSources(errors, warnings) {
  for (const url of officialUrls) {
    try {
      let response = await fetch(url, { method: "HEAD", redirect: "follow", signal: AbortSignal.timeout(20000) });
      if (response.status >= 400) {
        response = await fetch(url, { method: "GET", redirect: "follow", signal: AbortSignal.timeout(20000) });
      }
      if (response.status >= 500) warnings.push(`server oficial indisponibil temporar HTTP ${response.status}: ${url}`);
      else if (response.status >= 400) errors.push(`sursă oficială inaccesibilă HTTP ${response.status}: ${url}`);
      else console.log(`sursă oficială HTTP ${response.status}: ${url}`);
    } catch (error) {
      errors.push(`sursă oficială inaccesibilă (${error.message}): ${url}`);
    }
  }
}

async function main() {
  const config = loadPriorityConfig();
  const hints = loadPageHints(ROOT);
  const errors = [];
  const warnings = [];
  const pages = Object.entries(config.pages).filter(([slug]) => STRUCTURED_DATA_PROGRAMS.has(slug));
  for (const [slug, page] of pages) validatePage(slug, page, config, hints.get(page.route), errors);
  if (LIVE && !errors.length) await verifyLiveSources(errors, warnings);
  for (const warning of warnings) console.warn(`Avertisment: ${warning}`);
  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  console.log(`Date structurate valide pentru ${pages.length} pagini prioritare${LIVE ? ", inclusiv sursele live" : ""}.`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
