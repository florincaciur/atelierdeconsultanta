#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { loadPriorityConfig } = require("../tools/priority-aeo");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const LIVE = process.argv.includes("--live");
const officialUrls = new Set();

function text(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function words(value) {
  return text(value).split(/\s+/u).filter(Boolean).length;
}

function comparable(value) {
  return text(value).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
}

function graphNodes($, errors, slug) {
  const nodes = [];
  $("script[type='application/ld+json']").each((_, script) => {
    try {
      const data = JSON.parse($(script).html());
      if (Array.isArray(data)) nodes.push(...data);
      else if (Array.isArray(data["@graph"])) nodes.push(...data["@graph"]);
      else nodes.push(data);
    } catch (error) {
      errors.push(`${slug}: JSON-LD invalid (${error.message})`);
    }
  });
  return nodes;
}

function types(node) {
  return Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]].filter(Boolean);
}

function validatePage(slug, config, errors) {
  const file = path.join(ROOT, slug, "index.html");
  const $ = cheerio.load(fs.readFileSync(file, "utf8"));
  const canonical = `${SITE}/${slug}`;
  const pageErrors = [];
  const exactHeading = (label) => $("main h2").filter((_, element) => text($(element).text()) === label);

  const quickHeadings = exactHeading("Răspuns rapid");
  if (quickHeadings.length !== 1) pageErrors.push(`trebuie exact un H2 „Răspuns rapid”, găsite ${quickHeadings.length}`);
  const quickText = text(quickHeadings.first().nextAll("p").first().text());
  const quickWords = words(quickText);
  if (quickWords < 60 || quickWords > 100) pageErrors.push(`răspunsul rapid are ${quickWords} cuvinte, necesar 60–100`);

  const checks = exactHeading("Ce trebuie verificat").first().nextAll("ul").first().find(":scope > li");
  if (checks.length < 5 || checks.length > 8) pageErrors.push(`„Ce trebuie verificat” are ${checks.length} elemente, necesar 5–8`);
  if (exactHeading("Documente de pregătit").length !== 1) pageErrors.push("lipsește secțiunea „Documente de pregătit”");
  if (exactHeading("Riscuri").length < 1) pageErrors.push("lipsește secțiunea „Riscuri”");
  if (!$("main").text().includes("Verificator editorial")) pageErrors.push("lipsește verificatorul editorial vizibil");
  if (!$(`main time[datetime='${config.lastVerified}']`).length) pageErrors.push(`lipsește data vizibilă ${config.lastVerified}`);
  if (!$("main").text().includes(config.author)) pageErrors.push("lipsește autorul vizibil");

  const sourceSections = $("main section").filter((_, element) => /Surse oficiale/i.test(text($(element).find("h2").first().text())));
  const officialLinks = sourceSections.find("a[href^='https://']");
  if (!sourceSections.length || !officialLinks.length) pageErrors.push("lipsește secțiunea vizibilă cu surse oficiale HTTPS");
  officialLinks.each((_, element) => {
    try {
      const url = new URL($(element).attr("href"));
      if (!url.hostname || /example\.(?:com|org)$/i.test(url.hostname)) pageErrors.push(`sursă oficială invalidă: ${url}`);
      officialUrls.add(url.toString());
    } catch { pageErrors.push(`link de sursă invalid: ${$(element).attr("href")}`); }
  });

  const nodes = graphNodes($, pageErrors, slug);
  const hasType = (type) => nodes.some((node) => types(node).includes(type));
  for (const required of ["WebPage", "BreadcrumbList", "FAQPage", "Organization", "Article"]) {
    if (!hasType(required)) pageErrors.push(`lipsește tipul schema ${required}`);
  }
  if (nodes.some((node) => types(node).some((type) => ["AggregateRating", "Review", "Award"].includes(type)))) {
    pageErrors.push("există rating, review sau premiu neverificat în schema");
  }

  const webPage = nodes.find((node) => types(node).includes("WebPage"));
  const article = nodes.find((node) => types(node).includes("Article"));
  if (!webPage || webPage.dateModified !== config.lastVerified) pageErrors.push("WebPage.dateModified nu corespunde implementării");
  if (!article?.author || !article?.publisher || !article?.mainEntityOfPage) pageErrors.push("Article trebuie să aibă author, publisher și mainEntityOfPage");
  if (article && article.dateModified !== config.lastVerified) pageErrors.push("Article.dateModified nu corespunde implementării");

  const faq = nodes.find((node) => types(node).includes("FAQPage"));
  const schemaQuestions = (faq?.mainEntity || []).map((item) => text(item.name));
  const visibleQuestions = $("main .faq-item h3, main section[id*='faq'] h3").map((_, element) => text($(element).text())).get();
  const uniqueVisible = new Set(visibleQuestions.map(comparable));
  if (!schemaQuestions.length) pageErrors.push("FAQPage nu conține întrebări");
  for (const question of schemaQuestions) {
    if (!uniqueVisible.has(comparable(question))) pageErrors.push(`FAQ schema fără întrebare vizibilă: ${question}`);
  }

  const canonicalHref = $("link[rel='canonical']").attr("href");
  if (canonicalHref !== canonical) pageErrors.push(`canonical diferit: ${canonicalHref}`);
  if ($("h1").length !== 1) pageErrors.push(`număr H1 invalid: ${$("h1").length}`);

  if (pageErrors.length) errors.push(...pageErrors.map((error) => `${slug}: ${error}`));
  else console.log(`${slug}: structură semantică și date structurate valide`);
}

async function verifyLiveSources(errors) {
  for (const url of officialUrls) {
    try {
      let response = await fetch(url, { method: "HEAD", redirect: "follow", signal: AbortSignal.timeout(20000) });
      if (response.status === 405 || response.status === 403) {
        response = await fetch(url, { method: "GET", redirect: "follow", signal: AbortSignal.timeout(20000) });
      }
      if (response.status >= 400) errors.push(`sursă oficială inaccesibilă HTTP ${response.status}: ${url}`);
      else console.log(`sursă oficială HTTP ${response.status}: ${url}`);
    } catch (error) {
      errors.push(`sursă oficială inaccesibilă (${error.message}): ${url}`);
    }
  }
}

async function main() {
  const config = loadPriorityConfig();
  const errors = [];
  for (const slug of Object.keys(config.pages)) validatePage(slug, config, errors);
  if (LIVE && !errors.length) await verifyLiveSources(errors);
  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  console.log(`Date structurate valide pentru ${Object.keys(config.pages).length} pagini prioritare.`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
