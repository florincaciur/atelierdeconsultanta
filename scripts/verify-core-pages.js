#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { SITE, cleanText, parseJsonLd, graphNodes, hasType, sitemapRoutes, visibleFaqItems } = require("../tools/structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const PAGES = [
  ["/consultanta-fonduri-europene", "consultanta-fonduri-europene/index.html", ".core-callout"],
  ["/despre-faber", "despre-faber/index.html", ".core-callout"],
  ["/fonduri-europene", "fonduri-europene/index.html", ".core-callout"],
  ["/contact", "contact/index.html", ".contact-layout"]
];

function pageOrder($, selector) {
  return $("body *").index($(selector).first());
}

function faqSchema($) {
  return parseJsonLd($)
    .flatMap((block) => graphNodes(block.data))
    .find((node) => hasType(node, "FAQPage"));
}

const sitemap = new Set(sitemapRoutes(ROOT));
const errors = [];

for (const [route, relativePath, primarySelector] of PAGES) {
  const file = path.join(ROOT, relativePath);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  const support = $("main .core-search-support");
  const faq = $("main .faq-item");
  const visibleFaq = visibleFaqItems($);
  const schema = faqSchema($);
  const schemaItems = Array.isArray(schema?.mainEntity) ? schema.mainEntity : [];
  const title = cleanText($("title").text());

  if (!sitemap.has(route)) errors.push(`${route}: lipsește din sitemap`);
  if ($("link[rel='canonical']").attr("href") !== `${SITE}${route}`) errors.push(`${route}: canonical incorect`);
  if ($("h1").length !== 1) errors.push(`${route}: trebuie exact un H1`);
  if (title.length < 45 || title.length > 65) errors.push(`${route}: titlul are ${title.length} caractere`);
  if (!$("body").hasClass("core-page")) errors.push(`${route}: lipsește clasa core-page`);
  if (support.length !== 1) errors.push(`${route}: trebuie exact o zonă finală de documentare`);
  if (support.find("details.core-search-details[data-non-faq]").length !== 1) errors.push(`${route}: zona finală nu folosește disclosure semantic`);
  if (support.find("details[open]").length) errors.push(`${route}: zona de documentare trebuie să fie închisă implicit`);
  if (faq.length !== 6) errors.push(`${route}: sunt necesare 6 întrebări, găsite ${faq.length}`);
  if (faq.filter((_, element) => !$(element).closest(".core-search-support").length).length) errors.push(`${route}: există FAQ înainte de subsolul editorial`);
  if ($("main h2").filter((_, element) => /răspuns scurt|raspuns scurt/iu.test(cleanText($(element).text()))).length) errors.push(`${route}: conține titlul generic «Răspuns scurt»`);
  if ($(".audit-design-summary, .design-card-grid").length) errors.push(`${route}: conține rezumat vizual generic vechi`);
  if (pageOrder($, ".core-search-support") <= pageOrder($, primarySelector)) errors.push(`${route}: documentarea apare înaintea acțiunii principale`);
  if (visibleFaq.length !== schemaItems.length) errors.push(`${route}: FAQ vizibil/schema diferit (${visibleFaq.length}/${schemaItems.length})`);

  console.log(`${route}: ${title.length} caractere în titlu, ${faq.length} FAQ în subsol, canonical și sitemap conforme`);
}

if (errors.length) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exit(1);
}

console.log("Cele 4 pagini centrale au conținut comercial prioritar și documentarea SEO/AEO/GEO numai la final.");
