#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const {
  ORGANIZATION_ID,
  WEBSITE_ID,
  organizationSchema
} = require("../tools/schema-helpers");
const {
  SITE,
  cleanText,
  comparableText,
  fileForRoute,
  hasType,
  loadPageHints,
  parseJsonLd,
  sitemapRoutes,
  typesOf,
  visibleFaqItems
} = require("../tools/structured-data-utils");

const routes = sitemapRoutes(ROOT);
const routeSet = new Set(routes);
const hints = loadPageHints(ROOT);
const forbiddenTypes = new Set(["AggregateRating", "Review", "LocalBusiness", "GovernmentService", "BlogPosting", "NewsArticle"]);
const forbiddenProperties = new Set(["aggregateRating", "review", "reviews", "award", "awards", "employee", "employees"]);
const allowedTopLevelTypes = new Set([
  "Organization",
  "ProfessionalService",
  "WebSite",
  "WebPage",
  "BreadcrumbList",
  "Article",
  "Service",
  "WebApplication",
  "FAQPage",
  "DefinedTerm"
]);

function walk(value, visit, key = "", pointer = "$") {
  if (Array.isArray(value)) return value.forEach((item, index) => walk(item, visit, key, `${pointer}[${index}]`));
  if (!value || typeof value !== "object") return;
  visit(value, key, pointer);
  for (const [childKey, child] of Object.entries(value)) walk(child, visit, childKey, `${pointer}.${childKey}`);
}

function internalTargetExists(raw, route) {
  const url = new URL(raw, SITE);
  if (url.origin !== SITE) return true;
  const pathname = url.pathname === "/" ? "/" : url.pathname.replace(/\/$/u, "");
  if (routeSet.has(pathname)) return true;
  const asset = path.join(ROOT, decodeURIComponent(pathname.replace(/^\//u, "")));
  assert(fs.existsSync(asset), `${route}: URL-ul JSON-LD intern nu corespunde unei rute 200 sau unui asset public: ${raw}`);
  return true;
}

let articleCount = 0;
let applicationCount = 0;
let modifiedCount = 0;

for (const route of routes) {
  const file = fileForRoute(ROOT, route);
  assert(fs.existsSync(file), `${route}: lipsește fișierul rutei canonice`);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  const blocks = parseJsonLd($);
  assert.equal(blocks.length, 1, `${route}: trebuie exact un bloc JSON-LD determinist`);
  assert.equal(blocks[0].error, "", `${route}: JSON-LD invalid: ${blocks[0].error}`);
  const nodes = blocks[0].nodes;
  const canonical = `${SITE}${route}`;

  const entityNodes = nodes.filter((node) => node?.["@id"] === ORGANIZATION_ID);
  assert.equal(entityNodes.length, 1, `${route}: trebuie exact o entitate FABER cu @id canonic`);
  assert.deepEqual(entityNodes[0], organizationSchema(), `${route}: entitatea FABER diferă de registrul juridic aprobat`);
  assert(hasType(entityNodes[0], "Organization") && hasType(entityNodes[0], "ProfessionalService"), `${route}: tipurile entității nu sunt reunite`);
  assert.equal(entityNodes[0].legalName, "FABER PUBLISHING S.R.L.", `${route}: legalName neaprobat`);
  assert.equal(entityNodes[0].telephone, "+40-769-828-338", `${route}: telefon canonic diferit`);
  assert.equal(entityNodes[0].address?.["@type"], "PostalAddress", `${route}: adresa nu este PostalAddress`);

  const websites = nodes.filter((node) => node?.["@id"] === WEBSITE_ID);
  assert.equal(websites.length, 1, `${route}: WebSite trebuie generat o singură dată`);
  const pages = nodes.filter((node) => hasType(node, "WebPage"));
  assert.equal(pages.length, 1, `${route}: WebPage trebuie generat o singură dată`);
  assert.equal(pages[0].url, canonical, `${route}: WebPage.url diferă de canonical`);

  for (const node of nodes) {
    for (const type of typesOf(node)) assert(allowedTopLevelTypes.has(type), `${route}: tip top-level necontrolat ${type}`);
  }

  walk(nodes, (node, key, pointer) => {
    for (const type of typesOf(node)) assert(!forbiddenTypes.has(type), `${route}: tip neverificabil ${type} la ${pointer}`);
    for (const property of Object.keys(node)) assert(!forbiddenProperties.has(property), `${route}: proprietate neverificabilă ${property} la ${pointer}`);
    if (["url", "@id", "item"].includes(key) && typeof node === "object") void node;
    for (const [property, value] of Object.entries(node)) {
      if (["url", "@id", "item"].includes(property) && typeof value === "string" && value.startsWith(SITE)) internalTargetExists(value, route);
    }
  });

  const expectedModified = hints.get(route)?.updatedAt;
  const dated = nodes.filter((node) => node.dateModified);
  modifiedCount += dated.length ? 1 : 0;
  if (expectedModified) {
    assert(dated.length, `${route}: lipsește dateModified din lastMeaningfulUpdate`);
    assert(dated.every((node) => node.dateModified === expectedModified), `${route}: dateModified nu provine exclusiv din lastMeaningfulUpdate`);
    const expectedSource = hints.get(route)?.citation?.[0]?.url;
    for (const node of nodes.filter((item) => hasType(item, "WebPage") || hasType(item, "Article"))) {
      assert(node.citation?.some((citation) => citation.url === expectedSource), `${route}: sursa oficială nu este sincronizată`);
    }
  } else {
    assert.equal(dated.length, 0, `${route}: dateModified publicat fără modificare editorială verificabilă`);
  }

  for (const article of nodes.filter((node) => hasType(node, "Article"))) {
    articleCount += 1;
    for (const property of ["author", "reviewedBy"]) {
      if (!article[property]) continue;
      assert.equal(article[property]["@type"], "Person", `${route}: ${property} nu este Person`);
      assert(/^https:\/\//iu.test(article[property].url || ""), `${route}: ${property} nu are profil oficial`);
      const visible = $(`a[href='${article[property].url}']`).filter((_, element) => comparableText($(element).text()).includes(comparableText(article[property].name)));
      assert(visible.length, `${route}: profilul ${property} nu este vizibil`);
    }
  }

  const applications = nodes.filter((node) => hasType(node, "WebApplication"));
  if (route === "/calculator-soc") {
    assert.equal(applications.length, 1, `${route}: WebApplication lipsește`);
    assert.equal(applications[0].name, cleanText($("h1").first().text()), `${route}: numele aplicației nu este vizibil`);
    assert.equal(applications[0].description, cleanText($("meta[name='description']").attr("content")), `${route}: descrierea aplicației diferă`);
    assert.equal(applications[0].applicationCategory, "BusinessApplication", `${route}: categorie exagerată/necontrolată`);
    assert.equal(applications[0].offers, undefined, `${route}: oferta gratuită nu este susținută vizibil`);
    applicationCount += 1;
  } else {
    assert.equal(applications.length, 0, `${route}: WebApplication este permis numai pe Calculator SO`);
  }

  const visibleFaq = visibleFaqItems($);
  const faqNodes = nodes.filter((node) => hasType(node, "FAQPage"));
  assert.equal(faqNodes.length, visibleFaq.length >= 2 ? 1 : 0, `${route}: FAQPage trebuie să existe numai pentru un FAQ vizibil real`);
  const schemaFaq = faqNodes[0]?.mainEntity || [];
  assert.equal(schemaFaq.length, visibleFaq.length, `${route}: numărul întrebărilor FAQPage diferă de HTML`);
  for (const [index, item] of schemaFaq.entries()) {
    assert.equal(comparableText(item.name), comparableText(visibleFaq[index].question), `${route}: întrebarea FAQPage ${index + 1} diferă sau este în altă ordine`);
    assert.equal(comparableText(item.acceptedAnswer?.text), comparableText(visibleFaq[index].answer), `${route}: răspunsul FAQPage ${index + 1} diferă de HTML`);
  }
}

assert(articleCount > 0, "Inventarul trebuie să păstreze Article pentru analize reale");
assert.equal(applicationCount, 1, "Inventarul trebuie să conțină un singur WebApplication");
assert(modifiedCount < Math.ceil(routes.length * 0.8), "dateModified pare derivat din build global");

console.log(`Contract P1.17 PASS: ${routes.length} URL-uri canonice/200, ${articleCount} analize Article, un WebApplication și un singur @id de entitate.`);
