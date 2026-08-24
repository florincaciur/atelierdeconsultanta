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
  incentiveStatusForProgram,
  organizationSchema,
  websiteSchema
} = require("../tools/schema-helpers");
const { loadProgramConfig, programForRoute } = require("../tools/program-factual-governance");
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
const programs = loadProgramConfig().programs;
const forbiddenTypes = new Set(["AggregateRating", "Review", "LocalBusiness", "GovernmentService", "BlogPosting", "NewsArticle", "FundingProgram"]);
const forbiddenProperties = new Set(["aggregateRating", "review", "reviews", "award", "awards", "employee", "employees", "numberOfEmployees", "foundingDate", "certification", "hasCertification"]);
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
  "FinancialIncentive",
  "CreativeWork"
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

function pureReference(value, id) {
  return value?.["@id"] === id && Object.keys(value).length === 1;
}

function referencedUrl(nodes, value) {
  if (value?.url) return value.url;
  if (!value?.["@id"]) return undefined;
  let url;
  walk(nodes, (node) => {
    if (!url && node["@id"] === value["@id"] && Object.keys(node).length > 1) url = node.url;
  });
  return url;
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
  assert.deepEqual(websites[0], websiteSchema(), `${route}: WebSite diferă de definiția canonică`);
  const pages = nodes.filter((node) => hasType(node, "WebPage"));
  assert.equal(pages.length, 1, `${route}: WebPage trebuie generat o singură dată`);
  assert.equal(pages[0].url, canonical, `${route}: WebPage.url diferă de canonical`);
  assert.equal(pages[0]["@id"], `${canonical}#webpage`, `${route}: WebPage.@id diferă de canonical`);
  assert.equal(pages[0].name, cleanText($("h1").first().text()), `${route}: WebPage.name diferă de H1`);
  assert.equal(pages[0].description, cleanText($("meta[name='description']").attr("content")), `${route}: WebPage.description diferă de meta description`);
  assert(pureReference(pages[0].publisher, ORGANIZATION_ID), `${route}: WebPage.publisher nu referă exclusiv FABER`);

  for (const node of nodes) {
    for (const type of typesOf(node)) assert(allowedTopLevelTypes.has(type), `${route}: tip top-level necontrolat ${type}`);
  }

  const topLevelIds = nodes.map((node) => node?.["@id"]);
  assert(topLevelIds.every(Boolean), `${route}: fiecare entitate top-level trebuie să aibă @id stabil`);
  assert.equal(new Set(topLevelIds).size, topLevelIds.length, `${route}: @id top-level duplicat`);
  const definitionsById = new Map();
  walk(nodes, (node, key, pointer) => {
    for (const type of typesOf(node)) assert(!forbiddenTypes.has(type), `${route}: tip neverificabil ${type} la ${pointer}`);
    for (const property of Object.keys(node)) assert(!forbiddenProperties.has(property), `${route}: proprietate neverificabilă ${property} la ${pointer}`);
    if (node["@id"]) {
      assert(/^https:\/\//iu.test(node["@id"]), `${route}: @id nestabil la ${pointer}: ${node["@id"]}`);
      if (Object.keys(node).some((property) => property !== "@id")) definitionsById.set(node["@id"], (definitionsById.get(node["@id"]) || 0) + 1);
    }
    if ((hasType(node, "Organization") || hasType(node, "CreativeWork")) && Object.keys(node).length > 1) {
      assert(node["@id"], `${route}: ${typesOf(node).join("+")} fără @id stabil la ${pointer}`);
    }
    if (node.sameAs !== undefined) {
      assert.equal(node["@id"], ORGANIZATION_ID, `${route}: sameAs este permis numai pe entitatea FABER aprobată`);
      assert.deepEqual(node.sameAs, organizationSchema().sameAs, `${route}: sameAs diferă de profilurile aprobate`);
    }
    if (["url", "@id", "item"].includes(key) && typeof node === "object") void node;
    for (const [property, value] of Object.entries(node)) {
      if (["url", "@id", "item"].includes(property) && typeof value === "string" && value.startsWith(SITE)) internalTargetExists(value, route);
    }
  });
  for (const [id, definitions] of definitionsById) assert.equal(definitions, 1, `${route}: @id ${id} are ${definitions} definiții concurente`);

  const breadcrumbs = nodes.filter((node) => hasType(node, "BreadcrumbList"));
  assert.equal(breadcrumbs.length, route === "/" ? 0 : 1, `${route}: BreadcrumbList invalid ca număr`);
  if (breadcrumbs[0]) assert.equal(breadcrumbs[0]["@id"], `${canonical}#breadcrumb`, `${route}: BreadcrumbList.@id diferă de canonical`);

  for (const article of nodes.filter((node) => hasType(node, "Article"))) {
    assert.equal(article.headline, cleanText($("h1").first().text()), `${route}: Article.headline diferă de H1`);
    assert.equal(article.description, cleanText($("meta[name='description']").attr("content")), `${route}: Article.description diferă de meta description`);
    assert(pureReference(article.publisher, ORGANIZATION_ID), `${route}: Article.publisher nu referă exclusiv FABER`);
    assert(pureReference(article.mainEntityOfPage, `${canonical}#webpage`), `${route}: Article.mainEntityOfPage redefinește WebPage`);
  }
  for (const service of nodes.filter((node) => hasType(node, "Service"))) {
    assert.equal(service.name, cleanText($("h1").first().text()), `${route}: Service.name diferă de H1`);
    assert.equal(service.description, cleanText($("meta[name='description']").attr("content")), `${route}: Service.description diferă de meta description`);
    assert(pureReference(service.provider, ORGANIZATION_ID), `${route}: Service.provider nu referă exclusiv FABER`);
  }

  const program = programForRoute(route, programs);
  const incentives = nodes.filter((node) => hasType(node, "FinancialIncentive"));
  assert.equal(incentives.length, program ? 1 : 0, `${route}: FinancialIncentive trebuie să existe numai pentru un program public din registru`);
  if (program) {
    const incentive = incentives[0];
    const authorityId = `${canonical}#program-authority`;
    assert.equal(incentive["@id"], `${canonical}#funding-program`, `${route}: FinancialIncentive.@id invalid`);
    assert.equal(incentive.name, program.name, `${route}: FinancialIncentive.name diferă de registru`);
    assert.equal(incentive.description, program.statusLabel, `${route}: FinancialIncentive.description diferă de statusul vizibil`);
    assert.equal(incentive.url, canonical, `${route}: FinancialIncentive.url diferă de canonical`);
    assert(pureReference(incentive.mainEntityOfPage, `${canonical}#webpage`), `${route}: FinancialIncentive.mainEntityOfPage invalid`);
    assert.equal(incentive.provider?.["@id"], authorityId, `${route}: autoritatea nu are @id stabil`);
    assert(hasType(incentive.provider, "Organization"), `${route}: autoritatea nu este Organization`);
    assert.equal(incentive.provider?.name, program.sourceName, `${route}: autoritatea diferă de registru`);
    assert.notEqual(incentive.provider?.["@id"], ORGANIZATION_ID, `${route}: FABER nu poate fi autoritatea programului`);
    assert.equal(incentive.subjectOf?.["@id"], `${canonical}#official-source`, `${route}: sursa oficială nu are @id stabil`);
    assert.equal(incentive.subjectOf?.url, program.sourceUrl, `${route}: sursa oficială diferă de registru`);
    assert(pureReference(incentive.subjectOf?.publisher, authorityId), `${route}: sursa oficială nu referă autoritatea`);
    assert.equal(incentive.incentiveStatus, incentiveStatusForProgram(program), `${route}: incentiveStatus diferă de registru`);
    assert.equal(incentive.validFrom, program.applicationStart || undefined, `${route}: validFrom diferă de registru`);
    assert.equal(incentive.validThrough, program.applicationEnd || undefined, `${route}: validThrough diferă de registru`);
    assert.equal(incentive.sameAs, undefined, `${route}: documentul-sursă nu poate fi sameAs`);
    assert.equal(incentive.funder, undefined, `${route}: funder neverificat`);
    assert.equal(incentive.publisher, undefined, `${route}: publisher-ul paginii nu poate fi atribuit stimulentului`);
    assert($(`main a[href='${program.sourceUrl}']`).length, `${route}: sursa oficială din JSON-LD nu este vizibilă`);
  }

  const expectedModified = hints.get(route)?.updatedAt;
  const dated = nodes.filter((node) => node.dateModified);
  modifiedCount += dated.length ? 1 : 0;
  if (expectedModified) {
    assert(dated.length, `${route}: lipsește dateModified din lastMeaningfulUpdate`);
    assert(dated.every((node) => node.dateModified === expectedModified), `${route}: dateModified nu provine exclusiv din lastMeaningfulUpdate`);
    const expectedSource = hints.get(route)?.citation?.[0]?.url;
    for (const node of nodes.filter((item) => hasType(item, "WebPage") || hasType(item, "Article"))) {
      assert(node.citation?.some((citation) => referencedUrl(nodes, citation) === expectedSource), `${route}: sursa oficială nu este sincronizată`);
    }
  } else {
    assert.equal(dated.length, 0, `${route}: dateModified publicat fără modificare editorială verificabilă`);
  }

  for (const article of nodes.filter((node) => hasType(node, "Article"))) {
    articleCount += 1;
    for (const property of ["author", "reviewedBy"]) {
      if (!article[property]) continue;
      if (pureReference(article[property], ORGANIZATION_ID)) continue;
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
  if (faqNodes[0]) assert.equal(faqNodes[0]["@id"], `${canonical}#faq`, `${route}: FAQPage.@id diferă de canonical`);
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

console.log(`Contract Task 16 PASS: ${routes.length} URL-uri canonice/200, ${articleCount} analize Article, ID-uri stabile și entități fără spam.`);
