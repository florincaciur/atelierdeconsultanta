import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const {
  FORBIDDEN_LOCAL_FACTS,
  SECTION_ORDER,
  TEMPLATE_VERSION,
  countWords,
  loadConfig,
  validateConfig
} = require("../tools/sync-program-page-template");
const { loadProgramConfig, statusStatement } = require("../tools/program-factual-governance");
const { loadEditorialGovernance } = require("../tools/editorial-governance");

const config = loadConfig();
const schema = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "program-page-template.schema.json"), "utf8"));
const guides = JSON.parse(fs.readFileSync(path.join(ROOT, "official-guides.json"), "utf8"));
const report = JSON.parse(fs.readFileSync(path.join(ROOT, "reports", "program-page-template-pilot-2026-07-21.json"), "utf8"));
const { programs } = loadProgramConfig();
const { records } = loadEditorialGovernance();
const programBySlug = new Map(programs.map((program) => [program.slug, program]));

assert.doesNotThrow(() => validateConfig(config, programs, guides, records));
assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
assert(schema.description.includes("nu sunt câmpuri editoriale locale"), "schema trebuie să interzică suprascrierea faptelor din registru");
assert.deepEqual(schema.$defs.page.required.includes("editorialGovernanceRecordId"), true);
assert.equal(report.templateVersion, TEMPLATE_VERSION);
assert.equal(report.pilotRoute, config.pilotRoute);
assert.equal(report.pages.length, config.pages.length);

function jsonLdNodes($) {
  const nodes = [];
  $("script[type='application/ld+json']").each((_, node) => {
    const value = JSON.parse($(node).text());
    if (Array.isArray(value?.["@graph"])) nodes.push(...value["@graph"]);
    else if (Array.isArray(value)) nodes.push(...value);
    else nodes.push(value);
  });
  return nodes;
}

function hasType(node, type) {
  const values = Array.isArray(node?.["@type"]) ? node["@type"] : [node?.["@type"]];
  return values.includes(type);
}

function absoluteUrl(value) {
  return new URL(value, "https://atelierdeconsultanta.ro").href.replace(/\/$/, "");
}

for (const page of config.pages) {
  const program = programBySlug.get(page.programSlug);
  const slug = page.route.replace(/^\//, "");
  const file = path.join(ROOT, slug, "index.html");
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const template = $("main article[data-program-template='p1_11']");

  assert.equal($("body").attr("data-program-template-version"), TEMPLATE_VERSION, `${page.route}: metadata template lipsă`);
  assert.equal(template.length, 1, `${page.route}: trebuie un singur template`);
  assert.equal($("link[data-program-page-template-style='p1_11']").length, 1, `${page.route}: CSS lipsă sau duplicat`);
  assert.equal($(".program-hero h1").text().trim(), program.shortName, `${page.route}: H1 nu vine din shortName-ul registrului`);
  assert.equal($(".program-hero [data-program-status-badge]").attr("data-program-status-badge"), program.status);

  const factual = $(".program-hero .program-factual-status--template-header");
  assert.equal(factual.length, 1, `${page.route}: statusul, data și sursa trebuie să fie lângă H1`);
  assert.equal(factual.attr("data-program-status"), program.status);
  assert.equal(factual.attr("data-verified-at"), program.verifiedAt);
  assert.equal(factual.attr("data-source-url"), program.sourceUrl);
  assert(factual.text().includes(statusStatement(program)), `${page.route}: statusul vizibil diferă de registru`);
  assert.equal(factual.find(`a[href='${program.sourceUrl}']`).length, 1, `${page.route}: sursa oficială lipsește din header`);

  const direct = $(".program-template__direct-answer");
  const directWords = countWords(direct.text());
  assert.equal(direct.length, 1);
  assert(directWords >= 50 && directWords <= 80, `${page.route}: răspunsul direct are ${directWords} cuvinte`);
  assert(direct.text().includes("Depunerea este deschisă"), `${page.route}: răspunsul direct nu spune dacă depunerea este deschisă`);

  const actualOrder = $("[data-program-template-section]").map((_, node) => $(node).attr("data-program-template-section")).get();
  assert.deepEqual(actualOrder, ["glance", ...SECTION_ORDER], `${page.route}: ordinea obligatorie a secțiunilor este încălcată`);
  assert.equal($("#program-glance-title").text().trim(), "La o privire");
  assert.deepEqual($("#program-glance-title").closest("section").find("th").map((_, node) => $(node).text().trim()).get(), ["Beneficiar", "Sprijin", "Contribuție proprie", "Calendar", "Document-cheie"]);
  $("#program-glance-title").closest("section").find("tr").each((_, row) => {
    assert.equal($(row).find("a[data-source-key]").length, 1, `${page.route}: fiecare valoare din tabel trebuie să aibă sursa alăturată`);
  });

  for (const id of ["program-eligibility", "program-funding", "program-score-risk", "program-documents"]) {
    const section = $(`#${id}`);
    assert.equal(section.find(":scope > .program-template__source-note a[data-source-key]").length > 0, true, `${page.route}: ${id} nu are sursă apropiată`);
  }
  assert.equal($(".program-template__disclaimer").length, 1, `${page.route}: trebuie un singur disclaimer`);
  assert.equal((template.text().match(/eventualele modificări se verifică la AFIR/giu) || []).length, 1, `${page.route}: disclaimer duplicat`);
  assert.equal(/\bPe scurt\b/iu.test(template.text()), false, `${page.route}: eticheta generică a rămas în template`);

  const questions = $("#program-questions details.faq-item");
  const openQuestions = questions.filter("[open]");
  assert.equal(questions.length, page.questions.length, `${page.route}: întrebări pierdute`);
  assert(openQuestions.length <= 6, `${page.route}: sunt deschise vizual mai mult de șase întrebări`);
  openQuestions.each((index, node) => assert.equal(questions.index(node), index, `${page.route}: numai primele întrebări pot fi deschise`));
  questions.each((_, node) => {
    assert($(node).find(".long-form-secondary-detail__body").text().trim(), `${page.route}: răspuns FAQ absent din HTML`);
    assert.equal($(node).find("a[data-source-key]").length > 0, true, `${page.route}: răspuns FAQ fără sursă`);
  });

  const toc = $("[data-program-template-toc]");
  assert.equal(toc.length, report.pages.find((item) => item.route === page.route).editorialWordCount > 1500 ? 1 : 0, `${page.route}: regula cuprinsului nu este respectată`);
  toc.find("a[href^='#']").each((_, link) => assert.equal($($(link).attr("href")).length, 1, `${page.route}: ancoră de cuprins invalidă`));

  const cta = $(".program-template__cta a");
  assert.equal(cta.text().trim(), page.cta.label);
  const ctaUrl = new URL(cta.attr("href"), "https://atelierdeconsultanta.ro");
  assert.equal(ctaUrl.pathname, "/contact");
  assert.equal(ctaUrl.searchParams.get("program"), program.slug);
  assert.equal(ctaUrl.searchParams.get("investment"), page.cta.investmentPrefill);
  assert.equal(ctaUrl.searchParams.get("source_channel"), "program_page");

  for (const field of FORBIDDEN_LOCAL_FACTS) assert.equal(Object.prototype.hasOwnProperty.call(page, field), false, `${page.route}: ${field} nu poate fi local`);
  for (const key of page.sourceKeys) {
    assert(/^https:\/\//u.test(guides[key].url), `${page.route}: ${key} nu are URL HTTPS`);
    assert(guides[key].institution, `${page.route}: ${key} nu are instituție`);
  }
  assert.equal($("#program-sources .editorial-governance").length, 1, `${page.route}: guvernanța editorială trebuie integrată în secțiunea de surse`);
  assert.equal($("#program-sources .editorial-governance__changelog").length, 1, `${page.route}: changelog-ul vizibil lipsește`);

  const nodes = jsonLdNodes($);
  const article = nodes.find((node) => hasType(node, "Article"));
  assert(article, `${page.route}: Article lipsește deși conținutul vizibil este editorial`);
  assert.equal(article.headline, $(".program-hero h1").text().trim(), `${page.route}: Article nu corespunde H1-ului vizibil`);
  assert.equal(article.description, direct.text().trim(), `${page.route}: Article nu corespunde răspunsului vizibil`);
  assert.equal(article.dateModified, program.lastMeaningfulUpdate, `${page.route}: dateModified nu vine din lastMeaningfulUpdate`);
  assert.equal(article.citation?.[0]?.url, program.sourceUrl, `${page.route}: citation nu indică sursa registrului`);

  const breadcrumb = nodes.find((node) => hasType(node, "BreadcrumbList"));
  assert(breadcrumb, `${page.route}: BreadcrumbList lipsește`);
  const visibleBreadcrumb = $("nav[aria-label='Breadcrumb']");
  assert.equal(visibleBreadcrumb.length, 1, `${page.route}: breadcrumb-ul vizibil trebuie să fie componenta standard`);
  const visibleItems = visibleBreadcrumb.find("li").map((_, node) => ({
    name: $(node).text().replace(/\s+/gu, " ").trim(),
    item: $(node).find("a").attr("href") || page.route
  })).get();
  assert.deepEqual(breadcrumb.itemListElement.map((item) => ({ name: item.name, item: absoluteUrl(item.item).replace("https://atelierdeconsultanta.ro", "") || "/" })), visibleItems.map((item) => ({ name: item.name, item: absoluteUrl(item.item).replace("https://atelierdeconsultanta.ro", "") || "/" })), `${page.route}: BreadcrumbList diferă de traseul vizibil`);
}

console.log(`Program page template contract PASS: ${config.pages.length} exemplu, ordine completă, registru unic, surse apropiate și CTA precompletat.`);
