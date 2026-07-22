import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import * as cheerio from "cheerio";

const ROOT = path.resolve(import.meta.dirname, "..");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "dr12-vs-dr14-expert.json"), "utf8"));
const registry = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8")).programs;
const governance = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "editorial-governance.json"), "utf8")).records;
const html = fs.readFileSync(path.join(ROOT, config.file), "utf8");
const $ = cheerio.load(html, { decodeEntities: false });

function countWords(value) {
  return String(value).match(/[\p{L}\p{N}]+(?:[’'-][\p{L}\p{N}]+)*/gu)?.length || 0;
}

function jsonLdNodes() {
  const blocks = $("script[type='application/ld+json']").map((_, node) => JSON.parse($(node).html())).get();
  return blocks.flatMap((value) => Array.isArray(value?.["@graph"]) ? value["@graph"] : [value]);
}

function hasType(node, type) {
  return (Array.isArray(node?.["@type"]) ? node["@type"] : [node?.["@type"]]).includes(type);
}

assert.equal($("link[rel='canonical']").attr("href"), "https://atelierdeconsultanta.ro/dr12-vs-dr14");
assert.equal($("title").text(), config.title);
assert.equal($("meta[name='description']").attr("content"), config.metaDescription);
assert.equal($("meta[property='og:title']").attr("content"), config.title);
assert.equal($("meta[property='og:description']").attr("content"), config.metaDescription);
assert(config.title.length >= 45 && config.title.length <= 65, "title-ul trebuie să rămână compact");
assert(config.metaDescription.length >= 120 && config.metaDescription.length <= 170, "meta description trebuie să fie utilă și compactă");

assert.equal($("h1").first().text().trim(), config.h1);
assert.equal($("h1").length, 1, "pagina trebuie să aibă un singur H1");
const directAnswer = $("[data-expert-direct-answer]").text().replace(/\s+/gu, " ").trim();
assert.equal(directAnswer, config.directAnswer);
assert(countWords(directAnswer) >= 60 && countWords(directAnswer) <= 80, `răspunsul direct are ${countWords(directAnswer)} cuvinte`);
assert($("[data-expert-direct-answer]").nextAll("[data-aeo-question-set]").first().length, "blocurile AEO trebuie să urmeze răspunsului direct");

const statusText = $(".expert-status-panel").text().replace(/\s+/gu, " ").trim();
assert(statusText.includes(config.statusStatement));
assert.match(statusText, /depunerea nu este deschisă/iu);
assert(!/\bActiv\b/u.test($("main, .post-container, .post-hero").text()), "un ghid consultativ nu poate fi numit Activ");

const rows = $("[data-expert-comparison-table] tbody tr");
assert.equal(rows.length, 10, "tabelul trebuie să aibă cele zece criterii contractuale");
assert.deepEqual(rows.map((_, row) => $(row).find("th").text().trim()).get(), config.comparisonRows.map((row) => row.label));
rows.each((_, row) => {
  const cells = $(row).find("td");
  assert.equal(cells.length, 2);
  cells.each((__, cell) => {
    assert($(cell).find(".expert-source-ref a").length === 1, "fiecare celulă comparativă trebuie să indice sursa");
    assert.equal($(cell).find(".expert-source-ref time").attr("datetime"), config.reviewedAt);
  });
});

const pageText = $(".post-container").text().replace(/\s+/gu, " ");
for (const forbidden of ["200.000", "80%", "65%", "50.000", "85%", "4.000 SO", "11.999 SO"]) {
  assert(!pageText.includes(forbidden), `valoare consultativă publicată fără reconfirmare: ${forbidden}`);
}
assert(!html.includes("DE_VALIDAT_UMAN"), "tokenul intern nu poate ajunge în pagina publică");
assert.match($("[data-comparison-row='Sprijin']").text(), /Nu publicăm/iu);
assert.match($("[data-comparison-row='Calendar']").text(), /Apel nedeschis/iu);

const scenarios = $("[data-hypothetical='true']");
assert.equal(scenarios.length, 3, "sunt necesare trei scenarii ipotetice");
scenarios.each((_, scenario) => {
  assert.match($(scenario).text(), /Ipoteză:/u);
  assert.match($(scenario).text(), /Orientare:/u);
});

for (const href of ["/dr12-afir", "/dr14", "/calculator-soc"]) {
  assert($(`.post-container a[href='${href}']`).length, `lipsește linkul canonic ${href}`);
}

const finalCta = $(".expert-final-cta a");
assert.equal(finalCta.text().trim(), "Compară proiectul tău cu criteriile DR 12 și DR 14");
assert.equal(finalCta.attr("href"), "/contact?source_page=%2Fdr12-vs-dr14");
assert.equal(finalCta.attr("data-analytics-event"), "cta_click");
assert.equal(finalCta.attr("data-analytics-target"), "/contact");
assert(!/[?&](?:email|phone|name|description)=/iu.test(finalCta.attr("href")), "CTA-ul nu poate expune PII în URL");

for (const programConfig of config.programs) {
  const program = registry.find((entry) => entry.slug === programConfig.slug);
  assert(program, `${programConfig.slug}: lipsește din registru`);
  assert.equal(program.status, "consultare_publica");
  assert.equal(program.verifiedAt, config.reviewedAt);
  assert.equal(program.sourceUrl, programConfig.sourceUrl);
  assert.equal(program.grantSummary, null);
  assert.equal(program.cofinancingSummary, null);
  const sourceCard = $(`#source-${programConfig.slug}`);
  assert.equal(sourceCard.length, 1);
  assert(sourceCard.find(`a[href='${programConfig.sourceUrl}']`).length, `${programConfig.slug}: URL-ul oficial nu este vizibil`);
}

const governanceRecord = governance.find((record) => record.route === config.route);
assert(governanceRecord, "înregistrarea de guvernanță lipsește");
assert.equal(governanceRecord.governanceState, "public");
assert.equal(governanceRecord.lastMeaningfulUpdate, config.reviewedAt);
assert.equal(governanceRecord.personalNameConsent, false);
const governanceSection = $(".editorial-governance[data-editorial-record='dr12-vs-dr14']");
assert.equal(governanceSection.length, 1, "autorul, reviewerul și changelog-ul trebuie să fie vizibile");
assert(governanceSection.text().includes(governanceRecord.author));
assert(governanceSection.text().includes(governanceRecord.reviewer));
assert.equal(governanceSection.find(".editorial-governance__changelog").length, 1);

assert.equal($("[data-long-form-toc]").length, 1, "pagina trebuie să aibă un singur cuprins dropdown");
assert.equal($("[data-long-form-toc] details[open]").length, 0, "cuprinsul pornește închis");
assert($("[data-long-form-toc-link]").length >= 6, "cuprinsul trebuie să acopere secțiunile decizionale");

const nodes = jsonLdNodes();
const article = nodes.find((node) => hasType(node, "Article"));
assert(article, "analiza reală trebuie descrisă ca Article");
assert.equal(article.headline, config.h1);
assert.equal(article.dateModified, config.reviewedAt);
assert(Array.isArray(article.citation) && article.citation.some((citation) => citation.url === governanceRecord.officialSourceUrl), "Article trebuie să citeze sursa oficială din guvernanță");
assert.equal(nodes.filter((node) => hasType(node, "FAQPage")).length, 0, "FAQPage nu trebuie generat automat pentru blocurile AEO");

assert.equal($("link[href^='/assets/dr12-vs-dr14-expert.css']").length, 1);
assert.equal($("[data-aeo-question-set]").length, 1);
assert(!/Pe scurt/iu.test($(".post-container h2, .post-container h3").text()), "eticheta generică de șablon nu trebuie publicată");

console.log(`P1.19 contract PASS: ${rows.length} criterii, ${scenarios.length} scenarii, ${countWords(directAnswer)} cuvinte în răspunsul direct și valori neconfirmate nepublicate.`);
