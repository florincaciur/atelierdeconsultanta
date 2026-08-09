import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import * as cheerio from "cheerio";

const ROOT = path.resolve(import.meta.dirname, "..");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "calculator-so-methodology.json"), "utf8"));
const governance = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "editorial-governance.json"), "utf8")).records;
const html = fs.readFileSync(path.join(ROOT, config.file), "utf8");
const client = fs.readFileSync(path.join(ROOT, "assets", "calculator-so-methodology.js"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "assets", "calculator-so-methodology.css"), "utf8");
const $ = cheerio.load(html, { decodeEntities: false });
const DISCLAIMER = "Rezultatul calculatorului este orientativ și nu înlocuiește ghidul sau verificarea documentelor.";

function nodes() {
  return $("script[type='application/ld+json']").map((_, script) => JSON.parse($(script).html())).get()
    .flatMap((value) => Array.isArray(value?.["@graph"]) ? value["@graph"] : [value]);
}

function hasType(node, type) {
  return (Array.isArray(node?.["@type"]) ? node["@type"] : [node?.["@type"]]).includes(type);
}

const coefficientEntries = config.coefficientGroups.flatMap((group) => group.entries);
const byCode = new Map(coefficientEntries.map((entry) => [entry.code, entry]));
assert.equal(coefficientEntries.length, 46, "setul publicat trebuie să conțină cele 46 de categorii selectate");
assert.equal(byCode.size, coefficientEntries.length, "codurile SOC trebuie să fie unice");
assert.match(config.source.pageUrl, /^https:\/\/www\.afir\.ro\//u);
assert.match(config.source.documentUrl, /^https:\/\/www\.afir\.ro\//u);
assert.match(config.source.version, /SOC 2020/u);
assert.match(config.source.documentSha256, /^[A-F0-9]{64}$/u);

for (const example of config.examples) {
  const exact = example.items.reduce((total, item) => total + byCode.get(item.code).coefficient * item.quantity, 0);
  assert(Math.abs(exact - example.exactTotal) < 0.000001, `${example.title}: totalul exact trebuie să urmeze formula`);
  assert.equal(Math.round(exact), example.displayTotal, `${example.title}: totalul afișat trebuie să urmeze Math.round`);
}

assert.equal($("[data-so-methodology]").length, 1, "metodologia trebuie să existe o singură dată");
assert.equal($("[data-so-example]").length, 3, "sunt necesare trei exemple pas cu pas");
assert.equal($("#calculator-errors[role='alert']").length, 1, "validarea are regiune de erori accesibilă");
assert.equal($("[data-copy-so-result]").length, 1, "lipsește copierea rezultatului");
assert.equal($("[data-print-so-result]").length, 1, "lipsește tipărirea rezultatului");
assert.equal($("#so-result-explanation").length, 1, "lipsește explicația rezultatului");
assert.equal($("#so-program-suggestion").length, 1, "lipsește sugestia prudentă de program");
assert.equal($("main").children().eq(1).attr("id"), "calculator", "calculatorul trebuie să urmeze imediat după banner");
assert.equal($(".so-page-disclosure").length, 4, "fragmentele metodologice lungi trebuie restrânse în disclosure-uri native");
assert.equal($("script[src^='/assets/calculator-so-methodology.js']").length, 1, "scriptul funcțional P1.20 trebuie încărcat exact o dată");
assert($("[data-so-methodology]").text().includes("Formula de înmulțire și însumare existentă nu a fost schimbată"));
assert($(".calc-result").text().includes(DISCLAIMER), "disclaimerul contractual trebuie să fie lângă rezultat");
assert($("[data-so-methodology] a").filter((_, link) => $(link).attr("href") === config.source.pageUrl).length, "pagina AFIR trebuie citată vizibil");
assert($("#calculator-input-help a").filter((_, link) => $(link).attr("href") === config.source.documentUrl).length, "documentul AFIR trebuie legat lângă inputuri");

assert(!html.includes("Tabel Complet SO 2023-2027"), "tabelul legacy fără proveniență trebuie eliminat");
assert(!html.includes("Clasificare Fermă pe Bază SO"), "clasificarea automată legacy trebuie eliminată");
assert(!/DR14 Ferme Mici|DR12 Tineri Fermieri|Sub pragul minim/u.test($("#calculator").text()), "rezultatul nu poate da verdict automat de program");
assert(!html.includes("DE_VALIDAT_UMAN"), "tokenul intern nu poate fi publicat");

const calculatorScript = $("script:not([src])").map((_, script) => $(script).html()).get().find((value) => value.includes("const soDatabase"));
assert(calculatorScript, "scriptul calculatorului lipsește");
assert(calculatorScript.includes("const rowTotal = so * area;"), "formula de înmulțire a fost modificată");
assert(calculatorScript.includes("totalSo += rowTotal;"), "formula de însumare a fost modificată");
assert(calculatorScript.includes("const roundedTotal = Math.round(totalSo);"), "regula de rotunjire trebuie să fie explicită");
assert(calculatorScript.includes("so < 2000") && calculatorScript.includes("so < 12000"), "orientarea prudentă DR 14/DR 12 trebuie să folosească reperele explicite");
assert(calculatorScript.includes("!hasTrackedCalculation"), "evenimentul calculatorului trebuie deduplicat");
const embeddedDataMatch = calculatorScript.match(/const soDatabase = ([\s\S]*?);\n\s*let hasTrackedCalculation/u);
assert(embeddedDataMatch, "setul de coeficienți nu poate fi extras din implementare");
const embeddedData = JSON.parse(embeddedDataMatch[1]);
for (const group of config.coefficientGroups) {
  for (const entry of group.entries) {
    const implemented = embeddedData[group.id][entry.name];
    assert(implemented, `${entry.code}: categoria lipsește din implementare`);
    assert.equal(implemented.code, entry.code);
    assert.equal(implemented.coefficient, entry.coefficient);
    assert.equal(implemented.unit, entry.unit);
  }
}

assert(client.includes("MAX_TECHNICAL_QUANTITY = 1000000"), "limita tehnică trebuie declarată");
assert(client.includes("navigator.clipboard.writeText"), "copierea trebuie implementată");
assert(client.includes("window.print()"), "tipărirea trebuie implementată");
assert(!/\b(?:email|telefon|phone|nume)\b|name=/iu.test(client), "rezumatul calculatorului nu trebuie să prelucreze PII");
assert(css.includes("@media print"), "lipsește stilul de tipărire");
assert(css.includes("prefers-reduced-motion"), "interacțiunile trebuie să respecte reducerea mișcării");
assert.match(css, /\.so-source-list li\s*\{[\s\S]*?overflow-wrap:\s*anywhere/u, "hash-ul sursei nu trebuie să creeze overflow mobil");

const resultCta = $("[data-calculator-context-cta]");
assert.equal(resultCta.text().trim(), "Folosește rezultatul pentru verificarea AFIR");
const resultUrl = new URL(resultCta.attr("href"), "https://atelierdeconsultanta.ro");
const resultContext = new URLSearchParams(resultUrl.hash.slice(1));
assert.equal(resultUrl.pathname, "/contact");
assert.equal(resultUrl.search, "");
assert.equal(resultContext.get("source_page"), "/calculator-soc");
for (const forbidden of ["email", "phone", "telefon", "name", "description"]) assert(!resultContext.has(forbidden));

const record = governance.find((entry) => entry.id === "calculator-soc");
assert(record, "înregistrarea editorială lipsește");
assert.equal(record.governanceState, "public");
assert.equal(record.verifiedAt, config.reviewedAt);
assert.equal(record.lastMeaningfulUpdate, config.reviewedAt);
assert.equal(record.officialSourceUrl, config.source.pageUrl);
assert.equal(record.sourceVersion, config.source.version);
assert.equal(record.personalNameConsent, false);
assert($(".editorial-governance[data-editorial-record='calculator-soc']").text().includes(record.reviewer), "reviewerul organizațional trebuie să fie vizibil");

const webApps = nodes().filter((node) => hasType(node, "WebApplication"));
assert.equal(webApps.length, 1, "Calculatorul trebuie să aibă exact un WebApplication");
assert.equal(webApps[0].url, "https://atelierdeconsultanta.ro/calculator-soc");
assert.equal(webApps[0].name, $("h1").first().text().trim());
assert(Array.isArray(webApps[0].citation) && webApps[0].citation.some((citation) => citation.url === config.source.pageUrl), "WebApplication trebuie să citeze sursa oficială sincronizată");
assert(!webApps[0].offers && !webApps[0].aggregateRating && !webApps[0].review, "schema nu poate conține afirmații neverificabile");

for (const link of $("[data-so-methodology] a[href^='http']").toArray()) {
  const host = new URL($(link).attr("href")).hostname;
  assert(["www.afir.ro", "so.afir.info", "ec.europa.eu"].includes(host), `sursă externă neaprobată: ${host}`);
}

console.log(`P1.20 contract PASS: ${coefficientEntries.length} coeficienți, ${config.examples.length} exemple, formulă păstrată și WebApplication sincronizat.`);
