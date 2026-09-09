import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { auditFaqs, inspectFaqHtml } = require("../tools/audit-faq-governance");
const { synchronizeFaqHtml } = require("../tools/faq-governance");

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fixture(schemaAnswers = ["Răspuns unu.", "Răspuns doi."], includeVisible = true) {
  const visible = includeVisible ? `<main>
    <details class="faq-item"><summary>Prima întrebare?</summary><p>Răspuns unu.</p></details>
    <details class="faq-item"><summary>A doua întrebare?</summary><p>Răspuns doi.</p></details>
  </main>` : "<main><p>Fără FAQ.</p></main>";
  const schema = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: [
      { "@type": "Question", name: "Prima întrebare?", acceptedAnswer: { "@type": "Answer", text: schemaAnswers[0] } },
      { "@type": "Question", name: "A doua întrebare?", acceptedAnswer: { "@type": "Answer", text: schemaAnswers[1] } }
    ]
  };
  return `<!doctype html><html><head><script type="application/ld+json">${JSON.stringify(schema)}</script></head><body>${visible}</body></html>`;
}

const exact = inspectFaqHtml(fixture(), "/test");
assert.deepEqual(exact.issues, [], "fixture-ul exact trebuie să treacă");

const divergent = inspectFaqHtml(fixture(["Răspuns schimbat.", "Răspuns doi."]), "/test");
assert(divergent.issues.some((issue) => issue.includes("răspunsul 1 diferă")), "contractul trebuie să detecteze răspunsul divergent");

const synchronized = synchronizeFaqHtml(fixture(["Răspuns schimbat.", "Răspuns doi."])).html;
assert.deepEqual(inspectFaqHtml(synchronized, "/test").issues, [], "sincronizarea trebuie să derive FAQPage exact din HTML");
assert.equal(JSON.parse(synchronized.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/u)[1])["@context"], "https://schema.org", "sincronizarea trebuie să păstreze contextul JSON-LD standalone");

const schemaOnly = inspectFaqHtml(fixture(undefined, false), "/test");
assert(schemaOnly.issues.some((issue) => issue.includes("fără minimum două întrebări")), "contractul trebuie să respingă FAQPage fără FAQ vizibil");

const staleProgram = {
  status: "apel_inchis",
  canonicalStatus: "CLOSED",
  applicationEnd: "2026-05-29"
};
const staleHtml = fixture().replaceAll("Prima întrebare?", "Este apelul deschis?").replaceAll("Răspuns unu.", "Da. Depunerea este deschisă.");
const stale = inspectFaqHtml(staleHtml, "/test", staleProgram);
assert(stale.issues.some((issue) => issue.includes("contrazice statutul")), "contractul trebuie să detecteze statutul FAQ expirat");

const report = auditFaqs(ROOT);
assert.equal(report.summary.routeCount, 105, "auditul FAQ trebuie să acopere inventarul stabil de 105 rute");
assert.equal(report.summary.fail, 0, `auditul FAQ local are rute neconforme: ${report.results.filter((result) => result.status === "FAIL").map((result) => result.route).join(", ")}`);
assert.equal(report.summary.visibleQuestionCount, report.summary.schemaQuestionCount, "numărul total de întrebări vizibile și schema trebuie să fie egal");
assert.equal(report.summary.legalRoutesWithFaqPage, 0, "paginile juridice nu trebuie să primească FAQPage automat");
assert.equal(report.summary.repeatedAnswerGroupCount, 0, "același răspuns FAQ generic nu trebuie repetat pe cel puțin cinci rute");

console.log(`Contract Task 15 PASS: ${report.summary.routeCount} rute, ${report.summary.sourceCount} surse și paritate exactă pentru ${report.summary.visibleQuestionCount} întrebări FAQ.`);
