#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { auditEditorialCopy } = require("../tools/editorial-copy-governance");
const { collectSiteState } = require("../tools/generate-sitemap");
const { normalizeJsonLdScripts } = require("../tools/normalize-copy-ro");
const { fileForRoute, sitemapRoutes } = require("../tools/structured-data-utils");
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const crlfJsonLd = '<script type="application/ld+json">{\r\n  "@context": "https://schema.org",\r\n  "@type": "WebPage",\r\n  "name": "Pagină verificată"\r\n}</script>';
assert.equal(
  normalizeJsonLdScripts(crlfJsonLd).changed,
  false,
  "CRLF formatting alone must not trigger a JSON-LD editorial change"
);

const audit = auditEditorialCopy();
assert.equal(audit.canonicalCount, collectSiteState().entries.length, "editorial gate must inspect every canonical sitemap URL");
assert.deepEqual(audit.pageIssues, [], `public copy issues:\n${audit.pageIssues.map((issue) => `${issue.route}: ${issue.oldFragment}`).join("\n")}`);
assert.deepEqual(audit.sourceIssues, [], `CMS/source copy issues:\n${audit.sourceIssues.map((issue) => `${issue.sourceFile}:${issue.location}: ${issue.oldFragment}`).join("\n")}`);
assert.deepEqual(audit.generatorIssues, [], `generator template issues:\n${audit.generatorIssues.map((issue) => `${issue.sourceFile}: ${issue.type}`).join("\n")}`);

const forbiddenProgramGrammar = [
  ["pronumele «aceasta» scris ca adjectiv", /\b[Aa]ceastă\s+(?:este|rămâne|se|să|nu|previne|tratează|grupează)(?=\s|[?!.,;:]|$)/u],
  ["formă personală folosită în locul infinitivului după verb modal", /\b(?:Pot|pot|Poți|poți|Poate|poate|Putem|putem|Puteți|puteți|Vor|vor|Va|va|Ar|ar) (?:adaugă|aplică|arată|ajută|compară|completă|confirmă|continuă|corectă|evită|există|explică|identifică|indică|insistă|justifică|lăsă|merită|publică|separă|schimbă|solicită|verifică)(?=\s|[?!.,;:]|$)/u],
  ["formă personală folosită după marca infinitivului", /\b(?:Pentru|pentru|Fără|fără|De|de|Înainte de|înainte de) a (?:adaugă|aplică|arată|ajută|compară|completă|confirmă|continuă|corectă|evită|există|explică|identifică|indică|insistă|justifică|lăsă|merită|publică|separă|schimbă|solicită|verifică)(?=\s|[?!.,;:]|$)/u],
  ["substantivul definit «adresa sediului»", /\b[Aa]dresă sediului(?=\s|[?!.,;:]|$)/u],
  ["substantivul definit «pagina» înaintea predicatului", /(?<![Aa]ceastă )(?<![Oo] )(?<![Ff]iecare )\b[Pp]agină\s+(?:această|evită|răspunde|ajută|este|include|oferă|trimite|insistă|rămâne|explică|centralizează|nu|tratează|grupează)(?=\s|[?!.,;:]|$)/u],
  ["substantiv feminin nearticulat după «această»", /\b[Aa]ceastă\s+(?:pagina|legătura|limita|structura|regula)(?=\s|[?!.,;:]|$)/u],
  ["substantivul definit «consultanța» înaintea predicatului", /(?<![Dd]e )\b[Cc]onsultanță\s+(?:poate|este|rămâne|include|oferă)(?=\s|[?!.,;:]|$)/u]
];

for (const route of sitemapRoutes(ROOT, "sitemap-programs.xml")) {
  const file = fileForRoute(ROOT, route);
  const source = fs.readFileSync(file, "utf8");
  for (const [label, pattern] of forbiddenProgramGrammar) {
    const match = source.match(pattern);
    assert.equal(match, null, `${route}: ${label}: ${match?.[0] || ""}`);
  }
}

console.log(`Editorial copy contract passed: ${audit.canonicalCount} canonical URLs, zero forbidden template labels or control-list forms.`);
