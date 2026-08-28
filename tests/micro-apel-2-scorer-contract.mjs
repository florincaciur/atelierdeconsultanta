import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const cheerio = require("cheerio");
const scorer = require("../assets/micro-apel-2-scorer.js");

assert.equal(scorer.scoreCaen("6210").points, 6, "CAEN 6210 must receive 6 points");
assert.equal(scorer.scoreCaen("9999").rejection, true, "A code missing from Annex 5 must be eliminatory");
assert.equal(scorer.scoreContribution(20), 3, "The 2.3 formula must be applied exactly");
assert.deepEqual(scorer.scoreGrantTurnover(300000, 200000).points, 6, "The AFN/CA formula must be applied exactly");
assert.equal(scorer.scoreProfitability(30000, 500000).points, 7, "A 6% profitability rate must receive 7 points");
assert.equal(scorer.scoreSolvency(150000, 100000).points, 3.54, "The solvency formula must be rounded to two decimals");
assert.equal(scorer.scoreTurnoverGrowth(100000, 120000, 150000), 6, "Growth in both fiscal years must receive 6 points");
assert.equal(scorer.scoreAge("2025-01-04").rejection, true, "Companies founded after 03.01.2025 must be rejected");
assert.equal(scorer.scoreEmployees(0).rejection, true, "A company without employees must be rejected");

const perfect = scorer.calculate({
  caen: "2110",
  newJobs: "3",
  headquartersCounty: "bt",
  implementationCounty: "vs",
  ownContribution: "30",
  grant: "100000",
  turnover2023: "250000",
  turnover2024: "300000",
  turnover2025: "350000",
  netProfit2025: "25000",
  assets2025: "500000",
  debts2025: "200000",
  establishedAt: "2020-01-01",
  employees2025: "7",
  disadvantagedHire: "yes",
  microenterprise: "yes",
  activityHistory: "yes",
  fixedAssets: "yes",
  deMinimis: "yes",
  siteRights: "yes",
  annexes: "yes",
  cashFlow: "yes"
});

assert.equal(perfect.objectivePoints, 75, "Determinable criteria must total 75 points");
assert.equal(perfect.qualitativeEstimate, 25, "ADR pre-assessment must add 25 provisional points");
assert.equal(perfect.estimatedTotal, 100, "A maximum pre-assessment must total 100 points");
assert.equal(perfect.rejections.length, 0, "A fully compliant scenario must not trigger a rejection warning");

const pageHtml = fs.readFileSync(new URL("../investitii-modernizarea-microintreprinderilor-apel-2/index.html", import.meta.url), "utf8");
const $ = cheerio.load(pageHtml);
const title = $("head > title").first().text().trim();
const directAnswer = $("[data-aeo-primary-answer], [data-answer-readiness-direct]").first().text().trim();
const directAnswerWords = directAnswer.split(/\s+/u).filter(Boolean).length;

assert.ok(title.length >= 45 && title.length <= 60, "The SEO title must stay inside the recommended length interval");
assert.equal($(".faq-item").length, 8, "The AEO FAQ block must contain eight focused questions");
assert.ok(directAnswerWords >= 30 && directAnswerWords <= 80, "The direct answer must remain concise and answer-engine friendly");
assert.equal($("[data-micro-apel-2-form]").length, 1, "The scoring simulator form must be present");
assert.equal($("script[src^='/assets/micro-apel-2-scorer.js']").length, 1, "The scoring engine must be loaded");
assert.equal($("link[href^='/assets/micro-apel-2.css']").length, 1, "The simulator stylesheet must be loaded");
assert.ok(pageHtml.includes("https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/"), "The official call page must be cited");
assert.ok(pageHtml.includes("Ghid-microintreprinderi-27.08.2026.zip"), "The final official guide archive must be cited");
assert.doesNotMatch(pageHtml, /generat(?:ă)? de AI|AI-generated|watermark/iu, "The page must not include AI or watermark labeling");

console.log("PASS micro-apel-2 scorer contract");
