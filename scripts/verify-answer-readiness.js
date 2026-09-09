#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  applicantSummaryText,
  applicationWindowText,
  contributionAnswerText,
  grantAnswerText,
  isPublicProgram,
  loadProgramConfig,
  statusStatement
} = require("../tools/program-factual-governance");
const { fileForRoute } = require("../tools/structured-data-utils");
const { surfaces } = require("../tools/sync-answer-first-surfaces");

const ROOT = path.resolve(__dirname, "..");
const { programs } = loadProgramConfig();
const publicProgramPages = programs.filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget);
const forbiddenBoilerplate = /în peisajul dinamic|în era digitală|ca model de limbaj|vizibilitate (?:AI|în AI)|garant(?:ăm|at).*clasare/iu;

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function wordCount(value) {
  return cleanText(value).split(/\s+/u).filter(Boolean).length;
}

function visible($, element) {
  const item = $(element);
  return !item.is("[hidden], [aria-hidden='true']")
    && !item.closest("[hidden], [aria-hidden='true'], details:not([open])").length
    && !/display\s*:\s*none|visibility\s*:\s*hidden/iu.test(item.attr("style") || "");
}

function inspectProgram(program) {
  const file = fileForRoute(ROOT, program.pageUrl);
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const summary = $("[data-aeo-program-summary]");
  assert.equal(summary.length, 1, `${program.pageUrl}: trebuie exact un rezumat semantic de program`);
  assert(visible($, summary.get(0)), `${program.pageUrl}: rezumatul semantic nu este vizibil`);
  assert.equal(summary.find("[data-aeo-primary-answer]").length, 1, `${program.pageUrl}: răspunsul direct trebuie să fie unic în rezumat`);
  assert(summary.find("[data-answer-field='status']").text().includes(statusStatement(program)), `${program.pageUrl}: statusul nu corespunde registrului`);

  const expected = {
    applicant: applicantSummaryText(program),
    grant: grantAnswerText(program),
    contribution: contributionAnswerText(program),
    deadline: applicationWindowText(program)
  };
  for (const [field, value] of Object.entries(expected)) {
    const node = summary.find(`[data-answer-field='${field}']`);
    assert.equal(node.length, 1, `${program.pageUrl}: câmpul ${field} lipsește sau este duplicat`);
    if (field !== "deadline" || (!program.applicationStart && !program.applicationEnd)) {
      assert(cleanText(node.text()).includes(cleanText(value)), `${program.pageUrl}: ${field} diferă de registru`);
    }
  }
  const deadline = summary.find("[data-answer-field='deadline']");
  for (const date of [program.applicationStart, program.applicationEnd].filter(Boolean)) {
    assert.equal(deadline.find(`time[datetime='${date}']`).length, 1, `${program.pageUrl}: data absolută ${date} lipsește din termen`);
  }
  const verified = summary.find("[data-answer-field='verifiedAt']");
  assert.equal(verified.length, 1, `${program.pageUrl}: verifiedAt lipsește sau este duplicat`);
  assert.equal(verified.find(`time[datetime='${program.verifiedAt}']`).length, 1, `${program.pageUrl}: verifiedAt diferă de registru`);
  assert(summary.find(`a[href='${program.sourceUrl}']`).length >= 1, `${program.pageUrl}: sursa oficială lipsește din rezumat`);
  assert.doesNotMatch(cleanText(summary.text()), forbiddenBoilerplate, `${program.pageUrl}: boilerplate interzis în rezumat`);
  if (!$("body").is("[data-program-template-version]")) {
    assert(!html.includes("<!-- ANSWER_READINESS_START -->"), `${program.pageUrl}: bloc answer-readiness redundant`);
  }
}

function inspectSurface(surface) {
  const file = fileForRoute(ROOT, surface.route);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  const lead = $(surface.selector).filter("[data-aeo-primary-answer]");
  assert.equal(lead.length, 1, `${surface.route}: lead-ul answer-first lipsește sau este duplicat`);
  assert(visible($, lead.get(0)), `${surface.route}: lead-ul answer-first nu este vizibil`);
  const words = wordCount(lead.text());
  assert(words >= 12 && words <= 90, `${surface.route}: lead-ul are ${words} cuvinte; intervalul acceptat este 12–90`);
  assert.doesNotMatch(cleanText(lead.text()), forbiddenBoilerplate, `${surface.route}: boilerplate interzis în lead`);
  const bodyElements = $("body *");
  assert(bodyElements.index(lead.first()) > bodyElements.index($("h1").first()), `${surface.route}: răspunsul direct trebuie să urmeze H1-ul`);
}

for (const program of publicProgramPages) inspectProgram(program);
for (const surface of surfaces) inspectSurface(surface);

console.log(`Answer-first contract PASS: ${publicProgramPages.length} programe și ${surfaces.length} suprafețe importante.`);
