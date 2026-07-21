#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  HUMAN_REVIEW,
  ROOT,
  isPublicProgram,
  loadProgramConfig,
  programForRoute
} = require("../tools/program-factual-governance");
const { CONFIG_PATH, addDays, isIsoDate } = require("../tools/editorial-governance");

const GUIDES_PATH = path.join(ROOT, "official-guides.json");
const TODAY = new Date().toISOString().slice(0, 10);
const AUTHOR = "FABER – Atelier de Consultanță";
const AUTHOR_ROLE = "Autor organizațional";
const REVIEWER = "Echipa editorială FABER";
const REVIEWER_ROLE = "Revizuire editorială și conformitate";

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function routeFromSlug(slug) {
  return `/${String(slug || "").replace(/^\/+|\/+$/gu, "")}`;
}

function idFromRoute(route) {
  return route.replace(/^\//u, "").replace(/\//gu, "-") || "homepage";
}

function guideForPage(page, guides) {
  for (const key of page?.sourceKeys || []) {
    const guide = guides[key];
    if (guide && typeof guide === "object") return guide;
  }
  return null;
}

function normalizedGuideSource(guide) {
  if (!guide) {
    return {
      verifiedAt: HUMAN_REVIEW,
      officialSourceName: HUMAN_REVIEW,
      officialSourceUrl: HUMAN_REVIEW,
      sourceVersion: HUMAN_REVIEW
    };
  }
  return {
    verifiedAt: isIsoDate(guide.verifiedAt || guide.accessedAt) ? (guide.verifiedAt || guide.accessedAt) : HUMAN_REVIEW,
    officialSourceName: String(guide.institution || guide.sourceName || HUMAN_REVIEW),
    officialSourceUrl: /^https?:\/\//iu.test(String(guide.url || "")) ? guide.url : HUMAN_REVIEW,
    sourceVersion: String(guide.name || guide.title || HUMAN_REVIEW)
  };
}

function programSource(program) {
  return {
    verifiedAt: program.verifiedAt,
    officialSourceName: program.sourceName,
    officialSourceUrl: program.sourceUrl,
    sourceVersion: program.sourceVersion
  };
}

function ensureMeaningfulHistory(record) {
  if (record.governanceState !== "public" || !isIsoDate(record.lastMeaningfulUpdate)) return record;
  const changelog = Array.isArray(record.changelog) ? record.changelog : [];
  if (changelog.some((change) => change?.meaningful === true && change.date === record.lastMeaningfulUpdate)) return record;
  return {
    ...record,
    changelog: [{
      date: record.lastMeaningfulUpdate,
      summary: "Snapshot factual substanțial preluat din registrul unic al programului; istoricul anterior migrării nu a fost rescris.",
      reviewer: record.reviewer,
      meaningful: true
    }, ...changelog]
  };
}

function programRecord(route, program, page, policy) {
  const source = programSource(program);
  const complete = isPublicProgram(program)
    && isIsoDate(source.verifiedAt)
    && /^https?:\/\//iu.test(source.officialSourceUrl)
    && isIsoDate(program.lastMeaningfulUpdate);
  const interval = program.status === "apel_deschis" ? policy.openCallReviewDays : policy.programReviewDays;
  return {
    id: idFromRoute(route),
    route,
    contentType: "program",
    programId: program.slug,
    governanceState: complete ? "public" : "pending_validation",
    author: AUTHOR,
    authorRole: AUTHOR_ROLE,
    reviewer: REVIEWER,
    reviewerRole: REVIEWER_ROLE,
    attributionType: "organization",
    personalNameConsent: false,
    ...source,
    nextReviewAt: complete ? addDays(source.verifiedAt, interval) : HUMAN_REVIEW,
    lastMeaningfulUpdate: program.lastMeaningfulUpdate,
    statusSnapshot: program.status,
    changelog: [{
      date: program.lastMeaningfulUpdate,
      summary: "Snapshot factual substanțial preluat din registrul unic al programului; istoricul anterior migrării nu a fost rescris.",
      reviewer: REVIEWER,
      meaningful: true
    }, {
      date: TODAY,
      summary: "Migrare tehnică în registrul de guvernanță; data modificării editoriale substanțiale a rămas neschimbată.",
      reviewer: REVIEWER,
      meaningful: false
    }]
  };
}

function supportingRecord(route, contentType, page, guides, policy) {
  const source = normalizedGuideSource(guideForPage(page, guides));
  return {
    id: idFromRoute(route),
    route,
    contentType,
    programId: null,
    governanceState: "pending_validation",
    author: AUTHOR,
    authorRole: AUTHOR_ROLE,
    reviewer: REVIEWER,
    reviewerRole: REVIEWER_ROLE,
    attributionType: "organization",
    personalNameConsent: false,
    ...source,
    nextReviewAt: isIsoDate(source.verifiedAt) ? addDays(source.verifiedAt, policy.evergreenReviewDays) : HUMAN_REVIEW,
    lastMeaningfulUpdate: HUMAN_REVIEW,
    statusSnapshot: null,
    changelog: [{
      date: TODAY,
      summary: "Înregistrare migrată; ultima modificare editorială substanțială necesită confirmare umană.",
      reviewer: REVIEWER,
      meaningful: false
    }]
  };
}

function migrate() {
  const { config: pageConfig, programs } = loadProgramConfig();
  const guides = fs.existsSync(GUIDES_PATH) ? readJson(GUIDES_PATH) : {};
  const previous = fs.existsSync(CONFIG_PATH) ? readJson(CONFIG_PATH) : null;
  const policy = previous?.policy || {
    openCallReviewDays: 30,
    programReviewDays: 60,
    evergreenReviewDays: 90,
    humanReviewToken: HUMAN_REVIEW
  };
  const previousByRoute = new Map((previous?.records || []).map((record) => [record.route, record]));
  const pageByRoute = new Map((pageConfig.pages || []).map((page) => [routeFromSlug(page.slug), page]));
  const candidateRoutes = new Map();

  for (const program of programs) candidateRoutes.set(program.pageUrl, { contentType: "program", page: pageByRoute.get(program.pageUrl) || null });
  for (const page of pageConfig.pages || []) {
    if (!["program", "resource", "tools"].includes(page.type)) continue;
    const route = routeFromSlug(page.slug);
    candidateRoutes.set(route, {
      contentType: page.type === "program" ? "program" : page.type === "tools" ? "tool" : "guide",
      page
    });
  }
  candidateRoutes.set("/calculator-soc", { contentType: "tool", page: null });

  const records = [...candidateRoutes.entries()].map(([route, candidate]) => {
    if (previousByRoute.has(route)) return ensureMeaningfulHistory(previousByRoute.get(route));
    const explicitProgram = candidate.page?.programId
      ? programs.find((program) => program.slug === candidate.page.programId)
      : null;
    const program = explicitProgram || programForRoute(route, programs);
    if (program) return programRecord(route, program, candidate.page, policy);
    return supportingRecord(route, candidate.contentType, candidate.page, guides, policy);
  }).sort((left, right) => left.route.localeCompare(right.route));

  const output = { schemaVersion: 1, policy, records };
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
  fs.writeFileSync(CONFIG_PATH, `${JSON.stringify(output, null, 2)}\n`, "utf8");
  console.log(`Migrare editorială: ${records.length} pagini (${records.filter((record) => record.governanceState === "public").length} publice, ${records.filter((record) => record.governanceState !== "public").length} în validare).`);
}

if (require.main === module) migrate();

module.exports = { migrate };
