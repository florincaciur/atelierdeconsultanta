"use strict";

const fs = require("fs");
const path = require("path");
const {
  HUMAN_REVIEW,
  PROGRAM_STATUSES,
  ROOT,
  isOfficialUrl,
  isPublicProgram,
  loadProgramConfig,
  summaryHasValues
} = require("./program-factual-governance");

const CONFIG_PATH = path.join(ROOT, "config", "editorial-governance.json");
const CONTENT_TYPES = Object.freeze(["program", "guide", "tool"]);
const GOVERNANCE_STATES = Object.freeze(["public", "pending_validation", "revoked"]);
const REQUIRED_RECORD_FIELDS = Object.freeze([
  "id",
  "route",
  "contentType",
  "programId",
  "governanceState",
  "author",
  "authorRole",
  "reviewer",
  "reviewerRole",
  "attributionType",
  "personalNameConsent",
  "verifiedAt",
  "officialSourceName",
  "officialSourceUrl",
  "sourceVersion",
  "nextReviewAt",
  "lastMeaningfulUpdate",
  "statusSnapshot",
  "changelog"
]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function normalizeRoute(value) {
  const route = String(value || "/").trim().replace(/^https?:\/\/[^/]+/iu, "");
  if (route === "/") return route;
  return `/${route.replace(/^\/+|\/+$/gu, "")}`;
}

function isIsoDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/u.test(String(value || ""))
    && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

function isPending(value) {
  return String(value || "").trim() === HUMAN_REVIEW;
}

function addDays(date, days) {
  if (!isIsoDate(date)) return HUMAN_REVIEW;
  const result = new Date(`${date}T00:00:00Z`);
  result.setUTCDate(result.getUTCDate() + Number(days || 0));
  return result.toISOString().slice(0, 10);
}

function daysBetween(start, end) {
  if (!isIsoDate(start) || !isIsoDate(end)) return null;
  return Math.round((Date.parse(`${end}T00:00:00Z`) - Date.parse(`${start}T00:00:00Z`)) / 86400000);
}

function isMissing(value) {
  return !String(value ?? "").trim() || isPending(value);
}

function sourceMissing(record) {
  return isMissing(record?.officialSourceName)
    || isMissing(record?.officialSourceUrl)
    || !isOfficialUrl(record?.officialSourceUrl)
    || isMissing(record?.sourceVersion)
    || !isIsoDate(record?.verifiedAt);
}

function reviewerMissing(record) {
  return isMissing(record?.reviewer) || isMissing(record?.reviewerRole);
}

function authorMissing(record) {
  return isMissing(record?.author) || isMissing(record?.authorRole);
}

function reviewExpired(record, today = new Date().toISOString().slice(0, 10)) {
  return isIsoDate(record?.nextReviewAt) && record.nextReviewAt < today;
}

function reviewIntervalDays(record, program, policy) {
  if (program?.status === "apel_deschis") return policy.openCallReviewDays;
  if (record?.contentType === "program") return policy.programReviewDays;
  return policy.evergreenReviewDays;
}

function programContradictions(record, program) {
  if (!program) return [];
  const comparisons = [
    ["verifiedAt", record.verifiedAt, program.verifiedAt],
    ["officialSourceName/sourceName", record.officialSourceName, program.sourceName],
    ["officialSourceUrl/sourceUrl", record.officialSourceUrl, program.sourceUrl],
    ["sourceVersion", record.sourceVersion, program.sourceVersion],
    ["lastMeaningfulUpdate", record.lastMeaningfulUpdate, program.lastMeaningfulUpdate],
    ["statusSnapshot/status", record.statusSnapshot, program.status]
  ];
  return comparisons
    .filter(([, editorial, factual]) => editorial !== factual)
    .map(([field, editorial, factual]) => `${field}: editorial=${editorial ?? "null"}, program=${factual ?? "null"}`);
}

function recordIssues(record, program, today = new Date().toISOString().slice(0, 10)) {
  const issues = [];
  if (sourceMissing(record)) issues.push("missing_source");
  if (reviewExpired(record, today)) issues.push("expired_review");
  if (reviewerMissing(record)) issues.push("missing_reviewer");
  if (programContradictions(record, program).length) issues.push("program_page_contradiction");
  if (!Array.isArray(record?.changelog) || !record.changelog.length) issues.push("missing_changelog");
  return issues;
}

function isCompleteRecord(record) {
  return record?.governanceState === "public"
    && !sourceMissing(record)
    && !reviewerMissing(record)
    && !authorMissing(record)
    && isIsoDate(record?.nextReviewAt)
    && isIsoDate(record?.lastMeaningfulUpdate)
    && Array.isArray(record?.changelog)
    && record.changelog.length > 0;
}

function validateRecord(record, index, context) {
  const errors = [];
  const where = `records[${index}]`;
  if (!record || typeof record !== "object" || Array.isArray(record)) return [`${where}: înregistrare invalidă`];
  for (const field of REQUIRED_RECORD_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(record, field)) errors.push(`${where}: lipsește ${field}`);
  }
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(String(record.id || ""))) errors.push(`${where}: id invalid`);
  if (normalizeRoute(record.route) !== record.route) errors.push(`${where}: rută necanonică (${record.route})`);
  if (!CONTENT_TYPES.includes(record.contentType)) errors.push(`${where}: contentType invalid (${record.contentType})`);
  if (!GOVERNANCE_STATES.includes(record.governanceState)) errors.push(`${where}: governanceState invalid (${record.governanceState})`);
  if (!["organization", "person"].includes(record.attributionType)) errors.push(`${where}: attributionType invalid (${record.attributionType})`);
  if (typeof record.personalNameConsent !== "boolean") errors.push(`${where}: personalNameConsent trebuie să fie boolean`);
  if (record.programId !== null && !context.programById.has(record.programId)) errors.push(`${where}: programId inexistent (${record.programId})`);
  for (const field of ["verifiedAt", "nextReviewAt", "lastMeaningfulUpdate"]) {
    if (!isIsoDate(record[field]) && !isPending(record[field])) errors.push(`${where}: ${field} trebuie să fie dată ISO sau ${HUMAN_REVIEW}`);
  }
  if (!Array.isArray(record.changelog)) errors.push(`${where}: changelog trebuie să fie listă`);
  for (const [changeIndex, change] of (record.changelog || []).entries()) {
    if (!isIsoDate(change?.date)) errors.push(`${where}.changelog[${changeIndex}]: date invalid`);
    if (!String(change?.summary || "").trim()) errors.push(`${where}.changelog[${changeIndex}]: summary lipsește`);
    if (!String(change?.reviewer || "").trim()) errors.push(`${where}.changelog[${changeIndex}]: reviewer lipsește`);
  }
  if (record.attributionType === "person" && record.personalNameConsent !== true && record.governanceState === "public") {
    errors.push(`${where}: un nume personal nu poate fi publicat fără personalNameConsent=true`);
  }

  const program = record.programId ? context.programById.get(record.programId) : null;
  if (record.governanceState === "public") {
    if (!isCompleteRecord(record)) errors.push(`${where}: o înregistrare publică necesită autor, reviewer, sursă, verificare, nextReviewAt, lastMeaningfulUpdate și changelog`);
    const meaningfulDates = (record.changelog || [])
      .filter((change) => change?.meaningful === true && isIsoDate(change.date))
      .map((change) => change.date)
      .sort();
    if (meaningfulDates.at(-1) !== record.lastMeaningfulUpdate) {
      errors.push(`${where}: lastMeaningfulUpdate trebuie să coincidă cu cea mai recentă intrare substanțială din changelog`);
    }
    if (program && !isPublicProgram(program)) errors.push(`${where}: pagina editorială este publică, dar programul este pending_validation`);
    if (program && programContradictions(record, program).length) errors.push(`${where}: contradicție între program și pagină (${programContradictions(record, program).join("; ")})`);
    if (program && (summaryHasValues(program.grantSummary) || summaryHasValues(program.cofinancingSummary) || PROGRAM_STATUSES.includes(program.status)) && sourceMissing(record)) {
      errors.push(`${where}: programul cu status/valori nu poate fi publicat fără sursă și verificare editorială`);
    }
  }
  if (record.governanceState !== "public" && record.contentType === "program" && program && isPublicProgram(program)) {
    errors.push(`${where}: programul public nu poate avea guvernanța editorială nevalidată`);
  }
  if (isIsoDate(record.verifiedAt) && isIsoDate(record.nextReviewAt)) {
    const interval = daysBetween(record.verifiedAt, record.nextReviewAt);
    const maximum = reviewIntervalDays(record, program, context.policy);
    if (interval <= 0 || interval > maximum) errors.push(`${where}: nextReviewAt depășește intervalul permis de ${maximum} zile`);
  }
  if (reviewExpired(record, context.today) && program && record.statusSnapshot !== program.status) {
    errors.push(`${where}: statusul programului a fost schimbat după expirarea revizuirii; revizuirea trebuie reînnoită înaintea schimbării`);
  }
  return errors;
}

function validateGovernance(config, programs, today = new Date().toISOString().slice(0, 10)) {
  const errors = [];
  if (config?.schemaVersion !== 1) errors.push("schemaVersion trebuie să fie 1");
  const policy = config?.policy || {};
  if (policy.openCallReviewDays !== 30) errors.push("openCallReviewDays trebuie să fie 30");
  if (!Number.isInteger(policy.programReviewDays) || policy.programReviewDays < 30 || policy.programReviewDays > 60) errors.push("programReviewDays trebuie să fie între 30 și 60");
  if (!Number.isInteger(policy.evergreenReviewDays) || policy.evergreenReviewDays < 60 || policy.evergreenReviewDays > 90) errors.push("evergreenReviewDays trebuie să fie între 60 și 90");
  const records = Array.isArray(config?.records) ? config.records : [];
  const programById = new Map(programs.map((program) => [program.slug, program]));
  const context = { policy, programById, today };
  const ids = new Set();
  const routes = new Set();
  records.forEach((record, index) => {
    errors.push(...validateRecord(record, index, context));
    if (ids.has(record.id)) errors.push(`id duplicat: ${record.id}`);
    if (routes.has(record.route)) errors.push(`rută duplicată: ${record.route}`);
    ids.add(record.id);
    routes.add(record.route);
  });
  for (const program of programs) {
    if (!routes.has(program.pageUrl)) errors.push(`program fără înregistrare editorială: ${program.slug} (${program.pageUrl})`);
  }
  return errors;
}

function loadEditorialGovernance(file = CONFIG_PATH) {
  const config = readJson(file);
  const { programs } = loadProgramConfig();
  const errors = validateGovernance(config, programs);
  if (errors.length) throw new Error(`Registrul de guvernanță editorială este invalid:\n- ${errors.join("\n- ")}`);
  return {
    config,
    programs,
    records: config.records,
    byRoute: new Map(config.records.map((record) => [record.route, record])),
    byId: new Map(config.records.map((record) => [record.id, record]))
  };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function renderEditorialGovernance(record) {
  if (!record) return "";
  if (!isCompleteRecord(record)) {
    return `<!-- EDITORIAL_GOVERNANCE_START -->
<section class="editorial-governance editorial-governance--pending" aria-label="Guvernanță editorială" data-editorial-record="${escapeHtml(record.id)}" data-governance-state="${escapeHtml(record.governanceState)}">
  <p><strong>Metadate editoriale în validare:</strong> autorul, reviewerul, sursa sau termenul de reverificare nu sunt încă publicate ca informații confirmate.</p>
</section>
<!-- EDITORIAL_GOVERNANCE_END -->`;
  }
  const changes = record.changelog
    .slice()
    .sort((left, right) => right.date.localeCompare(left.date))
    .map((change) => `<li><time datetime="${escapeHtml(change.date)}">${escapeHtml(change.date)}</time> — ${escapeHtml(change.summary)} <span>(${escapeHtml(change.reviewer)})</span></li>`)
    .join("\n      ");
  return `<!-- EDITORIAL_GOVERNANCE_START -->
<section class="editorial-governance" aria-label="Guvernanță editorială" data-editorial-record="${escapeHtml(record.id)}" data-governance-state="public" data-next-review-at="${escapeHtml(record.nextReviewAt)}">
  <p class="editorial-governance__verified"><strong>Verificat la <time datetime="${escapeHtml(record.verifiedAt)}">${escapeHtml(record.verifiedAt)}</time> de ${escapeHtml(record.reviewer)}, ${escapeHtml(record.reviewerRole)}.</strong></p>
  <p>Autor: ${escapeHtml(record.author)}, ${escapeHtml(record.authorRole)}.</p>
  <p>Sursa oficială: <a href="${escapeHtml(record.officialSourceUrl)}" target="_blank" rel="noopener noreferrer" data-analytics-event="source_document_click" data-analytics-component="editorial_governance" data-analytics-cta-id="official_source">${escapeHtml(record.officialSourceName)} — ${escapeHtml(record.sourceVersion)}</a>.</p>
  <p>Următoarea reverificare internă: <time datetime="${escapeHtml(record.nextReviewAt)}">${escapeHtml(record.nextReviewAt)}</time>. <a href="#editorial-changelog-${escapeHtml(record.id)}">Vezi modificările</a>.</p>
  <details id="editorial-changelog-${escapeHtml(record.id)}" class="editorial-governance__changelog">
    <summary>Istoric editorial</summary>
    <ol>
      ${changes}
    </ol>
  </details>
</section>
<!-- EDITORIAL_GOVERNANCE_END -->`;
}

module.exports = {
  CONFIG_PATH,
  CONTENT_TYPES,
  GOVERNANCE_STATES,
  REQUIRED_RECORD_FIELDS,
  ROOT,
  addDays,
  authorMissing,
  daysBetween,
  isCompleteRecord,
  isIsoDate,
  loadEditorialGovernance,
  normalizeRoute,
  programContradictions,
  recordIssues,
  renderEditorialGovernance,
  reviewExpired,
  reviewIntervalDays,
  reviewerMissing,
  sourceMissing,
  validateGovernance,
  validateRecord
};
