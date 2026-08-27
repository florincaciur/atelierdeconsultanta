#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { auditFundingStatus, exitCode, isDate, markdownReport } = require("../tools/audit-funding-status.js");
const { loadData } = require("../tools/generate-status-governance-docs.js");
const { policy } = require("../config/editorial-governance.json");
const taxonomy = require("../config/program-status-taxonomy.json");
const today = "2026-08-26";

// Synthetic fixtures only; these are never funding facts or public assets.
const base = {
  id: "fixture-open", slug: "fixture-open", name: "Fixture audit", canonicalStatus: "OPEN", status: "apel_deschis",
  applicationStart: "2026-08-01", applicationEnd: "2026-09-30", verifiedAt: "2026-08-23",
  sourceType: "official", sourceUrl: "https://www.afir.ro/fixture-session", sourceName: "Fixture authority", sourceVersion: "Fixture session",
  officialSources: { roles: { sessionAnnouncement: ["guide:fixture-session"], corrigenda: ["guide:fixture-extension"] } },
};
const extended = {
  originalEnd: "2026-08-20", extendedEnd: "2026-09-30", sourceRef: "guide:fixture-extension", verifiedAt: "2026-08-23",
};
const sources = {
  taxonomy,
  guides: {
    "fixture-session": { title: "Fixture session", url: "https://www.afir.ro/fixture-session", programIds: [base.id] },
    "fixture-extension": { title: "Fixture extension", url: "https://www.afir.ro/fixture-extension", programIds: [base.id] },
  },
  sourceRegistry: { supplementalSources: {} }, approvals: [],
};

function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

function runFixture(overrides = {}, sourceOverrides = {}, auditDate = today) {
  const data = freeze(structuredClone({ ...sources, ...sourceOverrides, programs: [{ ...base, ...overrides }] }));
  const before = JSON.stringify(data);
  const report = auditFundingStatus(data, { today: auditDate, policy });
  assert.equal(JSON.stringify(data), before, "Auditul nu poate modifica programul, datele sau sursele.");
  assert.deepEqual(report, auditFundingStatus(data, { today: auditDate, policy }), "Aceleași intrări/data produc același raport.");
  for (const finding of report.findings) {
    for (const field of ["program", "status", "sessionStart", "sessionEnd", "verifiedAt", "source", "problem", "severity", "recommendedAction"]) {
      assert.ok(Object.hasOwn(finding, field), `Lipsește câmpul de raport ${field}.`);
    }
    assert.ok(finding.recommendedAction.length > 10);
  }
  return report;
}

const codes = report => report.findings.map(finding => finding.code);
const fixtures = [
  ["open valid", {}, [], 0],
  ["open expired", { applicationEnd: "2026-08-25" }, ["OPEN_EXPIRED"], 1],
  ["open extended, applicationEnd pending editorial sync", { applicationEnd: extended.originalEnd, extensionData: extended }, ["EXTENSION_NOT_APPLIED"], 0],
  ["open extended and synced", { extensionData: extended }, [], 0],
  ["open end date inclusive", { applicationEnd: today }, [], 0],
  ["open not started", { applicationStart: "2026-08-27" }, ["OPEN_NOT_STARTED"], 1],
  ["open missing official source", { sourceUrl: "DE_VALIDAT_UMAN" }, ["OPEN_SOURCE_MISSING"], 1],
  ["open private source", { sourceUrl: "https://consultant.example/guide" }, ["OPEN_SOURCE_MISSING"], 1],
  ["open misleading official hostname", { sourceUrl: "https://afir.ro.example/guide" }, ["OPEN_SOURCE_MISSING"], 1],
  ["open missing session evidence", { officialSources: { roles: { sessionAnnouncement: [] } } }, ["OPEN_SESSION_EVIDENCE_MISSING"], 1],
  ["open broken session reference", { officialSources: { roles: { sessionAnnouncement: ["guide:absent"] } } }, ["OPEN_SESSION_EVIDENCE_MISSING"], 1],
  ["open missing session dates", { applicationStart: null, applicationEnd: null }, ["OPEN_SESSION_DATES_MISSING"], 1],
  ["scheduled past", { canonicalStatus: "SCHEDULED", status: "ghid_aprobat_nedeschis", applicationStart: "2026-08-24" }, ["SCHEDULED_REVIEW_REQUIRED"], 0],
  ["scheduled reverified on start", { canonicalStatus: "SCHEDULED", status: "ghid_aprobat_nedeschis", applicationStart: "2026-08-23" }, [], 0],
  ["scheduled future", { canonicalStatus: "SCHEDULED", status: "ghid_aprobat_nedeschis", applicationStart: "2026-09-01" }, [], 0],
  ["consultation expired without review", { canonicalStatus: "PUBLIC_CONSULTATION", status: "consultare_publica", consultationEnd: "2026-08-24" }, ["CONSULTATION_REVIEW_REQUIRED"], 0],
  ["consultation reverified after end", { canonicalStatus: "PUBLIC_CONSULTATION", status: "consultare_publica", consultationEnd: "2026-08-22" }, [], 0],
  ["consultation verified on end still needs review", { canonicalStatus: "PUBLIC_CONSULTATION", status: "consultare_publica", consultationEnd: "2026-08-23" }, ["CONSULTATION_REVIEW_REQUIRED"], 0],
  ["consultation missing end", { canonicalStatus: "PUBLIC_CONSULTATION", status: "consultare_publica", applicationEnd: "2026-08-20" }, ["CONSULTATION_END_MISSING"], 0],
  ["draft guide is not active consultation", { canonicalStatus: "CONSULTATIVE_GUIDE", status: "consultare_publica", consultationEnd: "2026-03-30" }, [], 0],
  ["closed historical", { canonicalStatus: "CLOSED", status: "apel_inchis", applicationStart: "2025-01-01", applicationEnd: "2025-02-01" }, [], 0],
  ["closed historical stale review is warning only", { canonicalStatus: "CLOSED", status: "apel_inchis", applicationStart: "2025-01-01", applicationEnd: "2025-02-01", verifiedAt: "2025-02-02" }, ["VERIFICATION_STALE"], 0],
  ["extension missing source", { extensionData: { ...extended, sourceRef: null } }, ["EXTENSION_SOURCE_MISSING"], 1],
  ["extension not assigned to this session", { extensionData: { ...extended, sourceRef: "program" } }, ["EXTENSION_SOURCE_MISSING"], 1],
  ["extension accepts assigned descriptor", { extensionData: { ...extended, sourceRef: { ref: "guide:fixture-extension", label: "Fixture corrigendum" } } }, [], 0],
  ["extension incomplete", { extensionData: {} }, ["EXTENSION_SOURCE_MISSING", "EXTENSION_INVALID"], 1],
  ["extension expired", { applicationEnd: "2026-08-20", extensionData: { ...extended, extendedEnd: "2026-08-25" } }, ["EXTENSION_NOT_APPLIED", "OPEN_EXPIRED"], 1],
  ["extension wrong session", { extensionData: { ...extended, originalEnd: "2026-08-01", extendedEnd: "2026-08-30" } }, ["EXTENSION_INVALID"], 1],
  ["extension review in future", { extensionData: { ...extended, verifiedAt: "2026-08-27" } }, ["EXTENSION_INVALID"], 1],
  ["extension not yet covered by program verification", { extensionData: { ...extended, verifiedAt: "2026-08-24" } }, ["EXTENSION_INVALID"], 1],
  ["invalid verifiedAt", { verifiedAt: "2026-02-30" }, ["VERIFICATION_INVALID"], 1],
  ["missing verifiedAt", { verifiedAt: null }, ["VERIFICATION_INVALID"], 1],
  ["future verifiedAt", { verifiedAt: "2026-08-27" }, ["VERIFICATION_INVALID"], 1],
  ["unknown canonical status cannot bypass OPEN", { canonicalStatus: "TYPO", applicationEnd: "2026-08-25" }, ["UNKNOWN_STATUS", "STATUS_CONTRADICTION", "OPEN_EXPIRED"], 1],
];
for (const [name, overrides, expected, expectedExit] of fixtures) {
  const report = runFixture(overrides);
  assert.deepEqual(codes(report), expected, name);
  assert.equal(exitCode(report), expectedExit, `${name}: exit code`);
}

assert.ok(codes(runFixture({ applicationEnd: "2026-08-20", extensionData: { ...extended, sourceRef: "guide:absent" } })).includes("OPEN_EXPIRED"), "O prelungire fără dovadă nu poate suprima expirarea.");
const wrongProgramGuides = structuredClone(sources.guides);
wrongProgramGuides["fixture-session"].programIds = ["another-program"];
assert.ok(codes(runFixture({}, { guides: wrongProgramGuides })).includes("OPEN_SESSION_EVIDENCE_MISSING"));
const privateExtension = structuredClone(sources.guides);
privateExtension["fixture-extension"].url = "https://consultant.example/extension";
assert.ok(codes(runFixture({ applicationEnd: extended.originalEnd, extensionData: extended }, { guides: privateExtension })).includes("OPEN_EXPIRED"));
const combined = runFixture({ applicationEnd: extended.originalEnd, extensionData: extended, verifiedAt: "2026-08-23" }, {}, "2026-09-24");
assert.ok(codes(combined).includes("VERIFICATION_STALE"));
assert.ok(combined.findings.every(row => row.effectiveSessionEnd === extended.extendedEnd && row.extensionSource === sources.guides["fixture-extension"].url));
for (const field of ["openCallReviewDays", "programReviewDays"]) {
  const overrides = field === "openCallReviewDays" ? {} : { canonicalStatus: "CLOSED", status: "apel_inchis" };
  const date = new Date(`${today}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() - policy[field]);
  assert.ok(!codes(runFixture({ ...overrides, verifiedAt: date.toISOString().slice(0, 10) })).includes("VERIFICATION_STALE"));
  date.setUTCDate(date.getUTCDate() - 1);
  assert.ok(codes(runFixture({ ...overrides, verifiedAt: date.toISOString().slice(0, 10) })).includes("VERIFICATION_STALE"));
}
assert.ok(isDate("2024-02-29"));
for (const value of [null, "", "2026-02-29", "2026-04-31", "2026-13-01", "2026-08-26T00:00:00Z"]) assert.ok(!isDate(value));
assert.throws(() => runFixture({}, {}, "2026-02-30"), /YYYY-MM-DD/);
assert.throws(() => auditFundingStatus({ ...sources, programs: [] }, { today, policy }), /nevidă/);
assert.throws(() => auditFundingStatus({ ...sources, programs: [base] }, { today, policy: {} }), /Politică invalidă/);
const escaped = markdownReport(runFixture({ id: "fixture|unsafe\n<value>", applicationEnd: "2026-08-25" }));
assert.match(escaped, /fixture\\\|unsafe &lt;value&gt;/);

// CLI integration: even a failing audit must leave all factual inputs byte-for-byte intact.
const inputFiles = ["config/seo-programs.json", "config/editorial-governance.json", "config/program-source-registry.json", "config/program-status-taxonomy.json", "config/program-status-approvals.json", "official-guides.json", "pocidif-21/index.html", "sitemap-programs.xml"];
const hashes = () => inputFiles.map(file => createHash("sha256").update(fs.readFileSync(path.join(ROOT, file))).digest("hex"));
const before = hashes();
const data = loadData();
const snapshotDate = data.sourceRegistry.factualSnapshotDate;
const cli = args => spawnSync(process.execPath, [path.join(ROOT, "tools/audit-funding-status.js"), ...args], { cwd: ROOT, encoding: "utf8" });
const valid = cli([`--today=${snapshotDate}`, "--format=json"]);
const expectedSnapshot = auditFundingStatus(data, { today: snapshotDate, policy });
assert.equal(valid.status, exitCode(expectedSnapshot), valid.stderr || valid.stdout);
assert.deepEqual(JSON.parse(valid.stdout), expectedSnapshot);
assert.equal(JSON.parse(valid.stdout).programsChecked, data.programs.length);
assert.equal(JSON.parse(valid.stdout).asOf, snapshotDate);
const openEnd = data.programs.filter(p => p.canonicalStatus === "OPEN").map(p => p.extensionData?.extendedEnd || p.applicationEnd).sort().at(-1);
if (isDate(openEnd)) {
  const afterDeadline = new Date(`${openEnd}T00:00:00Z`);
  afterDeadline.setUTCDate(afterDeadline.getUTCDate() + 1);
  const failed = cli([`--today=${afterDeadline.toISOString().slice(0, 10)}`, "--format=json"]);
  assert.equal(failed.status, 1, failed.stderr || failed.stdout);
  assert.ok(codes(JSON.parse(failed.stdout)).includes("OPEN_EXPIRED"));
}
for (const args of [["--today=2026-02-30"], ["--today="], ["--format=unknown"], ["--unknown"], ["--today=2026-08-26", "--today=2026-08-27"]]) assert.equal(cli(args).status, 2);
assert.deepEqual(hashes(), before, "CLI-ul nu poate actualiza facts, HTML, verifiedAt sau sitemap/lastmod.");
assert.equal(require("../package.json").scripts.prebuild, "npm run test:funding-status && npm run audit:funding-status && npm run test:brand-entity");
const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/funding-status-audit.yml"), "utf8");
assert.match(workflow, /contents: read/);
assert.match(workflow, /cron:/);
assert.match(workflow, /npm run audit:funding-status -- --report/);
assert.doesNotMatch(workflow, /continue-on-error:\s*true|git push|contents: write/);

console.log(`Funding status audit PASS: ${fixtures.length} fixtures, date boundaries, source resolution, exit codes and read-only CLI.`);
