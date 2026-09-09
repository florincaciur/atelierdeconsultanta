#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { HUMAN_REVIEW, ROOT, isPublicProgram, loadProgramConfig } = require("./program-factual-governance");

const GOVERNANCE_PATH = path.join(ROOT, "config", "editorial-governance.json");
const CHECK = process.argv.includes("--check");

function addDays(date, days) {
  const value = new Date(`${date}T00:00:00Z`);
  value.setUTCDate(value.getUTCDate() + days);
  return value.toISOString().slice(0, 10);
}

function syncRecord(record, program, policy) {
  const before = JSON.stringify({
    governanceState: record.governanceState,
    verifiedAt: record.verifiedAt,
    officialSourceUpdatedAt: record.officialSourceUpdatedAt,
    officialSourceName: record.officialSourceName,
    officialSourceUrl: record.officialSourceUrl,
    sourceVersion: record.sourceVersion,
    lastMeaningfulUpdate: record.lastMeaningfulUpdate,
    statusSnapshot: record.statusSnapshot
  });

  record.governanceState = isPublicProgram(program) ? "public" : "pending_validation";
  record.verifiedAt = program.verifiedAt;
  record.officialSourceUpdatedAt = program.officialSourceUpdatedAt || HUMAN_REVIEW;
  record.officialSourceName = program.sourceName;
  record.officialSourceUrl = program.sourceUrl;
  record.sourceVersion = program.sourceVersion;
  record.lastMeaningfulUpdate = program.lastMeaningfulUpdate;
  record.statusSnapshot = program.status;
  record.nextReviewAt = addDays(
    program.verifiedAt,
    program.status === "apel_deschis" ? policy.openCallReviewDays : policy.programReviewDays
  );

  const after = JSON.stringify({
    governanceState: record.governanceState,
    verifiedAt: record.verifiedAt,
    officialSourceUpdatedAt: record.officialSourceUpdatedAt,
    officialSourceName: record.officialSourceName,
    officialSourceUrl: record.officialSourceUrl,
    sourceVersion: record.sourceVersion,
    lastMeaningfulUpdate: record.lastMeaningfulUpdate,
    statusSnapshot: record.statusSnapshot
  });
  if (before === after) return false;

  const reviewer = record.reviewer || "Echipa editorială FABER";
  const generatedMeaningfulSummary = `Statutul și sursa oficială pentru ${program.shortName} au fost actualizate din registrul factual unic.`;
  record.changelog = (record.changelog || []).filter((entry) => !(
    entry.meaningful === true
    && entry.summary === generatedMeaningfulSummary
    && entry.date > program.lastMeaningfulUpdate
  ));
  const latestMeaningful = (record.changelog || [])
    .filter((entry) => entry.meaningful === true)
    .map((entry) => entry.date)
    .sort()
    .at(-1);
  if (latestMeaningful !== program.lastMeaningfulUpdate) {
    record.changelog.unshift({
      date: program.lastMeaningfulUpdate,
      summary: generatedMeaningfulSummary,
      reviewer,
      meaningful: true
    });
  } else if (!(record.changelog || []).some((entry) => entry.date === program.verifiedAt && /reverificat/iu.test(entry.summary))) {
    record.changelog.unshift({
      date: program.verifiedAt,
      summary: `Statutul ${program.shortName} a fost reverificat în sursa oficială; nu a fost identificată o schimbare editorială substanțială suplimentară.`,
      reviewer,
      meaningful: false
    });
  }
  return true;
}

function main() {
  const before = fs.readFileSync(GOVERNANCE_PATH, "utf8");
  const config = JSON.parse(before);
  const { programs } = loadProgramConfig();
  const byId = new Map(programs.map((program) => [program.id, program]));
  let changed = 0;

  for (const record of config.records || []) {
    if (!record.programId) continue;
    const program = byId.get(record.programId);
    if (!program) throw new Error(`Program inexistent în registrul factual: ${record.programId}`);
    if (syncRecord(record, program, config.policy)) changed += 1;
  }

  const after = `${JSON.stringify(config, null, 2)}\n`;
  if (CHECK) {
    if (before !== after) {
      console.error(`Registrul editorial este nesincronizat pentru ${changed} pagini de program.`);
      process.exitCode = 1;
      return;
    }
    console.log("Registrul editorial este sincronizat cu registrul factual.");
    return;
  }
  if (before !== after) fs.writeFileSync(GOVERNANCE_PATH, after, "utf8");
  console.log(`Registru editorial sincronizat: ${changed} pagini de program actualizate.`);
}

main();
