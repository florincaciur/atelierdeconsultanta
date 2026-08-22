#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const {
  EXPECTED_STATUS_IDS,
  LEGACY_STATUS_IDS,
  SOURCE_ROLES,
  buildDocuments,
  checkDocuments,
  loadData,
  resolveSourceReference,
  validateData
} = require("../tools/generate-status-governance-docs.js");

const data = loadData();
const documents = buildDocuments(data);
const statusById = new Map(data.taxonomy.statuses.map((status) => [status.id, status]));
const programsById = new Map(data.programs.map((program) => [program.slug, program]));
const sourceEntryById = new Map(data.sourceRegistry.programs.map((entry) => [entry.programId, entry]));

assert.deepEqual(validateData(data), [], "Configurațiile taxonomiei și registrului de surse trebuie să fie valide.");
assert.deepEqual(data.taxonomy.statuses.map((status) => status.id), EXPECTED_STATUS_IDS, "Taxonomia trebuie să păstreze exact cele 13 stări canonice și ordinea reviewable.");
assert.deepEqual(Object.keys(data.taxonomy.legacyCompatibility), LEGACY_STATUS_IDS, "Toate cele șase stări legacy trebuie mapate explicit.");
assert.equal(data.taxonomy.statuses.filter((status) => status.acceptsApplications).length, 1, "O singură stare poate permite depunerea.");
assert.equal(statusById.get("OPEN").acceptsApplications, true, "OPEN trebuie să permită depunerea.");
assert.equal(statusById.get("FINAL_GUIDE").acceptsApplications, false, "FINAL_GUIDE nu înseamnă OPEN.");
assert.equal(statusById.get("APPROVED_SCHEME").acceptsApplications, false, "APPROVED_SCHEME nu înseamnă OPEN.");
assert.match(statusById.get("SCHEDULED").publicLabel, /\{startDate\}.*\{endDate\}/, "SCHEDULED trebuie să afișeze fereastra oficială viitoare.");
assert.match(statusById.get("UNCONFIRMED").publicLabel, /neconfirmat/i, "UNCONFIRMED nu poate fi prezentat drept fapt cert.");

assert.equal(Object.keys(data.taxonomy.programAssignments).length, data.programs.length, "Fiecare program trebuie să aibă o singură atribuire canonică.");
assert.equal(data.sourceRegistry.programs.length, data.programs.length, "Fiecare program trebuie să aibă o fișă de surse.");
assert.equal(data.taxonomy.programAssignments["dr14-afir"].canonicalStatus, "SCHEDULED");
assert.equal(data.taxonomy.programAssignments["dr18-afir"].canonicalStatus, "SCHEDULED");
assert.equal(data.taxonomy.programAssignments["pocidif-21"].canonicalStatus, "OPEN");
assert.equal(data.taxonomy.programAssignments["pro-infra"].canonicalStatus, "APPROVED_SCHEME");
assert.equal(data.taxonomy.programAssignments["fondul-modernizare-pc1-stocare"].canonicalStatus, "FINAL_GUIDE");
assert.equal(data.taxonomy.programAssignments["dr12-afir"].canonicalStatus, "CONSULTATIVE_GUIDE");

for (const id of ["program-regional-nord-est", "fonduri-regionale", "apeluri-gal", "gal-afir-leader", "pnrr", "programul-tranzitie-justa", "fondul-de-modernizare"]) {
  assert.equal(data.taxonomy.programAssignments[id].canonicalStatus, "UNCONFIRMED", `${id} este pagină-umbrelă și nu poate moșteni OPEN de la un apel.`);
}

for (const program of data.programs) {
  const assignment = data.taxonomy.programAssignments[program.slug];
  const sourceEntry = sourceEntryById.get(program.slug);
  assert.ok(sourceEntry, `${program.slug} trebuie să existe în registrul de surse.`);
  assert.deepEqual(Object.keys(sourceEntry.roles), SOURCE_ROLES, `${program.slug} trebuie să declare toate rolurile oficiale în ordinea standard.`);
  assert.ok(sourceEntry.roles.programPage.length > 0, `${program.slug} trebuie să aibă pagină oficială.`);
  assert.ok(documents.status.includes(`| \`${program.slug}\` |`), `${program.slug} trebuie să apară în maparea taxonomiei.`);
  assert.ok(documents.sources.includes(`## \`${program.slug}\` —`), `${program.slug} trebuie să aibă fișă în registrul oficial.`);
  assert.ok(documents.sources.includes(program.sourceUrl), `${program.slug} trebuie să includă URL-ul oficial principal.`);

  for (const role of SOURCE_ROLES) {
    for (const reference of sourceEntry.roles[role]) {
      const resolved = resolveSourceReference(reference, program, data);
      assert.match(resolved.url, /^https:\/\//, `${program.slug}/${role} trebuie să rezolve la HTTPS.`);
      assert.ok(resolved.label, `${program.slug}/${role} trebuie să aibă label auditabil.`);
    }
  }

  if (["OPEN", "SCHEDULED"].includes(assignment.canonicalStatus)) {
    assert.ok(program.applicationStart && program.applicationEnd, `${program.slug} cere fereastră oficială.`);
    assert.ok(sourceEntry.roles.sessionAnnouncement.length, `${program.slug} cere dovadă de sesiune.`);
  }
}

assert.equal(programsById.get("pocidif-21").applicationStart <= data.taxonomy.reviewedAt, true, "OPEN trebuie să fi început.");
assert.equal(data.taxonomy.reviewedAt <= programsById.get("pocidif-21").applicationEnd, true, "OPEN nu poate avea deadline depășit.");
assert.equal(programsById.get("dr14-afir").applicationStart > data.taxonomy.reviewedAt, true, "SCHEDULED trebuie să fie în viitor.");
assert.equal(programsById.get("dr18-afir").applicationStart > data.taxonomy.reviewedAt, true, "SCHEDULED trebuie să fie în viitor.");

for (const field of ["Stable program ID", "Authority", "Pagină oficială program/apel", "Ghid", "Anexe", "Schemă / ordin", "Anunț sesiune", "Corrigenda / erate", "Clarificări", "Latest official update", "Verification date", "Sursă primară în registry-ul operațional", "Notes"]) {
  assert.ok(documents.sources.includes(`| ${field} |`), `Câmpul obligatoriu ${field} trebuie să existe.`);
}
assert.match(documents.status, /CLOSED.*COMPLETED.*poate rămâne indexabilă/s, "Paginile închise cu valoare SEO trebuie să poată fi păstrate.");
assert.doesNotMatch(documents.status + documents.sources, /\b(?:TODO|TBD|TODO_SURSA_OFICIALA)\b/, "Documentele nu pot publica placeholder-e.");
assert.deepEqual(checkDocuments(documents), [], "Documentele versionate trebuie să fie sincronizate exact cu configurațiile.");
assert.ok(fs.existsSync(path.join(ROOT, "docs", "faber-remediation", "STATUS_TAXONOMY.md")));
assert.ok(fs.existsSync(path.join(ROOT, "docs", "faber-remediation", "OFFICIAL_SOURCE_REGISTRY.md")));

console.log(`Status governance contract PASS (${EXPECTED_STATUS_IDS.length} statuses; ${data.programs.length} programs; ${SOURCE_ROLES.length} source roles).`);
