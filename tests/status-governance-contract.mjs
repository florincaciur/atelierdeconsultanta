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
  FACTUAL_FIELD_LABELS,
  LEGACY_STATUS_IDS,
  SOURCE_ROLES,
  buildDocuments,
  checkDocuments,
  loadData,
  resolveSourceReference,
  sameDocumentContent,
  validateData
} = require("../tools/generate-status-governance-docs.js");

const data = loadData();
const documents = buildDocuments(data);
const statusById = new Map(data.taxonomy.statuses.map((status) => [status.id, status]));
const programsById = new Map(data.programs.map((program) => [program.id, program]));

assert.deepEqual(validateData(data), [], "Configurațiile taxonomiei și registrului de surse trebuie să fie valide.");
assert.deepEqual(data.taxonomy.statuses.map((status) => status.id), EXPECTED_STATUS_IDS, "Taxonomia trebuie să păstreze exact cele 13 stări canonice și ordinea reviewable.");
assert.deepEqual(Object.keys(data.taxonomy.legacyCompatibility), LEGACY_STATUS_IDS, "Toate cele șase stări legacy trebuie mapate explicit.");
assert.equal(data.taxonomy.statuses.filter((status) => status.acceptsApplications).length, 1, "O singură stare poate permite depunerea.");
assert.equal(statusById.get("OPEN").acceptsApplications, true, "OPEN trebuie să permită depunerea.");
assert.equal(statusById.get("FINAL_GUIDE").acceptsApplications, false, "FINAL_GUIDE nu înseamnă OPEN.");
assert.equal(statusById.get("APPROVED_SCHEME").acceptsApplications, false, "APPROVED_SCHEME nu înseamnă OPEN.");
assert.match(statusById.get("SCHEDULED").publicLabel, /\{startDate\}.*\{endDate\}/, "SCHEDULED trebuie să afișeze fereastra oficială viitoare.");
assert.match(statusById.get("UNCONFIRMED").publicLabel, /neconfirmat/i, "UNCONFIRMED nu poate fi prezentat drept fapt cert.");

assert.equal(programsById.size, data.programs.length, "Fiecare program trebuie să aibă un singur ID stabil.");
assert.equal(FACTUAL_FIELD_LABELS.length, 32, "Auditul trebuie să păstreze exact cele 32 de categorii factuale Task 04.");
assert.equal(programsById.get("dr14-afir").canonicalStatus, "OPEN");
assert.equal(programsById.get("dr18-afir").canonicalStatus, "OPEN");
assert.equal(programsById.get("pocidif-21").canonicalStatus, "OPEN");
assert.equal(programsById.get("pro-infra").canonicalStatus, "APPROVED_SCHEME");
assert.equal(programsById.get("fondul-modernizare-pc1-stocare").canonicalStatus, "FINAL_GUIDE");
assert.equal(programsById.get("dr12-afir").canonicalStatus, "CONSULTATIVE_GUIDE");

for (const id of ["program-regional-nord-est", "fonduri-regionale", "apeluri-gal", "gal-afir-leader", "pnrr", "programul-tranzitie-justa", "fondul-de-modernizare"]) {
  assert.equal(programsById.get(id).canonicalStatus, "UNCONFIRMED", `${id} este pagină-umbrelă și nu poate moșteni OPEN de la un apel.`);
}

for (const program of data.programs) {
  const assignment = program;
  const sourceEntry = program.officialSources;
  assert.ok(sourceEntry, `${program.slug} trebuie să existe în registrul de surse.`);
  assert.deepEqual(Object.keys(sourceEntry.roles), SOURCE_ROLES, `${program.slug} trebuie să declare toate rolurile oficiale în ordinea standard.`);
  assert.ok(sourceEntry.roles.programPage.length > 0, `${program.slug} trebuie să aibă pagină oficială.`);
  assert.ok(documents.status.includes(`| \`${program.id}\` |`), `${program.id} trebuie să apară în maparea taxonomiei.`);
  assert.ok(documents.sources.includes(`## \`${program.id}\` —`), `${program.id} trebuie să aibă fișă în registrul oficial.`);
  assert.ok(documents.sources.includes(program.sourceUrl), `${program.slug} trebuie să includă URL-ul oficial principal.`);
  assert.ok(program.verifiedAt >= data.sourceRegistry.factualSnapshotDate, `${program.slug} trebuie verificat cel puțin la data snapshot-ului factual de bază.`);
  for (const field of FACTUAL_FIELD_LABELS) {
    assert.ok(documents.sources.includes(`| ${field} |`), `${program.slug}: categoria factuală ${field} lipsește.`);
  }

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
assert.equal(programsById.get("dr14-afir").applicationStart <= data.taxonomy.reviewedAt, true, "Sesiunea verificată OPEN trebuie să fi început.");
assert.equal(programsById.get("dr18-afir").applicationStart <= data.taxonomy.reviewedAt, true, "Sesiunea verificată OPEN trebuie să fi început.");

for (const field of ["Stable program ID", "Pagină oficială program/apel", "Ghid", "Anexe", "Schemă / ordin", "Anunț sesiune", "Corrigenda / erate", "Clarificări", "Sursă primară în registry-ul operațional", "Notes"]) {
  assert.ok(documents.sources.includes(`| ${field} |`), `Câmpul obligatoriu ${field} trebuie să existe.`);
}
assert.match(documents.status, /CLOSED.*COMPLETED.*poate rămâne indexabilă/s, "Paginile închise cu valoare SEO trebuie să poată fi păstrate.");
assert.match(documents.sources, /Documentația oficială publicată și verificată la 23\.08\.2026 nu stabilește încă această informație\./, "Golurile factuale trebuie explicate explicit, fără placeholder.");
for (const field of ["Program", "Câmp", "Before", "After", "Sursă", "Verificat", "Motiv"]) {
  assert.ok(documents.sources.includes(field), `Jurnalul factual trebuie să includă ${field}.`);
}
assert.equal(data.factualChanges.length, 4, "Reverificarea Task 04 trebuie să documenteze cele patru corecții factuale.");
assert.doesNotMatch(documents.status + documents.sources, /\b(?:TODO|TBD|TODO_SURSA_OFICIALA)\b/, "Documentele nu pot publica placeholder-e.");
assert.equal(sameDocumentContent("linie 1\r\nlinie 2\r\n", "linie 1\nlinie 2\n"), true, "Verificarea documentelor trebuie să accepte CRLF și LF ca același conținut.");
assert.equal(sameDocumentContent("linie 1\n", "linie diferită\n"), false, "Verificarea documentelor trebuie să detecteze diferențele reale de conținut.");
assert.deepEqual(checkDocuments(documents), [], "Documentele versionate trebuie să fie sincronizate exact cu configurațiile.");
assert.ok(fs.existsSync(path.join(ROOT, "docs", "faber-remediation", "STATUS_TAXONOMY.md")));
assert.ok(fs.existsSync(path.join(ROOT, "docs", "faber-remediation", "OFFICIAL_SOURCE_REGISTRY.md")));

console.log(`Status governance contract PASS (${EXPECTED_STATUS_IDS.length} statuses; ${data.programs.length} programs; ${SOURCE_ROLES.length} source roles).`);
