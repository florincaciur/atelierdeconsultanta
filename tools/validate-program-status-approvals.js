#!/usr/bin/env node
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

const APPROVALS_PATH = path.join(ROOT, "config", "program-status-approvals.json");
const VALIDATION_REPORT_PATH = path.join(ROOT, "reports", "program-status-validation-2026-07-21.md");
const CHANGELOG_PATH = path.join(ROOT, "reports", "editorial-status-changelog-2026-07-21.md");
const REQUIRED_PROGRAMS = Object.freeze(["dr12-afir", "dr14-afir", "pro-infra", "digitalizare-imm"]);
const APPROVAL_STATES = new Set(["pending", "approved"]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function isIsoDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || ""))
    && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

function containsHumanReview(value) {
  if (typeof value === "string") return value.includes(HUMAN_REVIEW);
  if (Array.isArray(value)) return value.some(containsHumanReview);
  if (value && typeof value === "object") return Object.values(value).some(containsHumanReview);
  return false;
}

function validateApprovalRegistry(approvalConfig, programs) {
  const errors = [];
  const rows = Array.isArray(approvalConfig?.programs) ? approvalConfig.programs : [];
  const programById = new Map(programs.map((program) => [program.id, program]));
  const approvalById = new Map();

  if (approvalConfig?.schemaVersion !== 1) errors.push("schemaVersion trebuie să fie 1");
  if (!isIsoDate(approvalConfig?.researchDate)) errors.push("researchDate trebuie să fie o dată ISO");
  if (!String(approvalConfig?.requiredValidatorRole || "").trim()) errors.push("requiredValidatorRole lipsește");

  for (const [index, row] of rows.entries()) {
    const where = `programs[${index}]`;
    if (!row || typeof row !== "object") {
      errors.push(`${where}: rând invalid`);
      continue;
    }
    if (approvalById.has(row.programId)) errors.push(`${where}: programId duplicat (${row.programId})`);
    approvalById.set(row.programId, row);
    const program = programById.get(row.programId);
    if (!program) errors.push(`${where}: program inexistent în registrul unic (${row.programId})`);
    if (!APPROVAL_STATES.has(row.approvalState)) errors.push(`${where}: approvalState invalid (${row.approvalState})`);
    if (!PROGRAM_STATUSES.includes(row.proposedStatus)) errors.push(`${where}: proposedStatus nu aparține taxonomiei controlate`);
    for (const field of [
      "proposedStatusLabel",
      "proposedCopy",
      "officialInstitution",
      "officialDocument",
      "officialDocumentVersion",
      "documentCharacter",
      "officialUrl",
      "observedBefore"
    ]) {
      if (!String(row[field] ?? "").trim()) errors.push(`${where}: ${field} lipsește`);
    }
    if (!isOfficialUrl(row.officialUrl)) errors.push(`${where}: officialUrl nu este URL oficial valid`);
    if (!Array.isArray(row.additionalOfficialEvidence) || row.additionalOfficialEvidence.some((url) => !isOfficialUrl(url))) {
      errors.push(`${where}: additionalOfficialEvidence trebuie să conțină numai URL-uri valide`);
    }
    if (!Array.isArray(row.unresolved) || !row.unresolved.length) errors.push(`${where}: unresolved trebuie să explice verificările umane rămase`);
    if (!Array.isArray(row.affectedUrls) || !row.affectedUrls.length) errors.push(`${where}: affectedUrls nu poate fi gol`);
    if (!Array.isArray(row.publicationHoldUrls) || !row.publicationHoldUrls.length) errors.push(`${where}: publicationHoldUrls nu poate fi gol`);
    const rowVerifiedAt = row.verifiedAt || approvalConfig.researchDate;
    if (!isIsoDate(rowVerifiedAt)) errors.push(`${where}: verifiedAt trebuie să fie o dată ISO când este furnizat`);
    if (!row.proposedCopy.includes(`verificat la ${rowVerifiedAt}`)) errors.push(`${where}: proposedCopy nu conține data verificării`);
    if (!/Depunerea (?:este|nu este) deschisă\./u.test(row.proposedCopy)) errors.push(`${where}: proposedCopy nu declară explicit dacă depunerea este deschisă`);
    if (!row.proposedCopy.includes("Sursa:")) errors.push(`${where}: proposedCopy nu citează sursa`);
    if (row.documentCharacter === "consultativ" && !row.proposedStatusLabel.includes("Condițiile se pot modifica.")) {
      errors.push(`${where}: documentul consultativ trebuie să folosească formularea obligatorie`);
    }
    if (row.proposedStatus === "apel_deschis" && (!isIsoDate(row.applicationStart) || !isIsoDate(row.applicationEnd))) {
      errors.push(`${where}: apel_deschis necesită interval exact`);
    }
    if (row.numericClaimsApproved !== false && row.approvalState !== "approved") {
      errors.push(`${where}: valorile numerice nu pot fi aprobate înaintea rândului`);
    }
    if (program) {
      if (!row.publicationHoldUrls.includes(program.pageUrl)) errors.push(`${where}: pagina canonică trebuie inclusă în publicationHoldUrls`);
      if (row.proposedStatus !== program.status) errors.push(`${where}: statusul candidat diferă de registrul unic`);
    }

    if (row.approvalState === "pending") {
      if (row.validatorName !== HUMAN_REVIEW) errors.push(`${where}: un rând pending trebuie să păstreze validatorName=${HUMAN_REVIEW}`);
      if (row.approvedAt !== null) errors.push(`${where}: un rând pending nu poate avea approvedAt`);
      if (program && isPublicProgram(program)) errors.push(`${where}: programul este public înainte de aprobarea FABER`);
      if (program && (summaryHasValues(program.grantSummary) || summaryHasValues(program.cofinancingSummary))) {
        errors.push(`${where}: programul pending publică valori numerice`);
      }
    }

    if (row.approvalState === "approved") {
      if (!String(row.validatorName || "").trim() || row.validatorName === HUMAN_REVIEW) errors.push(`${where}: aprobarea necesită numele consultantului FABER`);
      if (!isIsoDate(row.approvedAt)) errors.push(`${where}: aprobarea necesită approvedAt ISO`);
      if (containsHumanReview(row)) errors.push(`${where}: un rând aprobat nu poate conține ${HUMAN_REVIEW}`);
      if (program && !isPublicProgram(program)) errors.push(`${where}: rândul este aprobat, dar registrul nu este public`);
      if (program && [program.verifiedAt, program.sourceUrl, program.sourceVersion].some((value) => !value || value === HUMAN_REVIEW)) {
        errors.push(`${where}: programul aprobat nu are metadatele oficiale complete`);
      }
      if (program && program.sourceName !== row.officialInstitution) errors.push(`${where}: instituția aprobată diferă de registrul unic`);
      if (program && program.sourceUrl !== row.officialUrl) errors.push(`${where}: URL-ul aprobat diferă de registrul unic`);
      if (program && program.verifiedAt < rowVerifiedAt) errors.push(`${where}: snapshot-ul factual este anterior aprobării nominale`);
      if (program && program.applicationStart !== row.applicationStart) errors.push(`${where}: applicationStart aprobat diferă de registrul unic`);
      if (program && program.applicationEnd !== row.applicationEnd) errors.push(`${where}: applicationEnd aprobat diferă de registrul unic`);
      if (program && (summaryHasValues(program.grantSummary) || summaryHasValues(program.cofinancingSummary)) && row.numericClaimsApproved !== true) {
        errors.push(`${where}: registrul publică valori numerice neaprobate în rândul factual`);
      }
    }
  }

  for (const id of REQUIRED_PROGRAMS) {
    if (!approvalById.has(id)) errors.push(`lipsește rândul obligatoriu ${id}`);
  }
  for (const id of approvalById.keys()) {
    if (!REQUIRED_PROGRAMS.includes(id)) errors.push(`program nepermis în această poartă P0.02: ${id}`);
  }
  return errors;
}

function markdownLink(label, url) {
  return `[${String(label).replace(/\|/g, "\\|")}](${url})`;
}

function validationReport(config) {
  const rows = config.programs.map((row) => {
    const dates = row.applicationStart || row.applicationEnd
      ? `${row.applicationStart || "—"}–${row.applicationEnd || "—"}`
      : "Depunerea nu este deschisă; interval neconfirmat";
    return `| ${row.programId} | ${row.proposedStatus} | ${row.proposedStatusLabel.replace(/\|/g, "\\|")} | ${row.verifiedAt || config.researchDate} | ${markdownLink(row.officialInstitution, row.officialUrl)} — ${row.officialDocumentVersion.replace(/\|/g, "\\|")} | ${dates} | ${row.validatorName} | ${row.approvalState} | ${row.affectedUrls.map((url) => `\`${url}\``).join(", ")} |`;
  }).join("\n");
  const details = config.programs.map((row) => `## ${row.programId}\n\n**Copy propus după aprobare:** ${row.proposedCopy}\n\n**Caracter document:** ${row.documentCharacter}. **Data documentului:** ${row.officialDocumentDate}. **Valori numerice aprobate:** ${row.numericClaimsApproved ? "da" : "nu"}.\n\n**Dovezi oficiale suplimentare:** ${row.additionalOfficialEvidence.length ? row.additionalOfficialEvidence.map((url, index) => markdownLink(`sursa ${index + 2}`, url)).join(", ") : "—"}.\n\n**DE_VALIDAT_UMAN:**\n\n${row.unresolved.map((item) => `- ${item}`).join("\n")}\n\n**URL-uri suspendate integral:** ${row.publicationHoldUrls.map((url) => `\`${url}\``).join(", ")}.`).join("\n\n");
  return `# P0.02 — Tabel de validare factuală\n\nData cercetării: **${config.researchDate}**. Rol de validare obligatoriu: **${config.requiredValidatorRole}**.\n\n> PUBLICARE OPRITĂ: toate cele patru rânduri sunt propuneri factuale, nu aprobări. Numele validatorului este \`${HUMAN_REVIEW}\`; copy-ul propus nu se publică până la aprobarea nominală FABER.\n\n| Program | Status propus | Formulare scurtă | Data verificării | Instituție, URL și versiune oficială | Interval depunere | Persoană care validează | Aprobare | Toate URL-urile afectate |\n|---|---|---|---|---|---|---|---|---|\n${rows}\n\nMeniul global este o suprafață afectată pe toate paginile; el este generat din registrul unic și exclude automat rândurile \`pending_validation\`. Menționarea editorială evergreen a numelui unui program nu publică status, calendar sau valori; cardurile, tabelele factuale, paginile prioritare și JSON-LD sunt însă blocate.\n\n${details}\n`;
}

function editorialChangelog(config) {
  const sections = config.programs.map((row) => `## ${row.programId}\n\n- **Înainte (observat live):** ${row.observedBefore}\n- **Corecție candidat:** \`${row.proposedStatus}\` — ${row.proposedStatusLabel}\n- **Acțiune aplicată:** exclus din meniu, homepage, carusele, carduri factuale și JSON-LD; URL-urile prioritare au \`noindex, follow\` și mesaj neutru de suspendare.\n- **Valori:** eliminate cât timp \`numericClaimsApproved=false\`.\n- **Publicare finală:** blocată; validator ${row.validatorName}, aprobare \`${row.approvalState}\`.\n- **Copy pregătit pentru aprobare:** ${row.proposedCopy}\n- **Sursă primară:** ${row.officialUrl}\n- **URL-uri afectate:** ${row.affectedUrls.map((url) => `\`${url}\``).join(", ")}.`).join("\n\n");
  return `# Changelog editorial P0.02\n\nData: **${config.researchDate}**. Acest changelog documentează corecțiile și blocajul editorial; nu reprezintă aprobarea copy-ului candidat.\n\n${sections}\n`;
}

function writeOrCheck(file, content, check) {
  if (check) {
    const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
    if (current !== content) throw new Error(`Raport nesincronizat: ${path.relative(ROOT, file)}`);
    return;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
}

function main() {
  try {
    const approvalConfig = readJson(APPROVALS_PATH);
    const { programs } = loadProgramConfig();
    const errors = validateApprovalRegistry(approvalConfig, programs);
    if (errors.length) throw new Error(`Poarta editorială P0.02 este invalidă:\n- ${errors.join("\n- ")}`);
    const check = process.argv.includes("--check-report");
    writeOrCheck(VALIDATION_REPORT_PATH, validationReport(approvalConfig), check);
    writeOrCheck(CHANGELOG_PATH, editorialChangelog(approvalConfig), check);
    const approved = approvalConfig.programs.filter((row) => row.approvalState === "approved").length;
    console.log(`Poartă P0.02 validă: ${approved} aprobate, ${approvalConfig.programs.length - approved} blocate pentru validare FABER.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  APPROVALS_PATH,
  CHANGELOG_PATH,
  REQUIRED_PROGRAMS,
  VALIDATION_REPORT_PATH,
  editorialChangelog,
  validateApprovalRegistry,
  validationReport
};
