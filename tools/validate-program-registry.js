#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  CONFIG_PATH,
  HUMAN_REVIEW,
  ROOT,
  isPublicProgram,
  loadProgramConfig
} = require("./program-factual-governance");

const REPORT_PATH = path.join(ROOT, "reports", "program-registry-human-validation.md");

function pendingFields(program) {
  const fields = [];
  for (const field of ["status", "verifiedAt", "sourceName", "sourceUrl", "sourceVersion", "applicationStart", "applicationEnd", "lastMeaningfulUpdate"]) {
    if (program[field] === HUMAN_REVIEW) fields.push(field);
  }
  for (const field of program.pendingValidation?.requestedFields || []) {
    if (!fields.includes(field)) fields.push(field);
  }
  return fields;
}

function humanValidationReport(programs) {
  const pending = programs.filter((program) => !isPublicProgram(program) || pendingFields(program).length);
  const rows = pending.length
    ? pending.map((program) => {
      const candidate = program.pendingValidation?.candidateSourceUrl || "—";
      const note = program.pendingValidation?.note || "Confirmare editorială necesară.";
      return `| ${program.slug} | ${program.pageUrl} | ${pendingFields(program).join(", ") || "publicationState"} | ${candidate} | ${note.replace(/\|/g, "\\|")} |`;
    }).join("\n")
    : "| — | — | — | — | Nu există înregistrări în așteptare. |";
  return `# Înregistrări DE_VALIDAT_UMAN\n\nSursa unică: \`config/seo-programs.json#programs\`.\n\nÎnregistrările de mai jos au \`publicationState=pending_validation\` și sunt excluse din meniu, homepage, carduri, carusel și JSON-LD. Paginile lor primesc un mesaj neutru și \`noindex, follow\` până la confirmarea editorială.\n\n| Program | Pagină | Câmpuri de confirmat | Sursă candidată | Acțiune umană |\n|---|---|---|---|---|\n${rows}\n\n## Regula de publicare\n\nUn responsabil uman trebuie să verifice documentul oficial, versiunea și data, apoi să completeze câmpurile și să schimbe \`publicationState\` în \`public\`. Pentru DR12, statusul \`consultare_publica\` este doar candidat de migrare și nu trebuie tratat ca actual fără această confirmare.\n`;
}

function main() {
  try {
    const { programs, publicPrograms } = loadProgramConfig(CONFIG_PATH);
    const report = humanValidationReport(programs);
    const checkReport = process.argv.includes("--check-report");
    if (checkReport) {
      const current = fs.existsSync(REPORT_PATH) ? fs.readFileSync(REPORT_PATH, "utf8") : "";
      if (current !== report) {
        console.error(`Raportul este nesincronizat: ${path.relative(ROOT, REPORT_PATH)}`);
        process.exitCode = 1;
        return;
      }
    } else {
      fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
      fs.writeFileSync(REPORT_PATH, report, "utf8");
    }
    console.log(`Registru valid: ${programs.length} programe, ${publicPrograms.length} publice, ${programs.length - publicPrograms.length} în validare umană.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { REPORT_PATH, humanValidationReport, pendingFields };
