#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { collectSiteState } = require("./generate-sitemap");
const {
  CONFIG_PATH,
  HUMAN_REVIEW,
  ROOT,
  carouselPrograms,
  isPublicProgram,
  loadProgramConfig,
  normalizeRoute
} = require("./program-factual-governance");

const REPORT_PATH = path.join(ROOT, "reports", "program-registry-human-validation.md");

function duplicateValues(items, selector) {
  const counts = new Map();
  for (const item of items) {
    const value = selector(item);
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return [...counts.entries()].filter(([, count]) => count > 1).map(([value]) => value);
}

function normalizeLineEndings(value) {
  return String(value).replace(/\r\n/g, "\n");
}

function registrySurfaceErrors(programs) {
  const errors = [];
  const ids = new Set(programs.map((program) => program.id));
  const siteState = collectSiteState();
  const publicEntries = siteState.entries;
  const entriesByRoute = new Map(publicEntries.map((entry) => [normalizeRoute(entry.route), entry]));
  const excludedByRoute = new Map(siteState.excluded.map((entry) => [normalizeRoute(entry.route), entry]));

  for (const program of programs) {
    const entry = entriesByRoute.get(normalizeRoute(program.pageUrl));
    if (!program.indexable) {
      if (!entry && !excludedByRoute.has(normalizeRoute(program.pageUrl))) {
        errors.push(`${program.id}: program neindexabil fără pagină sau rută exclusă documentată (${program.pageUrl})`);
      }
      continue;
    }
    if (!entry) {
      errors.push(`${program.id}: program indexabil fără pagină canonical 200 (${program.pageUrl})`);
      continue;
    }
    const $ = cheerio.load(fs.readFileSync(path.join(ROOT, entry.sourceFile), "utf8"), { decodeEntities: false });
    if ($("body").attr("data-program-id") !== program.id) {
      errors.push(`${program.id}: pagina canonical nu declară același data-program-id (${entry.route})`);
    }
  }

  for (const entry of publicEntries) {
    const $ = cheerio.load(fs.readFileSync(path.join(ROOT, entry.sourceFile), "utf8"), { decodeEntities: false });
    const body = $("body");
    if (body.attr("data-analytics-page-type") !== "program" && body.attr("data-page-type") !== "program") continue;
    const programId = body.attr("data-program-id");
    if (!programId || !ids.has(programId)) errors.push(`${entry.route}: pagină de program fără înregistrare validă (${programId || "ID absent"})`);
  }

  const banners = JSON.parse(fs.readFileSync(path.join(ROOT, "banners.json"), "utf8"));
  for (const duplicate of duplicateValues(banners, (banner) => banner.id)) errors.push(`ID de banner duplicat: ${duplicate}`);
  for (const duplicate of duplicateValues(banners.filter((banner) => banner.active !== false), (banner) => normalizeRoute(banner.ctaLink))) {
    errors.push(`Canonical de banner duplicat: ${duplicate}`);
  }
  for (const duplicate of duplicateValues(banners.filter((banner) => banner.active !== false), (banner) => banner.programId)) {
    errors.push(`Program cu bannere active duplicate: ${duplicate}`);
  }
  const expectedBannerIds = new Set(carouselPrograms(programs).map((program) => program.id));
  const actualBannerIds = new Set(banners.filter((banner) => banner.active !== false).map((banner) => banner.programId));
  for (const id of expectedBannerIds) if (!actualBannerIds.has(id)) errors.push(`${id}: banner activ lipsă`);
  for (const id of actualBannerIds) if (!expectedBannerIds.has(id)) errors.push(`${id}: banner activ fără bannerEnabled în registru`);
  const programsById = new Map(programs.map((program) => [program.id, program]));
  for (const banner of banners.filter((item) => item.active !== false)) {
    const program = programsById.get(banner.programId);
    if (!program) continue;
    const expectedFields = {
      title: program.name,
      description: program.metaDescription,
      ctaLink: program.pageUrl,
      order: program.presentation.carouselOrder,
      programStatus: program.status,
      statusLabel: program.statusLabel,
      verifiedAt: program.verifiedAt,
      sourceUrl: program.sourceUrl
    };
    for (const [field, expected] of Object.entries(expectedFields)) {
      if (banner[field] !== expected) errors.push(`${banner.programId}: banner.${field} diferă de registrul unic`);
    }
    if (banner.image !== program.presentation?.image) errors.push(`${banner.programId}: banner.image diferă de registrul unic`);
    if (!entriesByRoute.has(normalizeRoute(banner.ctaLink))) errors.push(`${banner.programId}: banner către rută publică inexistentă (${banner.ctaLink})`);
  }

  for (const field of ["carouselOrder", "heroOrder", "navigationOrder"]) {
    for (const duplicate of duplicateValues(programs.filter((program) => Number.isInteger(program.presentation?.[field])), (program) => program.presentation[field])) {
      errors.push(`presentation.${field} duplicat: ${duplicate}`);
    }
  }
  return errors;
}

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
    const surfaceErrors = registrySurfaceErrors(programs);
    if (surfaceErrors.length) throw new Error(`Relațiile registrului sunt invalide:\n- ${surfaceErrors.join("\n- ")}`);
    const report = humanValidationReport(programs);
    const checkReport = process.argv.includes("--check-report");
    if (checkReport) {
      const current = fs.existsSync(REPORT_PATH) ? fs.readFileSync(REPORT_PATH, "utf8") : "";
      if (normalizeLineEndings(current) !== normalizeLineEndings(report)) {
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

module.exports = { REPORT_PATH, humanValidationReport, pendingFields, registrySurfaceErrors };
