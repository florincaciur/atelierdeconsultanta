#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "seo-programs.json");
const BANNERS_PATH = path.join(ROOT, "banners.json");
const HUMAN_REVIEW = "DE_VALIDAT_UMAN";

const STATUS_MAP = Object.freeze({
  open: "apel_deschis",
  final: "ghid_aprobat_nedeschis",
  consultation: "consultare_publica",
  draft: "consultare_publica",
  announced: "calendar_estimativ",
  unknown: "calendar_estimativ",
  closed: "apel_inchis",
  archived: "arhivat"
});

const STATUS_LABELS = Object.freeze({
  apel_deschis: "Apel deschis",
  ghid_aprobat_nedeschis: "Ghid aprobat – depunerea nu este deschisă",
  consultare_publica: "Consultare publică – depunerea nu este deschisă",
  calendar_estimativ: "Calendar estimativ – depunerea nu este confirmată",
  apel_inchis: "Apel închis",
  arhivat: "Arhivat"
});

const FAMILY_BY_ID = Object.freeze({
  "program-regional-nord-est": "regional-adr",
  "fonduri-regionale": "regional-adr",
  "dr12-afir": "afir-agricultura",
  "dr14-afir": "afir-agricultura",
  "start-up-nation": "antreprenoriat",
  "femeia-antreprenor": "antreprenoriat",
  "digitalizare-imm": "digitalizare",
  "modernizare-microintreprinderi-ne-2": "regional-adr",
  "fondul-modernizare-autoconsum": "energie",
  "fondul-modernizare-regenerabile": "energie",
  "afir-energie-autoconsum": "afir-energie",
  "autoconsum-institutii-publice": "energie-public",
  "pro-infra": "infrastructura",
  "apeluri-gal": "afir-leader",
  "gal-afir-leader": "afir-leader",
  "e-move-ro": "mobilitate-energie",
  "pocidif-21": "digitalizare-inovare"
});

const HERO_ROUTES = new Set([
  "/afir-autoconsum-agroalimentar",
  "/dr12-afir",
  "/dr14",
  "/e-move",
  "/pro-infra",
  "/pocidif-21",
  "/start-up-nation-2026",
  "/programul-tranzitie-justa",
  "/investitii-modernizarea-microintreprinderilor-apel-2"
]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function hasValue(value) {
  if (value === null || value === undefined || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

function grantSummary(program) {
  if (![program.minimumGrant, program.maximumGrant, program.budget].some(hasValue)) return null;
  return {
    minimum: program.minimumGrant ?? null,
    maximum: program.maximumGrant ?? null,
    budget: program.budget ?? null
  };
}

function cofinancingSummary(program) {
  if (![program.intensity, program.ownContribution].some(hasValue)) return null;
  return {
    intensity: program.intensity ?? null,
    ownContribution: program.ownContribution ?? null
  };
}

function presentationFor(program, banner) {
  return {
    carousel: Boolean(banner),
    hero: HERO_ROUTES.has(program.route),
    order: Number.isFinite(Number(banner?.order)) ? Number(banner.order) : 999,
    icon: banner?.icon || "ph-file-text",
    image: banner?.image || null,
    beneficiary: null
  };
}

function migrateProgram(program, bannersByProgram) {
  if (program.slug && program.pageUrl && program.status) return program;
  const slug = program.id;
  const status = STATUS_MAP[program.sourceStatus];
  if (!status) throw new Error(`Nu există mapare de status pentru ${slug}: ${program.sourceStatus}`);
  const needsExplicitHumanReview = slug === "dr12-afir";
  const sourceUrl = needsExplicitHumanReview ? HUMAN_REVIEW : program.officialSourceUrl;
  const sourceVersion = needsExplicitHumanReview ? HUMAN_REVIEW : program.sourceDocumentName;
  const verifiedAt = needsExplicitHumanReview ? HUMAN_REVIEW : program.reviewedAt;
  const migrated = {
    slug,
    name: program.officialName,
    shortName: program.shortName,
    family: FAMILY_BY_ID[slug] || "alte-programe",
    status,
    statusLabel: slug === "dr12-afir"
      ? "Ghid consultativ – depunerea nu este deschisă"
      : STATUS_LABELS[status],
    publicationState: needsExplicitHumanReview ? "pending_validation" : "public",
    verifiedAt,
    sourceName: program.authority,
    sourceUrl,
    sourceVersion,
    sourceType: "official",
    applicationStart: program.applicationStart ?? null,
    applicationEnd: program.applicationEnd ?? null,
    grantSummary: needsExplicitHumanReview ? null : grantSummary(program),
    cofinancingSummary: needsExplicitHumanReview ? null : cofinancingSummary(program),
    pageUrl: program.route,
    lastMeaningfulUpdate: needsExplicitHumanReview ? HUMAN_REVIEW : program.reviewedAt,
    evergreenValue: true,
    archivedNoindexDecision: null,
    cardSummary: needsExplicitHumanReview
      ? "Statutul, documentul și data de verificare pentru DR12 așteaptă confirmarea responsabilului editorial."
      : program.metaDescription,
    metaTitle: needsExplicitHumanReview
      ? "DR12 AFIR – informații în validare editorială | FABER"
      : program.metaTitle,
    metaDescription: needsExplicitHumanReview
      ? "Pagina DR12 este temporar în validare editorială. Statutul, documentul oficial și data vor fi publicate numai după confirmarea umană."
      : program.metaDescription,
    editorialDisclaimer: needsExplicitHumanReview
      ? "Nu publicați statutul, documentul, datele sau valorile înainte de confirmarea responsabilului editorial."
      : program.factualDisclaimer,
    eligibleApplicants: needsExplicitHumanReview ? [] : (program.eligibleApplicants || []),
    keyConditions: needsExplicitHumanReview ? [] : (program.keyConditions || []),
    officialGuideKeys: program.officialGuideKeys || [],
    presentation: presentationFor(program, bannersByProgram.get(slug))
  };
  if (needsExplicitHumanReview) {
    migrated.pendingValidation = {
      requestedFields: ["status", "sourceUrl", "sourceVersion", "verifiedAt", "lastMeaningfulUpdate"],
      candidateStatus: status,
      candidateSourceUrl: program.officialSourceUrl,
      candidateSourceVersion: program.sourceDocumentName,
      candidateVerifiedAt: program.reviewedAt,
      note: "Confirmare umană obligatorie înainte de revenirea publicationState la public."
    };
  }
  return migrated;
}

function pendingProgram({ slug, name, shortName, family, pageUrl, candidateSourceUrl }) {
  return {
    slug,
    name,
    shortName,
    family,
    status: "calendar_estimativ",
    statusLabel: "Calendar estimativ – depunerea nu este confirmată",
    publicationState: "pending_validation",
    verifiedAt: HUMAN_REVIEW,
    sourceName: HUMAN_REVIEW,
    sourceUrl: HUMAN_REVIEW,
    sourceVersion: HUMAN_REVIEW,
    sourceType: "official",
    applicationStart: null,
    applicationEnd: null,
    grantSummary: null,
    cofinancingSummary: null,
    pageUrl,
    lastMeaningfulUpdate: HUMAN_REVIEW,
    evergreenValue: true,
    archivedNoindexDecision: null,
    cardSummary: "Statutul și documentul oficial sunt în validare editorială.",
    metaTitle: `${shortName} – informații în validare editorială | FABER`,
    metaDescription: `Informațiile curente despre ${shortName} vor fi publicate după validarea sursei oficiale de către responsabilul editorial.`,
    editorialDisclaimer: "Nu publicați statutul, datele sau valorile înainte de confirmarea responsabilului editorial.",
    eligibleApplicants: [],
    keyConditions: [],
    officialGuideKeys: [],
    presentation: { carousel: false, hero: false, order: 999, icon: "ph-file-text", image: null, beneficiary: null },
    pendingValidation: {
      requestedFields: ["status", "sourceName", "sourceUrl", "sourceVersion", "verifiedAt", "lastMeaningfulUpdate"],
      candidateSourceUrl,
      note: "Înregistrare creată dintr-o suprafață homepage care nu avea corespondent în registrul vechi."
    }
  };
}

function hasLocalProgramFact(value) {
  const text = String(value || "");
  return /(?:\d[\d.\s]*(?:€|EUR|euro|lei|RON|%)|apel(?:ul)?\s+(?:este\s+)?deschis|variant(?:a|ă)\s+consultativ|ghid(?:ul)?\s+(?:este\s+)?final)/iu.test(text);
}

function sanitizeProgramPages(config, programs) {
  const byPageUrl = new Map(programs.map((program) => [program.pageUrl, program]));
  for (const page of config.pages || []) {
    const program = byPageUrl.get(`/${String(page.slug || "").replace(/^\/+/, "")}`);
    if (!program) continue;
    page.programId = program.slug;
    page.factualGovernanceRef = `#/programs/${program.slug}`;
    for (const key of ["programName", "title", "description", "funding", "programStatus", "applicationWindow", "quickAnswer", "cofinancingRows"]) {
      delete page[key];
    }
    if (Array.isArray(page.applicantRows)) {
      page.applicantRows = page.applicantRows.filter((row) => !hasLocalProgramFact(Array.isArray(row) ? row.join(" ") : row));
    }
    if (Array.isArray(page.faq)) {
      page.faq = page.faq.filter((entry) => {
        const text = Array.isArray(entry) ? entry.join(" ") : JSON.stringify(entry);
        return !hasLocalProgramFact(text) && !/(?:care este statutul|când se deschide|cand se deschide|este ghidul final|este apelul deschis)/iu.test(text);
      });
    }
  }
  return config;
}

function migrate(config, banners) {
  const bannersByProgram = new Map((banners || []).filter((banner) => banner.programId).map((banner) => [banner.programId, banner]));
  const programs = (config.programs || []).map((program) => migrateProgram(program, bannersByProgram));
  const existing = new Set(programs.map((program) => program.slug));
  const additions = [
    pendingProgram({
      slug: "pnrr",
      name: "Planul Național de Redresare și Reziliență",
      shortName: "PNRR",
      family: "pnrr",
      pageUrl: "/pnrr",
      candidateSourceUrl: "https://mfe.gov.ro/pnrr/"
    }),
    pendingProgram({
      slug: "programul-tranzitie-justa",
      name: "Programul Tranziție Justă",
      shortName: "Programul Tranziție Justă",
      family: "tranzitie-justa",
      pageUrl: "/programul-tranzitie-justa",
      candidateSourceUrl: HUMAN_REVIEW
    }),
    pendingProgram({
      slug: "fondul-de-modernizare",
      name: "Fondul pentru Modernizare",
      shortName: "Fondul pentru Modernizare",
      family: "energie",
      pageUrl: "/fondul-de-modernizare",
      candidateSourceUrl: "https://energie.gov.ro/category/fondul-pentru-modernizare/"
    })
  ];
  for (const program of additions) if (!existing.has(program.slug)) programs.push(program);
  config.$schema = "./program-registry.schema.json";
  config.programs = programs;
  return sanitizeProgramPages(config, programs);
}

function main() {
  const check = process.argv.includes("--check");
  const config = readJson(CONFIG_PATH);
  const banners = fs.existsSync(BANNERS_PATH) ? readJson(BANNERS_PATH) : [];
  const before = `${JSON.stringify(config, null, 2)}\n`;
  const migrated = migrate(config, banners);
  const after = `${JSON.stringify(migrated, null, 2)}\n`;
  if (before === after) {
    console.log("Registrul programelor este deja migrat.");
    return;
  }
  if (check) {
    console.error("Registrul programelor necesită migrare: node scripts/migrate-program-registry.js");
    process.exitCode = 1;
    return;
  }
  fs.writeFileSync(CONFIG_PATH, after, "utf8");
  console.log(`Registru migrat: ${migrated.programs.length} programe; datele factuale locale au fost eliminate din paginile asociate.`);
}

if (require.main === module) main();

module.exports = { HUMAN_REVIEW, STATUS_LABELS, migrate, migrateProgram, sanitizeProgramPages };
