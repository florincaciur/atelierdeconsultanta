#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "about-faber-governance.json");
const REPORT_PATH = path.join(ROOT, "reports", "about-faber-p1-16.md");
const CHECK = process.argv.includes("--check");

function sameTextContent(actual, expected) {
  const normalize = (value) => String(value).replace(/\r\n?/gu, "\n");
  return normalize(actual) === normalize(expected);
}

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function validateConfig(config) {
  const errors = [];
  if (config.schemaVersion !== 1) errors.push("schemaVersion trebuie să fie 1");
  if (config.pageVersion !== "p1_16") errors.push("pageVersion trebuie să fie p1_16");
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(String(config.updatedAt || ""))) errors.push("updatedAt trebuie să fie ISO YYYY-MM-DD");
  if (config.humanReviewToken !== "DE_VALIDAT_UMAN") errors.push("tokenul de validare umană este invalid");

  const policy = config.publicationPolicy || {};
  for (const key of ["missingFactsStayPrivate", "noInventedPeopleOrExperience", "noEvidenceClaimsWithoutDocumentsAndConsent", "noAfirAccreditationClaim"]) {
    if (policy[key] !== true) errors.push(`politica ${key} trebuie să fie activă`);
  }

  const requiredIds = ["team_profiles", "case_studies_and_results", "afir_nomenclature_listing", "other_affiliations"];
  const validations = Array.isArray(config.pendingValidations) ? config.pendingValidations : [];
  for (const id of requiredIds) {
    const record = validations.find((item) => item.id === id);
    if (!record) {
      errors.push(`lipsește validarea ${id}`);
      continue;
    }
    if (record.status !== config.humanReviewToken) errors.push(`${id}: statusul trebuie să fie DE_VALIDAT_UMAN`);
    if (record.publicationState !== "blocked") errors.push(`${id}: publicarea trebuie blocată`);
    if (!Array.isArray(record.required) || !record.required.length) errors.push(`${id}: lista de dovezi este goală`);
  }
  return errors;
}

function renderReport(config) {
  const validationRows = config.pendingValidations.map((item) => {
    const requirements = item.required.map((value) => `\`${value}\``).join("; ");
    return `| ${item.id} | ${item.status} | ${item.publicationState} | ${requirements} |`;
  }).join("\n");

  return `# P1.16 — Despre FABER: copy, wireframe și validări

Generat din \`config/about-faber-governance.json\` la ${config.updatedAt}. Acest raport este intern; valorile marcate \`DE_VALIDAT_UMAN\` nu sunt randate ca fapte publice.

## Copy public implementat

- Hero: „Consultanță prudentă înainte de dosar”.
- Poziționare: „Verificare prudentă, documentată și interdisciplinară — consultanță și proiectare — înainte de dosar.”
- Operator: randat exclusiv din registrul juridic aprobat \`config/legal-identity.json\`.
- Echipă: politica de publicare și câmpurile necesare sunt explicate, fără nume, fotografii sau experiență presupusă.
- Metodă: triere → documente → punctaj → dosar → clarificări și implementare.
- Limite: fără promisiune de aprobare, fără a echivala listarea cu acreditarea din partea AFIR, fără rezultate neverificate.
- Dovezi: studii de caz, rezultate și testimoniale numai cu documente, metodă și acord.
- CTA: „Vezi dacă proiectul merită pregătit”.

## Wireframe implementat

\`\`\`
[Header + navigație]
[Hero: poziționare | CTA principal | CTA metodă | 4 repere]
[Introducere: ce este FABER | criterii de lucru]
[Operator: entitate, CUI, ONRC, sediu, contact — registru canonic]
[Echipă: politica de publicare | checklist profil aprobat]
[Metodă: 01 Triere → 02 Documente → 03 Punctaj → 04 Dosar → 05 Clarificări/implementare]
[Ce nu promite FABER: 3 limite]
[Dovezi publicabile: studiu de caz | rezultat | testimonial]
[Afilieri/listări: formulare condiționată de document oficial]
[Metodologie | Studii de caz | Contact]
[CTA contextual]
[Întrebări frecvente]
[Footer]
\`\`\`

## Active și dovezi necesare

- Fotografie reală pentru fiecare persoană, fișier original, text alternativ, autor/drept de utilizare și acord scris de publicare.
- Fișă aprobată pentru fiecare persoană: nume, rol, specializări, experiență verificabilă, LinkedIn oficial și paginile de analiză atribuite.
- Pentru studii de caz: documente justificative, program/versiune, perioadă, metodă, acord și regulă de anonimizare.
- Pentru rezultate: baza de calcul, universul analizat, perioada și limitele comparației.
- Pentru nomenclatorul AFIR: URL oficial, document/versiune, dată și potrivirea exactă a FABER PUBLISHING S.R.L.
- Pentru alte afilieri: documentul organizației, valabilitate, entitatea exactă și acordul de publicare.

## Puncte de validare umană

| Înregistrare | Status | Publicare | Date/dovezi necesare |
|---|---|---|---|
${validationRows}

## Poarta de publicare

Până la aprobarea fiecărui rând, site-ul poate afișa doar faptul că informația nu este încă publicată. Nu se publică placeholderul \`DE_VALIDAT_UMAN\`, profiluri parțiale, rezultate, afilieri sau formulări care sugerează acreditare ori clasament.
`;
}

function main() {
  const config = loadConfig();
  const errors = validateConfig(config);
  if (errors.length) {
    console.error("About FABER governance FAILED:");
    errors.forEach((error) => console.error(`- ${error}`));
    process.exit(1);
  }

  const expected = renderReport(config);
  const actual = fs.existsSync(REPORT_PATH) ? fs.readFileSync(REPORT_PATH, "utf8") : "";
  if (CHECK && !sameTextContent(actual, expected)) {
    console.error("About FABER governance FAILED: raportul este absent sau nesincronizat.");
    process.exit(1);
  }
  if (!CHECK && !sameTextContent(actual, expected)) {
    fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
    fs.writeFileSync(REPORT_PATH, expected, "utf8");
  }
  console.log(`About FABER governance PASS: ${config.pendingValidations.length} grupe rămân DE_VALIDAT_UMAN și blocate de la publicare.`);
}

if (require.main === module) main();

module.exports = { loadConfig, renderReport, validateConfig };
