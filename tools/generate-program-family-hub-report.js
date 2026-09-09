#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { catalogPrograms, loadProgramConfig } = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_FILE = path.join(ROOT, "config", "program-family-hubs.json");
const REPORT_FILE = path.join(ROOT, "reports", "program-family-hubs-architecture-2026-07-21.md");
const CHECK_ONLY = process.argv.includes("--check");

function tableRows(dictionary) {
  return Object.entries(dictionary).map(([value, label]) => `| \`${value}\` | ${label} |`).join("\n");
}

function report() {
  const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
  const { programs } = loadProgramConfig();
  const catalog = catalogPrograms(programs);
  const hubByRoute = new Map(config.hubs.map((hub) => [hub.route, hub]));
  const routeRationales = {
    "/afir": "Rută canonică și indexabilă deja folosită ca punct de intrare AFIR.",
    "/fonduri-regionale": "Rută canonică existentă pentru familia regională; devine hub, fără schimbare cosmetică de URL.",
    "/fonduri-europene-digitalizare": "Rută canonică existentă, aliniată intenției de familie Digitalizare & inovare.",
    "/finantari-panouri-fotovoltaice": "Ruta performantă existentă este păstrată; H1 lărgește prudent rolul către familia Energie.",
    "/fonduri-europene-imm": "Ruta canonică existentă este păstrată și primește rolul Antreprenoriat & GAL."
  };
  const pending = programs.filter((program) => program.publicationState !== "public");

  return `# P1.03 — Arhitectura hub-urilor Programe

Data deciziei inițiale: 2026-07-21

Revizie catalog și relații family: 2026-08-24

Sursa de configurare: \`config/program-family-hubs.json\`
Sursa programelor: \`config/seo-programs.json\`

## Decizia de URL

Convenția este **păstrarea rutelor canonice existente**. Familia este o proprietate controlată din registru, nu un segment nou impus în URL. Nu se creează rute și nu se implementează redirecturi în P1.03. O schimbare viitoare de rută rămâne blocată până la o mapare source → target și aprobare SEO bazată inclusiv pe date GSC și backlink-uri.

Ruta canonică \`/fonduri-europene\` este catalogul public. Echivalentul repo pentru \`catalogEnabled=true\` este \`discovery.listed=true\`; selecția unică \`catalogPrograms()\` produce în prezent **${catalog.length}** intrări publice, fără redirect targets. Reuniunea cardurilor celor cinci familii trebuie să fie identică acestei selecții.

| Familie | Rută canonică păstrată | Decizie | Redirect | Motiv |
|---|---|---|---|---|
${config.hubs.map((hub) => `| ${hub.label} | \`${hub.route}\` | KEEP / REWRITE | Nu | ${routeRationales[hub.route]} |`).join("\n")}

## Taxonomie controlată

Fiecare program are exact un \`discovery.parentHub\`. Filtrele nu acceptă valori editoriale în HTML; opțiunile sunt calculate din clasificarea registrului și din programele publicabile.

### Tip solicitant

| Valoare | Etichetă publică |
|---|---|
${tableRows(config.filters.applicantTypes)}

### Regiune

| Valoare | Etichetă publică |
|---|---|
${tableRows(config.filters.regions)}

### Tip investiție

| Valoare | Etichetă publică |
|---|---|
${tableRows(config.filters.investmentTypes)}

Statusul folosește exclusiv taxonomia registrului: \`apel_deschis\`, \`ghid_aprobat_nedeschis\`, \`consultare_publica\`, \`calendar_estimativ\`, \`apel_inchis\`, \`arhivat\`.

## Atribuirea programelor

| Program | Pagină | Hub părinte unic | Stare registru | Card public |
|---|---|---|---|---|
${programs.map((program) => {
    const hub = hubByRoute.get(program.discovery.parentHub);
    const card = program.publicationState === "public" && program.discovery.listed !== false ? "Da" : program.discovery.listed === false ? "Nu — pagina este chiar hub-ul" : "Nu — validare umană în așteptare";
    return `| ${program.shortName} | \`${program.pageUrl}\` | ${hub.label} — \`${hub.route}\` | \`${program.publicationState}\` | ${card} |`;
  }).join("\n")}

Înregistrări excluse din cardurile publice până la validare: ${pending.map((program) => `\`${program.slug}\``).join(", ")}.

## Wireframe funcțional

### Desktop

\`\`\`text
┌──────────────────────────────────────────────────────────────────────────┐
│ H1 + introducere 50–80 cuvinte                 [Verifică proiectul]     │
├──────────────────────────────────────────────────────────────────────────┤
│ Tip solicitant │ Regiune │ Tip investiție │ Status │ [Resetează]       │
│ Regiune live: „N programe afișate din N”                                │
├───────────────────────────────────┬──────────────────────────────────────┤
│ Card program                      │ Card program                         │
│ status complet + verificat la     │ status complet + verificat la       │
│ beneficiar + rezumat + sursă      │ beneficiar + rezumat + sursă        │
│ [Vezi condițiile]                 │ [Vezi condițiile]                   │
├───────────────────────────────────┴──────────────────────────────────────┤
│ Cum alegi (3 pași)                         │ CTA verificare proiect     │
├──────────────────────────────────────────────────────────────────────────┤
│ Ghiduri / instrumente relevante │ 5 întrebări reale                    │
└──────────────────────────────────────────────────────────────────────────┘
\`\`\`

### Mobil

\`\`\`text
┌─────────────────────────────┐
│ H1 + introducere            │
│ [Verifică proiectul]        │
├─────────────────────────────┤
│ Tip solicitant              │
│ Regiune                     │
│ Tip investiție              │
│ Status                      │
│ [Resetează]                 │
│ Rezultat aria-live          │
├─────────────────────────────┤
│ Card program                │
│ [Vezi condițiile]           │
├─────────────────────────────┤
│ Cum alegi + CTA             │
├─────────────────────────────┤
│ Resurse + FAQ               │
└─────────────────────────────┘
\`\`\`

## Reguli de publicare și indexare

- cardurile sunt generate numai pentru \`publicationState=public\`, cu \`verifiedAt\`, \`sourceUrl\` și \`sourceVersion\` oficiale;
- beneficiarul este preluat din \`eligibleApplicants\`; dacă registrul nu îl precizează, cardul cere consultarea ghidului și nu inventează o categorie;
- statusul, data verificării, rezumatul și sursa provin din registrul unic;
- filtrele folosesc controale native, actualizează o regiune \`aria-live="polite"\` și păstrează selecția în query string prin \`history.replaceState\`;
- query-urile de filtrare nu sunt linkuri crawlable, iar canonical-ul rămâne ruta hub-ului fără parametri;
- fără JavaScript, toate cardurile și informațiile esențiale rămân vizibile;
- homepage-ul leagă direct cele cinci hub-uri, iar fiecare program public listat este legat din hub: adâncime maximă două clickuri de navigare.

## Copy și întrebări

H1-urile, introducerile, secțiunile „Cum alegi”, cele 25 de întrebări și linkurile strict relevante sunt versionate în \`config/program-family-hubs.json\`. Introducerile au între 50 și 80 de cuvinte, iar fiecare hub are exact 5 întrebări.
`;
}

function main() {
  const content = report();
  const existing = fs.existsSync(REPORT_FILE) ? fs.readFileSync(REPORT_FILE, "utf8") : "";
  if (CHECK_ONLY) {
    if (existing !== content) {
      console.error(`Raportul nu este sincronizat: ${path.relative(ROOT, REPORT_FILE)}`);
      process.exitCode = 1;
      return;
    }
    console.log("Raportul arhitecturii hub-urilor este sincronizat.");
    return;
  }
  fs.mkdirSync(path.dirname(REPORT_FILE), { recursive: true });
  fs.writeFileSync(REPORT_FILE, content, "utf8");
  console.log(`Raport generat: ${path.relative(ROOT, REPORT_FILE)}`);
}

if (require.main === module) main();

module.exports = { report };
