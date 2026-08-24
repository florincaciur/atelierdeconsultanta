#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  CONFIG_PATH,
  HUMAN_REVIEW,
  REQUIRED_FIELD_IDS,
  ROOT,
  SURFACES,
  isPublicationApproved,
  loadLegalIdentity,
  publicationIssues
} = require("./legal-identity-governance");

const REPORT_PATH = path.join(ROOT, "reports", "legal-identity-approval.md");

function sameTextContent(actual, expected) {
  const normalize = (value) => String(value).replace(/\r\n?/gu, "\n");
  return normalize(actual) === normalize(expected);
}
const SURFACE_LABELS = Object.freeze({
  footer: "Footer",
  contact: "Contact",
  about: "Despre FABER",
  terms: "Termeni",
  privacy: "Politica de confidențialitate/GDPR",
  automated_emails: "Emailuri automate și formulare",
  contracts_invoices: "Contracte/facturi",
  jsonld_organization: "JSON-LD Organization",
  jsonld_professional_service: "JSON-LD ProfessionalService",
  google_business_profile: "Google Business Profile",
  bing_places: "Bing Places"
});

function escapeCell(value) {
  const text = Array.isArray(value) ? value.join("; ") : String(value ?? "");
  return text.replace(/\|/gu, "\\|").replace(/\r?\n/gu, " ");
}

function report(config) {
  const rows = REQUIRED_FIELD_IDS.map((id) => {
    const field = config.fields[id];
    return `| ${escapeCell(field.label)} | ${escapeCell(field.approvedValue)} | ${escapeCell(field.internalSource)} | ${escapeCell(field.approvedBy)} | ${escapeCell(field.approvedAt)} | ${field.surfaces.map((surface) => SURFACE_LABELS[surface]).join("; ")} |`;
  }).join("\n");
  const candidates = REQUIRED_FIELD_IDS
    .filter((id) => config.fields[id].candidateValues.length)
    .map((id) => `| ${escapeCell(config.fields[id].label)} | ${escapeCell(config.fields[id].candidateValues)} | ${escapeCell(config.fields[id].notes)} |`)
    .join("\n");
  const blockers = publicationIssues(config).map((issue) => `- ${issue}`).join("\n");
  const surfaceRows = SURFACES.map((surface) => {
    const fields = REQUIRED_FIELD_IDS.filter((id) => config.fields[id].surfaces.includes(surface)).map((id) => config.fields[id].label);
    const inventory = {
      footer: "Brand prezent; datele juridice/NAP complete nu sunt încă generate dintr-un registru aprobat.",
      contact: "Publică Gmail și două telefoane; valori candidate, fără dovadă de aprobare în repository.",
      about: "Publică brandul, Gmail și două telefoane ca «date consecvente»; necesită corectare după aprobare.",
      terms: "Folosește afirmația neprobată «persoană juridică română» și nu identifică operatorul contractual complet.",
      privacy: "Folosește brandul drept operator și Gmail pentru contact, fără denumire juridică/CUI/sediu.",
      automated_emails: "Nu au fost găsite șabloane de email; formularele FormSubmit/mailto folosesc Gmail ca destinație.",
      contracts_invoices: "În afara repository-ului; decidentul trebuie să confirme entitatea și să coordoneze actualizarea documentelor operaționale.",
      jsonld_organization: "tools/schema-helpers.js publică brand, Gmail, două telefoane și România; nu publică legalName, taxID sau address.",
      jsonld_professional_service: "Publică Gmail, două telefoane, România și Mo–Fr 09:00–18:00 fără aprobare atașată.",
      google_business_profile: "Profil/URL și acces administrativ neidentificate în repository; actualizare externă după aprobare.",
      bing_places: "Profil/URL și acces administrativ neidentificate în repository; actualizare externă după aprobare."
    }[surface];
    return `| ${SURFACE_LABELS[surface]} | ${fields.join("; ")} | ${inventory} |`;
  }).join("\n");

  return `# Fișă juridică și NAP — aprobare umană obligatorie\n\nStare: **${config.publicationState.toUpperCase()}**. Această fișă este un instrument de colectare și control al datelor; **nu este opinie juridică**. Nicio valoare candidat nu este considerată aprobată.\n\n## Tabel de aprobare\n\n| Câmp | Valoare aprobată | Sursă internă | Aprobat de | Data aprobării | Suprafețe unde apare |\n|---|---|---|---|---|---|\n${rows}\n\n## Valori candidate neaprobate\n\nValorile de mai jos provin din brief sau din codul/site-ul existent. Ele nu trebuie copiate în coloana „Valoare aprobată” fără confirmarea decidentului.\n\n| Câmp | Candidați observați | Condiție/observație |\n|---|---|---|\n${candidates}\n\n## Blocaje de publicare\n\n${blockers}\n\nDeploy-ul site-ului este blocat prin \`npm run validate:legal-identity:publish\` până când toate blocajele sunt rezolvate. Gmail poate fi folosit drept adresă operațională numai dacă aprobarea separată a proprietarului este completată.\n\n## Inventarul suprafețelor\n\n| Suprafață | Câmpuri coordonate | Situație curentă / acțiune după aprobare |\n|---|---|---|\n${surfaceRows}\n\n## Instrucțiuni pentru decident și jurist\n\n1. Înlocuiți fiecare \`${HUMAN_REVIEW}\` numai dintr-o sursă internă controlată și completați nominal aprobatorul și data.\n2. Pentru Registrul Comerțului, adresa publică sau profilurile inexistente, folosiți \`status=not_applicable\` și \`approvedValue=NU_SE_APLICA\`, cu aprobare explicită.\n3. Confirmați separat dacă \`atelier.consultanta@gmail.com\` este adresa operațională a proprietarului.\n4. Juristul confirmă Termenii, politica de confidențialitate, operatorul de date, contractantul și emitentul facturilor.\n5. După aprobare, datele se propagă identic în toate suprafețele inventariate și se verifică profilurile externe.\n`;
}

function writeOrCheck(content, check) {
  if (check) {
    const current = fs.existsSync(REPORT_PATH) ? fs.readFileSync(REPORT_PATH, "utf8") : "";
    if (!sameTextContent(current, content)) throw new Error(`Raport nesincronizat: ${path.relative(ROOT, REPORT_PATH)}`);
    return;
  }
  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  fs.writeFileSync(REPORT_PATH, content, "utf8");
}

function main() {
  try {
    const config = loadLegalIdentity(CONFIG_PATH);
    const check = process.argv.includes("--check-report");
    const publicationGate = process.argv.includes("--publication-gate");
    writeOrCheck(report(config), check);
    if (publicationGate && !isPublicationApproved(config)) {
      throw new Error(`PUBLICARE BLOCATĂ — fișa juridică nu este aprobată:\n- ${publicationIssues(config).join("\n- ")}`);
    }
    console.log(`Fișă juridică validă structural; publicare ${isPublicationApproved(config) ? "aprobată" : "blocată pentru validare umană și aviz juridic"}.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { REPORT_PATH, report };
