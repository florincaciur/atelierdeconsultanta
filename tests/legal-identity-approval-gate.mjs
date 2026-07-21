#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const {
  HUMAN_REVIEW,
  NOT_APPLICABLE,
  REQUIRED_FIELD_IDS,
  SURFACES,
  approvedIdentity,
  isPublicationApproved,
  loadLegalIdentity,
  publicationIssues,
  validateConfig
} = require("../tools/legal-identity-governance");

const config = loadLegalIdentity();
assert.equal(config.publicationState, "blocked", "Fișa neaprobată trebuie să blocheze publicarea");
assert.equal(config.approvalState, "pending", "Decizia de business nu poate fi presupusă");
assert.equal(config.notLegalOpinion, true, "Livrabilul trebuie delimitat de o opinie juridică");
assert.equal(isPublicationApproved(config), false, "Fișa DE_VALIDAT_UMAN nu poate deveni publicabilă");
assert.equal(approvedIdentity(config), null, "Nu trebuie expusă o identitate canonică înainte de aprobare");
assert.deepEqual(Object.keys(config.fields).sort(), [...REQUIRED_FIELD_IDS].sort(), "Lista câmpurilor juridice trebuie să fie controlată");

for (const [id, field] of Object.entries(config.fields)) {
  assert.equal(field.status, "pending", `${id}: statusul inițial trebuie să rămână pending`);
  assert.equal(field.approvedValue, HUMAN_REVIEW, `${id}: nu trebuie inventată o valoare aprobată`);
  assert.equal(field.approvedBy, HUMAN_REVIEW, `${id}: aprobatorul nu poate fi dedus`);
  assert.equal(field.approvedAt, HUMAN_REVIEW, `${id}: data aprobării nu poate fi dedusă`);
}

assert(config.fields.publicEmail.candidateValues.includes("atelier.consultanta@gmail.com"), "Gmail trebuie inventariat ca simplu candidat");
assert.equal(config.approvals.operationalEmailOwnerConfirmation.state, "pending", "Gmail nu poate fi operațional fără confirmarea proprietarului");
assert(config.fields.publicPhone.candidateValues.includes("+40769828338"), "Primul telefon existent trebuie inventariat");
assert(config.fields.publicPhone.candidateValues.includes("+40753326229"), "Al doilea telefon existent trebuie inventariat");

const coveredSurfaces = new Set(Object.values(config.fields).flatMap((field) => field.surfaces));
for (const surface of SURFACES) assert(coveredSurfaces.has(surface), `Lipsește suprafața obligatorie ${surface}`);

const reportPath = path.join(ROOT, "reports", "legal-identity-approval.md");
assert(fs.existsSync(reportPath), "Lipsește tabelul de aprobare juridică");
const report = fs.readFileSync(reportPath, "utf8");
for (const heading of ["Câmp", "Valoare aprobată", "Sursă internă", "Aprobat de", "Data aprobării", "Suprafețe unde apare"]) {
  assert(report.includes(heading), `Raportul nu conține coloana ${heading}`);
}
for (const surface of ["Footer", "Contact", "Despre FABER", "Termeni", "Politica de confidențialitate/GDPR", "Emailuri automate și formulare", "Contracte/facturi", "JSON-LD Organization", "JSON-LD ProfessionalService", "Google Business Profile", "Bing Places"]) {
  assert(report.includes(surface), `Raportul nu inventariază suprafața ${surface}`);
}
assert(report.includes("nu este opinie juridică"), "Raportul trebuie să conțină delimitarea juridică");

const gate = spawnSync(process.execPath, [path.join(ROOT, "tools", "validate-legal-identity.js"), "--publication-gate", "--check-report"], {
  cwd: ROOT,
  encoding: "utf8"
});
assert.notEqual(gate.status, 0, "Poarta de publicare trebuie să eșueze cât timp fișa este pending");
assert.match(`${gate.stdout}\n${gate.stderr}`, /PUBLICARE BLOCATĂ/iu, "Eșecul trebuie să explice blocarea publicării");

const values = {
  brandName: "Brand de test",
  websiteUrl: "https://example.invalid/",
  legalName: "Entitate de test SRL",
  legalForm: "SRL",
  taxIdentifier: "RO12345678",
  tradeRegisterNumber: NOT_APPLICABLE,
  registeredOffice: "Adresă internă de test",
  publicWorkplaceAddress: NOT_APPLICABLE,
  personalDataController: "Entitate de test SRL",
  contractingEntity: "Entitate de test SRL",
  invoicingEntity: "Entitate de test SRL",
  publicPhone: "+40123456789",
  publicEmail: "contact@example.invalid",
  officialProfileUrls: NOT_APPLICABLE,
  contactHours: "Luni–vineri 09:00–18:00",
  serviceArea: "România"
};
const approved = structuredClone(config);
approved.approvalState = "approved";
approved.publicationState = "approved";
for (const id of REQUIRED_FIELD_IDS) {
  const notApplicable = values[id] === NOT_APPLICABLE;
  Object.assign(approved.fields[id], {
    status: notApplicable ? "not_applicable" : "approved",
    approvedValue: values[id],
    internalSource: "Fixture internă sintetică — nu se publică",
    approvedBy: "Decident fixture",
    approvedAt: "2026-07-21"
  });
}
for (const id of ["businessDecision", "legalReview"]) {
  Object.assign(approved.approvals[id], {
    state: "approved",
    approvedBy: "Aprobator fixture",
    approvedAt: "2026-07-21",
    internalSource: "Fixture internă sintetică — nu se publică"
  });
}
approved.approvals.legalReview.scope = "Fixture: Termeni, confidențialitate, operator, contractant și facturare";
assert.deepEqual(validateConfig(approved), [], "O fișă sintetică complet aprobată trebuie să treacă validarea");
assert.equal(isPublicationApproved(approved), true, "Poarta trebuie să se deschidă numai pentru o fișă completă");

const gmailWithoutOwner = structuredClone(approved);
gmailWithoutOwner.fields.publicEmail.approvedValue = "atelier.consultanta@gmail.com";
assert(publicationIssues(gmailWithoutOwner).some((issue) => /proprietarul.*Gmail/iu.test(issue)), "Gmail trebuie respins fără confirmarea proprietarului");
Object.assign(gmailWithoutOwner.approvals.operationalEmailOwnerConfirmation, {
  state: "approved",
  approvedBy: "Proprietar fixture",
  approvedAt: "2026-07-21",
  internalSource: "Fixture internă sintetică — nu se publică"
});
assert.equal(isPublicationApproved(gmailWithoutOwner), true, "Confirmarea proprietarului trebuie să deblocheze Gmail numai în fixture completă");

const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
for (const deployScript of ["deploy", "deploy:pages"]) {
  assert(packageJson.scripts[deployScript].startsWith("npm run validate:legal-identity:publish &&"), `${deployScript} trebuie să înceapă cu poarta juridică`);
}

console.log(`Poartă identitate juridică: ${REQUIRED_FIELD_IDS.length} câmpuri și ${SURFACES.length} suprafețe rămân blocate până la aprobarea umană și avizul juristului.`);
