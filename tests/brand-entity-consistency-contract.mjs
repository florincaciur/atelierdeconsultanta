#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PUBLIC_ROOT = process.argv.includes("--dist") ? path.join(REPO_ROOT, "dist") : REPO_ROOT;
const { findPublicHtmlFiles } = require("../tools/sync-global-header");
const { approvedIdentity, loadLegalIdentity } = require("../tools/legal-identity-governance");
const { LEGACY_BRAND_NAMES, LEGACY_EMAIL } = require("../tools/sync-brand-entity");
const { ORGANIZATION_ID } = require("../tools/schema-helpers");

const identity = approvedIdentity(loadLegalIdentity());
assert(identity, "Identitatea aprobată trebuie să existe înaintea auditului public.");

function read(relativePath) {
  return fs.readFileSync(path.join(PUBLIC_ROOT, ...relativePath.split("/")), "utf8");
}

function routeFile(route) {
  if (route === "/") return "index.html";
  const slug = route.replace(/^\//u, "");
  const candidates = [`${slug}/index.html`, `${slug}.html`];
  const match = candidates.find((relativePath) => fs.existsSync(path.join(PUBLIC_ROOT, ...relativePath.split("/"))));
  assert(match, `${route}: lipsește sursa HTML publică.`);
  return match;
}

function graphNodes($) {
  const nodes = [];
  $("script[type='application/ld+json']").each((_, script) => {
    const parsed = JSON.parse($(script).html());
    nodes.push(...(Array.isArray(parsed?.["@graph"]) ? parsed["@graph"] : [parsed]));
  });
  return nodes;
}

function hasType(node, type) {
  return (Array.isArray(node?.["@type"]) ? node["@type"] : [node?.["@type"]]).includes(type);
}

const publicFiles = findPublicHtmlFiles(PUBLIC_ROOT);
assert(publicFiles.length >= 100, "Auditul de identitate trebuie să acopere întregul site public.");

for (const relativePath of publicFiles) {
  const html = read(relativePath);
  for (const legacyName of LEGACY_BRAND_NAMES) {
    assert(!html.includes(legacyName), `${relativePath}: variantă de brand necanonică: ${legacyName}`);
  }
  assert(!html.includes(LEGACY_EMAIL), `${relativePath}: adresa de email este afișată cu diacritică.`);

  const fullBrandForms = html.match(/FABER\s*[-–—]\s*Atelier de Consultan(?:ță|ta)/gu) || [];
  for (const brandForm of fullBrandForms) {
    assert.equal(brandForm, identity.brandName, `${relativePath}: numele complet al brandului trebuie să fie exact.`);
  }

  const $ = cheerio.load(html);
  $("a[href^='tel:']").each((_, anchor) => {
    const phone = $(anchor).attr("href").slice(4);
    assert([identity.publicPhone, ...(loadLegalIdentity().approvedContactChannels?.additionalPhones || [])].includes(phone), `${relativePath}: telefon public neaprobat ${phone}`);
  });
  $("a[href^='mailto:']").each((_, anchor) => {
    const email = $(anchor).attr("href").slice(7).split("?")[0];
    if (/atelier|faber/iu.test(email)) assert.equal(email, identity.publicEmail, `${relativePath}: email FABER contradictoriu.`);
  });
}

const keySurfaces = [
  "/",
  "/despre-faber",
  "/contact",
  "/politica-de-confidentialitate",
  "/termeni-si-conditii",
  "/gdpr"
].map(routeFile);
for (const relativePath of keySurfaces) {
  const $ = cheerio.load(read(relativePath));
  const organization = graphNodes($).find((node) => node?.["@id"] === ORGANIZATION_ID && hasType(node, "Organization"));
  assert(organization, `${relativePath}: Organization canonic lipsește.`);
  assert(hasType(organization, "ProfessionalService"), `${relativePath}: Organization și ProfessionalService trebuie să descrie aceeași entitate.`);
  assert.equal(organization.name, identity.brandName, `${relativePath}: nume Organization divergent.`);
  assert.equal(organization.legalName, identity.legalName, `${relativePath}: legalName divergent.`);
  assert.equal(organization.email, identity.publicEmail, `${relativePath}: email Organization divergent.`);
  assert.equal(organization.taxID, identity.taxIdentifier, `${relativePath}: CUI Organization divergent.`);
  const schemaPhones = [identity.publicPhone, ...loadLegalIdentity().approvedContactChannels.additionalPhones]
    .map((phone) => phone.replace(/^\+40(\d{3})(\d{3})(\d{3})$/u, "+40-$1-$2-$3"));
  assert.deepEqual(organization.telephone, schemaPhones, `${relativePath}: telefoane Organization divergente.`);
}

const legalPanelSurfaces = [...new Set([
  routeFile("/despre-faber"),
  routeFile("/contact"),
  routeFile("/politica-de-confidentialitate"),
  routeFile("/termeni-si-conditii"),
  routeFile("/gdpr")
])];
for (const relativePath of legalPanelSurfaces) {
  const $ = cheerio.load(read(relativePath));
  const panel = $("[data-canonical-legal-identity='approved']");
  assert.equal(panel.length, 1, `${relativePath}: panoul juridic canonic lipsește sau este duplicat.`);
  const panelText = panel.text().replace(/\s+/gu, " ");
  for (const value of [
    identity.legalName,
    identity.taxIdentifier,
    identity.tradeRegisterNumber,
    identity.registeredOffice,
    identity.publicWorkplaceAddress,
    identity.personalDataController,
    identity.publicEmail
  ]) {
    assert(panelText.includes(value), `${relativePath}: panoul juridic nu conține ${value}.`);
  }
}

const about = cheerio.load(read(routeFile("/despre-faber")));
const aboutText = about("main").text().replace(/\s+/gu, " ");
for (const required of [
  "FABER este brandul sub care FABER PUBLISHING S.R.L.",
  "servicii de consultanță și coordonare a proiectării",
  "documentul oficial aplicabil",
  "Nu promitem aprobarea",
  "Cine lucrează la proiect",
  "Vezi dacă proiectul merită pregătit"
]) {
  assert(aboutText.includes(required), `Despre FABER: lipsește explicația obligatorie „${required}”.`);
}
assert.equal(about(".about-team img").length, 0, "Echipa nu poate conține fotografii neverificate.");
assert(!graphNodes(about).some((node) => hasType(node, "Person")), "Schema Person nu poate fi publicată fără profil aprobat.");

const privacyText = cheerio.load(read(routeFile("/politica-de-confidentialitate")))("#operator").text().replace(/\s+/gu, " ");
assert(privacyText.includes(`Operatorul de date cu caracter personal este ${identity.personalDataController}`), "Politica trebuie să numească operatorul aprobat.");
assert(privacyText.includes(`brandul ${identity.brandName}`), "Politica trebuie să separe brandul de operator.");
assert(privacyText.includes(`entitatea care contractează și facturează este ${identity.contractingEntity}`), "Politica trebuie să numească entitatea contractuală.");

const termsText = cheerio.load(read(routeFile("/termeni-si-conditii")))("main").text().replace(/\s+/gu, " ");
assert(termsText.includes(`FABER” — brandul ${identity.brandName}`), "Termenii trebuie să definească FABER drept brand.");
assert(termsText.includes(`Prestator” — ${identity.contractingEntity}`), "Termenii trebuie să definească separat entitatea juridică.");
assert(!termsText.includes(`${identity.brandName}, persoană juridică`), "Brandul nu poate fi descris drept persoană juridică.");

const gdprText = cheerio.load(read(routeFile("/gdpr")))("main").text().replace(/\s+/gu, " ");
assert(gdprText.includes(`${identity.personalDataController} este operatorul de date pentru acest site`), "GDPR trebuie să numească operatorul aprobat.");
assert(!gdprText.includes("garantează controlul deplin"), "GDPR nu trebuie să formuleze o garanție absolută.");

console.log(`Brand/entity contract PASS (${process.argv.includes("--dist") ? "dist" : "source"}): ${publicFiles.length} fișiere publice, ${keySurfaces.length} suprafețe structurale și ${legalPanelSurfaces.length} panouri juridice validate.`);
