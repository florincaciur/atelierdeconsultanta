#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { ROOT, findPublicHtmlFiles } = require("./sync-global-header");
const { approvedIdentity, loadLegalIdentity } = require("./legal-identity-governance");

const CHECK = process.argv.includes("--check");
const LEGACY_BRAND_NAMES = [
  "FABER - Atelier de Consultanță",
  "FABER - Atelier de Consultanta"
];
const LEGACY_EMAIL = "atelier.consultanță@gmail.com";

function replaceKnownStatement(html, legacy, canonical, relativePath) {
  if (legacy instanceof RegExp && legacy.test(html)) return html.replace(legacy, canonical);
  if (typeof legacy === "string" && html.includes(legacy)) return html.replaceAll(legacy, canonical);
  if (html.replace(/\r\n/gu, "\n").includes(canonical)) return html;
  throw new Error(`${relativePath}: formularea juridică a ieșit din contractul de sincronizare.`);
}

function synchronize(html, relativePath, identity) {
  let output = html;
  for (const legacyName of LEGACY_BRAND_NAMES) {
    output = output.replaceAll(legacyName, identity.brandName);
  }
  output = output.replaceAll(LEGACY_EMAIL, identity.publicEmail);

  if (relativePath === "politica-de-confidentialitate.html") {
    output = replaceKnownStatement(
      output,
      "<p>Operatorul de date cu caracter personal este <strong>FABER – Atelier de Consultanță</strong>, cu activitate în domeniul consultanței pentru fonduri europene nerambursabile.</p>",
      `<p>Operatorul de date cu caracter personal este <strong>${identity.personalDataController}</strong>. Site-ul și serviciile sunt prezentate sub brandul <strong>${identity.brandName}</strong>, iar entitatea care contractează și facturează este <strong>${identity.contractingEntity}</strong>.</p>`,
      relativePath
    );
  }

  if (relativePath === "termeni-si-conditii.html") {
    output = replaceKnownStatement(
      output,
      "<li><strong>„FABER\"</strong> — FABER – Atelier de Consultanță, persoană juridică română, cu activitate de consultanță în accesarea fondurilor europene nerambursabile;</li>",
      `<li><strong>„FABER”</strong> — brandul ${identity.brandName}, sub care ${identity.contractingEntity} prezintă serviciile de consultanță și coordonare a proiectării;</li>\n        <li><strong>„Prestator”</strong> — ${identity.contractingEntity}, entitatea juridică ce încheie contractele și emite facturile pentru serviciile asumate;</li>`,
      relativePath
    );
  }

  if (relativePath === "gdpr.html") {
    output = replaceKnownStatement(
      output,
      /FABER – Atelier de Consultanță respectă toate prevederile GDPR\s+și îți garantează controlul deplin asupra datelor tale personale\./u,
      `${identity.personalDataController} este operatorul de date pentru acest site și aplică regulile GDPR\n        activităților prezentate sub brandul ${identity.brandName}. Drepturile și modalitățile de exercitare sunt explicate mai jos.`,
      relativePath
    );
  }

  return output;
}

function main() {
  const identity = approvedIdentity(loadLegalIdentity());
  if (!identity) throw new Error("Identitatea juridică nu este aprobată pentru publicare.");
  const changed = [];

  for (const relativePath of findPublicHtmlFiles()) {
    const file = path.join(ROOT, ...relativePath.split("/"));
    const before = fs.readFileSync(file, "utf8");
    const after = synchronize(before, relativePath, identity);
    if (before === after) continue;
    changed.push(relativePath);
    if (!CHECK) fs.writeFileSync(file, after, "utf8");
  }

  if (CHECK && changed.length) {
    console.error(`Brand/entity sync FAILED: ${changed.length} pagini nesincronizate.`);
    changed.slice(0, 30).forEach((file) => console.error(`- ${file}`));
    process.exitCode = 1;
    return;
  }

  console.log(`Brand/entity ${CHECK ? "PASS" : "sincronizat"}: ${changed.length} pagini ${CHECK ? "nesincronizate" : "actualizate"}; brandul și entitatea juridică rămân distincte.`);
}

if (require.main === module) main();

module.exports = { LEGACY_BRAND_NAMES, LEGACY_EMAIL, synchronize };
