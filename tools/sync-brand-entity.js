#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { ROOT, findPublicHtmlFiles } = require("./sync-global-header");
const { approvedIdentity, loadLegalIdentity } = require("./legal-identity-governance");
const { FILE: PRIVACY_FILE, renderPrivacyPolicy } = require("./privacy-policy");

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

  if (relativePath === PRIVACY_FILE) output = renderPrivacyPolicy(output, ROOT, identity);

  if (relativePath === "termeni-si-conditii.html") {
    output = replaceKnownStatement(
      output,
      "<li><strong>„FABER\"</strong> — FABER – Atelier de Consultanță, persoană juridică română, cu activitate de consultanță în accesarea fondurilor europene nerambursabile;</li>",
      `<li><strong>„FABER”</strong> — brandul ${identity.brandName}, sub care ${identity.contractingEntity} prezintă serviciile de consultanță și coordonare a proiectării;</li>\n        <li><strong>„Prestator”</strong> — ${identity.contractingEntity}, entitatea juridică ce încheie contractele și emite facturile pentru serviciile asumate;</li>`,
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
