#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { ROOT, findPublicHtmlFiles } = require("./sync-global-header");
const { loadLegalIdentity } = require("./legal-identity-governance");
const { renderFooterContact, renderLegalIdentityPanel } = require("./canonical-contact");

const CHECK = process.argv.includes("--check");
const START = "<!-- CANONICAL_CONTACT_START -->";
const END = "<!-- CANONICAL_CONTACT_END -->";
const BLOCK = new RegExp(`${START}[\\s\\S]*?${END}`, "gu");
const LEGAL_START = "<!-- CANONICAL_LEGAL_IDENTITY_START -->";
const LEGAL_END = "<!-- CANONICAL_LEGAL_IDENTITY_END -->";
const ABOUT_LEGAL_SLOT = "<!-- CANONICAL_LEGAL_IDENTITY_SLOT -->";
const LEGAL_BLOCK = new RegExp(`${LEGAL_START}[\\s\\S]*?${LEGAL_END}`, "gu");
const LEGAL_SURFACES = new Set([
  "despre-faber.html",
  "despre-faber/index.html",
  "contact.html",
  "contact/index.html",
  "politica-de-confidentialitate.html",
  "politica-de-confidentialitate/index.html",
  "termeni-si-conditii.html",
  "termeni-si-conditii/index.html"
]);

function synchronize(html, footerContact, legalIdentityPanel = "", aboutLegalIdentityPanel = "") {
  let output = html.replace(BLOCK, "").replace(LEGAL_BLOCK, "");
  if (legalIdentityPanel && output.includes(ABOUT_LEGAL_SLOT)) {
    output = output.replace(
      ABOUT_LEGAL_SLOT,
      `${ABOUT_LEGAL_SLOT}\n${aboutLegalIdentityPanel || legalIdentityPanel}`
    );
  } else if (legalIdentityPanel && /<\/main>/iu.test(output)) {
    output = output.replace(/<\/main>/iu, `${legalIdentityPanel}\n</main>`);
  }
  if (!/<footer\b/iu.test(output)) return output;
  return output.replace(/<\/footer>/iu, `${footerContact}</footer>`);
}

function main() {
  const identity = loadLegalIdentity();
  const footerContact = renderFooterContact(identity);
  const legalIdentityPanel = renderLegalIdentityPanel(identity);
  const aboutLegalIdentityPanel = renderLegalIdentityPanel(identity, {
    titleId: "about-operator-title",
    sectionId: "about-public-data",
    title: "Cine este operatorul FABER",
    kicker: "Entitatea care contractează și facturează",
    className: "about-operator-card"
  });
  const changed = [];

  for (const relativePath of findPublicHtmlFiles()) {
    const file = path.join(ROOT, ...relativePath.split("/"));
    const before = fs.readFileSync(file, "utf8");
    const selectedLegalPanel = relativePath === "despre-faber/index.html"
      ? aboutLegalIdentityPanel
      : legalIdentityPanel;
    const after = synchronize(
      before,
      footerContact,
      LEGAL_SURFACES.has(relativePath) ? selectedLegalPanel : "",
      selectedLegalPanel
    );
    if (before === after) continue;
    changed.push(relativePath);
    if (!CHECK) fs.writeFileSync(file, after, "utf8");
  }

  if (CHECK && changed.length) {
    console.error(`Canonical contact sync FAILED: ${changed.length} pagini nesincronizate.`);
    changed.slice(0, 20).forEach((file) => console.error(`- ${file}`));
    process.exit(1);
  }

  console.log(`Canonical contact ${CHECK ? "PASS" : "sincronizat"}: ${changed.length} pagini ${CHECK ? "nesincronizate" : "actualizate"}; datele neaprobate nu sunt randate.`);
}

if (require.main === module) main();

module.exports = { synchronize };
