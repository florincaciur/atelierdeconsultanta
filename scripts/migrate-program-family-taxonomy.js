#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const REGISTRY_FILE = path.join(ROOT, "config", "seo-programs.json");

const assignments = {
  "program-regional-nord-est": ["/fonduri-regionale", ["nespecificat"], ["nord_est"], ["investitii_productive"]],
  "fonduri-regionale": ["/fonduri-regionale", ["nespecificat"], ["regional"], ["investitii_productive"], false],
  "dr12-afir": ["/afir", ["fermieri_agroalimentar"], ["national"], ["agricultura"]],
  "dr14-afir": ["/afir", ["fermieri_agroalimentar"], ["national"], ["agricultura"]],
  "start-up-nation": ["/fonduri-europene-imm", ["imm_micro"], ["national"], ["antreprenoriat"]],
  "femeia-antreprenor": ["/fonduri-europene-imm", ["imm_micro"], ["national"], ["antreprenoriat"]],
  "digitalizare-imm": ["/fonduri-europene-digitalizare", ["imm_micro"], ["national"], ["digitalizare"]],
  "modernizare-microintreprinderi-ne-2": ["/fonduri-regionale", ["imm_micro"], ["nord_est"], ["investitii_productive"]],
  "fondul-modernizare-autoconsum": ["/finantari-panouri-fotovoltaice", ["nespecificat"], ["national"], ["energie_autoconsum"]],
  "fondul-modernizare-regenerabile": ["/finantari-panouri-fotovoltaice", ["nespecificat"], ["national"], ["energie_regenerabila"]],
  "afir-energie-autoconsum": ["/afir", ["fermieri_agroalimentar"], ["national"], ["energie_autoconsum"]],
  "autoconsum-institutii-publice": ["/finantari-panouri-fotovoltaice", ["institutii_publice"], ["national"], ["energie_autoconsum"]],
  "pro-infra": ["/fonduri-regionale", ["nespecificat"], ["national"], ["infrastructura"]],
  "apeluri-gal": ["/fonduri-europene-imm", ["beneficiari_gal"], ["local_gal"], ["dezvoltare_locala"]],
  "gal-afir-leader": ["/fonduri-europene-imm", ["beneficiari_gal"], ["local_gal"], ["dezvoltare_locala"]],
  "e-move-ro": ["/finantari-panouri-fotovoltaice", ["nespecificat"], ["national"], ["mobilitate"]],
  "pocidif-21": ["/fonduri-europene-digitalizare", ["imm_micro"], ["national"], ["digitalizare", "inovare"]],
  "pnrr": ["/fonduri-europene-digitalizare", ["nespecificat"], ["national"], ["digitalizare"]],
  "programul-tranzitie-justa": ["/fonduri-regionale", ["nespecificat"], ["regional"], ["investitii_productive"]],
  "fondul-de-modernizare": ["/finantari-panouri-fotovoltaice", ["nespecificat"], ["national"], ["energie_autoconsum", "energie_regenerabila"]]
};

function main() {
  const registry = JSON.parse(fs.readFileSync(REGISTRY_FILE, "utf8"));
  const slugs = new Set(registry.programs.map((program) => program.slug));
  const missing = Object.keys(assignments).filter((slug) => !slugs.has(slug));
  const unassigned = [...slugs].filter((slug) => !assignments[slug]);
  if (missing.length || unassigned.length) {
    throw new Error(`Migrare incompletă. Lipsesc din registru: ${missing.join(", ") || "-"}; fără atribuire: ${unassigned.join(", ") || "-"}.`);
  }

  for (const program of registry.programs) {
    const [parentHub, applicantTypes, regions, investmentTypes, listed = true] = assignments[program.slug];
    program.discovery = { parentHub, applicantTypes, regions, investmentTypes, listed };
  }
  registry.lastReviewed = "2026-07-21";
  fs.writeFileSync(REGISTRY_FILE, `${JSON.stringify(registry, null, 2)}\n`, "utf8");
  console.log(`Taxonomie de descoperire migrată pentru ${registry.programs.length} programe.`);
}

if (require.main === module) main();

module.exports = { assignments };
