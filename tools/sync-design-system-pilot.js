"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const STYLESHEET = '<link rel="stylesheet" href="/assets/design-system.css?v=20260721-1" data-design-system-stylesheet="p1_07">';
const TARGETS = [
  "index.html",
  path.join("contact", "index.html"),
  "contact.html",
  path.join("afir-autoconsum-agroalimentar", "index.html"),
  "afir-autoconsum-agroalimentar.html"
];

function synchronizeHtml(source, relativePath) {
  const stylesheetPattern = /<link\b[^>]*data-design-system-stylesheet=["']p1_07["'][^>]*>/gi;
  const existingStylesheets = source.match(stylesheetPattern) || [];
  let output = source;
  if (!/<\/head>/i.test(output)) throw new Error(`${relativePath}: lipsește </head>.`);
  if (!/<body\b[^>]*>/i.test(output)) throw new Error(`${relativePath}: lipsește <body>.`);

  const stylesheetIsCanonical = existingStylesheets.length === 1
    && existingStylesheets[0].includes('href="/assets/design-system.css?v=20260721-1"');
  if (!stylesheetIsCanonical) {
    output = output.replace(/\s*<link\b[^>]*data-design-system-stylesheet=["']p1_07["'][^>]*>/gi, "");
    if (/<script\b[^>]*src=["']\/assets\/lead-attribution\.js[^>]*>/i.test(output)) {
      output = output.replace(/(<script\b[^>]*src=["']\/assets\/lead-attribution\.js[^>]*>)/i, `  ${STYLESHEET}\n  $1`);
    } else {
      output = output.replace(/<\/head>/i, `  ${STYLESHEET}\n</head>`);
    }
  }

  const bodyTag = output.match(/<body\b[^>]*>/i)[0];
  if (!/\sdata-design-system=["']p1_07["']/i.test(bodyTag)) {
    output = output.replace(/<body\b([^>]*)>/i, (_match, attributes) => {
      const clean = attributes.replace(/\s+data-design-system=(?:"[^"]*"|'[^']*')/gi, "");
      return `<body${clean} data-design-system="p1_07">`;
    });
  }
  return output;
}

function main() {
  const stale = [];
  for (const relativePath of TARGETS) {
    const file = path.join(ROOT, relativePath);
    const before = fs.readFileSync(file, "utf8");
    const after = synchronizeHtml(before, relativePath);
    if (after !== before) {
      stale.push(relativePath.replace(/\\/g, "/"));
      if (!CHECK_ONLY) fs.writeFileSync(file, after, "utf8");
    }
  }

  if (CHECK_ONLY && stale.length) {
    throw new Error(`Pilotul P1.07 nu este sincronizat: ${stale.join(", ")}. Rulează npm run sync:design-system-pilot.`);
  }
  console.log(CHECK_ONLY
    ? `Design system pilot sync PASS (${TARGETS.length} fișiere).`
    : `Design system pilot sincronizat (${TARGETS.length} fișiere${stale.length ? `, ${stale.length} actualizate` : ", fără modificări"}).`);
}

if (require.main === module) main();

module.exports = { STYLESHEET, TARGETS, synchronizeHtml };
