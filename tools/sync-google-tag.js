#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { ROOT, findPublicHtmlFiles } = require("./sync-global-header");

const GOOGLE_TAG_ID = "G-P2ZNZV4TNW";
const GOOGLE_TAG_START = "<!-- Google tag (gtag.js) -->";
const GOOGLE_TAG_END = "<!-- /Google tag (gtag.js) -->";
const GOOGLE_TAG_SNIPPET = `${GOOGLE_TAG_START}
<script async src="https://www.googletagmanager.com/gtag/js?id=${GOOGLE_TAG_ID}"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', '${GOOGLE_TAG_ID}');
</script>
${GOOGLE_TAG_END}`;

function count(text, token) {
  return text.split(token).length - 1;
}

function removeGoogleTag(html) {
  return html.replace(
    /(?:\r?\n)?[ \t]*<!-- Google tag \(gtag\.js\) -->[\s\S]*?<!-- \/Google tag \(gtag\.js\) -->[ \t]*(?:\r?\n)?/gi,
    ""
  );
}

function synchronizeGoogleTag(html, relativePath = "pagina HTML") {
  const eol = html.includes("\r\n") ? "\r\n" : "\n";
  const snippet = GOOGLE_TAG_SNIPPET.replace(/\n/g, eol);
  const withoutGoogleTag = removeGoogleTag(html);
  if (!/<head\b[^>]*>/i.test(withoutGoogleTag)) throw new Error(`${relativePath}: lipsește <head>`);
  return withoutGoogleTag.replace(/<head\b[^>]*>/i, (head) => `${head}${eol}${snippet}${eol}`);
}

function validateGoogleTag(html) {
  const errors = [];
  if (count(html, GOOGLE_TAG_START) !== 1) errors.push(`${GOOGLE_TAG_START} nu apare exact o dată`);
  if (count(html, GOOGLE_TAG_END) !== 1) errors.push(`${GOOGLE_TAG_END} nu apare exact o dată`);
  if (count(html, GOOGLE_TAG_ID) !== 2) errors.push(`${GOOGLE_TAG_ID} nu apare exact de două ori`);
  if (!/<head\b[^>]*>\s*<!-- Google tag \(gtag\.js\) -->/i.test(html)) {
    errors.push("Google tag nu este imediat după <head>");
  }
  if (!new RegExp(`gtag\\(['"]config['"],\\s*['"]${GOOGLE_TAG_ID}['"]\\)`).test(html)) {
    errors.push(`lipsește configurarea ${GOOGLE_TAG_ID}`);
  }
  return errors;
}

function main() {
  const check = process.argv.includes("--check");
  const changed = [];
  const invalid = [];
  const publicFiles = findPublicHtmlFiles();

  for (const relativePath of publicFiles) {
    const filePath = path.join(ROOT, ...relativePath.split("/"));
    const before = fs.readFileSync(filePath, "utf8");
    const after = synchronizeGoogleTag(before, relativePath);
    const errors = validateGoogleTag(check ? before : after);
    if (errors.length) invalid.push(`${relativePath}: ${errors.join("; ")}`);
    if (after === before) continue;
    changed.push(relativePath);
    if (!check) fs.writeFileSync(filePath, after, "utf8");
  }

  if (check && (changed.length || invalid.length)) {
    console.error(`Google tag sync FAILED: ${changed.length} pagini nesincronizate, ${invalid.length} pagini invalide.`);
    [...new Set([...changed, ...invalid])].slice(0, 20).forEach((file) => console.error(` - ${file}`));
    process.exitCode = 1;
    return;
  }

  if (invalid.length) {
    console.error(`Google tag sync FAILED: ${invalid.length} pagini invalide.`);
    invalid.slice(0, 20).forEach((error) => console.error(` - ${error}`));
    process.exitCode = 1;
    return;
  }

  console.log(`Google tag sync ${check ? "PASS" : "completat"}: ${publicFiles.length} pagini publice, ${changed.length} fișiere ${check ? "deja conforme" : "actualizate"}.`);
}

if (require.main === module) main();

module.exports = {
  GOOGLE_TAG_END,
  GOOGLE_TAG_ID,
  GOOGLE_TAG_SNIPPET,
  GOOGLE_TAG_START,
  removeGoogleTag,
  synchronizeGoogleTag,
  validateGoogleTag
};
