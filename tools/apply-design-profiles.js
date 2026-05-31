#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { CANONICAL_LOGO } = require("./site-logo");

const ROOT = path.resolve(__dirname, "..");
const DESIGN_CSS = '<link rel="stylesheet" href="/assets/design-profiles.css">';
const EXCLUDED_DIRS = new Set([".git", ".github", ".wrangler", "dist", "node_modules", "reports"]);

function* walkHtml(target) {
  const stat = fs.statSync(target);
  if (stat.isFile()) {
    if (target.toLowerCase().endsWith(".html")) yield target;
    return;
  }
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) yield* walkHtml(full);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html")) yield full;
  }
}

function addDesignCss(html) {
  if (html.includes("/assets/design-profiles.css")) return html;
  return html.replace(/<\/head>/i, `  ${DESIGN_CSS}\n</head>`);
}

function normalizeHeaderLogo(html) {
  const logoPatterns = [
    /<a\b(?=[^>]*\bclass="[^"]*\bnav-logo\b[^"]*")(?=[^>]*\bhref="\/")[\s\S]*?<\/a>/gi,
    /<a\b(?=[^>]*\bclass="[^"]*\bbrand\b[^"]*")(?=[^>]*\bhref="\/")[^>]*>\s*FABER\s*<\/a>/gi,
    /<a\b(?=[^>]*\bclass="[^"]*\bnavbar-brand\b[^"]*")(?=[^>]*\bhref="\/")[\s\S]*?<\/a>/gi,
    /<a\b(?=[^>]*\bclass="[^"]*\btopbar-logo\b[^"]*")(?=[^>]*\bhref="\/")[\s\S]*?<\/a>/gi
  ];
  let output = html;
  for (const pattern of logoPatterns) {
    output = output.replace(pattern, CANONICAL_LOGO);
  }
  return output;
}

function cleanEmptyButtons(html) {
  return html
    .replace(/<a\b(?=[^>]*\bclass="[^"]*\bbtn[^"]*")(?=[^>]*\bhref="(?:|#|undefined|null|javascript:void\(0\))")[^>]*>\s*<\/a>/gi, "")
    .replace(/<button\b(?=[^>]*\bclass="[^"]*\bbtn[^"]*")[^>]*>\s*<\/button>/gi, "");
}

function processFile(file) {
  const before = fs.readFileSync(file, "utf8");
  let html = before;
  html = addDesignCss(html);
  html = normalizeHeaderLogo(html);
  html = cleanEmptyButtons(html);
  if (html !== before) fs.writeFileSync(file, html, "utf8");
  return html !== before;
}

let checked = 0;
let touched = 0;

for (const file of walkHtml(ROOT)) {
  checked += 1;
  if (processFile(file)) touched += 1;
}

console.log(`Applied design profiles to ${touched} file(s); checked ${checked} HTML file(s).`);
