#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG = path.join(ROOT, "config", "priority-conversion-pages.json");
const START = "<!-- PRIORITY_CONVERSION_START -->";
const END = "<!-- PRIORITY_CONVERSION_END -->";
const CHECK = process.argv.includes("--check");

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function contactHref(page) {
  const params = new URLSearchParams({ program_slug: page.programSlug, source_page: page.route });
  return `/contact#${params.toString()}`;
}

function render(page) {
  const steps = page.steps.map(([title, copy], index) => `<li><span>${index + 1}</span><div><strong>${esc(title)}</strong><small>${esc(copy)}</small></div></li>`).join("\n      ");
  const external = /^https?:\/\//i.test(page.secondaryHref);
  return `${START}
<section class="priority-conversion priority-conversion--${esc(page.family)}" data-priority-conversion="${esc(page.id)}" aria-labelledby="priority-conversion-${esc(page.id)}">
  <p class="priority-conversion__eyebrow">${esc(page.eyebrow)}</p>
  <h2 id="priority-conversion-${esc(page.id)}">${esc(page.title)}</h2>
  <p class="priority-conversion__lead">${esc(page.lead)}</p>
  <ol class="priority-conversion__steps">
      ${steps}
  </ol>
  <div class="priority-conversion__actions">
    <a class="btn btn-primary" href="${esc(contactHref(page))}" data-analytics-event="cta_click" data-analytics-component="priority_conversion" data-analytics-cta-id="${esc(page.id)}_priority_conversion" data-analytics-target="/contact" data-analytics-program-slug="${esc(page.programSlug)}">${esc(page.primaryLabel)}</a>
    <a class="btn btn-secondary" href="${esc(page.secondaryHref)}"${external ? ' target="_blank" rel="noopener noreferrer"' : ""} data-analytics-event="cta_click" data-analytics-component="priority_conversion_secondary" data-analytics-cta-id="${esc(page.id)}_priority_secondary" data-analytics-target="${esc(page.secondaryHref)}">${esc(page.secondaryLabel)}</a>
  </div>
  <p class="priority-conversion__note">${esc(page.note)}</p>
</section>
${END}`;
}

function synchronize(source, page) {
  const markerPattern = new RegExp(`${START}[\\s\\S]*?${END}\\s*`, "u");
  const assetPattern = /\s*<link\b[^>]*href=["']\/assets\/priority-program-conversion\.css[^>]*>\s*/giu;
  let output = source.replace(markerPattern, "").replace(assetPattern, "\n");
  output = output.replace("</head>", '  <link rel="stylesheet" href="/assets/priority-program-conversion.css?v=20260815-1">\n</head>');
  const anchors = [
    /<section\s+class=["'][^"']*\bcta-box\b/iu,
    /<!-- PROGRAM_CONTEXTUAL_LINKS_START -->/u,
    /<\/article>/iu,
    /<\/main>/iu
  ];
  const insertionIndex = anchors.map((pattern) => output.search(pattern)).find((index) => index >= 0);
  if (insertionIndex == null) throw new Error(`${page.file}: reperul de inserare nu a fost găsit`);
  return `${output.slice(0, insertionIndex)}${render(page)}\n${output.slice(insertionIndex)}`;
}

function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG, "utf8"));
  const changed = [];
  for (const page of config.pages) {
    const file = path.join(ROOT, page.file);
    const before = fs.readFileSync(file, "utf8");
    const after = synchronize(before, page);
    if (after !== before) {
      changed.push(page.file);
      if (!CHECK) fs.writeFileSync(file, after, "utf8");
    }
  }
  if (CHECK && changed.length) throw new Error(`Blocuri de conversie nesincronizate: ${changed.join(", ")}`);
  console.log(`Blocuri de conversie prioritare: ${config.pages.length} pagini${changed.length ? `, ${changed.length} actualizate` : ""}.`);
}

if (require.main === module) main();
module.exports = { contactHref, render, synchronize };
