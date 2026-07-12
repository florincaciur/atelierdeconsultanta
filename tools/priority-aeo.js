#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "priority-pages.json");
const START = "<!-- PRIORITY_AEO_START -->";
const END = "<!-- PRIORITY_AEO_END -->";

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function loadPriorityConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function list(items) {
  return items.map((item) => `          <li>${escapeHtml(item)}</li>`).join("\n");
}

function formatRomanianDate(isoDate) {
  return new Intl.DateTimeFormat("ro-RO", {
    day: "numeric",
    month: "long",
    year: "numeric",
    timeZone: "Europe/Bucharest"
  }).format(new Date(`${isoDate}T12:00:00+03:00`));
}

function renderPriorityAeo(slug, config = loadPriorityConfig()) {
  const page = config.pages[slug];
  if (!page) return "";
  const id = `aeo-${slug}`;
  return `${START}
      <section class="priority-aeo" aria-labelledby="${id}-quick-answer">
        <h2 id="${id}-quick-answer">Răspuns rapid</h2>
        <p>${escapeHtml(page.quickAnswer)}</p>

        <h2 id="${id}-checks">Ce trebuie verificat</h2>
        <ul aria-labelledby="${id}-checks">
${list(page.checks)}
        </ul>

        <h2 id="${id}-documents">Documente de pregătit</h2>
        <ul aria-labelledby="${id}-documents">
${list(page.documents)}
        </ul>

        <h2 id="${id}-risks">Riscuri</h2>
        <ul aria-labelledby="${id}-risks">
${list(page.risks)}
        </ul>

        <aside class="editorial-meta" aria-label="Responsabilitate editorială">
          <dl>
            <div><dt>Autor</dt><dd>${escapeHtml(config.author)}</dd></div>
            <div><dt>Verificator editorial</dt><dd>${escapeHtml(config.reviewer)}</dd></div>
            <div><dt>Ultima verificare</dt><dd><time datetime="${escapeHtml(config.lastVerified)}">${escapeHtml(formatRomanianDate(config.lastVerified))}</time></dd></div>
          </dl>
        </aside>
      </section>
${END}`;
}

function removeExistingBlock(html) {
  const pattern = new RegExp(`${START}[\\s\\S]*?${END}\\s*`, "g");
  return html.replace(pattern, "");
}

function renameLegacyQuickAnswer(html) {
  return html.replace(/(<h2\b[^>]*>)\s*Răspuns rapid\s*(<\/h2>)/i, "$1Context și reguli detaliate$2");
}

function applyPriorityAeo(html, slug, config = loadPriorityConfig()) {
  if (!config.pages[slug]) return html;
  let output = removeExistingBlock(html);
  output = renameLegacyQuickAnswer(output);
  const marker = '<article class="panel">';
  const block = renderPriorityAeo(slug, config);
  if (!output.includes(marker)) throw new Error(`${slug}: nu exista <article class="panel">.`);
  return output.replace(marker, `${marker}\n${block}`);
}

function syncPriorityPages() {
  const config = loadPriorityConfig();
  for (const slug of Object.keys(config.pages)) {
    const file = path.join(ROOT, slug, "index.html");
    const before = fs.readFileSync(file, "utf8");
    const after = applyPriorityAeo(before, slug, config);
    fs.writeFileSync(file, after, "utf8");
    console.log(`${slug}: ${before === after ? "fără modificări" : "actualizat"}`);
  }
}

if (require.main === module) syncPriorityPages();

module.exports = {
  END,
  START,
  applyPriorityAeo,
  loadPriorityConfig,
  renderPriorityAeo,
  renameLegacyQuickAnswer,
  syncPriorityPages
};
