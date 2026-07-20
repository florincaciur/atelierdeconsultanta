#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "priority-pages.json");
const START = "<!-- ANSWER_READINESS_START -->";
const END = "<!-- ANSWER_READINESS_END -->";
const LEGACY_START = "<!-- PRIORITY_AEO_START -->";
const LEGACY_END = "<!-- PRIORITY_AEO_END -->";

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

function formatRomanianDate(isoDate) {
  return new Intl.DateTimeFormat("ro-RO", {
    day: "numeric",
    month: "long",
    year: "numeric",
    timeZone: "Europe/Bucharest"
  }).format(new Date(`${isoDate}T12:00:00+03:00`));
}

function renderFacts(items) {
  return items.map((item) => `          <div>
            <dt>${escapeHtml(item.term)}</dt>
            <dd>${escapeHtml(item.description)}</dd>
          </div>`).join("\n");
}

function renderPriorityAeo(slug, config = loadPriorityConfig()) {
  const page = config.pages[slug];
  if (!page) return "";
  const id = `answer-readiness-${slug}`;
  const reviewed = page.lastReviewed || config.lastReviewed || config.lastVerified;
  const source = `      <p class="source-note answer-readiness__source"><strong>Sursă oficială:</strong> <a href="${escapeHtml(page.source.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(page.source.document)}</a>. <strong>Instituție:</strong> ${escapeHtml(page.source.institution)}. <strong>Statut:</strong> ${escapeHtml(page.source.status)} <strong>Ultima verificare:</strong> <time datetime="${escapeHtml(reviewed)}">${escapeHtml(formatRomanianDate(reviewed))}</time>.</p>${page.interpretation ? `

      <aside aria-labelledby="${id}-interpretation">
        <h3 id="${id}-interpretation">Interpretarea FABER</h3>
        <p>${escapeHtml(page.interpretation)}</p>
      </aside>` : ""}`;
  const facts = `      <dl class="answer-readiness__facts" aria-labelledby="${id}-conditions">
${renderFacts(page.facts)}
      </dl>`;
  const directClass = page.presentation === "compact-disclosure" ? " class=\"answer-readiness__direct\"" : "";
  const directAnswer = `      <p${directClass} data-answer-readiness-direct="" data-information-status="${escapeHtml(page.source.status)}">${escapeHtml(page.directAnswer)}</p>`;
  const content = page.presentation === "compact-disclosure"
    ? `${directAnswer}

      <h2 id="${id}-conditions">${escapeHtml(page.sectionTitle)}</h2>

      <details class="answer-readiness__details" data-non-faq="">
        <summary>
          <span>Vezi criteriile verificate înainte de depunere</span>
          <span class="answer-readiness__summary-meta">8 criterii + sursa oficială</span>
        </summary>
        <div class="answer-readiness__details-body">
${facts}

${source}
        </div>
      </details>`
    : `${directAnswer}

      <h2 id="${id}-conditions">${escapeHtml(page.sectionTitle)}</h2>
${facts}

${source}`;
  const modifier = page.presentation === "compact-disclosure" ? " answer-readiness--compact" : "";

  if (page.layout === "standalone") {
    return `${START}
  <section class="section answer-readiness${modifier}" aria-labelledby="${id}-conditions">
    <div class="container">
${content}
    </div>
  </section>
${END}`;
  }

  return `${START}
    <section class="answer-readiness${modifier}" aria-labelledby="${id}-conditions">
${content}
    </section>
${END}`;
}

function removeMarkedBlock(html, start, end) {
  const pattern = new RegExp(`${start}[\\s\\S]*?${end}\\s*`, "g");
  return html.replace(pattern, "");
}

function removeExistingBlock(html) {
  return removeMarkedBlock(removeMarkedBlock(html, START, END), LEGACY_START, LEGACY_END);
}

function removeCompactCalculatorSummaries(html) {
  return html
    .replace(/<aside class="audit-design-summary"[\s\S]*?<\/aside>\s*/i, "")
    .replace(/<section id="seo-plan-calculator-soc"[\s\S]*?<\/section>\s*/i, "")
    .replace(/<section class="program-cluster"[\s\S]*?(?=<section class="vezi-si-section")/i, "");
}

function ensureCalculatorMain(html) {
  if (/<main\b/i.test(html)) return html;
  const heroMarker = '<header class="hero';
  const footerMarker = '<footer class="page-footer">';
  if (!html.includes(heroMarker) || !html.includes(footerMarker)) {
    throw new Error("calculator-soc: nu pot delimita conținutul principal.");
  }
  return html
    .replace(heroMarker, `<main id="main-content">\n${heroMarker}`)
    .replace(footerMarker, `</main>\n\n${footerMarker}`);
}

function renameLegacyQuickAnswer(html) {
  return html
    .replace(/(<h2\b[^>]*>)\s*Răspuns rapid\s*(<\/h2>)/gi, "$1Context și reguli detaliate$2")
    .replace(/(<h2\b[^>]*>)\s*Răspuns scurt\s*(<\/h2>)/gi, "$1Statutul documentației programului$2");
}

function insertAfterHero(html, block, slug) {
  const opening = /<header\b[^>]*class="[^"]*\bhero\b[^"]*"[^>]*>/i.exec(html);
  if (!opening) throw new Error(`${slug}: nu există un header hero pentru inserare.`);
  const closeIndex = html.indexOf("</header>", opening.index + opening[0].length);
  if (closeIndex === -1) throw new Error(`${slug}: header-ul hero nu este închis.`);
  const end = closeIndex + "</header>".length;
  return `${html.slice(0, end)}\n${block}\n${html.slice(end).replace(/^\s+/, "")}`;
}

function applyPriorityAeo(html, slug, config = loadPriorityConfig()) {
  const page = config.pages[slug];
  if (!page) return html;
  let output = removeExistingBlock(html);
  output = renameLegacyQuickAnswer(output);
  if (slug === "calculator-soc") {
    output = removeCompactCalculatorSummaries(output);
    output = ensureCalculatorMain(output);
  }
  const block = renderPriorityAeo(slug, config);

  if (page.beforeMarker) {
    if (!output.includes(page.beforeMarker)) throw new Error(`${slug}: lipsește marcajul de inserare ${page.beforeMarker}.`);
    return output.replace(page.beforeMarker, `${block}\n    ${page.beforeMarker}`);
  }
  if (page.afterHero) return insertAfterHero(output, block, slug);

  const marker = '<article class="panel">';
  if (!output.includes(marker)) throw new Error(`${slug}: nu există <article class="panel">.`);
  return output.replace(marker, `${marker}\n${block}`);
}

function fileForPage(slug, page) {
  return path.join(ROOT, page.file || path.join(slug, "index.html"));
}

function syncPriorityPages() {
  const config = loadPriorityConfig();
  for (const [slug, page] of Object.entries(config.pages)) {
    const file = fileForPage(slug, page);
    const before = fs.readFileSync(file, "utf8");
    const after = applyPriorityAeo(before, slug, config);
    if (after !== before) fs.writeFileSync(file, after, "utf8");
    console.log(`${page.route}: ${before === after ? "fără modificări" : "actualizat"}`);
  }
}

if (require.main === module) syncPriorityPages();

module.exports = {
  END,
  START,
  applyPriorityAeo,
  fileForPage,
  loadPriorityConfig,
  renderPriorityAeo,
  renameLegacyQuickAnswer,
  syncPriorityPages
};
