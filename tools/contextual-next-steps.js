#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { isPublicProgram, loadProgramConfig, programForRoute } = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "contextual-next-steps.json");
const START = "<!-- CONTEXTUAL_NEXT_STEP_START -->";
const END = "<!-- CONTEXTUAL_NEXT_STEP_END -->";

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function loadNextStepConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function publicNextStepLinks(page, programs = loadProgramConfig().programs) {
  return (page.links || []).filter((link) => {
    if (!String(link.href || "").startsWith("/")) return true;
    const program = programForRoute(link.href, programs);
    return !program || isPublicProgram(program);
  });
}

function renderNextStepBlock(slug, config = loadNextStepConfig()) {
  const page = config.pages[slug];
  if (!page) return "";
  const id = `next-step-${slug}`;
  const sectionClass = page.layout === "standalone"
    ? "vezi-si-section next-step-block"
    : "next-step-block";
  const links = publicNextStepLinks(page).map((link) => {
    const external = /^https:\/\//u.test(link.href);
    const relation = link.relation || (/^\/contact(?:[?#]|$)/u.test(link.href) ? "conversion" : "editorial");
    const conversion = relation === "conversion";
    const tracking = conversion
      ? ` data-analytics-event="cta_click" data-analytics-component="contextual_cta" data-analytics-cta-id="${escapeHtml(slug)}_contextual_conversion" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="default"`
      : "";
    return `      <li class="see-also-card">
        <a href="${escapeHtml(link.href)}"${external ? ' target="_blank" rel="noopener noreferrer"' : ""} data-link-type="${conversion ? "conversion" : "contextual"}" data-link-relation="${escapeHtml(relation)}"${tracking}>
          <span class="see-also-card-title">${escapeHtml(link.anchor)}</span>
          <span class="see-also-card-text">${escapeHtml(link.explanation)}</span>
        </a>
      </li>`;
  }).join("\n");

  return `${START}
  <section class="${sectionClass}" data-contextual-next-step="" aria-labelledby="${id}-title">
    <h2 id="${id}-title">${escapeHtml(page.title)}</h2>
    <ul class="vezi-si see-also-grid">
${links}
    </ul>
  </section>
${END}`;
}

function replaceLast(html, pattern, replacement) {
  const matches = [...html.matchAll(pattern)];
  if (!matches.length) return null;
  const match = matches.at(-1);
  return `${html.slice(0, match.index)}${replacement}${html.slice(match.index + match[0].length)}`;
}

function applyContextualNextSteps(html, slug, config = loadNextStepConfig()) {
  const page = config.pages[slug];
  if (!page) return html;
  const program = programForRoute(page.route, loadProgramConfig().programs);
  if (program && !isPublicProgram(program)) {
    return html.replace(/<!-- CONTEXTUAL_NEXT_STEP_START -->[\s\S]*?<!-- CONTEXTUAL_NEXT_STEP_END -->\s*/gu, "");
  }
  const block = renderNextStepBlock(slug, config);
  const marked = /<!-- CONTEXTUAL_NEXT_STEP_START -->[\s\S]*?<!-- CONTEXTUAL_NEXT_STEP_END -->/u;
  if (marked.test(html)) return html.replace(marked, block);

  const pattern = page.layout === "standalone"
    ? /<section\b[^>]*class="[^"]*\bvezi-si-section\b[^"]*"[^>]*>[\s\S]*?<\/section>/gu
    : /<div\b[^>]*class="[^"]*\brelated-links\b[^"]*"[^>]*>[\s\S]*?<\/div>/gu;
  const output = replaceLast(html, pattern, block);
  if (output === null) throw new Error(`${page.route}: nu există blocul editorial care trebuie înlocuit.`);
  return output;
}

function syncContextualNextSteps() {
  const config = loadNextStepConfig();
  const managedProgramRoutes = new Set(loadProgramConfig().programs.map((program) => program.pageUrl));
  for (const [slug, page] of Object.entries(config.pages)) {
    if (managedProgramRoutes.has(page.route)) continue;
    const program = programForRoute(page.route, loadProgramConfig().programs);
    if (program && !isPublicProgram(program)) continue;
    const file = path.join(ROOT, page.file);
    const before = fs.readFileSync(file, "utf8");
    const after = applyContextualNextSteps(before, slug, config);
    if (after !== before) fs.writeFileSync(file, after, "utf8");
    console.log(`${page.route}: ${after === before ? "fără modificări" : "actualizat"}`);
  }
}

if (require.main === module) syncContextualNextSteps();

module.exports = {
  END,
  START,
  applyContextualNextSteps,
  loadNextStepConfig,
  publicNextStepLinks,
  renderNextStepBlock,
  syncContextualNextSteps
};
