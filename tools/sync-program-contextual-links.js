#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { parentForRoute } = require("./breadcrumb-registry");
const { isPublicProgram, loadProgramConfig } = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "program-contextual-links.json");
const REPORT_PATH = path.join(ROOT, "reports", "program-contextual-links-migration-2026-07-21.json");
const START = "<!-- PROGRAM_CONTEXTUAL_LINKS_START -->";
const END = "<!-- PROGRAM_CONTEXTUAL_LINKS_END -->";
const STYLESHEET = '<link rel="stylesheet" href="/assets/program-contextual-links.css">';
const CHECK = process.argv.includes("--check");

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function programFiles(route) {
  const clean = String(route || "").replace(/^\/+|\/+$/gu, "");
  return [...new Set([
    path.join(ROOT, clean, "index.html"),
    path.join(ROOT, `${clean}.html`)
  ])].filter((file) => fs.existsSync(file));
}

function resolvedLinks(program, config = loadConfig()) {
  const row = config.programs?.[program.slug];
  if (!row) throw new Error(`${program.slug}: lipsește din matricea program-contextual-links`);
  const parentRoute = parentForRoute(program.pageUrl);
  const parent = config.parents?.[parentRoute];
  if (!parent) throw new Error(`${program.slug}: părintele ${parentRoute || "lipsește"} nu are copy în matrice`);
  const instrument = config.resources?.[row.instrument];
  const comparison = config.resources?.[row.comparison];
  if (!instrument || !comparison) throw new Error(`${program.slug}: instrument sau comparație nedefinită`);

  return [
    { relation: "parent", href: parentRoute, ...parent },
    { relation: "instrument", ...instrument },
    { relation: "comparison", ...comparison },
    {
      relation: "conversion",
      href: `/contact#program_slug=${encodeURIComponent(program.slug)}&source_page=${encodeURIComponent(program.pageUrl)}`,
      anchor: row.conversionAnchor,
      explanation: row.conversionMicrocopy || "Trimite contextul proiectului pentru o verificare inițială, fără promisiunea eligibilității."
    }
  ];
}

function relationLabel(relation) {
  return {
    parent: "Părinte",
    instrument: "Instrument",
    comparison: "Ghid sau comparație",
    conversion: "Următorul pas"
  }[relation] || relation;
}

function renderProgramContextualLinks(program, config = loadConfig()) {
  const links = resolvedLinks(program, config);
  const items = links.map((link) => {
    const isConversion = link.relation === "conversion";
    const tracking = isConversion
      ? ` data-analytics-event="cta_click" data-analytics-component="program_contextual_cta" data-analytics-cta-id="${escapeHtml(program.slug)}_contextual_conversion" data-analytics-target="/contact" data-analytics-program-slug="${escapeHtml(program.slug)}" data-analytics-program-family="${escapeHtml(program.family)}" data-analytics-cta-view="true" data-analytics-copy-variant="default"`
      : "";
    return `      <li>
        <a class="program-contextual-links__link" href="${escapeHtml(link.href)}" data-link-type="${isConversion ? "conversion" : "contextual"}" data-link-relation="${escapeHtml(link.relation)}"${tracking}>
          <span class="program-contextual-links__relation">${escapeHtml(relationLabel(link.relation))}</span>
          <span class="program-contextual-links__anchor">${escapeHtml(link.anchor)}</span>
          <span class="program-contextual-links__explanation">${escapeHtml(link.explanation)}</span>
        </a>
      </li>`;
  }).join("\n");

  return `${START}
  <section class="program-contextual-links" data-program-contextual-links="" data-program-id="${escapeHtml(program.slug)}" aria-labelledby="program-contextual-${escapeHtml(program.slug)}-title">
    <h2 id="program-contextual-${escapeHtml(program.slug)}-title">Continuă cu traseul potrivit</h2>
    <p>Patru legături intenționate: contextul programului, un instrument, un reper complementar și verificarea proiectului.</p>
    <ul class="program-contextual-links__list">
${items}
    </ul>
  </section>
${END}`;
}

function legacyCounts(html) {
  const $ = cheerio.load(html);
  const blocks = $("main .related-links, main [data-contextual-next-step]");
  return { blocks: blocks.length, links: blocks.find("a[href]").length };
}

function removeManagedBlocks(html) {
  return html
    .replace(new RegExp(`${START}[\\s\\S]*?${END}`, "giu"), "")
    .replace(/\s*<!-- CONTEXTUAL_NEXT_STEP_START -->[\s\S]*?<!-- CONTEXTUAL_NEXT_STEP_END -->\s*/giu, "\n")
    .replace(/\s*<section\b[^>]*data-contextual-next-step[^>]*>[\s\S]*?<\/section>\s*/giu, "\n")
    .replace(/\s*<div\b[^>]*class=["'][^"']*\brelated-links\b[^"']*["'][^>]*>[\s\S]*?<\/div>\s*/giu, "\n")
    .replace(/\s*<p>\s*<a\b(?=[^>]*href=["']\/contact["'])[^>]*>\s*Contact FABER\s*<\/a>\s*<\/p>\s*/giu, "\n");
}

function syncStylesheet(html) {
  const matches = html.match(/<link\b[^>]*href=["']\/assets\/program-contextual-links\.css["'][^>]*>/giu) || [];
  if (matches.length === 1) return html;
  const withoutDuplicates = html.replace(/\s*<link\b[^>]*href=["']\/assets\/program-contextual-links\.css["'][^>]*>\s*/giu, "\n");
  return withoutDuplicates.replace(/<\/head>/iu, `  ${STYLESHEET}\n</head>`);
}

function removeStylesheet(html) {
  return html.replace(/\s*<link\b[^>]*href=["']\/assets\/program-contextual-links\.css["'][^>]*>\s*/giu, "\n");
}

function insertBeforeMainEnd(html, block) {
  const templateSlotIndex = html.indexOf("<!-- PROGRAM_TEMPLATE_GOVERNANCE_SLOT -->");
  const governanceIndex = html.indexOf("<!-- EDITORIAL_GOVERNANCE_START -->");
  const mainEndIndex = html.toLocaleLowerCase("en-US").lastIndexOf("</main>");
  const index = templateSlotIndex < 0 && governanceIndex >= 0
    ? governanceIndex
    : mainEndIndex;
  if (index < 0) throw new Error("pagina nu conține </main>");
  return `${html.slice(0, index).replace(/\s+$/u, "")}\n${block}\n${html.slice(index)}`;
}

function synchronizedHtml(html, program, config = loadConfig()) {
  const clean = removeManagedBlocks(html);
  const withBlock = insertBeforeMainEnd(clean, renderProgramContextualLinks(program, config));
  return syncStylesheet(withBlock);
}

function validateMatrix(programs, config) {
  const programIds = new Set(programs.map((program) => program.slug));
  const matrixIds = new Set(Object.keys(config.programs || {}));
  const missing = [...programIds].filter((id) => !matrixIds.has(id));
  const unknown = [...matrixIds].filter((id) => !programIds.has(id));
  if (missing.length || unknown.length) throw new Error(`Matrice incompletă: lipsesc [${missing.join(", ")}], necunoscute [${unknown.join(", ")}]`);
  for (const program of programs) {
    const links = resolvedLinks(program, config);
    if (links.length !== 4) throw new Error(`${program.slug}: sunt necesare exact patru relații`);
    if (new Set(links.map((link) => link.href)).size !== links.length) throw new Error(`${program.slug}: destinații duplicate`);
  }
}

function main() {
  const config = loadConfig();
  const allPrograms = loadProgramConfig().programs;
  const programs = allPrograms.filter((program) => !program.discovery?.redirectTarget);
  validateMatrix(programs, config);
  const publicPrograms = programs.filter((program) => isPublicProgram(program) && program.discovery?.listed !== false);
  const excludedRoutes = new Set(config.excludedRoutes || []);
  const managedPrograms = publicPrograms.filter((program) => !excludedRoutes.has(program.pageUrl));
  const managedProgramIds = new Set(managedPrograms.map((program) => program.slug));
  const changed = [];
  const migration = [];

  for (const program of allPrograms) {
    for (const file of programFiles(program.pageUrl)) {
      const before = fs.readFileSync(file, "utf8");
      const counts = legacyCounts(before);
      const after = managedProgramIds.has(program.slug)
        ? synchronizedHtml(before, program, config)
        : removeStylesheet(removeManagedBlocks(before));
      if (after !== before) {
        changed.push(path.relative(ROOT, file).replace(/\\/gu, "/"));
        if (!CHECK) fs.writeFileSync(file, after, "utf8");
      }
      migration.push({
        programId: program.slug,
        route: program.pageUrl,
        file: path.relative(ROOT, file).replace(/\\/gu, "/"),
        eligible: managedProgramIds.has(program.slug),
        excludedByEditorialDecision: excludedRoutes.has(program.pageUrl),
        removedManagedBlocks: counts.blocks,
        removedManagedLinks: counts.links,
        resultingRelations: managedProgramIds.has(program.slug) ? resolvedLinks(program, config).map((link) => link.relation) : []
      });
    }
  }

  if (CHECK && changed.length) {
    console.error(`Program contextual links FAIL: ${changed.length} fișiere nesincronizate.`);
    console.error(changed.slice(0, 25).map((file) => `- ${file}`).join("\n"));
    process.exit(1);
  }
  if (!CHECK) {
    fs.writeFileSync(REPORT_PATH, `${JSON.stringify({ generatedAt: "2026-07-21", evidence: config.evidence, files: migration }, null, 2)}\n`, "utf8");
  }
  console.log(`Program contextual links ${CHECK ? "PASS" : "OK"}: ${publicPrograms.length} programe publice, ${managedPrograms.length} cu bloc contextual, ${excludedRoutes.size} excluse editorial, ${migration.length} fișiere, ${changed.length} actualizate.`);
}

if (require.main === module) main();

module.exports = {
  loadConfig,
  renderProgramContextualLinks,
  resolvedLinks,
  removeManagedBlocks,
  removeStylesheet,
  synchronizedHtml,
  validateMatrix
};
