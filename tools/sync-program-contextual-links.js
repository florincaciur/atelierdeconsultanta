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

function intersection(left = [], right = []) {
  const rightSet = new Set(right);
  return left.filter((value) => rightSet.has(value));
}

function relatedPrograms(program, programs = loadProgramConfig().programs) {
  const parentHub = program.discovery?.parentHub;
  const parentRoute = parentForRoute(program.pageUrl);
  if (!parentHub) return [];
  return programs
    .filter((candidate) => candidate.id !== program.id
      && isPublicProgram(candidate)
      && !candidate.discovery?.redirectTarget
      && candidate.pageUrl !== parentRoute
      && candidate.discovery?.parentHub === parentHub)
    .map((candidate) => ({
      candidate,
      score: (intersection(program.discovery?.investmentTypes, candidate.discovery?.investmentTypes).length * 4)
        + (intersection(program.discovery?.applicantTypes, candidate.discovery?.applicantTypes).length * 2)
        + intersection(program.discovery?.regions, candidate.discovery?.regions).length
    }))
    .sort((left, right) => right.score - left.score
      || (left.candidate.presentation?.navigationOrder ?? Number.MAX_SAFE_INTEGER) - (right.candidate.presentation?.navigationOrder ?? Number.MAX_SAFE_INTEGER)
      || left.candidate.name.localeCompare(right.candidate.name, "ro"))
    .slice(0, 4)
    .map(({ candidate }) => ({
      relation: "related",
      href: candidate.pageUrl,
      programId: candidate.id,
      anchor: `compară cu ${candidate.shortName}`,
      explanation: `Program din aceeași familie; compară solicitantul, investiția, stadiul oficial și documentele aplicabile.`
    }));
}

function relevantService(program, config) {
  const key = config.serviceByProgram?.[program.id] || config.serviceByParent?.[program.discovery?.parentHub];
  const service = config.services?.[key];
  if (!service) throw new Error(`${program.slug}: serviciul relevant nu poate fi derivat`);
  return { relation: "service", ...service };
}

function programFiles(route) {
  const clean = String(route || "").replace(/^\/+|\/+$/gu, "");
  return [...new Set([
    path.join(ROOT, clean, "index.html"),
    path.join(ROOT, `${clean}.html`)
  ])].filter((file) => fs.existsSync(file));
}

function resolvedLinks(program, config = loadConfig(), programs = loadProgramConfig().programs) {
  const row = config.programs?.[program.id];
  if (!row) throw new Error(`${program.slug}: lipsește din matricea program-contextual-links`);
  const parentRoute = parentForRoute(program.pageUrl);
  const parent = config.parents?.[parentRoute];
  if (!parent) throw new Error(`${program.slug}: părintele ${parentRoute || "lipsește"} nu are copy în matrice`);
  const instrument = config.resources?.[row.instrument];
  if (!instrument) throw new Error(`${program.slug}: instrument nedefinit`);
  const related = relatedPrograms(program, programs);
  const service = relevantService(program, config);
  const reserved = new Set([parentRoute, ...related.map((link) => link.href), service.href, instrument.href]);
  const guideKey = [row.comparison, config.fallbackGuide]
    .find((key) => config.resources?.[key] && !reserved.has(config.resources[key].href));
  const guide = config.resources?.[guideKey];
  if (!guide) throw new Error(`${program.slug}: ghid relevant nedefinit sau duplicat`);

  return [
    { relation: "parent", href: parentRoute, ...parent },
    ...related,
    service,
    { relation: "instrument", ...instrument },
    { relation: "guide", ...guide },
    {
      relation: "conversion",
      href: `/contact#program_slug=${encodeURIComponent(row.contactProgramSlug || program.slug)}&source_page=${encodeURIComponent(program.pageUrl)}`,
      anchor: row.conversionAnchor,
      explanation: row.conversionMicrocopy || "Trimite contextul proiectului pentru o verificare inițială, fără promisiunea eligibilității."
    }
  ];
}

function relationLabel(relation) {
  return {
    parent: "Familie",
    related: "Program asociat",
    service: "Serviciu relevant",
    instrument: "Instrument",
    guide: "Ghid relevant",
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
    const targetProgram = link.programId ? ` data-target-program-id="${escapeHtml(link.programId)}"` : "";
    return `      <li>
        <a class="program-contextual-links__link" href="${escapeHtml(link.href)}" data-link-type="${isConversion ? "conversion" : "contextual"}" data-link-relation="${escapeHtml(link.relation)}"${targetProgram}${tracking}>
          <span class="program-contextual-links__relation">${escapeHtml(relationLabel(link.relation))}</span>
          <span class="program-contextual-links__anchor">${escapeHtml(link.anchor)}</span>
          <span class="program-contextual-links__explanation">${escapeHtml(link.explanation)}</span>
        </a>
      </li>`;
  }).join("\n");

  return `${START}
  <section class="program-contextual-links" data-program-contextual-links="" data-program-id="${escapeHtml(program.id)}" aria-labelledby="program-contextual-${escapeHtml(program.slug)}-title">
    <h2 id="program-contextual-${escapeHtml(program.slug)}-title">Continuă cu traseul potrivit</h2>
    <p>Compară familia și programele apropiate, apoi folosește serviciul, instrumentul și ghidul relevante înainte de verificarea proiectului.</p>
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
  const programIds = new Set(programs.map((program) => program.id));
  const matrixIds = new Set(Object.keys(config.programs || {}));
  const missing = [...programIds].filter((id) => !matrixIds.has(id));
  const unknown = [...matrixIds].filter((id) => !programIds.has(id));
  if (missing.length || unknown.length) throw new Error(`Matrice incompletă: lipsesc [${missing.join(", ")}], necunoscute [${unknown.join(", ")}]`);
  for (const program of programs) {
    const links = resolvedLinks(program, config, programs);
    const related = links.filter((link) => link.relation === "related");
    const availableRelated = programs.filter((candidate) => candidate.id !== program.id
      && isPublicProgram(candidate)
      && !candidate.discovery?.redirectTarget
      && candidate.pageUrl !== parentForRoute(program.pageUrl)
      && candidate.discovery?.parentHub === program.discovery?.parentHub).length;
    const expectedRelated = Math.min(4, availableRelated);
    if (related.length !== expectedRelated || (availableRelated >= 2 && related.length < 2)) {
      throw new Error(`${program.slug}: ${related.length} programe asociate, necesar ${expectedRelated}`);
    }
    for (const relation of ["parent", "service", "instrument", "guide", "conversion"]) {
      if (links.filter((link) => link.relation === relation).length !== 1) throw new Error(`${program.slug}: relația ${relation} trebuie să fie unică`);
    }
    if (new Set(links.map((link) => link.href)).size !== links.length) throw new Error(`${program.slug}: destinații duplicate`);
  }
}

function main() {
  const config = loadConfig();
  const allPrograms = loadProgramConfig().programs;
  const programs = allPrograms.filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget);
  validateMatrix(programs, config);
  const publicPrograms = programs;
  const excludedRoutes = new Set(config.excludedRoutes || []);
  const managedPrograms = publicPrograms.filter((program) => !excludedRoutes.has(program.pageUrl));
  const managedProgramIds = new Set(managedPrograms.map((program) => program.id));
  const changed = [];
  const migration = [];

  for (const program of allPrograms) {
    for (const file of programFiles(program.pageUrl)) {
      const before = fs.readFileSync(file, "utf8");
      const counts = legacyCounts(before);
      const after = managedProgramIds.has(program.id)
        ? synchronizedHtml(before, program, config)
        : removeStylesheet(removeManagedBlocks(before));
      if (after !== before) {
        changed.push(path.relative(ROOT, file).replace(/\\/gu, "/"));
        if (!CHECK) fs.writeFileSync(file, after, "utf8");
      }
      migration.push({
        programId: program.id,
        route: program.pageUrl,
        file: path.relative(ROOT, file).replace(/\\/gu, "/"),
        eligible: managedProgramIds.has(program.id),
        excludedByEditorialDecision: excludedRoutes.has(program.pageUrl),
        removedManagedBlocks: counts.blocks,
        removedManagedLinks: counts.links,
        resultingRelations: managedProgramIds.has(program.id) ? resolvedLinks(program, config).map((link) => link.relation) : []
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
