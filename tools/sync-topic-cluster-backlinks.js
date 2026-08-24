#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { isPublicProgram, loadProgramConfig } = require("./program-factual-governance");
const { loadConfig, resolvedLinks } = require("./sync-program-contextual-links");
const { fileForRoute, sitemapRoutes } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const CHECK = process.argv.includes("--check");
const START = "<!-- TOPIC_CLUSTER_BACKLINKS_START -->";
const END = "<!-- TOPIC_CLUSTER_BACKLINKS_END -->";
const STYLESHEET = '<link rel="stylesheet" href="/assets/program-contextual-links.css">';

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function removeBlock(html) {
  return html.replace(new RegExp(`\\s*${START}[\\s\\S]*?${END}\\s*`, "giu"), "\n");
}

function syncStylesheet(html) {
  const matches = html.match(/<link\b[^>]*href=["']\/assets\/program-contextual-links\.css["'][^>]*>/giu) || [];
  if (matches.length === 1) return html;
  const clean = html.replace(/\s*<link\b[^>]*href=["']\/assets\/program-contextual-links\.css["'][^>]*>\s*/giu, "\n");
  return clean.replace(/<\/head>/iu, `  ${STYLESHEET}\n</head>`);
}

function insertBeforeMainEnd(html, block) {
  const governanceIndex = html.indexOf("<!-- EDITORIAL_GOVERNANCE_START -->");
  const mainEndIndex = html.toLocaleLowerCase("en-US").lastIndexOf("</main>");
  const index = governanceIndex >= 0 ? governanceIndex : mainEndIndex;
  if (index < 0) throw new Error("pagina nu conține </main>");
  return `${html.slice(0, index).replace(/\s+$/u, "")}\n${block}\n${html.slice(index)}`;
}

function backlinkGroups(programs, config) {
  const groups = new Map();
  for (const program of programs) {
    for (const link of resolvedLinks(program, config, programs)) {
      if (!["service", "instrument", "guide"].includes(link.relation)) continue;
      if (!groups.has(link.href)) groups.set(link.href, { relations: new Set(), programs: new Map() });
      const group = groups.get(link.href);
      group.relations.add(link.relation);
      group.programs.set(program.id, program);
    }
  }
  return groups;
}

function headingFor(route, relations) {
  if (route === "/calculator-soc") return "Programe pentru care folosești calculatorul SO";
  if (relations.has("service") || route === "/verificare-eligibilitate-fonduri-europene") {
    return "Programe pentru care serviciul este relevant";
  }
  return "Programe asociate acestui ghid";
}

function renderBlock(route, relations, programs) {
  const id = `topic-cluster-${route.replace(/^\/+|\/+$/gu, "").replace(/[^a-z0-9]+/giu, "-") || "home"}`;
  const items = programs.map((program) => `      <li>
        <a class="program-contextual-links__link" href="${escapeHtml(program.pageUrl)}" data-link-type="contextual" data-link-relation="program-backlink" data-target-program-id="${escapeHtml(program.id)}">
          <span class="program-contextual-links__relation">Program asociat</span>
          <span class="program-contextual-links__anchor">${escapeHtml(program.shortName)}</span>
          <span class="program-contextual-links__explanation">Compară statusul, solicitantul și investiția programului cu reperele acestei pagini.</span>
        </a>
      </li>`).join("\n");
  return `${START}
  <section class="program-contextual-links program-contextual-links--backlinks" data-topic-cluster-backlinks="" aria-labelledby="${id}-title">
    <h2 id="${id}-title">${escapeHtml(headingFor(route, relations))}</h2>
    <p>Selecție scurtă derivată din familia și relațiile programelor din registrul verificat.</p>
    <ul class="program-contextual-links__list">
${items}
    </ul>
  </section>
${END}`;
}

function sortPrograms(programs) {
  return [...programs].sort((left, right) =>
    (left.presentation?.navigationOrder ?? Number.MAX_SAFE_INTEGER) - (right.presentation?.navigationOrder ?? Number.MAX_SAFE_INTEGER)
      || left.name.localeCompare(right.name, "ro"));
}

function synchronizedHtml(html, route, group) {
  const clean = removeBlock(html);
  const $ = cheerio.load(clean, { decodeEntities: false });
  const existingTargets = new Set($("main a[href]").toArray().map((element) => $(element).attr("href")));
  const missing = sortPrograms(group.programs.values())
    .filter((program) => !existingTargets.has(program.pageUrl))
    .slice(0, 4);
  if (!missing.length) return clean;
  return syncStylesheet(insertBeforeMainEnd(clean, renderBlock(route, group.relations, missing)));
}

function sameText(left, right) {
  return left.replace(/\r\n/gu, "\n") === right.replace(/\r\n/gu, "\n");
}

function main() {
  const config = loadConfig();
  const programs = loadProgramConfig().programs
    .filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget);
  const programRoutes = new Set(programs.map((program) => program.pageUrl));
  const sitemap = new Set(sitemapRoutes(ROOT));
  const groups = backlinkGroups(programs, config);
  const changed = [];
  let managed = 0;

  for (const [route, group] of groups) {
    if (programRoutes.has(route)) continue;
    if (!sitemap.has(route)) throw new Error(`${route}: destinația topic cluster nu este în sitemap`);
    const file = fileForRoute(ROOT, route);
    if (!fs.existsSync(file)) throw new Error(`${route}: fișier canonic inexistent`);
    const before = fs.readFileSync(file, "utf8");
    const after = synchronizedHtml(before, route, group);
    if (after.includes(START)) managed += 1;
    if (sameText(before, after)) continue;
    changed.push(path.relative(ROOT, file).replace(/\\/gu, "/"));
    if (!CHECK) fs.writeFileSync(file, after, "utf8");
  }

  if (CHECK && changed.length) throw new Error(`Backlinkuri topic cluster nesincronizate:\n- ${changed.join("\n- ")}`);
  console.log(`Topic cluster backlinks ${CHECK ? "PASS" : "sincronizate"}: ${groups.size} destinații derivate, ${managed} blocuri gestionate, ${changed.length} fișiere actualizate.`);
}

if (require.main === module) main();

module.exports = { backlinkGroups, removeBlock, renderBlock, synchronizedHtml };
