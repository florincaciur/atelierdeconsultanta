#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  ROOT,
  fundingSummary,
  loadProgramConfig,
  programForRoute,
  programIndexes,
  renderProgramFactualStatus,
  statusLabel,
  statusStatement
} = require("./program-factual-governance");

const FILES = Object.freeze({
  config: path.join(ROOT, "config", "seo-programs.json"),
  guides: path.join(ROOT, "official-guides.json"),
  banners: path.join(ROOT, "banners.json"),
  priority: path.join(ROOT, "config", "priority-pages.json"),
  snippets: path.join(ROOT, "config", "seo-snippets.json"),
  header: path.join(ROOT, "partials", "global-header.html"),
  llms: path.join(ROOT, "llms.txt")
});

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function jsonText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function updateJsonFile(file, transform) {
  if (!fs.existsSync(file)) return null;
  const before = fs.readFileSync(file, "utf8");
  const value = JSON.parse(before);
  const after = jsonText(transform(value));
  return { file, before, after };
}

function syncSeoConfig(config, programs) {
  const byRoute = programIndexes(programs).byRoute;
  for (const page of config.pages || []) {
    if (page.redirectTo) continue;
    const program = byRoute.get(`/${page.slug}`);
    if (!program) continue;
    page.programId = program.id;
    page.factualGovernanceRef = `#/programs/${program.id}`;
    page.programName = program.shortName;
    page.title = program.metaTitle;
    page.description = program.metaDescription;
    page.sourceKeys = [...(program.officialGuideKeys || [])];
    delete page.funding;
    delete page.programStatus;
    delete page.applicationWindow;
  }
  return config;
}

function syncGuides(guides, programs) {
  const programsByKey = new Map();
  for (const program of programs) {
    for (const key of program.officialGuideKeys || []) {
      if (!programsByKey.has(key)) programsByKey.set(key, []);
      programsByKey.get(key).push(program);
    }
  }

  for (const [key, linkedPrograms] of programsByKey) {
    const primary = linkedPrograms.find((program) => program.officialGuideKeys?.[0] === key);
    const entry = typeof guides[key] === "string" ? { url: guides[key] } : (guides[key] || {});
    entry.programIds = [...new Set(linkedPrograms.map((program) => program.id))];
    if (primary) {
      entry.name = primary.sourceDocumentName;
      entry.title = primary.sourceDocumentName;
      entry.institution = primary.authority;
      entry.url = primary.officialSourceUrl;
      entry.accessedAt = primary.reviewedAt;
      entry.sourceStatus = primary.sourceStatus;
      entry.reviewedAt = primary.reviewedAt;
      entry.isPrimaryFor = primary.id;
    }
    guides[key] = entry;
  }
  return guides;
}

function syncBanners(banners, programs) {
  const byId = programIndexes(programs).byId;
  for (const banner of banners) {
    const program = byId.get(banner.programId) || programForRoute(banner.ctaLink || banner.href, programs);
    if (!program) continue;
    if (!banner.ctaLink) banner.ctaLink = program.route;
    banner.programId = program.id;
    banner.sourceStatus = program.sourceStatus;
    banner.reviewedAt = program.reviewedAt;
    banner.officialSourceUrl = program.officialSourceUrl;
    banner.sourceDocumentName = program.sourceDocumentName;
    banner.applicationStart = program.applicationStart;
    banner.applicationEnd = program.applicationEnd;
    banner.factualDisclaimer = program.factualDisclaimer;
    banner.description = program.metaDescription;
    banner.amount = fundingSummary(program);
    if (program.officialGuideKeys?.length) banner.officialGuideKey = program.officialGuideKeys[0];
  }
  return banners;
}

function syncPriority(priority, programs) {
  for (const page of Object.values(priority.pages || {})) {
    const program = programForRoute(page.route, programs);
    if (!program) continue;
    page.programId = program.id;
    page.lastReviewed = program.reviewedAt;
    page.source = {
      document: program.sourceDocumentName,
      institution: program.authority,
      status: `${statusStatement(program)} ${program.factualDisclaimer}`.trim(),
      url: program.officialSourceUrl
    };
  }
  return priority;
}

function syncSnippets(snippets, programs) {
  const records = Array.isArray(snippets) ? snippets : snippets.pages || snippets.routes || [];
  for (const item of records) {
    const program = programForRoute(item.route, programs);
    if (!program) continue;
    item.title = program.metaTitle;
    item.description = program.metaDescription;
    item.ogTitle = program.metaTitle;
    item.ogDescription = program.metaDescription;
    item.sourceOfTruth = ["config/seo-programs.json#programs", program.officialSourceUrl];
    item.factualStatus = program.sourceStatus;
    item.lastReviewed = program.reviewedAt;
  }
  return snippets;
}

function syncHeaderText(source, programs) {
  const $ = cheerio.load(source, { decodeEntities: false }, false);
  $("#navbar").attr("data-factual-governance", "config/seo-programs.json#programs");
  for (const program of programs) {
    const anchors = $(`a[href="${program.route}"]`);
    anchors.each((_, element) => {
      const anchor = $(element);
      const inProgramMenu = anchor.hasClass("dropdown-item") || anchor.closest("#mobileMenu").length;
      if (!inProgramMenu) return;
      anchor.attr("data-program-id", program.id);
      anchor.attr("data-source-status", program.sourceStatus);
      anchor.attr("data-reviewed-at", program.reviewedAt);
      if (anchor.hasClass("dropdown-item")) {
        const text = anchor.find(".d-text").first();
        const firstText = text.contents().filter((__, node) => node.type === "text").first();
        if (firstText.length) firstText[0].data = program.menuLabel;
        else text.prepend(program.menuLabel);
        text.find(".d-label").first().text(program.menuSecondaryLabel);
      } else if (anchor.closest("#mobileMenu").length) {
        anchor.text(program.menuLabel);
      }
    });
  }
  return $.root().html();
}

function syncLlmsText(source, programs) {
  let output = source;
  for (const program of programs) {
    const url = `https://atelierdeconsultanta.ro${program.route}`;
    const description = `  ${program.shortName} — ${statusLabel(program.sourceStatus).toLowerCase()}. ${program.factualDisclaimer}`;
    const escaped = url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const existing = new RegExp(`(^- ${escaped}\\r?\\n)(?:  [^\\r\\n]*)(?=\\r?\\n|$)`, "m");
    if (existing.test(output)) {
      output = output.replace(existing, `$1${description}`);
    } else {
      const inlineEntry = new RegExp(`^[-*] [^\\r\\n]*${escaped}[^\\r\\n]*$`, "m");
      if (inlineEntry.test(output)) output = output.replace(inlineEntry, `- ${url}\n${description}`);
    }
  }

  const markerStart = "<!-- PROGRAM_FACTUAL_GOVERNANCE_START -->";
  const markerEnd = "<!-- PROGRAM_FACTUAL_GOVERNANCE_END -->";
  const markerPattern = new RegExp(`${markerStart}[\\s\\S]*?${markerEnd}`);
  const baseOutput = output.replace(markerPattern, "").replace(/\s+$/g, "");
  const missingPrograms = programs.filter((program) => !baseOutput.includes(`https://atelierdeconsultanta.ro${program.route}`));
  const missingEntries = missingPrograms.length
    ? `\n\n### Alte pagini de program din registru\n\n${missingPrograms.map((program) => `- https://atelierdeconsultanta.ro${program.route}\n  ${program.shortName} — ${statusLabel(program.sourceStatus).toLowerCase()}. ${program.factualDisclaimer}`).join("\n\n")}`
    : "";
  const block = `${markerStart}\n## Guvernanță factuală a programelor\n\n- Sursa de adevăr: config/seo-programs.json, câmpul programs.\n- Statusurile nu sunt deduse din disponibilitatea URL-ului; un document final nu este echivalent cu un apel deschis.\n- Valorile consultative sunt prezentate numai cu delimitarea explicită a statutului.\n- Ultima sincronizare a registrului: ${programs.reduce((latest, program) => program.reviewedAt > latest ? program.reviewedAt : latest, "0000-00-00")}${missingEntries}\n${markerEnd}`;
  return `${baseOutput}\n\n${block}\n`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function replaceTagAttribute(tag, attribute, value) {
  const escaped = escapeHtml(value);
  const pattern = new RegExp(`\\s${attribute}=(?:"[^"]*"|'[^']*')`, "i");
  if (pattern.test(tag)) return tag.replace(pattern, ` ${attribute}="${escaped}"`);
  return tag.replace(/\s*\/?>(?=$)/, (ending) => ` ${attribute}="${escaped}"${ending}`);
}

function replaceMeta(html, selectorPattern, value) {
  return html.replace(selectorPattern, (tag) => replaceTagAttribute(tag, "content", value));
}

function syncProgramHtml(source, program) {
  let output = source;
  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  output = output.replace(/<title>[^<]*<\/title>/i, `<title>${escapeHtml(program.metaTitle)}</title>`);
  output = replaceMeta(output, /<meta\b[^>]*\bname=["']description["'][^>]*>/i, program.metaDescription);
  output = replaceMeta(output, /<meta\b[^>]*\bproperty=["']og:title["'][^>]*>/i, program.metaTitle);
  output = replaceMeta(output, /<meta\b[^>]*\bproperty=["']og:description["'][^>]*>/i, program.metaDescription);
  output = output.replace(/<body\b[^>]*>/i, (tag) => {
    let next = replaceTagAttribute(tag, "data-program-id", program.id);
    next = replaceTagAttribute(next, "data-source-status", program.sourceStatus);
    next = replaceTagAttribute(next, "data-reviewed-at", program.reviewedAt);
    return replaceTagAttribute(next, "data-factual-governance", "config/seo-programs.json#programs");
  });

  const block = renderProgramFactualStatus(program).replace(/\r?\n/g, eol);
  const marked = /<!-- PROGRAM_FACTUAL_STATUS_START -->[\s\S]*?<!-- PROGRAM_FACTUAL_STATUS_END -->/;
  if (marked.test(output)) return output.replace(marked, block);
  if (/<article\b[^>]*>/i.test(output)) return output.replace(/<article\b[^>]*>/i, (tag) => `${tag}${eol}${block}`);
  if (/<main\b[^>]*>/i.test(output)) return output.replace(/<main\b[^>]*>/i, (tag) => `${tag}${eol}${block}`);
  return output;
}

function programHtmlUpdates(programs) {
  const updates = [];
  const seen = new Set();
  for (const program of programs) {
    const slug = program.route.replace(/^\//, "");
    for (const file of [path.join(ROOT, slug, "index.html"), path.join(ROOT, `${slug}.html`)]) {
      if (seen.has(file) || !fs.existsSync(file)) continue;
      seen.add(file);
      const before = fs.readFileSync(file, "utf8");
      updates.push({ file, before, after: syncProgramHtml(before, program) });
    }
  }
  return updates;
}

function textUpdate(file, transform) {
  const before = fs.readFileSync(file, "utf8");
  return { file, before, after: transform(before) };
}

function main() {
  const check = process.argv.includes("--check");
  const { config, programs } = loadProgramConfig();
  const updates = [
    { file: FILES.config, before: fs.readFileSync(FILES.config, "utf8"), after: jsonText(syncSeoConfig(config, programs)) },
    updateJsonFile(FILES.guides, (value) => syncGuides(value, programs)),
    updateJsonFile(FILES.banners, (value) => syncBanners(value, programs)),
    updateJsonFile(FILES.priority, (value) => syncPriority(value, programs)),
    updateJsonFile(FILES.snippets, (value) => syncSnippets(value, programs)),
    textUpdate(FILES.header, (value) => syncHeaderText(value, programs)),
    textUpdate(FILES.llms, (value) => syncLlmsText(value, programs)),
    ...programHtmlUpdates(programs)
  ].filter(Boolean);

  const changed = updates.filter((update) => update.before !== update.after);
  for (const update of changed) {
    const relative = path.relative(ROOT, update.file).split(path.sep).join("/");
    console.log(`${check ? "OUTDATED" : "SYNC"} ${relative}`);
    if (!check) fs.writeFileSync(update.file, update.after, "utf8");
  }
  console.log(`${programs.length} programe validate; ${changed.length} consumatori ${check ? "nesincronizați" : "actualizați"}.`);
  if (check && changed.length) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = {
  FILES,
  syncBanners,
  syncGuides,
  syncHeaderText,
  syncLlmsText,
  syncPriority,
  syncProgramHtml,
  syncSeoConfig,
  syncSnippets
};
