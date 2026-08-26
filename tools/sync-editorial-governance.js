#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { serializeJsonLd } = require("./schema-helpers");
const { normalizeJsonLdValue } = require("./normalize-copy-ro");
const {
  ROOT,
  isCompleteRecord,
  isIsoDate,
  loadEditorialGovernance,
  programContradictions,
  recordIssues,
  renderEditorialGovernance,
  reviewExpired
} = require("./editorial-governance");

const CSS_URL = "/assets/editorial-governance.css";
const ADMIN_PATH = path.join(ROOT, "admin", "index.html");
const DATA_START = "<!-- EDITORIAL_GOVERNANCE_DATA_START -->";
const DATA_END = "<!-- EDITORIAL_GOVERNANCE_DATA_END -->";
const PROGRAM_TEMPLATE_SLOT = "<!-- PROGRAM_TEMPLATE_GOVERNANCE_SLOT -->";

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function replaceTagAttribute(tag, attribute, value) {
  const pattern = new RegExp(`\\s${attribute}=(?:"[^"]*"|'[^']*')`, "iu");
  if (pattern.test(tag)) return tag.replace(pattern, ` ${attribute}="${escapeHtml(value)}"`);
  return tag.replace(/\s*\/?>(?=$)/u, (ending) => ` ${attribute}="${escapeHtml(value)}"${ending}`);
}

function removeTagAttribute(tag, attribute) {
  return tag.replace(new RegExp(`\\s${attribute}=(?:"[^"]*"|'[^']*')`, "giu"), "");
}

function addEditorialProperties(node, record) {
  if (!node || typeof node !== "object") return;
  const types = new Set(Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]]);
  const eligible = ["WebPage", "CollectionPage", "Article", "BlogPosting", "TechArticle", "HowTo", "SoftwareApplication", "GovernmentService"]
    .some((type) => types.has(type));
  if (!eligible) return;
  delete node.author;
  delete node.reviewedBy;
  delete node.datePublished;
  delete node.dateModified;
  if (!isCompleteRecord(record)) {
    delete node.citation;
    return;
  }
  if (isIsoDate(record.datePublished)) node.datePublished = record.datePublished;
  node.dateModified = record.lastMeaningfulUpdate;
  // Profilurile Person nu sunt publicate până când numele, rolul, acordul și
  // URL-ul profilului vizibil nu sunt aprobate împreună. Pentru atribuirea
  // organizațională, publisher/provider indică deja entitatea canonică.
  if (record.attributionType === "person" && record.personalNameConsent === true && record.authorProfileUrl) {
    node.author = { "@type": "Person", name: record.author, url: record.authorProfileUrl };
    if (record.reviewerProfileUrl) {
      node.reviewedBy = { "@type": "Person", name: record.reviewer, url: record.reviewerProfileUrl };
    }
  }
  const citation = {
    "@type": "CreativeWork",
    name: `${record.officialSourceName} — ${record.sourceVersion}`,
    url: record.officialSourceUrl
  };
  if (isIsoDate(record.officialSourceUpdatedAt)) citation.dateModified = record.officialSourceUpdatedAt;
  if (!Array.isArray(node.citation) || !node.citation.length) node.citation = [citation];
}

function syncOfficialSourceDate(value, record) {
  if (Array.isArray(value)) return value.forEach((item) => syncOfficialSourceDate(item, record));
  if (!value || typeof value !== "object") return;
  const types = new Set(Array.isArray(value["@type"]) ? value["@type"] : [value["@type"]]);
  if (types.has("CreativeWork") && value.url === record.officialSourceUrl) {
    if (isCompleteRecord(record) && isIsoDate(record.officialSourceUpdatedAt)) {
      value.dateModified = record.officialSourceUpdatedAt;
    } else {
      delete value.dateModified;
    }
  }
  Object.values(value).forEach((item) => syncOfficialSourceDate(item, record));
}

function syncJsonLd(html, record) {
  return html.replace(/(<script\b[^>]*type=["']application\/ld\+json["'][^>]*>)([\s\S]*?)(<\/script>)/giu, (full, open, source, close) => {
    try {
      const value = JSON.parse(source);
      const nodes = Array.isArray(value?.["@graph"]) ? value["@graph"] : Array.isArray(value) ? value : [value];
      syncOfficialSourceDate(value, record);
      nodes.forEach((node) => addEditorialProperties(node, record));
      const newline = source.includes("\r\n") ? "\r\n" : "\n";
      const serialized = serializeJsonLd(normalizeJsonLdValue(value)).replace(/\n/gu, newline);
      return `${open}${serialized}${close}`;
    } catch {
      return full;
    }
  });
}

function insertBeforeLast(html, pattern, block, trailingNewline = "\n") {
  const matches = [...html.matchAll(pattern)];
  if (!matches.length) return null;
  const last = matches.at(-1);
  return `${html.slice(0, last.index).trimEnd()}\n${block}${trailingNewline}${html.slice(last.index)}`;
}

function syncPageHtml(source, record) {
  const existingBoundary = source.match(/<!-- EDITORIAL_GOVERNANCE_END -->(\r\n|\n)/u)?.[1];
  let output = source.replace(/<!-- EDITORIAL_GOVERNANCE_START -->[\s\S]*?<!-- EDITORIAL_GOVERNANCE_END -->\s*/giu, "");
  if (!output.includes(CSS_URL)) {
    const link = `<link rel="stylesheet" href="${CSS_URL}">`;
    output = /<\/head>/iu.test(output) ? output.replace(/<\/head>/iu, `${link}\n</head>`) : `${link}\n${output}`;
  }
  output = output.replace(/<body\b[^>]*>/iu, (tag) => {
    let next = tag;
    next = replaceTagAttribute(next, "data-editorial-record", record.id);
    next = replaceTagAttribute(next, "data-governance-state", record.governanceState);
    if (isCompleteRecord(record)) {
      next = replaceTagAttribute(next, "data-editorial-verified-at", record.verifiedAt);
      next = replaceTagAttribute(next, "data-date-modified", record.lastMeaningfulUpdate);
      if (isIsoDate(record.datePublished)) next = replaceTagAttribute(next, "data-date-published", record.datePublished);
      else next = removeTagAttribute(next, "data-date-published");
      if (isIsoDate(record.officialSourceUpdatedAt)) {
        next = replaceTagAttribute(next, "data-official-source-updated-at", record.officialSourceUpdatedAt);
      } else {
        next = removeTagAttribute(next, "data-official-source-updated-at");
      }
    } else {
      for (const attribute of ["data-editorial-verified-at", "data-date-published", "data-date-modified", "data-official-source-updated-at"]) {
        next = removeTagAttribute(next, attribute);
      }
    }
    for (const internalAttribute of ["data-next-review-at", "data-last-meaningful-update"]) {
      next = removeTagAttribute(next, internalAttribute);
    }
    return next;
  });
  output = syncJsonLd(output, record);
  const block = renderEditorialGovernance(record);
  const trailingNewline = existingBoundary || (source.includes("\r\n") ? "\r\n" : "\n");
  if (output.includes(PROGRAM_TEMPLATE_SLOT)) {
    return output.replace(/<!-- PROGRAM_TEMPLATE_GOVERNANCE_SLOT -->(?:\r\n|\n)?/u, `${PROGRAM_TEMPLATE_SLOT}\n${block}${trailingNewline}`);
  }
  output = insertBeforeLast(output, /<\/main>/giu, block, trailingNewline)
    || insertBeforeLast(output, /<\/body>/giu, block, trailingNewline)
    || `${output}\n${block}${trailingNewline}`;
  return output;
}

function filesForRoute(route) {
  const slug = String(route || "").replace(/^\/+|\/+$/gu, "");
  if (!slug) return [path.join(ROOT, "index.html")];
  return [path.join(ROOT, slug, "index.html"), path.join(ROOT, `${slug}.html`)];
}

function dashboardPayload(records, programs, today) {
  const programById = new Map(programs.map((program) => [program.id, program]));
  return records.map((record) => {
    const program = record.programId ? programById.get(record.programId) : null;
    return {
      id: record.id,
      route: record.route,
      contentType: record.contentType,
      governanceState: record.governanceState,
      programId: record.programId,
      programStatus: program?.status || null,
      verifiedAt: record.verifiedAt,
      datePublished: record.datePublished,
      officialSourceUpdatedAt: record.officialSourceUpdatedAt,
      nextReviewAt: record.nextReviewAt,
      lastMeaningfulUpdate: record.lastMeaningfulUpdate,
      officialSourceName: record.officialSourceName,
      officialSourceUrl: record.officialSourceUrl,
      sourceVersion: record.sourceVersion,
      reviewer: record.reviewer,
      reviewerRole: record.reviewerRole,
      expired: reviewExpired(record, today),
      contradictions: programContradictions(record, program),
      issues: recordIssues(record, program, today)
    };
  });
}

function syncAdminHtml(source, payload) {
  const json = JSON.stringify(payload).replace(/<\//gu, "<\\/");
  const block = `${DATA_START}\n<script id="editorialGovernanceData" type="application/json">${json}</script>\n${DATA_END}`;
  const pattern = new RegExp(`${DATA_START}[\\s\\S]*?${DATA_END}`, "u");
  if (pattern.test(source)) return source.replace(pattern, block);
  return /<\/body>/iu.test(source) ? source.replace(/<\/body>/iu, `${block}\n</body>`) : `${source}\n${block}\n`;
}

function main() {
  try {
    const check = process.argv.includes("--check");
    const today = new Date().toISOString().slice(0, 10);
    const { records, programs } = loadEditorialGovernance();
    const updates = [];
    const seen = new Set();
    for (const record of records) {
      for (const file of filesForRoute(record.route)) {
        if (seen.has(file) || !fs.existsSync(file)) continue;
        seen.add(file);
        const before = fs.readFileSync(file, "utf8");
        updates.push({ file, before, after: syncPageHtml(before, record) });
      }
    }
    if (fs.existsSync(ADMIN_PATH)) {
      const before = fs.readFileSync(ADMIN_PATH, "utf8");
      updates.push({ file: ADMIN_PATH, before, after: syncAdminHtml(before, dashboardPayload(records, programs, today)) });
    }
    const changed = updates.filter((update) => update.before !== update.after);
    for (const update of changed) {
      console.log(`${check ? "OUTDATED" : "SYNC"} ${path.relative(ROOT, update.file).split(path.sep).join("/")}`);
      if (!check) fs.writeFileSync(update.file, update.after, "utf8");
    }
    console.log(`Guvernanță sincronizată: ${records.length} înregistrări, ${changed.length} fișiere ${check ? "nesincronizate" : "actualizate"}.`);
    if (check && changed.length) process.exitCode = 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { CSS_URL, PROGRAM_TEMPLATE_SLOT, dashboardPayload, filesForRoute, syncAdminHtml, syncJsonLd, syncPageHtml };
