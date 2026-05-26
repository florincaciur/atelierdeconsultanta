#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { normalizeQuestion } = require("./schema-helpers");

const ROOT = path.resolve(__dirname, "..");
const REPORT_PATH = path.join(ROOT, "reports", "structured-data-audit.json");
const EXCLUDED_DIRS = new Set([".git", ".github", ".wrangler", "dist", "node_modules", "reports"]);
const RATING_TYPES = new Set(["AggregateRating"]);
const TODAY = new Date("2026-05-26T12:00:00Z");

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function walkHtmlFiles(root) {
  const files = [];

  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name) && !entry.name.endsWith("_files")) walk(full);
        continue;
      }
      if (entry.isFile() && entry.name.toLowerCase().endsWith(".html")) files.push(full);
    }
  }

  walk(root);
  return files.sort((a, b) => toPosix(a).localeCompare(toPosix(b)));
}

function parseJsonLd($) {
  const blocks = [];
  $("script[type='application/ld+json']").each((index, element) => {
    const raw = $(element).text().trim();
    if (!raw) return;
    try {
      blocks.push({ index, raw, json: JSON.parse(raw), error: "" });
    } catch (error) {
      blocks.push({ index, raw, json: null, error: error.message });
    }
  });
  return blocks;
}

function nodeTypes(node) {
  const types = [];
  function visit(value) {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    const type = value["@type"];
    if (Array.isArray(type)) types.push(...type);
    else if (type) types.push(type);
    if (Array.isArray(value["@graph"])) value["@graph"].forEach(visit);
    for (const child of Object.values(value)) {
      if (child && typeof child === "object" && child !== value["@graph"]) visit(child);
    }
  }
  visit(node);
  return types;
}

function graphNodes(node) {
  if (!node || typeof node !== "object") return [];
  if (Array.isArray(node["@graph"])) return node["@graph"].filter(Boolean);
  return [node];
}

function visibleFaqQuestions($) {
  const selectors = [
    ".faq-item h3",
    ".faq-item .faq-q",
    ".faq-q",
    ".faq-item summary",
    "details summary",
    "[itemprop='mainEntity'] [itemprop='name']"
  ];
  const questions = new Set();
  for (const selector of selectors) {
    $(selector).each((_, element) => {
      const text = $(element).text().replace(/\s+/g, " ").trim();
      const key = normalizeQuestion(text);
      if (key) questions.add(key);
    });
  }
  return questions;
}

function faqQuestionsFromNode(node) {
  const items = [];
  for (const candidate of graphNodes(node)) {
    if (!hasType(candidate, "FAQPage")) continue;
    for (const entity of candidate.mainEntity || []) {
      const question = entity.name || entity.question || "";
      const answer = entity.acceptedAnswer?.text || entity.answer || "";
      items.push({ question: String(question), answer: String(answer) });
    }
  }
  return items;
}

function hasType(node, type) {
  const nodeType = node && node["@type"];
  return nodeType === type || (Array.isArray(nodeType) && nodeType.includes(type));
}

function collectDateIssues(node) {
  const issues = [];
  function visit(value, pathLabel) {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${pathLabel}[${index}]`));
      return;
    }
    for (const [key, raw] of Object.entries(value)) {
      if (!/^date(Published|Modified|Created)$/i.test(key)) continue;
      const date = String(raw || "");
      if (!/^\d{4}-\d{2}-\d{2}/.test(date)) {
        issues.push(`${pathLabel}.${key}: invalid date '${date}'`);
        continue;
      }
      const parsed = new Date(`${date.slice(0, 10)}T12:00:00Z`);
      if (parsed > TODAY) issues.push(`${pathLabel}.${key}: future date '${date}'`);
    }
    for (const [key, child] of Object.entries(value)) {
      if (key === "@context") continue;
      visit(child, `${pathLabel}.${key}`);
    }
  }
  visit(node, "$");
  return issues;
}

function checkFile(filePath) {
  const relativePath = toPosix(path.relative(ROOT, filePath));
  const html = fs.readFileSync(filePath, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const blocks = parseJsonLd($);
  const visibleFaq = visibleFaqQuestions($);
  const typeCounts = {};
  const issues = [];

  for (const block of blocks) {
    if (block.error) {
      issues.push(`invalid JSON-LD block ${block.index + 1}: ${block.error}`);
      continue;
    }

    const raw = JSON.stringify(block.json);
    if (/SpeakableSpecification/i.test(raw)) issues.push(`SpeakableSpecification in block ${block.index + 1}`);
    if (/SearchAction/i.test(raw)) issues.push(`SearchAction in block ${block.index + 1}`);
    if (/aggregateRating|ratingValue|reviewRating/i.test(raw)) issues.push(`rating/review claim in block ${block.index + 1}`);

    for (const type of nodeTypes(block.json)) {
      typeCounts[type] = (typeCounts[type] || 0) + 1;
      if (RATING_TYPES.has(type)) issues.push(`${type} schema in block ${block.index + 1}`);
    }

    const faq = faqQuestionsFromNode(block.json);
    if (faq.length) {
      const seen = new Set();
      for (const item of faq) {
        const key = normalizeQuestion(item.question);
        if (!key) issues.push(`empty FAQ question in block ${block.index + 1}`);
        if (key && seen.has(key)) issues.push(`duplicate FAQ question '${item.question}' in block ${block.index + 1}`);
        seen.add(key);
        if (key && !visibleFaq.has(key)) issues.push(`FAQ question not visible: '${item.question}'`);
        if (!item.answer.trim()) issues.push(`empty FAQ answer for '${item.question}'`);
      }
    }

    for (const dateIssue of collectDateIssues(block.json)) issues.push(dateIssue);
  }

  return {
    file: relativePath,
    blocks: blocks.length,
    types: typeCounts,
    issues
  };
}

function summarize(results) {
  const types = {};
  for (const result of results) {
    for (const [type, count] of Object.entries(result.types)) {
      types[type] = (types[type] || 0) + count;
    }
  }
  return {
    filesChecked: results.length,
    filesWithStructuredData: results.filter((result) => result.blocks > 0).length,
    filesWithIssues: results.filter((result) => result.issues.length > 0).length,
    types
  };
}

function main() {
  const results = walkHtmlFiles(ROOT).map(checkFile);
  const report = { generatedAt: new Date().toISOString(), summary: summarize(results), results };
  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  fs.writeFileSync(REPORT_PATH, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  console.log(`Structured data report written to ${toPosix(path.relative(ROOT, REPORT_PATH))}`);
  console.log(`Files: ${report.summary.filesChecked}; with schema: ${report.summary.filesWithStructuredData}; with issues: ${report.summary.filesWithIssues}`);
  console.log(`Types: ${Object.entries(report.summary.types).map(([type, count]) => `${type}:${count}`).join(", ")}`);

  if (report.summary.filesWithIssues > 0) {
    const topIssues = results.filter((result) => result.issues.length).slice(0, 10);
    for (const result of topIssues) {
      console.log(`- ${result.file}`);
      for (const issue of result.issues.slice(0, 5)) console.log(`  * ${issue}`);
      if (result.issues.length > 5) console.log(`  * ... ${result.issues.length - 5} more`);
    }
    process.exitCode = 1;
  }
}

main();
