#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const cheerio = require("cheerio");
const { classifyTarget, clean, loadPages } = require("./audit-editorial-links");
const { parseRedirects } = require("./audit-site-links");
const { fileForRoute } = require("./structured-data-utils");
const entries = require("../config/editorial-contextual-links.json");

const root = path.resolve(__dirname, "..");
const check = process.argv.includes("--check");
const pages = loadPages(root);
const redirects = parseRedirects(root);
const plans = new Map();
const pairs = new Set();
const escape = value => value.replace(/[&<">]/gu, character => ({
  "&": "&amp;", "<": "&lt;", '"': "&quot;", ">": "&gt;"
})[character]);

for (const entry of entries) {
  const { source, target, match, sentence, anchor, reason } = entry;
  const pair = `${source} → ${target}`;
  if (!pages.has(source) || source === target || classifyTarget(target, source, pages, redirects)?.route !== target) {
    throw new Error(`Legătură fără destinație canonică: ${pair}`);
  }
  if (pairs.has(pair) || !match || !anchor || !reason || sentence.split("{{link}}").length !== 2) {
    throw new Error(`Legătură duplicată sau incompletă: ${pair}`);
  }
  pairs.add(pair);
  if (!plans.has(source)) plans.set(source, []);
  plans.get(source).push(entry);
}

const changed = [];
for (const [source, plan] of plans) {
  const file = fileForRoute(root, source);
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { sourceCodeLocationInfo: true });
  const edits = new Map();
  for (const { target, match, sentence, anchor } of plan) {
    const paragraph = $("main p").filter((_, node) => clean($(node).text()).startsWith(match));
    const marker = $("span[data-editorial-context]").filter((_, node) => $(node).attr("data-editorial-context") === target);
    if (paragraph.length !== 1 || paragraph.closest("nav, details, [hidden], [inert], [aria-hidden=true]").length
      || marker.length > 1 || (marker.length && marker.parent()[0] !== paragraph[0])) {
      throw new Error(`Paragraf negăsit, duplicat sau ascuns: ${source} → ${target}`);
    }
    if (paragraph.find("a[href]").filter((_, node) => $(node).attr("href") === target && !$(node).closest(marker).length).length) {
      throw new Error(`Destinația apare deja în paragraf: ${source} → ${target}`);
    }
    const link = `<a href="${escape(target)}">${escape(anchor)}</a>`;
    const fragment = `<span data-editorial-context="${escape(target)}">${escape(sentence).replace("{{link}}", link)}</span>`;
    if (marker.length) {
      const { startOffset, endOffset } = marker[0].sourceCodeLocation;
      edits.set(startOffset, { end: endOffset, markup: fragment });
    } else {
      const { startOffset } = paragraph[0].sourceCodeLocation.endTag;
      const edit = edits.get(startOffset) || { end: startOffset, markup: "" };
      edit.markup += ` ${fragment}`;
      edits.set(startOffset, edit);
    }
  }
  let next = html;
  for (const [offset, { end, markup }] of [...edits].sort(([a], [b]) => b - a)) {
    next = next.slice(0, offset) + markup + next.slice(end);
  }
  if (next !== html) changed.push({ file, next });
}

if (check && changed.length) {
  console.error(changed.map(({ file }) => path.relative(root, file)).join("\n"));
  process.exitCode = 1;
} else if (!check) {
  for (const { file, next } of changed) fs.writeFileSync(file, next);
}
console.log(`${entries.length} legături editoriale pe ${plans.size} pagini. Fișiere cu diferențe: ${changed.length}.`);
