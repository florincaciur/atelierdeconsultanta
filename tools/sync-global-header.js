#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const PARTIAL_PATH = path.join(ROOT, "partials", "global-header.html");
const START = "<!-- GLOBAL_HEADER_START -->";
const END = "<!-- GLOBAL_HEADER_END -->";
const EXCLUDED_DIRECTORIES = new Set([
  ".git",
  "admin",
  "archive",
  "dist",
  "node_modules",
  "partials",
  "rapoarte",
  "reports",
  "test",
  "tests"
]);

function isTestFile(fileName) {
  return /(?:^|[._-])(?:spec|test)(?:[._-]|$)/i.test(fileName);
}

function isVerificationToken(fileName) {
  return /^google[a-f0-9]+\.html$/i.test(fileName);
}

function findPublicHtmlFiles(directory = ROOT, relativeDirectory = "") {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (EXCLUDED_DIRECTORIES.has(entry.name.toLowerCase())) continue;
      files.push(...findPublicHtmlFiles(path.join(directory, entry.name), path.posix.join(relativeDirectory, entry.name)));
      continue;
    }
    if (!entry.isFile() || path.extname(entry.name).toLowerCase() !== ".html" || isTestFile(entry.name) || isVerificationToken(entry.name)) continue;
    files.push(path.posix.join(relativeDirectory, entry.name));
  }
  return files.sort((left, right) => left.localeCompare(right));
}

function count(text, token) {
  return text.split(token).length - 1;
}

function partialSource() {
  const partial = fs.readFileSync(PARTIAL_PATH, "utf8").replace(/^\uFEFF/, "").trim();
  if (count(partial, START) !== 1 || count(partial, END) !== 1) {
    throw new Error(`Partialul trebuie să conțină exact o pereche de delimitatori: ${PARTIAL_PATH}`);
  }
  if (!partial.includes('id="navbar"') || !partial.includes('id="mobileMenu"')) {
    throw new Error("Partialul global nu conține navbarul desktop și meniul mobil.");
  }
  return partial;
}

function findElementRange(html, startIndex) {
  const opening = html.slice(startIndex).match(/^<([A-Za-z][\w:-]*)\b[^>]*>/);
  if (!opening) throw new Error(`Nu pot interpreta elementul HTML de la offset ${startIndex}.`);
  const tagName = opening[1].toLowerCase();
  const tagPattern = new RegExp(`<\\/?${tagName}\\b[^>]*>`, "gi");
  tagPattern.lastIndex = startIndex;
  let depth = 0;
  let match;
  while ((match = tagPattern.exec(html))) {
    const token = match[0];
    const closing = /^<\//.test(token);
    const selfClosing = /\/>$/.test(token);
    if (closing) depth -= 1;
    else if (!selfClosing) depth += 1;
    if (depth === 0) return { start: startIndex, end: tagPattern.lastIndex };
  }
  throw new Error(`Elementul <${tagName}> început la offset ${startIndex} nu este închis.`);
}

function markedRange(html) {
  const start = html.indexOf(START);
  const end = html.indexOf(END);
  if (start === -1 && end === -1) return null;
  if (count(html, START) !== 1 || count(html, END) !== 1 || end < start) {
    throw new Error("Delimitatorii GLOBAL_HEADER sunt incompleți sau duplicați.");
  }
  return { start, end: end + END.length };
}

function legacyRange(html) {
  const globalNavMatch = /<nav\b[^>]*\bid=["']navbar["'][^>]*>/i.exec(html);
  if (globalNavMatch) {
    const navRange = findElementRange(html, globalNavMatch.index);
    const mobileMatch = /<div\b[^>]*\bid=["']mobileMenu["'][^>]*>/i.exec(html.slice(navRange.end));
    if (!mobileMatch) return navRange;
    const mobileStart = navRange.end + mobileMatch.index;
    const mobileRange = findElementRange(html, mobileStart);
    return { start: navRange.start, end: mobileRange.end };
  }

  const legacyNavMatch = /<nav\b[^>]*\bclass=["'][^"']*\bnavbar\b[^"']*["'][^>]*>/i.exec(html);
  if (legacyNavMatch) return findElementRange(html, legacyNavMatch.index);
  return null;
}

function removeHomepageLegacyBehavior(html, relativePath) {
  if (relativePath !== "index.html") return html;
  const startToken = "    var navbar = document.getElementById('navbar');";
  const start = html.indexOf(startToken);
  if (start === -1) return html;
  const taskIndex = html.indexOf("TASK SCHEDULING", start);
  if (taskIndex === -1) throw new Error("Nu am găsit limita TASK SCHEDULING din scriptul homepage.");
  const end = html.lastIndexOf("    /*", taskIndex);
  if (end <= start) throw new Error("Nu am putut delimita comportamentul navbar vechi din homepage.");
  return `${html.slice(0, start)}${html.slice(end)}`;
}

function withTargetNewlines(text, eol) {
  return text.replace(/\r\n/g, "\n").replace(/\n/g, eol);
}

function synchronizeFile(relativePath, partial) {
  const filePath = path.join(ROOT, ...relativePath.split("/"));
  const before = fs.readFileSync(filePath, "utf8");
  const eol = before.includes("\r\n") ? "\r\n" : "\n";
  const replacement = withTargetNewlines(partial, eol);
  let source = before;

  if (relativePath === "index.html" && count(source, START) === 1 && count(source, END) === 0) {
    const interruptedStart = source.indexOf(START);
    const taskIndex = source.indexOf("TASK SCHEDULING", interruptedStart);
    const taskStart = source.lastIndexOf("    /*", taskIndex);
    if (taskIndex === -1 || taskStart <= interruptedStart) {
      throw new Error("Homepage are o migrare GLOBAL_HEADER întreruptă care nu poate fi recuperată automat.");
    }
    source = `${source.slice(0, interruptedStart)}${replacement}${eol}${eol}${source.slice(taskStart)}`;
  }

  if (relativePath === "index.html" && count(source, START) === 0) {
    source = removeHomepageLegacyBehavior(source, relativePath);
  }

  const existingMarkedRange = markedRange(source);
  let after;

  if (existingMarkedRange) {
    after = `${source.slice(0, existingMarkedRange.start)}${replacement}${source.slice(existingMarkedRange.end)}`;
  } else {
    const existingLegacyRange = legacyRange(source);
    if (existingLegacyRange) {
      after = `${source.slice(0, existingLegacyRange.start)}${replacement}${source.slice(existingLegacyRange.end)}`;
    } else {
      const body = /<body\b[^>]*>/i.exec(source);
      if (!body) throw new Error(`${relativePath}: lipsește elementul <body>.`);
      const insertion = body.index + body[0].length;
      after = `${source.slice(0, insertion)}${eol}${replacement}${source.slice(insertion)}`;
    }
  }

  if (after === before) return false;
  fs.writeFileSync(filePath, after, "utf8");
  return true;
}

function main() {
  const partial = partialSource();
  const files = findPublicHtmlFiles();
  let changed = 0;
  for (const file of files) {
    if (synchronizeFile(file, partial)) changed += 1;
  }
  const indexFiles = files.filter((file) => path.posix.basename(file) === "index.html").length;
  console.log(`Global header sincronizat: ${changed} fișiere modificate, ${files.length} HTML publice verificate (${indexFiles} index.html).`);
}

if (require.main === module) main();

module.exports = {
  END,
  PARTIAL_PATH,
  ROOT,
  START,
  findPublicHtmlFiles,
  legacyRange,
  markedRange,
  partialSource,
  removeHomepageLegacyBehavior
};
