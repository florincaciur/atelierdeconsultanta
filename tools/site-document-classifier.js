"use strict";

const fs = require("fs");
const path = require("path");

const DOCUMENT_CATEGORIES = Object.freeze({
  PUBLIC_PAGE: "public-page",
  PARTIAL: "partial",
  TEMPLATE: "template",
  GENERATED_OUTPUT: "generated-output"
});

const SOURCE_EXCLUDED_DIRECTORIES = new Set([
  ".git",
  ".github",
  ".wrangler",
  "node_modules",
  "reports"
]);

function toPosix(value) {
  return String(value).split(path.sep).join("/");
}

function classifyHtmlFile(root, filePath) {
  const relative = toPosix(path.relative(root, filePath)).replace(/^\.\//u, "");
  const segments = relative.toLowerCase().split("/");
  const name = segments.at(-1) || "";

  if (segments[0] === "dist" || segments.includes("generated")) {
    return DOCUMENT_CATEGORIES.GENERATED_OUTPUT;
  }
  if (segments[0] === "partials" || name.endsWith(".partial.html")) {
    return DOCUMENT_CATEGORIES.PARTIAL;
  }
  if (
    segments.includes("templates")
    || segments.includes("fixtures")
    || name.endsWith(".template.html")
  ) {
    return DOCUMENT_CATEGORIES.TEMPLATE;
  }
  return DOCUMENT_CATEGORIES.PUBLIC_PAGE;
}

function discoverHtmlDocuments(root, options = {}) {
  const includeGenerated = options.includeGenerated === true;
  const documents = [];

  function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (SOURCE_EXCLUDED_DIRECTORIES.has(entry.name.toLowerCase())) continue;
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.toLowerCase() === "dist" && !includeGenerated) continue;
        walk(fullPath);
        continue;
      }
      if (!entry.isFile() || path.extname(entry.name).toLowerCase() !== ".html") continue;
      if (entry.name.startsWith("FABER")) continue;
      documents.push({
        filePath: fullPath,
        relativePath: toPosix(path.relative(root, fullPath)),
        category: classifyHtmlFile(root, fullPath)
      });
    }
  }

  walk(root);
  return documents.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
}

function classificationCounts(documents) {
  const counts = Object.fromEntries(Object.values(DOCUMENT_CATEGORIES).map((category) => [category, 0]));
  for (const document of documents) counts[document.category] = (counts[document.category] || 0) + 1;
  return counts;
}

function relevantChecks(category) {
  switch (category) {
    case DOCUMENT_CATEGORIES.PARTIAL:
      return ["utf8", "html-assets", "json-ld-syntax", "links", "interactive-fragments", "copy"];
    case DOCUMENT_CATEGORIES.TEMPLATE:
      return ["utf8", "html-assets", "json-ld-syntax", "literal-links", "copy"];
    case DOCUMENT_CATEGORIES.GENERATED_OUTPUT:
      return ["deployment-layout", "redirects", "headers", "runtime-assets"];
    default:
      return ["metadata", "canonical", "indexing", "h1", "accessibility", "json-ld", "links", "copy"];
  }
}

module.exports = {
  DOCUMENT_CATEGORIES,
  classificationCounts,
  classifyHtmlFile,
  discoverHtmlDocuments,
  relevantChecks,
  toPosix
};
