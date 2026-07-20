#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForRoute } = require("./structured-data-utils");
const { validateConfig } = require("./validate-seo-snippets");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "seo-snippets.json");
const CHECK_ONLY = process.argv.includes("--check");

function escapeText(value) {
  return String(value).replace(/&/gu, "&amp;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;");
}

function escapeAttribute(value) {
  return escapeText(value).replace(/"/gu, "&quot;");
}

function attribute(tag, name) {
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*(["'])(.*?)\\1`, "iu"));
  return match ? match[2] : "";
}

function setContentAttribute(tag, value) {
  if (/\bcontent\s*=\s*(["']).*?\1/iu.test(tag)) {
    return tag.replace(/\bcontent\s*=\s*(["']).*?\1/iu, `content="${escapeAttribute(value)}"`);
  }
  return tag.replace(/\s*\/?\s*>$/u, ` content="${escapeAttribute(value)}">`);
}

function replaceMeta(head, key, expectedValue) {
  let matches = 0;
  const output = head.replace(/<meta\b[^>]*>/giu, (tag) => {
    const identifier = attribute(tag, "name") || attribute(tag, "property");
    if (identifier.toLowerCase() !== key.toLowerCase()) return tag;
    matches += 1;
    return setContentAttribute(tag, expectedValue);
  });
  if (matches !== 1) throw new Error(`${key} apare de ${matches} ori în <head>`);
  return output;
}

function applySnippet(html, page) {
  const headMatch = html.match(/<head\b[^>]*>[\s\S]*?<\/head>/iu);
  if (!headMatch) throw new Error("lipsește <head>");
  const originalHead = headMatch[0];
  const titleMatches = originalHead.match(/<title\b[^>]*>[\s\S]*?<\/title>/giu) || [];
  if (titleMatches.length !== 1) throw new Error(`title apare de ${titleMatches.length} ori în <head>`);

  let head = originalHead.replace(/<title\b[^>]*>[\s\S]*?<\/title>/iu, `<title>${escapeText(page.title)}</title>`);
  head = replaceMeta(head, "description", page.description);
  head = replaceMeta(head, "og:title", page.ogTitle);
  head = replaceMeta(head, "og:description", page.ogDescription);
  const output = html.replace(originalHead, head);

  const beforeBody = html.slice((html.match(/<\/head>/iu)?.index || 0) + "</head>".length);
  const afterBody = output.slice((output.match(/<\/head>/iu)?.index || 0) + "</head>".length);
  if (beforeBody !== afterBody) throw new Error("aplicarea snippetului a modificat conținutul din afara <head>");

  const before = cheerio.load(html, { decodeEntities: false });
  const after = cheerio.load(output, { decodeEntities: false });
  if (before("link[rel='canonical']").attr("href") !== after("link[rel='canonical']").attr("href")) throw new Error("canonical modificat accidental");
  if (before("h1").first().text() !== after("h1").first().text()) throw new Error("H1 modificat accidental");
  return output;
}

function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  const validation = validateConfig(config);
  if (validation.errors.length) throw new Error(validation.errors.join("\n"));
  const changed = [];
  for (const page of config.pages) {
    const file = fileForRoute(ROOT, page.route);
    const input = fs.readFileSync(file, "utf8");
    const output = applySnippet(input, page);
    if (input === output) continue;
    changed.push(path.relative(ROOT, file).split(path.sep).join("/"));
    if (!CHECK_ONLY) fs.writeFileSync(file, output, "utf8");
  }
  if (CHECK_ONLY && changed.length) {
    console.error(`Snippeturi nesincronizate în ${changed.length} fișiere:\n${changed.map((file) => `- ${file}`).join("\n")}`);
    process.exitCode = 1;
    return;
  }
  console.log(`${CHECK_ONLY ? "Verificate" : "Aplicate"} ${config.pages.length} snippeturi; ${changed.length} ${CHECK_ONLY ? "abateri" : "fișiere actualizate"}.`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message || error);
    process.exitCode = 1;
  }
}

module.exports = { applySnippet };
