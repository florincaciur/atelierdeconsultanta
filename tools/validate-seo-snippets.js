#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  fileForRoute,
  sitemapRoutes
} = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "seo-snippets.json");
const REQUIRED_FIELDS = [
  "route",
  "primaryIntent",
  "primaryQuery",
  "secondaryQueries",
  "title",
  "description",
  "ogTitle",
  "ogDescription",
  "sourceOfTruth",
  "factualStatus",
  "lastReviewed",
  "notes"
];
const STOP_WORDS = new Set(["de", "din", "la", "pentru", "si", "sau", "cu", "un", "o", "ale", "al"]);
const ALLOWED_UPPERCASE = new Set(["AFIR", "CAEN", "DR12", "DR14", "FABER", "IMM", "RO", "SO", "SOC"]);
const FORBIDDEN_CLAIMS = /\b(?:garantat(?:ă|e|i)?|sigur(?:ă|e|i)?|obține finanțarea|aprobarea este garantată)\b/iu;

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function comparable(value) {
  return cleanText(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, " ")
    .trim();
}

function intentCoverage(title, primaryQuery) {
  const titleWords = new Set(comparable(title).split(/\s+/u).filter(Boolean));
  const queryWords = comparable(primaryQuery)
    .split(/\s+/u)
    .filter((word) => word.length > 1 && !STOP_WORDS.has(word));
  if (!queryWords.length) return 1;
  const matched = queryWords.filter((word) => titleWords.has(word)).length;
  return matched / queryWords.length;
}

function duplicateIssues(pages, field, label) {
  const byValue = new Map();
  for (const page of pages) {
    const key = comparable(page[field]);
    if (!key) continue;
    if (!byValue.has(key)) byValue.set(key, []);
    byValue.get(key).push(page.route);
  }
  return [...byValue.entries()]
    .filter(([, routes]) => routes.length > 1)
    .map(([, routes]) => `${label} duplicat pentru rutele: ${routes.join(", ")}`);
}

function metadataFromHtml(file) {
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  return {
    title: cleanText($("head > title").first().text()),
    description: cleanText($("head meta[name='description']").first().attr("content")),
    ogTitle: cleanText($("head meta[property='og:title']").first().attr("content")),
    ogDescription: cleanText($("head meta[property='og:description']").first().attr("content")),
    h1: cleanText($("h1").first().text()),
    counts: {
      title: $("head > title").length,
      description: $("head meta[name='description']").length,
      ogTitle: $("head meta[property='og:title']").length,
      ogDescription: $("head meta[property='og:description']").length
    }
  };
}

function validateConfig(config) {
  const errors = [];
  const warnings = [];
  if (!config || !Array.isArray(config.pages) || !config.pages.length) return { errors: ["config/seo-snippets.json nu conține pages"], warnings };

  const routes = new Set();
  const sitemap = new Set(sitemapRoutes(ROOT));
  for (const [index, page] of config.pages.entries()) {
    const label = page.route || `pages[${index}]`;
    for (const field of REQUIRED_FIELDS) {
      const value = page[field];
      if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) errors.push(`${label}: lipsește ${field}`);
    }
    if (routes.has(page.route)) errors.push(`${label}: rută duplicată în config`);
    routes.add(page.route);
    if (!sitemap.has(page.route)) errors.push(`${label}: ruta nu este indexabilă în sitemap.xml`);
    if (!/^\d{4}-\d{2}-\d{2}$/u.test(page.lastReviewed || "")) errors.push(`${label}: lastReviewed invalid`);
    if (!Array.isArray(page.secondaryQueries) || !page.secondaryQueries.every((query) => typeof query === "string" && cleanText(query))) {
      errors.push(`${label}: secondaryQueries trebuie să conțină numai interogări textuale`);
    }
    if (!Array.isArray(page.sourceOfTruth)) {
      errors.push(`${label}: sourceOfTruth trebuie să fie o listă`);
    } else {
      for (const source of page.sourceOfTruth) {
        const reference = cleanText(source);
        const localPath = reference.split("#", 1)[0].split(":", 1)[0];
        if (!reference || (!/^https?:\/\//iu.test(reference) && !fs.existsSync(path.join(ROOT, localPath)))) {
          errors.push(`${label}: sursa locală nu există (${reference || "valoare goală"})`);
        }
      }
    }

    if (intentCoverage(page.title, page.primaryQuery) < 0.6) errors.push(`${label}: titlul nu include suficient intenția principală '${page.primaryQuery}'`);

    for (const [field, value] of [["title", page.title], ["description", page.description], ["ogTitle", page.ogTitle], ["ogDescription", page.ogDescription]]) {
      if (FORBIDDEN_CLAIMS.test(value)) errors.push(`${label}: ${field} conține o promisiune nepermisă`);
      if (/\p{Extended_Pictographic}/u.test(value)) errors.push(`${label}: ${field} conține emoji`);
    }
    const uppercase = cleanText(page.title).match(/\b[A-ZĂÂÎȘȚ0-9-]{3,}\b/gu) || [];
    const excessiveUppercase = uppercase.filter((word) => /\p{Lu}/u.test(word) && !ALLOWED_UPPERCASE.has(word));
    if (excessiveUppercase.length > 1) errors.push(`${label}: majuscule excesive în titlu (${excessiveUppercase.join(", ")})`);
  }
  errors.push(...duplicateIssues(config.pages, "title", "Titlu"));
  errors.push(...duplicateIssues(config.pages, "description", "Descriere"));
  return { errors, warnings };
}

function validateHtml(config) {
  const errors = [];
  const metrics = [];
  for (const page of config.pages) {
    const file = fileForRoute(ROOT, page.route);
    if (!fs.existsSync(file)) {
      errors.push(`${page.route}: fișier HTML lipsă`);
      continue;
    }
    const actual = metadataFromHtml(file);
    for (const [field, count] of Object.entries(actual.counts)) if (count !== 1) errors.push(`${page.route}: ${field} apare de ${count} ori în <head>`);
    for (const field of ["title", "description", "ogTitle", "ogDescription"]) {
      if (actual[field] !== cleanText(page[field])) errors.push(`${page.route}: ${field} diferă între config și HTML`);
    }
    if (comparable(actual.h1) === comparable(page.title)) errors.push(`${page.route}: title și H1 sunt identice; trebuie distincte, dar coerente`);
    if (comparable(actual.h1) === comparable(page.description)) errors.push(`${page.route}: meta-description și H1 sunt identice`);
    metrics.push({
      route: page.route,
      titleCharacters: cleanText(page.title).length,
      descriptionCharacters: cleanText(page.description).length
    });
  }
  return { errors, metrics };
}

function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  const configResult = validateConfig(config);
  const htmlResult = validateHtml(config);
  for (const warning of configResult.warnings) console.warn(`Avertisment: ${warning}`);
  const errors = [...configResult.errors, ...htmlResult.errors];
  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exitCode = 1;
    return;
  }
  console.log(`SEO snippets valide pentru ${config.pages.length} rute prioritare.`);
  for (const metric of htmlResult.metrics) {
    console.log(`${metric.route}: title ${metric.titleCharacters} caractere; description ${metric.descriptionCharacters} caractere`);
  }
}

if (require.main === module) main();

module.exports = {
  cleanText,
  metadataFromHtml,
  validateConfig,
  validateHtml
};
