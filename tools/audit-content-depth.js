#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DIR = path.join(ROOT, "reports");
const OUT = path.join(REPORT_DIR, "content-depth-audit.csv");

function parseArgs() {
  const args = { minWords: 0 };
  for (let i = 2; i < process.argv.length; i += 1) {
    if (process.argv[i] === "--min-words") args.minWords = Number(process.argv[++i] || 0);
  }
  return args;
}

function files() {
  try {
    return cp.execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: ROOT, encoding: "utf8" })
      .split("\0")
      .filter((file) => /\.html?$/i.test(file))
      .filter((file) => !/^(dist|node_modules|reports)\//.test(file.replace(/\\/g, "/")));
  } catch {
    return [];
  }
}

function visibleText($) {
  $("script,style,noscript,svg,template").remove();
  return $("body").text().replace(/\s+/g, " ").trim();
}

function wordCount(text) {
  const words = text.match(/[\p{L}\p{N}]+(?:[-''][\p{L}\p{N}]+)*/gu);
  return words ? words.length : 0;
}

function jsonLdTypes($) {
  const types = [];
  $('script[type="application/ld+json"]').each((_, element) => {
    try {
      const data = JSON.parse($(element).text());
      const visit = (node) => {
        if (!node || typeof node !== "object") return;
        if (node["@type"]) types.push(Array.isArray(node["@type"]) ? node["@type"].join("+") : node["@type"]);
        if (Array.isArray(node["@graph"])) node["@graph"].forEach(visit);
      };
      visit(data);
    } catch {
      types.push("INVALID_JSONLD");
    }
  });
  return [...new Set(types)].join("|");
}

function csv(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function main() {
  const args = parseArgs();
  const rows = [[
    "file",
    "title",
    "h1",
    "canonical",
    "robots",
    "words",
    "json_ld_types",
    "faq_visible",
    "faq_required",
    "speakable_blocks",
    "speakable_schema",
    "words_required",
    "under_min_words"
  ]];
  for (const file of files()) {
    const html = fs.readFileSync(path.join(ROOT, file), "utf8");
    const $ = cheerio.load(html, { decodeEntities: true });
    const words = wordCount(visibleText($));
    const types = jsonLdTypes($);
    const robots = $('meta[name="robots"]').first().attr("content") || "";
    const metaMinWords = Number($('meta[name="seo-min-words"]').first().attr("content") || 0);
    const requiredWords = Math.max(args.minWords || 0, metaMinWords || 0);
    const requiredFaq = Number($('meta[name="seo-min-faq"]').first().attr("content") || 0);
    const faqCount = $(".faq-item, .faq-q, details").length;
    const indexable = /index, follow/i.test(robots);
    rows.push([
      file.replace(/\\/g, "/"),
      $("title").first().text().replace(/\s+/g, " ").trim(),
      $("h1").first().text().replace(/\s+/g, " ").trim(),
      $('link[rel="canonical"]').first().attr("href") || "",
      robots,
      words,
      types,
      faqCount,
      requiredFaq || "",
      $(".speakable,[data-speakable='true']").length,
      /SpeakableSpecification/.test(html) ? "yes" : "no",
      requiredWords || "",
      requiredWords && indexable && words < requiredWords ? "yes" : (requiredFaq && indexable && faqCount < requiredFaq ? "faq" : "no")
    ]);
  }
  fs.mkdirSync(REPORT_DIR, { recursive: true });
  fs.writeFileSync(OUT, rows.map((row) => row.map(csv).join(",")).join("\n") + "\n", "utf8");
  const under = rows.slice(1).filter((row) => row[row.length - 1] !== "no");
  console.log(`Wrote ${path.relative(ROOT, OUT)} with ${rows.length - 1} HTML rows.`);
  if (under.length) {
    console.log(`${under.length} indexable pages are under ${args.minWords} words. See report for details.`);
  }
}

main();
