#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForRoute } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const seo = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8"));
const families = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "program-family-hubs.json"), "utf8"));

const servicePages = seo.pages.filter((page) => page.type === "service" && !page.redirectTo);
const surfaces = [
  { route: "/", selector: ".homepage-hero__copy .hero-subtitle" },
  { route: "/fonduri-europene", selector: "main [data-direct-answer]" },
  ...families.hubs.map((hub) => ({ route: hub.route, selector: "header.hero > p" })),
  ...servicePages.map((page) => ({ route: `/${page.slug}`, selector: "header.hero > p", answer: page.quickAnswer })),
  { route: "/calculator-soc", selector: "header.hero .hero-sub" },
  { route: "/metodologie-verificare-eligibilitate", selector: "header.hero > p" }
];

function synchronize(source, surface) {
  const $ = cheerio.load(source, { decodeEntities: false, sourceCodeLocationInfo: true });
  const lead = $(surface.selector).first();
  if (!lead.length) throw new Error(`${surface.route}: nu există lead-ul ${surface.selector}.`);
  const scope = lead.closest("header.hero, .homepage-decision-hero");
  const touched = scope.find("[data-aeo-primary-answer], [data-aeo-direct-answer]").add(lead).get();
  scope.find("[data-aeo-primary-answer], [data-aeo-direct-answer]")
    .removeAttr("data-aeo-primary-answer")
    .removeAttr("data-aeo-direct-answer");
  if (surface.answer) lead.text(surface.answer);
  lead.attr("data-aeo-primary-answer", "").attr("data-aeo-direct-answer", "");
  const replacements = [...new Set(touched)]
    .map((node) => ({
      start: node.sourceCodeLocation?.startOffset,
      end: node.sourceCodeLocation?.endOffset,
      value: $.html(node)
    }))
    .filter((item) => Number.isInteger(item.start) && Number.isInteger(item.end))
    .sort((left, right) => right.start - left.start);
  if (!replacements.length) throw new Error(`${surface.route}: poziția lead-ului nu poate fi determinată.`);
  return replacements.reduce((value, item) => `${value.slice(0, item.start)}${item.value}${value.slice(item.end)}`, source);
}

function sameText(left, right) {
  return left.replace(/\r\n/gu, "\n") === right.replace(/\r\n/gu, "\n");
}

function main() {
  const changed = [];
  for (const surface of surfaces) {
    const file = fileForRoute(ROOT, surface.route);
    const before = fs.readFileSync(file, "utf8");
    const after = synchronize(before, surface);
    if (sameText(before, after)) continue;
    changed.push(path.relative(ROOT, file).split(path.sep).join("/"));
    if (!CHECK_ONLY) fs.writeFileSync(file, after, "utf8");
  }
  if (CHECK_ONLY && changed.length) {
    throw new Error(`Suprafețe answer-first nesincronizate:\n- ${changed.join("\n- ")}`);
  }
  console.log(`Answer-first ${CHECK_ONLY ? "sync PASS" : "sincronizat"}: ${surfaces.length} suprafețe, ${changed.length} actualizate.`);
}

if (require.main === module) main();

module.exports = { servicePages, surfaces, synchronize };
