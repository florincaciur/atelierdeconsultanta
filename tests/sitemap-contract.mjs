#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { generate, editorialLastmods, loadPolicy } = require("../tools/generate-sitemap");
const { readSitemapEntries } = require("../tools/sitemap-utils");
const { validateLastmodDistribution } = require("../tools/verify-sitemap");

const policy = loadPolicy();
const generatedFiles = [policy.indexFile, ...policy.families.map((family) => family.file)];

generate();
const firstBuild = new Map(generatedFiles.map((file) => [file, fs.readFileSync(path.join(ROOT, file), "utf8")]));
generate();
for (const file of generatedFiles) {
  assert.equal(fs.readFileSync(path.join(ROOT, file), "utf8"), firstBuild.get(file), `${file} must be deterministic across global builds`);
}

const parsed = readSitemapEntries(ROOT, policy.indexFile, policy.site);
assert.equal(parsed.documents.length, policy.families.length + 1, "the index must reference every and only the configured family sitemaps");
assert.equal(parsed.entries.length, 104, "canonical inventory must include the consolidated 2026 program pages and the restored program frameworks");
for (const route of [
  "/diaspora-investeste-acasa",
  "/e-drive",
  "/e-mobility",
  "/fondul-modernizare-pc1-stocare",
  "/dr18",
  "/pnrr",
  "/programul-tranzitie-justa",
  "/fondul-de-modernizare"
]) {
  assert(parsed.entries.some((entry) => new URL(entry.url).pathname === route), `${route}: consolidated program page must remain discoverable`);
}
assert(!parsed.entries.some((entry) => new URL(entry.url).pathname === "/por-adr-nord-est"), "approved POR source redirect must stay out of sitemap");
assert(parsed.entries.some((entry) => new URL(entry.url).pathname === "/investitii-modernizarea-microintreprinderilor-apel-2"), "approved regional conversion target must remain in sitemap");
for (const route of [
  "/dr-12-afir-instalarea-tinerilor-fermieri",
  "/dr-14-afir-conditii-eligibilitate-greseli-frecvente"
]) {
  assert(parsed.entries.some((entry) => new URL(entry.url).pathname === route), `${route}: approved page must remain in sitemap`);
}
assert.equal(new Set(parsed.entries.map((entry) => entry.url)).size, parsed.entries.length, "sitemap URLs must be unique");

const familyFiles = new Set(policy.families.map((family) => family.file));
assert.deepEqual(new Set(parsed.entries.map((entry) => entry.sourceFile)), familyFiles, "each monitoring family must contain URLs");
for (const entry of parsed.entries) {
  const url = new URL(entry.url);
  assert.equal(url.protocol, "https:", `${entry.url}: sitemap URL must use HTTPS`);
  assert.equal(url.origin, policy.site, `${entry.url}: sitemap URL must stay on the canonical origin`);
  assert.equal(url.search, "", `${entry.url}: parameter URL must not be in sitemap`);
  assert.equal(url.hash, "", `${entry.url}: fragment URL must not be in sitemap`);
  assert(!url.pathname.endsWith(".html"), `${entry.url}: historical .html URL must not be in sitemap`);
}
assert(!parsed.entries.some((entry) => new URL(entry.url).pathname === "/gdpr"), "the duplicate /gdpr policy must stay out of sitemap");

const officialLastmods = editorialLastmods();
for (const entry of parsed.entries) {
  assert.equal(entry.lastmod, officialLastmods.get(entry.url) || null, `${entry.url}: lastmod must come only from lastMeaningfulUpdate`);
}
for (const [url, lastmod] of officialLastmods) {
  const entry = parsed.entries.find((candidate) => candidate.url === url);
  if (entry) assert.equal(entry.lastmod, lastmod, `${url}: verified lastMeaningfulUpdate must be emitted`);
}

const globalStampFixture = Array.from({ length: policy.suspiciousSharedLastmodThreshold }, (_, index) => ({
  url: `${policy.site}/fixture-${index}`,
  lastmod: "2026-07-21",
}));
assert.equal(
  validateLastmodDistribution(globalStampFixture, policy.suspiciousSharedLastmodThreshold).length,
  1,
  "CI guard must reject a build-wide shared lastmod stamp"
);

console.log(`Sitemap contract passed: ${parsed.entries.length} URLs, ${parsed.entries.filter((entry) => entry.lastmod).length} verified lastmod values.`);
