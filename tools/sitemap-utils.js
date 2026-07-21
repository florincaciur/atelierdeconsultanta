"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_SITE = "https://atelierdeconsultanta.ro";

function decodeXml(value) {
  return String(value)
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function parseUrlsetEntries(xml, sourceFile = "sitemap.xml") {
  const entries = [];
  for (const match of String(xml).matchAll(/<url>\s*([\s\S]*?)\s*<\/url>/giu)) {
    const block = match[1];
    const loc = block.match(/<loc>\s*([^<]+?)\s*<\/loc>/iu)?.[1];
    if (!loc) continue;
    const lastmod = block.match(/<lastmod>\s*([^<]+?)\s*<\/lastmod>/iu)?.[1] || null;
    entries.push({
      url: decodeXml(loc.trim()),
      lastmod: lastmod ? decodeXml(lastmod.trim()) : null,
      sourceFile,
    });
  }
  return entries;
}

function parseSitemapIndex(xml) {
  const locations = [];
  for (const match of String(xml).matchAll(/<sitemap>\s*([\s\S]*?)\s*<\/sitemap>/giu)) {
    const loc = match[1].match(/<loc>\s*([^<]+?)\s*<\/loc>/iu)?.[1];
    if (loc) locations.push(decodeXml(loc.trim()));
  }
  return locations;
}

function localSitemapFile(location, site = DEFAULT_SITE) {
  let parsed;
  try {
    parsed = new URL(location);
  } catch {
    return null;
  }
  if (parsed.origin !== site || parsed.search || parsed.hash) return null;
  const relative = decodeURIComponent(parsed.pathname).replace(/^\/+/, "");
  if (!relative || relative.includes("..") || relative.includes("\\")) return null;
  return relative;
}

function readSitemapEntriesFromReader(readFile, entryFile = "sitemap.xml", site = DEFAULT_SITE) {
  const entries = [];
  const documents = [];
  const visited = new Set();

  function visit(file) {
    if (visited.has(file)) throw new Error(`Sitemap reference loop: ${file}`);
    visited.add(file);
    const xml = readFile(file);
    if (typeof xml !== "string") throw new Error(`Missing sitemap document: ${file}`);
    const childLocations = parseSitemapIndex(xml);
    const urlEntries = parseUrlsetEntries(xml, file);
    if (childLocations.length && urlEntries.length) throw new Error(`${file} mixes sitemapindex and urlset entries`);
    documents.push({ file, type: childLocations.length ? "index" : "urlset", childLocations });
    for (const entry of urlEntries) entries.push(entry);
    for (const location of childLocations) {
      const child = localSitemapFile(location, site);
      if (!child) throw new Error(`${file} references a non-local sitemap: ${location}`);
      visit(child);
    }
  }

  visit(entryFile);
  return { documents, entries };
}

function readSitemapEntries(root, entryFile = "sitemap.xml", site = DEFAULT_SITE) {
  return readSitemapEntriesFromReader((file) => {
    const absolute = path.resolve(root, file);
    if (!absolute.startsWith(path.resolve(root) + path.sep) && absolute !== path.resolve(root, file)) return null;
    return fs.existsSync(absolute) ? fs.readFileSync(absolute, "utf8") : null;
  }, entryFile, site);
}

function sitemapUrls(root, entryFile = "sitemap.xml", site = DEFAULT_SITE) {
  return readSitemapEntries(root, entryFile, site).entries.map((entry) => entry.url);
}

function sitemapLastmods(root, entryFile = "sitemap.xml", site = DEFAULT_SITE) {
  return new Map(readSitemapEntries(root, entryFile, site).entries
    .filter((entry) => entry.lastmod)
    .map((entry) => [entry.url, entry.lastmod]));
}

module.exports = {
  DEFAULT_SITE,
  localSitemapFile,
  parseSitemapIndex,
  parseUrlsetEntries,
  readSitemapEntries,
  readSitemapEntriesFromReader,
  sitemapLastmods,
  sitemapUrls,
};
