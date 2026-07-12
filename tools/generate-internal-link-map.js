#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { loadPriorityConfig } = require("./priority-aeo");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const OUTPUT_PATH = path.join(ROOT, "reports", "internal-link-map.csv");

function sitemapUrls() {
  return [...fs.readFileSync(SITEMAP_PATH, "utf8").matchAll(/<loc>([^<]+)<\/loc>/g)]
    .map((match) => match[1].trim());
}

function fileForUrl(url) {
  const pathname = new URL(url).pathname;
  if (pathname === "/") return path.join(ROOT, "index.html");
  const directoryIndex = path.join(ROOT, pathname.slice(1), "index.html");
  if (fs.existsSync(directoryIndex)) return directoryIndex;
  return path.join(ROOT, `${pathname.slice(1)}.html`);
}

function normalizeInternalUrl(href) {
  if (!href || /^(?:#|mailto:|tel:|javascript:)/i.test(href)) return null;
  try {
    const url = new URL(href, SITE);
    if (url.origin !== SITE && url.origin !== "https://www.atelierdeconsultanta.ro") return null;
    url.protocol = "https:";
    url.hostname = "atelierdeconsultanta.ro";
    url.search = "";
    url.hash = "";
    if (url.pathname !== "/") url.pathname = url.pathname.replace(/\/+$/, "");
    return url.toString();
  } catch {
    return null;
  }
}

function cleanText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function contextFor($, element) {
  const section = $(element).closest("section, article, .card, .slide, .related-links");
  const heading = section.find("h1, h2, h3").first().text();
  return cleanText(heading) || "Conținut principal";
}

function csv(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function generate() {
  const urls = sitemapUrls();
  const canonicalSet = new Set(urls);
  const priorityPaths = new Set(Object.keys(loadPriorityConfig().pages).map((slug) => `/${slug}`));
  const edges = [];

  for (const sourceUrl of urls) {
    const file = fileForUrl(sourceUrl);
    if (!fs.existsSync(file)) throw new Error(`Lipsește sursa locală pentru ${sourceUrl}: ${file}`);
    const $ = cheerio.load(fs.readFileSync(file, "utf8"));
    const main = $("main").first();
    if (!main.length) continue;
    main.find("a[href]").each((_, element) => {
      const targetUrl = normalizeInternalUrl($(element).attr("href"));
      if (!targetUrl || !canonicalSet.has(targetUrl) || targetUrl === sourceUrl) return;
      const sourcePath = new URL(sourceUrl).pathname;
      const targetPath = new URL(targetUrl).pathname;
      edges.push({
        sourceUrl,
        targetUrl,
        anchorText: cleanText($(element).text()),
        context: contextFor($, element),
        sourcePriority: priorityPaths.has(sourcePath) ? "yes" : "no",
        targetPriority: priorityPaths.has(targetPath) ? "yes" : "no"
      });
    });
  }

  edges.sort((a, b) => a.targetUrl.localeCompare(b.targetUrl) || a.sourceUrl.localeCompare(b.sourceUrl) || a.anchorText.localeCompare(b.anchorText));
  const header = ["source_url", "target_url", "anchor_text", "context", "source_priority", "target_priority"];
  const rows = edges.map((edge) => [edge.sourceUrl, edge.targetUrl, edge.anchorText, edge.context, edge.sourcePriority, edge.targetPriority]);
  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, [header, ...rows].map((row) => row.map(csv).join(",")).join("\n") + "\n", "utf8");

  const errors = [];
  for (const targetPath of priorityPaths) {
    const targetUrl = `${SITE}${targetPath}`;
    const inboundSources = new Set(edges.filter((edge) => edge.targetUrl === targetUrl).map((edge) => edge.sourceUrl));
    if (inboundSources.size < 5) errors.push(`${targetPath}: doar ${inboundSources.size} pagini-sursă contextuale (minimum 5)`);
    const fromHomepage = edges.some((edge) => edge.sourceUrl === `${SITE}/` && edge.targetUrl === targetUrl);
    if (!fromHomepage) errors.push(`${targetPath}: lipsește linkul direct din conținutul homepage`);
    console.log(`${targetPath}: ${inboundSources.size} surse interne; homepage=${fromHomepage ? "da" : "nu"}`);
  }

  console.log(`Matrice scrisă: ${path.relative(ROOT, OUTPUT_PATH)} (${edges.length} linkuri contextuale)`);
  if (errors.length) throw new Error(errors.join("\n"));
}

try {
  generate();
} catch (error) {
  console.error(error.message || error);
  process.exit(1);
}
