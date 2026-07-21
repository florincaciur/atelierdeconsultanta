#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { sitemapUrls: readSitemapUrls } = require("./sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const INPUT = path.join(ROOT, "blog.json");
const OUTPUT = path.join(ROOT, "feed.xml");
const MAX_ITEMS = 50;

function xml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function canonicalUrls() {
  return new Set(readSitemapUrls(ROOT));
}

function safeDate(post) {
  const value = post.publishedAt || post.date || post.createdAt || post.updatedAt;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

const source = JSON.parse(fs.readFileSync(INPUT, "utf8"));
const sitemapUrls = canonicalUrls();
const deduped = new Map();

for (const post of source.posts || []) {
  if (post.published === false || post.status === "draft") continue;
  const link = String(post.canonicalUrl || "").trim();
  if (!link.startsWith(`${SITE}/`) || !sitemapUrls.has(link)) continue;
  const date = safeDate(post);
  if (!date) continue;
  const candidate = {
    title: post.title || post.metaTitle,
    description: post.excerpt || post.metaDescription || post.seo?.metaDescription,
    link,
    author: post.author || "FABER – Atelier de Consultanță",
    date
  };
  if (!candidate.title || !candidate.description) continue;
  const current = deduped.get(link);
  if (!current || candidate.date > current.date) deduped.set(link, candidate);
}

const items = [...deduped.values()]
  .sort((a, b) => b.date - a.date)
  .slice(0, MAX_ITEMS);

const lastBuildDate = items[0]?.date || new Date();
const itemXml = items.map((item) => `
    <item>
      <title>${xml(item.title)}</title>
      <description>${xml(item.description)}</description>
      <link>${xml(item.link)}</link>
      <guid isPermaLink="true">${xml(item.link)}</guid>
      <pubDate>${item.date.toUTCString()}</pubDate>
      <author>${xml(item.author)}</author>
    </item>`).join("");

const feed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>FABER – Fonduri europene</title>
    <description>Ghiduri FABER despre fonduri europene, eligibilitate, documente, proiectare și implementare.</description>
    <link>${SITE}/blog</link>
    <language>ro-RO</language>
    <lastBuildDate>${lastBuildDate.toUTCString()}</lastBuildDate>
    <generator>FABER static feed generator</generator>${itemXml}
  </channel>
</rss>
`;

fs.writeFileSync(OUTPUT, feed, "utf8");
console.log(`Generated feed.xml with ${items.length} canonical items.`);
