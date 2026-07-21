#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { ROOT, findPublicHtmlFiles } = require("./sync-global-header");
const { sitemapUrls } = require("./sitemap-utils");

const CONFIG_PATH = path.join(ROOT, "config", "url-consolidation-candidates.json");
const GSC_PATH = path.join(ROOT, "reports", "gsc-page-opportunities.csv");
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const OUT_CSV = path.join(ROOT, "reports", "url-consolidation-inventory-2026-07-21.csv");
const OUT_MD = path.join(ROOT, "reports", "url-consolidation-inventory-2026-07-21.md");
const SITE = "https://atelierdeconsultanta.ro";

function parseCsv(text) {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === '"') {
      if (quoted && text[index + 1] === '"') { value += '"'; index += 1; }
      else quoted = !quoted;
    } else if (char === "," && !quoted) {
      row.push(value); value = "";
    } else if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && text[index + 1] === "\n") index += 1;
      row.push(value); value = "";
      if (row.some((cell) => cell !== "")) rows.push(row);
      row = [];
    } else value += char;
  }
  if (value || row.length) { row.push(value); rows.push(row); }
  const headers = rows.shift() || [];
  return rows.map((cells) => Object.fromEntries(headers.map((header, index) => [header, cells[index] || ""])));
}

function routeFromHref(href) {
  if (typeof href !== "string" || !href.trim() || href.startsWith("#")) return "";
  try {
    const url = new URL(href, SITE);
    if (url.origin !== SITE) return "";
    let route = url.pathname.replace(/\/+$/u, "") || "/";
    route = route.replace(/\.html$/u, "");
    return route;
  } catch {
    return "";
  }
}

function normalizedText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function tokens(value) {
  const stop = new Set(["acest", "aceasta", "aceste", "pentru", "care", "este", "sunt", "prin", "despre", "din", "sau", "mai", "poate", "trebuie", "faber", "fonduri", "europene"]);
  return new Set(normalizedText(value).toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/gu, "").match(/[a-z0-9]{4,}/gu)?.filter((word) => !stop.has(word)) || []);
}

function jaccard(left, right) {
  const intersection = [...left].filter((item) => right.has(item)).length;
  const union = new Set([...left, ...right]).size;
  return union ? Math.round((intersection / union) * 100) : 0;
}

function csvCell(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function writeOrCheck(filePath, content, check) {
  if (check) {
    const current = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
    if (current !== content) throw new Error(`${path.relative(ROOT, filePath)} nu este sincronizat`);
    return;
  }
  fs.writeFileSync(filePath, content, "utf8");
}

function main() {
  const check = process.argv.includes("--check");
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  const gscRows = parseCsv(fs.readFileSync(GSC_PATH, "utf8"));
  const gscByRoute = new Map();
  for (const record of gscRows) {
    const route = routeFromHref(record.page);
    if (route && !gscByRoute.has(route) && record.date_filter === "Last 3 months") gscByRoute.set(route, record);
  }
  const sitemapRoutes = new Set(sitemapUrls(ROOT).map(routeFromHref));

  const inbound = new Map(config.rows.map((row) => [row.url, { total: 0, contextual: 0, pages: new Set() }]));
  for (const relativePath of findPublicHtmlFiles()) {
    const html = fs.readFileSync(path.join(ROOT, ...relativePath.split("/")), "utf8");
    const $ = cheerio.load(html);
    $("a[href]").each((_, element) => {
      const route = routeFromHref($(element).attr("href"));
      if (!inbound.has(route)) return;
      const data = inbound.get(route);
      data.total += 1;
      if ($(element).closest("main").length) data.contextual += 1;
      data.pages.add(relativePath);
    });
  }

  const extracted = new Map();
  for (const row of config.rows) {
    const html = fs.readFileSync(path.join(ROOT, ...row.file.split("/")), "utf8");
    const $ = cheerio.load(html, { decodeEntities: false });
    const main = $("main").first().clone();
    main.find("script,style,nav,footer,[data-editorial-governance],[data-contextual-next-steps]").remove();
    const text = normalizedText(main.text());
    const headings = main.find("h2").map((_, element) => normalizedText($(element).text())).get().filter(Boolean);
    extracted.set(row.url, {
      title: normalizedText($("title").first().text()),
      h1: normalizedText($("h1").first().text()),
      canonical: $("link[rel='canonical']").first().attr("href") || "",
      robots: $("meta[name='robots']").map((_, element) => $(element).attr("content") || "").get().join("; ") || "implicit index",
      text,
      tokenSet: tokens(text),
      wordCount: text.split(/\s+/u).filter(Boolean).length,
      headings
    });
  }

  const groupMembers = new Map();
  for (const row of config.rows) {
    if (!groupMembers.has(row.group)) groupMembers.set(row.group, []);
    groupMembers.get(row.group).push(row.url);
  }

  const inventory = config.rows.map((row) => {
    const page = extracted.get(row.url);
    const peerUrl = groupMembers.get(row.group).find((url) => url !== row.url) || "";
    const peer = extracted.get(peerUrl);
    const uniqueHeadings = peer
      ? page.headings.filter((heading) => !peer.headings.some((other) => normalizedText(other).toLowerCase() === normalizedText(heading).toLowerCase()))
      : page.headings;
    const links = inbound.get(row.url);
    const gsc = gscByRoute.get(row.url);
    const inSitemap = sitemapRoutes.has(row.url);
    const locallyIndexable = !/noindex/iu.test(page.robots);
    return {
      group: row.group,
      url: row.url,
      primary_intent: row.primaryIntent,
      query_cluster: row.queryCluster,
      page_type: row.pageType,
      gsc_window: gsc ? `${gsc.date_start}..${gsc.date_end}` : "DE_VALIDAT_UMAN",
      gsc_clicks: gsc ? gsc.clicks : "DE_VALIDAT_UMAN",
      gsc_impressions: gsc ? gsc.impressions : "DE_VALIDAT_UMAN",
      gsc_ctr_percent: gsc ? gsc.ctr_percent : "DE_VALIDAT_UMAN",
      gsc_position: gsc ? gsc.position : "DE_VALIDAT_UMAN",
      backlinks: "DE_VALIDAT_UMAN — export Ahrefs/Search Console Links necesar",
      conversions: "DE_VALIDAT_UMAN — export analytics/CRM necesar",
      unique_content: `${page.wordCount} cuvinte; ${uniqueHeadings.length}/${page.headings.length} H2 unice față de pereche: ${uniqueHeadings.slice(0, 4).join(" | ") || "niciun exemplu"}`,
      pair_token_similarity_percent: peer ? jaccard(page.tokenSet, peer.tokenSet) : 0,
      canonical_current: page.canonical,
      canonical_state: routeFromHref(page.canonical) === row.url ? "self-canonical" : `canonical către ${routeFromHref(page.canonical) || "lipsă"}`,
      internal_links_total: links.total,
      internal_links_contextual: links.contextual,
      internal_linking_pages: links.pages.size,
      indexation_status: `${locallyIndexable ? "indexabil local" : "noindex local"}; ${inSitemap ? "în sitemap" : "absent din sitemap"}; GSC URL Inspection: DE_VALIDAT_UMAN`,
      title: page.title,
      h1: page.h1,
      recommendation: row.recommendation,
      target_or_keep: row.target || "KEEP",
      content_to_migrate: row.contentToMigrate,
      risks: row.risks,
      approval_status: config.decisionStatus
    };
  });

  const headers = Object.keys(inventory[0]);
  const csv = [headers.map(csvCell).join(","), ...inventory.map((row) => headers.map((header) => csvCell(row[header])).join(","))].join("\n") + "\n";
  writeOrCheck(OUT_CSV, csv, check);

  const lines = [
    "# Inventar URL-uri concurente",
    "",
    `Generat: 2026-07-21 · GSC Performance: ${config.gscWindow} · decizii: **${config.decisionStatus}**.`,
    "",
    "> Performance GSC este istoric și nu înlocuiește URL Inspection. Backlink-urile și conversiile nu sunt disponibile în repository.",
    "",
    "| URL | GSC clicuri / impresii / poziție | Canonical | Linkuri interne total/context | Indexare locală | Similaritate pereche | Recomandare |",
    "|---|---:|---|---:|---|---:|---|"
  ];
  for (const row of inventory) {
    lines.push(`| \`${row.url}\` | ${row.gsc_clicks} / ${row.gsc_impressions} / ${row.gsc_position} | ${row.canonical_state} | ${row.internal_links_total}/${row.internal_links_contextual} | ${row.indexation_status} | ${row.pair_token_similarity_percent}% | ${row.recommendation} → ${row.target_or_keep} |`);
  }
  lines.push("", "CSV-ul conține intenția, clusterul, titlul/H1, conținutul unic, migrarea și riscurile pentru fiecare rând.", "");
  writeOrCheck(OUT_MD, lines.join("\n"), check);
  console.log(`Inventar consolidare ${check ? "PASS" : "generat"}: ${inventory.length} URL-uri.`);
}

main();
