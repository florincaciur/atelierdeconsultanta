#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { fileForRoute } = require("./structured-data-utils");
const { sitemapUrls } = require("./sitemap-utils");
const { sceneArtwork } = require("./hero-program-scenes");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const STYLE_HREF = "/assets/program-visuals.css?v=20260901-2";
const START = "PROGRAM_VISUAL_START";
const END = "PROGRAM_VISUAL_END";
const PROGRAMS = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8")).programs;

function routes() {
  return sitemapUrls(ROOT, "sitemap-programs.xml")
    .map((value) => new URL(value).pathname.replace(/\/$/u, "") || "/");
}

function filesForRoute(route) {
  if (route === "/") return [path.join(ROOT, "index.html")];
  const relative = decodeURIComponent(route.replace(/^\//u, ""));
  return [...new Set([
    fileForRoute(ROOT, route),
    path.join(ROOT, relative, "index.html"),
    path.join(ROOT, `${relative}.html`)
  ])].filter((file) => fs.existsSync(file));
}

function programForRoute(route) {
  const exact = PROGRAMS.find((program) => program.pageUrl === route);
  if (exact) return exact;
  if (route.startsWith("/dr-12-")) return PROGRAMS.find((program) => program.id === "dr12-afir");
  if (route.startsWith("/dr-14-")) return PROGRAMS.find((program) => program.id === "dr14-afir");
  return null;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function familyLabel(family) {
  if (/afir|agricultur|leader/iu.test(family)) return "Investiții rurale";
  if (/energie|mobilitate/iu.test(family)) return "Energie și mobilitate";
  if (/digital/iu.test(family)) return "Digitalizare și inovare";
  if (/regional|tranzitie/iu.test(family)) return "Dezvoltare regională";
  if (/antrepren/iu.test(family)) return "Antreprenoriat";
  if (/pnrr/iu.test(family)) return "Investiții și reforme";
  return "Program de finanțare";
}

function sceneSvg(id, record, variant) {
  const title = record.shortName || record.name;
  return `<svg class="program-visual__svg program-visual__svg--${variant}" viewBox="0 0 420 270" role="img" aria-labelledby="${id}-${variant}-title ${id}-${variant}-desc" preserveAspectRatio="xMidYMid meet">
      <title id="${id}-${variant}-title">Reper vizual pentru ${escapeHtml(title)}</title>
      <desc id="${id}-${variant}-desc">Compoziție simbolică pentru domeniul programului și traseul de verificare: solicitant, investiție, buget și sursă oficială.</desc>
      <ellipse class="pv-shadow" cx="213" cy="231" rx="142" ry="18"/>
      <path class="pv-platform" d="m55 216 149-51 158 51-150 48Z"/>
      ${sceneArtwork(record)}
      <path class="program-visual__track" d="M42 29H378"/>
      <g class="program-visual__markers" aria-hidden="true"><circle cx="42" cy="29" r="8"/><circle cx="154" cy="29" r="8"/><circle cx="266" cy="29" r="8"/><circle cx="378" cy="29" r="8"/></g>
    </svg>`;
}

function visualPane(route, record = programForRoute(route)) {
  if (!record) throw new Error(`${route}: programul nu poate fi asociat registrului factual`);
  const slug = route.replace(/[^a-z0-9]+/giu, "-").replace(/^-|-$/gu, "") || "program";
  const id = `program-visual-${slug}`;
  const verifiedIso = record.verifiedAt || "";
  const verified = verifiedIso ? verifiedIso.split("-").reverse().join(".") : "—";
  const title = record.shortName || record.name;
  const steps = ["Solicitant", "Investiție", "Buget", "Sursă oficială"];
  return `<!-- PROGRAM_HERO_VISUAL_START -->
  <div class="program-hero__visual program-hero__visual--immersive">
    <div class="program-visual__canvas">
      ${sceneSvg(id, record, "desktop")}
      ${sceneSvg(id, record, "mobile")}
    </div>
    <div class="program-visual__steps" aria-label="Repere pentru verificarea programului">
      ${steps.map((label, index) => `<button class="program-visual__step" type="button" data-program-step="${index + 1}" aria-pressed="${index === 0 ? "true" : "false"}"><span>0${index + 1}</span>${label}</button>`).join("\n      ")}
    </div>
    <div class="program-visual__footer">
      <span class="program-visual__live" aria-live="polite">Reper activ: Solicitant</span>
      <span>Verificat <time${verifiedIso ? ` datetime="${escapeHtml(verifiedIso)}"` : ""}>${escapeHtml(verified)}</time></span>
      <a href="${escapeHtml(record.sourceUrl)}" rel="noopener noreferrer" target="_blank" data-analytics-event="source_document_click" data-analytics-component="program_hero" data-analytics-cta-id="official_source">Sursa oficială<span class="sr-only"> pentru ${escapeHtml(title)} (se deschide într-o filă nouă)</span></a>
    </div>
  </div>
  <!-- PROGRAM_HERO_VISUAL_END -->`;
}

function enhanceOpeningTag(tag, record) {
  let next = tag.replace(/\s(?:data-program-visual|data-active-step|data-program-family)=(?:"[^"]*"|'[^']*')/giu, "")
    .replace(/\sdata-immersive-card(?:=(?:"[^"]*"|'[^']*'))?/giu, "");
  next = next.replace(/class=(['"])([^'"]*)\1/iu, (_, quote, classes) => {
    const values = new Set(classes.split(/\s+/u).filter(Boolean));
    values.add("program-hero");
    values.add("program-hero--immersive");
    values.add("program-visual");
    return `class=${quote}${[...values].join(" ")}${quote}`;
  });
  return next.replace(/>$/u, ` data-program-visual="immersive-verification" data-program-family="${escapeHtml(record.family || "program")}" data-active-step="1" data-immersive-card>`);
}

function removeLegacyHeroVisual(hero) {
  return hero
    .replace(/\s*<!--\s*PROGRAM_HERO_VISUAL_START\s*-->[\s\S]*?<!--\s*PROGRAM_HERO_VISUAL_END\s*-->\s*/giu, "\n")
    .replace(/\s*<span\b[^>]*class=(['"])[^'"]*(?:hero-icon|post-icon)[^'"]*\1[^>]*>[\s\S]*?<\/span>\s*/giu, "\n")
    .replace(/\s*<div\b[^>]*class=(['"])[^'"]*program-hero__visual[^'"]*\1[^>]*>\s*<svg\b[\s\S]*?<\/svg>\s*<\/div>\s*/giu, "\n")
    .replace(/\s*<a\b[^>]*>\s*(?:Sursă oficială|Ghid oficial|Vezi sursa oficială|Consultă documentul oficial)\s*<\/a>\s*/giu, "\n");
}

function enhanceHero(hero, route, record) {
  const eol = hero.includes("\r\n") ? "\r\n" : "\n";
  const opening = hero.match(/^<(?:header|section)\b[^>]*>/iu)?.[0];
  if (!opening) throw new Error(`${route}: bannerul existent nu poate fi interpretat`);
  const closing = hero.match(/<\/(?:header|section)>\s*$/iu)?.[0];
  if (!closing) throw new Error(`${route}: bannerul existent nu are închidere validă`);
  let next = removeLegacyHeroVisual(hero).replace(/\r?\n/gu, eol);
  next = next.replace(opening, enhanceOpeningTag(opening, record));
  if (/post-hero/iu.test(opening) && !next.includes(record.statusLabel)) {
    next = next.replace(/(<p\b[^>]*class=(['"])[^'"]*post-excerpt[^'"]*\2[^>]*>[\s\S]*?<\/p>)/iu, `$1\n    <p class="program-hero__status">${escapeHtml(record.statusLabel)}</p>`);
  }
  const pane = visualPane(route, record).replace(/\r?\n/gu, eol);
  return next.replace(closing, `${pane}${eol}${closing}`);
}

function generatedHero(route, record) {
  const title = record.shortName || record.name;
  const summary = record.cardSummary || record.metaDescription || `Repere verificate pentru ${title}.`;
  const contact = `/contact#program_slug=${encodeURIComponent(record.id)}&source_page=${encodeURIComponent(route)}`;
  return `<!-- ${START} -->
<section class="program-hero program-hero--immersive program-visual" aria-labelledby="program-title-${escapeHtml(record.id)}" data-program-visual="immersive-verification" data-program-family="${escapeHtml(record.family || "program")}" data-active-step="1" data-immersive-card>
  <div class="program-hero__content">
    <p class="program-eyebrow">${escapeHtml(familyLabel(record.family || ""))}</p>
    <h1 id="program-title-${escapeHtml(record.id)}">${escapeHtml(title)}</h1>
    <p class="program-lead">${escapeHtml(summary)}</p>
    <p class="program-hero__status">${escapeHtml(record.statusLabel)}</p>
    <div class="program-hero__actions"><a class="btn btn-primary" href="${escapeHtml(contact)}">Verifică încadrarea proiectului</a></div>
  </div>
  ${visualPane(route, record)}
</section>
<!-- ${END} -->`;
}

function seoSignature(html) {
  const head = html.match(/<head\b[^>]*>[\s\S]*?<\/head>/iu)?.[0] || "";
  const patterns = [
    /<title\b[^>]*>[\s\S]*?<\/title>/giu,
    /<meta\b[^>]*(?:name|property)=["'][^"']+["'][^>]*>/giu,
    /<link\b[^>]*rel=["']canonical["'][^>]*>/giu,
    /<script\b[^>]*type=["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script>/giu
  ];
  return patterns.flatMap((pattern) => head.match(pattern) || []).join("\n");
}

function synchronizePass(html, route) {
  const eol = html.includes("\r\n") ? "\r\n" : "\n";
  const record = programForRoute(route);
  if (!record) throw new Error(`${route}: programul nu poate fi asociat registrului factual`);
  const signatureBefore = seoSignature(html);
  const oldBlock = new RegExp(`\\s*<!--\\s*${START}\\s*-->[\\s\\S]*?<!--\\s*${END}\\s*-->\\s*`, "giu");
  let current = html.replace(oldBlock, eol);

  const stylePattern = /<link\b[^>]*href=["']\/assets\/program-visuals\.css(?:\?[^"']*)?["'][^>]*>/giu;
  let kept = false;
  if (stylePattern.test(current)) {
    stylePattern.lastIndex = 0;
    current = current.replace(stylePattern, () => {
      if (kept) return "";
      kept = true;
      return `<link rel="stylesheet" href="${STYLE_HREF}">`;
    });
  } else {
    current = current.replace(/<\/head>/iu, `  <link rel="stylesheet" href="${STYLE_HREF}">${eol}</head>`);
  }

  const heroPatterns = [
    /<header\b[^>]*class=(['"])[^'"]*\bhero\b[^'"]*\1[^>]*>[\s\S]*?<\/header>/iu,
    /<section\b[^>]*class=(['"])[^'"]*(?:program-hero|post-hero)[^'"]*\1[^>]*>[\s\S]*?<\/section>/iu
  ];
  const match = heroPatterns.map((pattern) => current.match(pattern)).find(Boolean);
  if (match) {
    current = current.replace(match[0], enhanceHero(match[0], route, record));
  } else {
    const mainOpen = /<main\b[^>]*>/iu.exec(current);
    if (!mainOpen) throw new Error(`${route}: lipsește elementul main`);
    current = current.replace(
      /(<article\b[^>]*class=(['"])[^'"]*\bpanel\b[^'"]*\2[^>]*>[\s\S]*?<!--\s*PROGRAM_FACTUAL_STATUS_END\s*-->)[\s\S]*?(<\/article>)/iu,
      (_, factualPanel, quote, closingArticle) => `${factualPanel}${eol}${closingArticle}`
    );
    const insertAt = mainOpen.index + mainOpen[0].length;
    current = `${current.slice(0, insertAt)}${eol}${generatedHero(route, record).replace(/\n/gu, eol)}${eol}${current.slice(insertAt)}`;
  }

  if (seoSignature(current) !== signatureBefore) throw new Error(`${route}: metadatele SEO sau JSON-LD au fost alterate`);
  return current;
}

function synchronize(html, route) {
  let current = html;
  for (let pass = 0; pass < 4; pass += 1) {
    const next = synchronizePass(current, route);
    if (next === current) return next;
    current = next;
  }
  throw new Error(`${route}: bannerul unic nu converge după patru treceri`);
}

function main() {
  const changed = [];
  for (const route of routes()) {
    const files = filesForRoute(route);
    if (!files.length) throw new Error(`${route}: fișierul canonic lipsește`);
    for (const file of files) {
      const before = fs.readFileSync(file, "utf8");
      const after = synchronize(before, route);
      if (after === before) continue;
      changed.push(path.relative(ROOT, file));
      if (!CHECK_ONLY) fs.writeFileSync(file, after, "utf8");
    }
  }
  if (CHECK_ONLY && changed.length) throw new Error(`Bannere de program nesincronizate: ${changed.join(", ")}`);
  console.log(`Bannere imersive unice: ${routes().length} rute verificate, ${changed.length} fișiere ${CHECK_ONLY ? "nesincronizate" : "actualizate"}.`);
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { filesForRoute, programForRoute, routes, seoSignature, synchronize, synchronizePass, visual: generatedHero, visualPane };
