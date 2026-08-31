#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { fileForRoute } = require("./structured-data-utils");
const { sitemapUrls } = require("./sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const STYLE_HREF = "/assets/program-visuals.css?v=20260901-1";
const START = "PROGRAM_VISUAL_START";
const END = "PROGRAM_VISUAL_END";
const PROGRAMS = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8")).programs;

function routes() {
  return sitemapUrls(ROOT, "sitemap-programs.xml")
    .map((value) => new URL(value).pathname.replace(/\/$/, "") || "/");
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

function sceneGlyph(family) {
  if (/afir|agricultur|leader/iu.test(family)) {
    return `<g class="program-visual__glyph" aria-hidden="true"><path d="M272 111c38-50 92-54 139-12-46 8-86 29-118 66"/><path d="M298 165c16-49 49-78 101-86"/><circle cx="268" cy="178" r="12"/></g>`;
  }
  if (/energie|mobilitate/iu.test(family)) {
    return `<g class="program-visual__glyph" aria-hidden="true"><rect x="272" y="85" width="116" height="82" rx="9"/><path d="M292 105h76M292 126h76M330 85v82M279 181h102"/><path d="M425 76l-22 42h25l-29 54"/></g>`;
  }
  if (/digital/iu.test(family)) {
    return `<g class="program-visual__glyph" aria-hidden="true"><circle cx="287" cy="104" r="16"/><circle cx="390" cy="89" r="12"/><circle cx="411" cy="170" r="17"/><circle cx="305" cy="184" r="11"/><path d="M302 101l76-10M296 117l13 56M321 181l73-9M398 104l9 49M305 115l91 44"/></g>`;
  }
  if (/regional|tranzitie/iu.test(family)) {
    return `<g class="program-visual__glyph" aria-hidden="true"><path d="M276 181V99h42v82M329 181V70h55v111M396 181v-58h38v58M264 181h181"/><path d="M343 90h27M343 111h27M343 132h27"/></g>`;
  }
  if (/antrepren/iu.test(family)) {
    return `<g class="program-visual__glyph" aria-hidden="true"><path d="M272 117h151l-12-42H285zM283 117v67h129v-67M320 184v-43h54v43"/><path d="M285 76l20 41M326 76l7 41M369 76l-7 41M410 76l-20 41"/></g>`;
  }
  return `<g class="program-visual__glyph" aria-hidden="true"><path d="M284 78h108l30 30v77H284zM392 78v31h30"/><path d="M307 129h91M307 151h91"/><circle cx="286" cy="78" r="7"/></g>`;
}

function desktopScene(id, family) {
  return `<svg class="program-visual__svg program-visual__svg--desktop" viewBox="0 0 920 260" role="img" aria-labelledby="${id}-desktop-title ${id}-desktop-desc" preserveAspectRatio="xMidYMid meet">
      <title id="${id}-desktop-title">Traseu vizual de verificare a programului</title>
      <desc id="${id}-desktop-desc">O compoziție animată conectează verificarea solicitantului, investiției, bugetului și sursei oficiale.</desc>
      <g class="program-visual__orbit" aria-hidden="true"><ellipse cx="351" cy="130" rx="235" ry="91"/><ellipse cx="351" cy="130" rx="155" ry="116"/></g>
      <g class="program-visual__slabs" aria-hidden="true"><rect x="227" y="65" width="246" height="142" rx="21"/><rect x="245" y="51" width="246" height="142" rx="21"/><rect x="263" y="37" width="246" height="142" rx="21"/></g>
      ${sceneGlyph(family)}
      <path class="program-visual__track" d="M92 211C226 229 284 210 351 218S560 233 828 197" fill="none"/>
      <g class="program-visual__markers" aria-hidden="true"><circle cx="92" cy="211" r="17"/><circle cx="338" cy="216" r="17"/><circle cx="579" cy="218" r="17"/><circle cx="828" cy="197" r="17"/></g>
    </svg>`;
}

function mobileScene(id) {
  return `<svg class="program-visual__svg program-visual__svg--mobile" viewBox="0 0 320 330" role="img" aria-labelledby="${id}-mobile-title ${id}-mobile-desc" preserveAspectRatio="xMidYMid meet">
      <title id="${id}-mobile-title">Traseu vizual de verificare a programului</title>
      <desc id="${id}-mobile-desc">O compoziție verticală animată conectează cele patru repere de verificare a programului.</desc>
      <g class="program-visual__orbit" aria-hidden="true"><ellipse cx="160" cy="133" rx="132" ry="83"/><ellipse cx="160" cy="133" rx="88" ry="112"/></g>
      <g class="program-visual__slabs" aria-hidden="true"><rect x="72" y="79" width="176" height="116" rx="18"/><rect x="83" y="68" width="176" height="116" rx="18"/><rect x="94" y="57" width="176" height="116" rx="18"/></g>
      <g class="program-visual__mobile-glyph" aria-hidden="true"><circle cx="160" cy="115" r="31"/><path d="M145 115l10 10 21-24"/></g>
      <path class="program-visual__track" d="M35 278C101 250 218 307 285 265" fill="none"/>
      <g class="program-visual__markers" aria-hidden="true"><circle cx="35" cy="278" r="14"/><circle cx="117" cy="271" r="14"/><circle cx="205" cy="283" r="14"/><circle cx="285" cy="265" r="14"/></g>
    </svg>`;
}

function visual(route, record = programForRoute(route)) {
  if (!record) throw new Error(`${route}: programul nu poate fi asociat registrului factual`);
  const slug = route.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "") || "program";
  const id = `program-visual-${slug}`;
  const family = record.family || "program";
  const title = record.shortName || record.name;
  const verified = record.verifiedAt ? record.verifiedAt.split("-").reverse().join(".") : "—";
  const steps = ["Solicitant", "Investiție", "Buget", "Sursă oficială"];
  return `<!-- ${START} -->
<figure class="program-visual" data-program-visual="immersive-verification" data-program-family="${escapeHtml(family)}" data-active-step="1" data-immersive-card>
  <figcaption class="program-visual__header">
    <span class="program-visual__eyebrow">${escapeHtml(familyLabel(family))} · verificat ${escapeHtml(verified)}</span>
    <strong>${escapeHtml(title)}</strong>
    <span class="program-visual__status">${escapeHtml(record.statusLabel)}</span>
  </figcaption>
  <div class="program-visual__canvas">
    ${desktopScene(id, family)}
    ${mobileScene(id)}
    <span class="program-visual__spark" aria-hidden="true"></span>
  </div>
  <div class="program-visual__steps" aria-label="Repere pentru verificarea programului">
    ${steps.map((label, index) => `<button class="program-visual__step" type="button" data-program-step="${index + 1}" aria-pressed="${index === 0 ? "true" : "false"}"><span>0${index + 1}</span>${label}</button>`).join("\n    ")}
  </div>
  <div class="program-visual__footer"><span class="program-visual__live" aria-live="polite">Reper activ: Solicitant</span><a href="${escapeHtml(record.sourceUrl)}" rel="noopener noreferrer" target="_blank">Consultă sursa oficială<span class="sr-only"> pentru ${escapeHtml(title)} (se deschide într-o filă nouă)</span></a></div>
</figure>
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
  const signatureBefore = seoSignature(html);
  const startPattern = new RegExp(`\\s*<!--\\s*${START}\\s*-->[\\s\\S]*?<!--\\s*${END}\\s*-->\\s*`, "g");
  let current = html.replace(startPattern, eol);
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
  const programHeroEnd = /<!--\s*PROGRAM_HERO_END\s*-->/iu.exec(current);
  const mainOpen = /<main\b[^>]*>/iu.exec(current);
  if (!mainOpen) throw new Error(`${route}: lipsește elementul main`);
  const mainClose = /<\/main>/iu.exec(current.slice(mainOpen.index));
  const mainEndIndex = mainClose ? mainOpen.index + mainClose.index : current.length;
  const heroIsInsideMain = programHeroEnd && programHeroEnd.index > mainOpen.index && programHeroEnd.index < mainEndIndex;
  const insertionIndex = heroIsInsideMain ? programHeroEnd.index + programHeroEnd[0].length : mainOpen.index + mainOpen[0].length;
  const block = visual(route).replace(/\n/gu, eol);
  current = `${current.slice(0, insertionIndex)}${eol}${block}${eol}${current.slice(insertionIndex)}`;
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
  throw new Error(`${route}: componenta vizuală nu converge după patru treceri`);
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
  if (CHECK_ONLY && changed.length) throw new Error(`Componente vizuale de program nesincronizate: ${changed.join(", ")}`);
  console.log(`Componente imersive program: ${routes().length} rute verificate, ${changed.length} fișiere ${CHECK_ONLY ? "nesincronizate" : "actualizate"}.`);
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { filesForRoute, programForRoute, routes, seoSignature, synchronize, visual };
