#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { synchronizedGraph } = require("./sync-structured-data");
const { loadPageHints } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "editorial-clusters.json");
const CSS_HREF = "/assets/editorial-clusters.css?v=20260721-1";
const CHECK_ONLY = process.argv.includes("--check");
const PAGE_HINTS = loadPageHints(ROOT);
const FEATURED_FUNDING_SLUGS = [
  "dr12-afir", "dr14-afir", "modernizare-microintreprinderi-ne-2",
  "afir-energie-autoconsum", "e-move-ro", "diaspora-investeste-acasa",
  "e-drive", "e-mobility-ro", "fondul-modernizare-pc1-stocare"
];
const PROGRAM_REGISTRY = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8")).programs;

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function attr(value) {
  return esc(value).replace(/'/g, "&#39;");
}

function wordCount(value) {
  return String(value || "").trim().split(/\s+/u).filter(Boolean).length;
}

function routeEntries(config) {
  return (config.clusters || []).flatMap((cluster) =>
    (cluster.routes || []).map((route) => ({ ...route, clusterId: cluster.id, clusterLabel: cluster.label }))
  );
}

function validate(config) {
  const errors = [];
  const routes = routeEntries(config);
  const routeIds = new Set();
  const intentIds = new Set();
  const topicOwners = new Map();

  for (const page of routes) {
    if (!page.route || !page.file || !page.role || !page.intentId || !page.primaryIntent) {
      errors.push(`${page.route || page.file || "unknown"}: câmpuri de identitate lipsă`);
      continue;
    }
    if (routeIds.has(page.route)) errors.push(`${page.route}: rută duplicată`);
    routeIds.add(page.route);
    if (intentIds.has(page.intentId)) errors.push(`${page.route}: intentId duplicat ${page.intentId}`);
    intentIds.add(page.intentId);

    for (const topic of page.ownedTopics || []) {
      if (topicOwners.has(topic)) errors.push(`${page.route}: tema ${topic} aparține deja ${topicOwners.get(topic)}`);
      else topicOwners.set(topic, page.route);
    }

    if (page.render) {
      if (!page.title || !page.description || !page.h1 || !page.directAnswer || !(page.sections || []).length || !page.cta) {
        errors.push(`${page.route}: copy public incomplet`);
      }
      const directWords = wordCount(page.directAnswer);
      if (directWords < 50 || directWords > 90) {
        errors.push(`${page.route}: răspunsul direct trebuie să aibă 50–90 de cuvinte; are ${directWords}`);
      }
      if (/\b2026\b/u.test(page.title) && page.yearVerified !== true) {
        errors.push(`${page.route}: anul 2026 nu este aprobat pentru title`);
      }
      if (!fs.existsSync(path.join(ROOT, page.file))) errors.push(`${page.route}: fișierul ${page.file} lipsește`);
    }
  }

  for (const redirect of config.redirects || []) {
    if (redirect.status !== "APROBARE_UMANĂ_NECESARĂ") {
      errors.push(`${redirect.source}: redirectul nu are o stare de aprobare controlată`);
    }
  }

  if (errors.length) throw new Error(`Configurația clusterelor editoriale este invalidă:\n- ${errors.join("\n- ")}`);
}

function setMeta($, selector, value, attributes = {}) {
  let element = $(selector).first();
  if (!element.length) {
    element = $("<meta>");
    for (const [name, attributeValue] of Object.entries(attributes)) element.attr(name, attributeValue);
    $("head").append(element);
  }
  element.attr("content", value);
}

function renderCell(cell) {
  if (cell && typeof cell === "object" && cell.href) {
    return `<a href="${attr(cell.href)}">${esc(cell.label || cell.href)}</a>`;
  }
  return esc(cell);
}

function renderTable(table) {
  if (!table || !Array.isArray(table.headers) || !Array.isArray(table.rows)) return "";
  return `<div class="editorial-cluster__table-wrap" tabindex="0" role="region" aria-label="Tabel comparativ">
          <table class="editorial-cluster__table">
            <thead><tr>${table.headers.map((header) => `<th scope="col">${esc(header)}</th>`).join("")}</tr></thead>
            <tbody>${table.rows.map((row) => `<tr>${row.map((cell, index) => index === 0
    ? `<th scope="row">${renderCell(cell)}</th>`
    : `<td>${renderCell(cell)}</td>`).join("")}</tr>`).join("")}</tbody>
          </table>
        </div>`;
}

function renderList(items, ordered = false) {
  if (!Array.isArray(items) || !items.length) return "";
  const tag = ordered ? "ol" : "ul";
  const className = ordered ? "editorial-cluster__steps" : "editorial-cluster__list";
  return `<${tag} class="${className}">${items.map((item) => {
    if (item && typeof item === "object") {
      const link = item.href ? ` <a href="${attr(item.href)}">${esc(item.label || "Vezi detaliile")}</a>` : "";
      return `<li>${item.title ? `<strong>${esc(item.title)}</strong> — ` : ""}${esc(item.text || "")}${link}</li>`;
    }
    return `<li>${esc(item)}</li>`;
  }).join("")}</${tag}>`;
}

function renderSection(section) {
  return `<section class="editorial-cluster__section" id="${attr(section.id)}" aria-labelledby="${attr(section.id)}-title">
        <h2 id="${attr(section.id)}-title">${esc(section.heading)}</h2>
        ${section.intro ? `<p class="editorial-cluster__section-intro">${esc(section.intro)}</p>` : ""}
        ${(section.paragraphs || []).map((paragraph) => `<p>${esc(paragraph)}</p>`).join("")}
        ${renderTable(section.table)}
        ${renderList(section.items)}
        ${renderList(section.steps, true)}
      </section>`;
}

function renderFundingOverview(page) {
  if (page.route !== "/fonduri-europene") return "";
  const bySlug = new Map(PROGRAM_REGISTRY.map((program) => [program.slug, program]));
  const cards = FEATURED_FUNDING_SLUGS.map((slug, index) => {
    const program = bySlug.get(slug);
    if (!program || program.publicationState !== "public") throw new Error(`${page.route}: programul ${slug} nu este public`);
    return `<a class="funding-program-card" href="${attr(program.pageUrl)}" data-program-id="${attr(program.slug)}" style="--card-delay:${index * 55}ms">
          <span class="funding-program-card__index">${String(index + 1).padStart(2, "0")}</span>
          <strong>${esc(program.shortName)}</strong>
          <small>${esc(program.statusLabel)}</small>
          <span class="funding-program-card__arrow" aria-hidden="true">→</span>
        </a>`;
  }).join("");
  return `<section class="funding-overview" aria-labelledby="funding-overview-title">
        <div class="funding-overview__copy"><p class="funding-overview__eyebrow">Hartă de orientare 2026</p><h2 id="funding-overview-title">Nouă trasee de finanțare, organizate după investiție</h2><p>Pornește de la tipul investiției și deschide pagina programului pentru statut, sursa oficială și condițiile care trebuie demonstrate.</p></div>
        <svg class="funding-overview__svg" viewBox="0 0 580 300" role="img" aria-labelledby="funding-svg-title funding-svg-desc"><title id="funding-svg-title">Hartă vizuală a traseelor de finanțare</title><desc id="funding-svg-desc">Un nucleu central conectează domeniul agricol, firmele, energia și mobilitatea.</desc><g fill="none" stroke="rgba(255,255,255,.28)" stroke-width="2"><path d="M290 150L78 72M290 150L84 236M290 150L500 64M290 150L506 238"/><circle cx="290" cy="150" r="68"/></g><g class="funding-svg__pulse"><circle cx="290" cy="150" r="36" fill="#b84716"/><text x="290" y="155" text-anchor="middle">PROIECT</text></g><g class="funding-svg__label"><circle cx="78" cy="72" r="33"/><text x="78" y="77" text-anchor="middle">AFIR</text><circle cx="84" cy="236" r="33"/><text x="84" y="241" text-anchor="middle">IMM</text><circle cx="500" cy="64" r="33"/><text x="500" y="69" text-anchor="middle">ENERGIE</text><circle cx="506" cy="238" r="33"/><text x="506" y="243" text-anchor="middle">MOBILITATE</text></g></svg>
        <div class="funding-program-grid">${cards}</div>
      </section>`;
}

function renderArticle(page) {
  const related = (page.internalLinks || []).length
    ? `<nav class="editorial-cluster__related" aria-label="Continuă documentarea">
        <h2>Continuă documentarea</h2>
        <ul>${page.internalLinks.map((link) => `<li><a href="${attr(link.href)}">${esc(link.label)}</a></li>`).join("")}</ul>
      </nav>`
    : "";

  return `<div class="editorial-cluster" data-cluster="${attr(page.clusterId)}" data-intent-id="${attr(page.intentId)}">
      <section class="editorial-cluster__answer" aria-label="Răspuns direct">
        <p class="intro" data-direct-answer>${esc(page.directAnswer)}</p>
      </section>
      ${renderFundingOverview(page)}
      ${(page.sections || []).map(renderSection).join("\n")}
      ${page.terminologyNote ? `<p data-terminology-note="own-contribution">${esc(page.terminologyNote)}</p>` : ""}
      <section class="editorial-cluster__source-note" aria-labelledby="${attr(page.intentId)}-sources">
        <h2 id="${attr(page.intentId)}-sources">Surse și limite</h2>
        <p>Valorile, procentele, calendarul și statusul unui program se publică numai din documentul oficial identificat prin instituție, versiune și data verificării. Pentru orientare folosește <a href="/surse-oficiale-fonduri-europene">directorul de surse oficiale</a>.</p>
      </section>
      ${related}
      <section class="editorial-cluster__cta" aria-labelledby="${attr(page.intentId)}-cta">
        <div><h2 id="${attr(page.intentId)}-cta">${esc(page.cta.heading)}</h2><p>${esc(page.cta.text)}</p></div>
        <a class="btn btn-primary" href="${attr(page.cta.href)}" data-cta-id="${attr(page.intentId)}">${esc(page.cta.label)}</a>
      </section>
    </div>`;
}

function synchronizeStructuredData(html, route) {
  if (!/<script\b[^>]*\btype=["']application\/ld\+json["']/iu.test(html)) {
    throw new Error(`${route}: lipsește blocul JSON-LD`);
  }
  const serialized = synchronizedGraph(html, route, PAGE_HINTS.get(route));
  let replaced = false;
  return html.replace(/<script\b[^>]*\btype=["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script>/giu, (full) => {
    if (replaced) return "";
    replaced = true;
    const opening = full.match(/^<script\b[^>]*>/iu)?.[0] || '<script type="application/ld+json">';
    return `${opening}${serialized}</script>`;
  }).replace(/[ \t]+$/gmu, "");
}

function syncPage(page) {
  const file = path.join(ROOT, page.file);
  const before = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(before, { decodeEntities: false });

  const robots = $("meta[name='robots']").first().attr("content") || "";
  if (/noindex/i.test(robots)) throw new Error(`${page.route}: pagina marcată pentru randare este noindex`);

  $("title").first().text(page.title);
  setMeta($, "meta[name='description']", page.description, { name: "description" });
  setMeta($, "meta[property='og:title']", page.title, { property: "og:title" });
  setMeta($, "meta[property='og:description']", page.description, { property: "og:description" });
  setMeta($, "meta[property='og:url']", `https://atelierdeconsultanta.ro${page.route}`, { property: "og:url" });
  setMeta($, "meta[name='seo-min-words']", "400", { name: "seo-min-words" });
  setMeta($, "meta[name='seo-min-faq']", "0", { name: "seo-min-faq" });

  let canonical = $("link[rel='canonical']").first();
  if (!canonical.length) {
    canonical = $('<link rel="canonical">');
    $("head").append(canonical);
  }
  canonical.attr("href", `https://atelierdeconsultanta.ro${page.route}`);

  if (!$(`link[href='${CSS_HREF}']`).length) $("head").append(`<link rel="stylesheet" href="${CSS_HREF}">`);
  if (page.route === "/fonduri-europene" && !$('link[href="/assets/site-refresh-2026.css?v=20260809-1"]').length) {
    $("head").append('<link rel="stylesheet" href="/assets/site-refresh-2026.css?v=20260809-1">');
    $("body").addClass("funding-hub-refresh-2026");
  }

  const hero = $("header.hero, .program-hero, .post-hero").first();
  if (!hero.length) throw new Error(`${page.route}: hero-ul nu a fost găsit`);
  hero.find(".eyebrow, .post-category").first().text(page.eyebrow);
  hero.find("h1").first().text(page.h1);
  const heroDescription = hero.find(".post-excerpt").first().length
    ? hero.find(".post-excerpt").first()
    : hero.children("p").first().length
      ? hero.children("p").first()
      : hero.find("p").first();
  heroDescription.text(page.heroDescription);
  if (Array.isArray(page.heroActions) && page.heroActions.length) {
    let actions = hero.find(".hero-actions").first();
    if (!actions.length) {
      actions = $('<div class="hero-actions">');
      hero.append(actions);
    }
    actions.html(page.heroActions.map((action) => `<a class="btn btn-${action.kind === "secondary" ? "secondary" : "primary"}" href="${attr(action.href)}">${esc(action.label)}</a>`).join(""));
  }

  const article = $("main article.panel, article.post-body").first();
  if (!article.length) throw new Error(`${page.route}: articolul principal nu a fost găsit`);
  article.html(renderArticle(page));
  $("main > .cta-box").remove();
  $("body").attr("data-editorial-cluster", page.clusterId).attr("data-primary-intent", page.intentId);

  const after = synchronizeStructuredData($.html(), page.route);
  if (after === before) return { changed: false, file: page.file };
  if (!CHECK_ONLY) fs.writeFileSync(file, after, "utf8");
  return { changed: true, file: page.file };
}

function main() {
  const config = readJson(CONFIG_PATH);
  validate(config);
  const publicPages = routeEntries(config).filter((page) => page.render);
  const results = publicPages.map(syncPage);
  const changed = results.filter((result) => result.changed);
  if (CHECK_ONLY && changed.length) {
    console.error(`Clusterele editoriale nu sunt sincronizate (${changed.length}):`);
    for (const result of changed) console.error(`- ${result.file}`);
    process.exitCode = 1;
    return;
  }
  console.log(`${CHECK_ONLY ? "Verificate" : "Sincronizate"} ${publicPages.length} pagini editoriale; ${changed.length} fișiere ${CHECK_ONLY ? "nesincronizate" : "actualizate"}.`);
}

main();
