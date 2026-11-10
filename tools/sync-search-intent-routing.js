#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForRoute, sitemapRoutes } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config/search-intent-routing.json"), "utf8"));
const CHECK = process.argv.includes("--check");

function esc(value) {
  return String(value).replace(/&/gu, "&amp;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;").replace(/"/gu, "&quot;");
}

function synchronize(source, page) {
  const $ = cheerio.load(source, { sourceCodeLocationInfo: true });
  const edits = new Map();
  const replace = (element, html) => {
    const node = element.get(0);
    const loc = node?.sourceCodeLocation;
    if (!loc) throw new Error(`${page?.route || "link"}: element without source location`);
    edits.set(loc.startOffset, { start: loc.startOffset, end: loc.endOffset, html: html ?? $.html(node) });
  };

  if (page) {
    const hero = $("h1").first().parent();
    const lead = hero.children("p").first();
    const article = $("main > article.panel, article.post-body").first();
    if (!lead.length || !article.length) throw new Error(`${page.route}: hero lead or article missing`);
    lead.text(page.introduction);
    replace(lead);
    const intro = article.find("p.intro").first();
    if (intro.length) { intro.text(page.introduction); replace(intro); }
    if (page.h1) { hero.find("h1").first().text(page.h1); replace(hero.find("h1").first()); }
    if (page.title) { $("head > title").first().text(page.title); replace($("head > title").first()); }
    for (const [selector, value] of [
      ['meta[name="description"]', page.description],
      ['meta[property="og:title"],meta[name="twitter:title"]', page.title],
      ['meta[property="og:description"],meta[name="twitter:description"]', page.description]
    ]) {
      if (value) $(selector).each((_, node) => { $(node).attr("content", value); replace($(node)); });
    }

    const bridge = `<section data-search-intent-links="${esc(page.route)}" aria-label="Resurse pentru următorul pas"><h2 id="search-intent-next-${esc(page.route.slice(1))}">${esc(page.heading)}</h2><ul>${page.links.map(link => `<li><a href="${esc(link.href)}">${esc(link.label)}</a></li>`).join("")}</ul></section>`;
    const previous = article.find("[data-search-intent-links]").first();
    if (previous.length) {
      const links = previous.find("a").map((_, node) => ({ href: $(node).attr("href"), label: $(node).text().trim() })).get();
      if (previous.find("h2").text().trim() !== page.heading || JSON.stringify(links) !== JSON.stringify(page.links)) replace(previous, bridge);
    }
    else {
      const anchor = intro.length ? intro : article.children("p").first();
      const at = anchor.length ? anchor.get(0).sourceCodeLocation.endOffset : article.get(0).sourceCodeLocation.startTag.endOffset;
      edits.set(at, { start: at, end: at, html: `\n${bridge}\n` });
    }

    // These labels describe editorial operations rather than the reader's task.
    article.find("h2,h3").each((_, node) => {
      const heading = $(node);
      const renames = {
        "CTA contextual": "Discută investiția cu un consultant",
        "Autor, reviewer și actualizare": "Responsabilitate editorială",
        "Context și intenție de căutare": "Contextul investiției",
        "De ce pagina rămâne indexabila": "Particularitățile investiției în regiune"
      };
      const value = renames[heading.text().trim()];
      if (value) { heading.text(value); replace(heading); }
    });
    article.find("p").each((_, node) => {
      const paragraph = $(node);
      if (/^(?:Aceasta este pagina suport|Pagina răspunde intenției de căutare)/u.test(paragraph.text().trim())) replace(paragraph, "");
    });
    if (/bucuresti|nord-est/u.test(page.route)) {
      article.find("p,li,h2,h3").each((_, node) => {
        const element = $(node);
        const text = element.text().trim();
        const plain = text.normalize("NFD").replace(/[\u0300-\u036f]/gu, "").toLowerCase();
        let value;
        if (/^bucuresti se analizeaza.*o pagina locala/u.test(plain)) value = "Pentru București-Ilfov, verifică locul implementării, profilul solicitantului și tipul investiției în documentele apelului regional sau național urmărit.";
        else if (/^regiunea nord-est include.*pagina regionala consolideaza/u.test(plain)) value = "În Nord-Est, verifică județul și localitatea investiției, apoi compară programele regionale, agricole și naționale compatibile cu solicitantul și activitatea.";
        else if (/^pagina consolideaza intentiile locale/u.test(plain)) value = "Analiza unei investiții în Nord-Est pornește de la regiune, program, locul implementării și documentele beneficiarului.";
        else if (/^o pagina seo buna/u.test(plain)) value = "Ghidul solicitantului, anexele și clarificările autorității stabilesc regulile aplicabile. Verifică modificările oficiale înainte de a decide continuarea proiectului.";
        else if (/^landing page local indexabil|^pentru bucuresti, recomandarea editoriala|^o pagina separata pentru un judet|^pagina regionala trimite catre pagini canonice/u.test(plain)) value = "";
        else if (/^decide daca pagina locala merita/u.test(plain)) value = "Confirmă în documentele apelului că amplasamentul investiției este acceptat.";
        else if (/^cand ar merita o pagina locala separata/u.test(plain)) value = "Cum verifici condițiile teritoriale";
        if (value !== undefined) {
          if (value) { element.text(value); replace(element); }
          else replace(element, "");
        }
      });
      article.find("details").each((_, node) => {
        const question = $(node).children("summary").text().normalize("NFD").replace(/[\u0300-\u036f]/gu, "").toLowerCase();
        if (/pagini.*consolidate|sunt consolidate paginile|nu sunt indexate|pagina locala|actualizeaza pagina/u.test(question)) replace($(node), "");
      });
    }
  }

  $("main a[href], header.hero a[href]").each((_, node) => {
    const link = $(node);
    if (link.attr("href") === "/digitalizare-imm" && /^Hub Digitalizare IMM$/iu.test(link.text().trim())) {
      link.attr("href", "/fonduri-europene-digitalizare").text("Programe pentru digitalizare");
      replace(link);
    } else if (link.attr("href") === "/digitalizare-imm-pnrr" && /^Pagina aplicată Digitalizare IMM\s*\/\s*PNRR$/iu.test(link.text().trim())) {
      link.text("Implementarea proiectului PNRR Digitalizare IMM");
      replace(link);
    }
  });
  const outerEdits = [...edits.values()].filter(edit => ![...edits.values()].some(other => other !== edit && other.end > other.start && (edit.start === edit.end
    ? other.start < edit.start && other.end > edit.end
    : other.start <= edit.start && other.end >= edit.end && (other.start < edit.start || other.end > edit.end))));
  return outerEdits.sort((a, b) => b.start - a.start).reduce((html, edit) => html.slice(0, edit.start) + edit.html + html.slice(edit.end), source);
}

const routes = sitemapRoutes(ROOT);
const overrides = new Map(config.pages.map(page => [page.route, page]));
const validRoutes = new Set(routes);
for (const group of config.groups) {
  for (const route of [group.primary, ...group.supporting]) {
    if (!validRoutes.has(route)) throw new Error(`${group.id}: destination is not a current sitemap route: ${route}`);
  }
}
const changed = [];
for (const route of routes) {
  const file = fileForRoute(ROOT, route);
  const before = fs.readFileSync(file, "utf8");
  const after = synchronize(before, overrides.get(route));
  if (after !== before) {
    changed.push(route);
    if (!CHECK) fs.writeFileSync(file, after, "utf8");
  }
}
if (CHECK && changed.length) throw new Error(`Search intent routing is stale: ${changed.join(", ")}`);
console.log(`Search intent routing ${CHECK ? "PASS" : "synchronized"}: ${config.groups.length} intent groups, ${changed.length} pages ${CHECK ? "pending" : "updated"}.`);
