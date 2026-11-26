#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const routes = [
  "/fonduri-regionale",
  "/fonduri-europene-nord-est",
  "/investitii-modernizarea-microintreprinderilor-apel-2"
];
const legacyPor = "/por-adr-nord-est";
const microCall = "/investitii-modernizarea-microintreprinderilor-apel-2";

const expected = {
  "/fonduri-regionale": {
    title: "Fonduri regionale 2021–2027 și ADR-uri | FABER",
    h1: "Programe regionale și apeluri ADR",
    introSelector: ".program-family-filter-panel__heading p:not(.program-family-kicker)",
    intro: /solicitantul, regiunea și etapa.*sursa oficială/i,
    links: ["/fonduri-europene-nord-est", microCall]
  },
  "/fonduri-europene-nord-est": {
    title: "Fonduri europene Nord-Est: programe pentru IMM și ferme",
    h1: "Fonduri europene în regiunea Nord-Est",
    intro: /județul și localitatea implementării.*apelurile ADR Nord-Est și programele naționale/i,
    links: ["/fonduri-regionale", microCall]
  },
  "/investitii-modernizarea-microintreprinderilor-apel-2": {
    title: "Modernizarea microîntreprinderilor – Apel 2 închis (2026)",
    h1: "Investiții pentru modernizarea microîntreprinderilor – Apel 2",
    intro: /Apel 2, cod PR\/NE\/2026\/P1\/RSO1\.3\/2\/1.*microîntreprinderilor/i,
    links: ["/fonduri-regionale", "/fonduri-europene-nord-est"]
  }
};

function normalize(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function fail(message) {
  throw new Error(message);
}

const titles = new Set();
const h1s = new Set();
const intros = new Set();

for (const route of routes) {
  const file = path.join(ROOT, route.slice(1), "index.html");
  if (!fs.existsSync(file)) fail(`${route}: index.html lipsește`);
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const spec = expected[route];
  const title = normalize($("head > title").first().text());
  const h1 = normalize($("h1").first().text());
  const intro = normalize($(spec.introSelector || ".intro").first().text() || $("main p").first().text());
  const canonical = $("link[rel='canonical']").attr("href");
  const hrefs = new Set($("a[href]").map((_, element) => $(element).attr("href")).get());
  const contextualHrefs = new Set($("main a[href]").map((_, element) => $(element).attr("href")).get());

  if (title !== spec.title) fail(`${route}: TITLE diferit: ${title}`);
  if ($("h1").length !== 1 || h1 !== spec.h1) fail(`${route}: H1 diferit sau multiplu: ${h1}`);
  if (!spec.intro.test(intro)) fail(`${route}: răspunsul introductiv nu exprimă intenția separată`);
  if (canonical !== `${SITE}${route}`) fail(`${route}: canonical incorect: ${canonical}`);
  if (!$(".breadcrumb").length) fail(`${route}: breadcrumb lipsește`);
  for (const requiredLink of spec.links) {
    if (!contextualHrefs.has(requiredLink)) fail(`${route}: lipsește linkul contextual ${requiredLink}`);
  }
  for (const href of hrefs) {
    if (new URL(href, SITE).pathname.replace(/\/$/u, "") === legacyPor) {
      fail(`${route}: link către aliasul istoric ${href}`);
    }
    if (/atelierdeconsultanta\.ro\/.+\.html(?:[?#]|$)/i.test(href) || /^\/.+\.html(?:[?#]|$)/i.test(href)) {
      fail(`${route}: link intern necanonic: ${href}`);
    }
  }

  if (titles.has(title)) fail(`TITLE duplicat: ${title}`);
  if (h1s.has(h1)) fail(`H1 duplicat: ${h1}`);
  if (intros.has(intro)) fail(`Răspuns introductiv duplicat: ${intro}`);
  titles.add(title);
  h1s.add(h1);
  intros.add(intro);
}

const redirectRules = fs.readFileSync(path.join(ROOT, "_redirects"), "utf8").split(/\r?\n/u).map(normalize);
for (const suffix of ["", "/", ".html", "/index.html"]) {
  if (!redirectRules.includes(`${legacyPor}${suffix} ${SITE}${microCall} 301`)) {
    fail(`${legacyPor}${suffix}: redirecționarea directă lipsește`);
  }
}
const regionalHtml = fs.readFileSync(path.join(ROOT, "fonduri-europene-nord-est", "index.html"), "utf8");
const regional$ = cheerio.load(regionalHtml, { decodeEntities: false });
for (const county of ["Bacău", "Botoșani", "Iași", "Neamț", "Suceava", "Vaslui"]) {
  if (!regional$("main").text().includes(county)) fail(`/fonduri-europene-nord-est: lipsește județul ${county}`);
}
const microHtml = fs.readFileSync(path.join(ROOT, microCall.slice(1), "index.html"), "utf8");
const micro$ = cheerio.load(microHtml, { decodeEntities: false });
for (const term of ["cod CAEN", "locul de implementare", "contribuția proprie", "Documente", "Întrebări frecvente", "Surse oficiale"]) {
  if (!micro$("main").text().toLowerCase().includes(term.toLowerCase())) fail(`${microCall}: lipsește ${term}`);
}

console.log("Regional intent separation PASS: 3 rute canonice distincte, linkuri contextuale, breadcrumburi și 4 redirecturi istorice directe.");
