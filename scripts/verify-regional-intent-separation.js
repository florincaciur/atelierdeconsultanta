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
  "/por-adr-nord-est",
  "/investitii-modernizarea-microintreprinderilor-apel-2"
];

const expected = {
  "/fonduri-regionale": {
    title: "Fonduri regionale 2021–2027 și ADR-uri | FABER",
    h1: "Programe regionale și ADR-uri din România",
    intro: /hub-ul național/i,
    links: ["/fonduri-europene-nord-est", "/por-adr-nord-est", "/investitii-modernizarea-microintreprinderilor-apel-2"]
  },
  "/fonduri-europene-nord-est": {
    title: "Fonduri europene Nord-Est: programe regionale, AFIR și IMM | FABER",
    h1: "Fonduri europene în regiunea Nord-Est",
    intro: /după județ.*tipul beneficiarului.*programul activ/i,
    links: ["/fonduri-regionale", "/por-adr-nord-est", "/investitii-modernizarea-microintreprinderilor-apel-2"]
  },
  "/por-adr-nord-est": {
    title: "Program Regional Nord-Est: finanțări IMM și apeluri | FABER",
    h1: "Programul Regional Nord-Est – finanțări pentru IMM și microîntreprinderi",
    intro: /POR ADR Nord-Est/,
    links: ["/fonduri-regionale", "/fonduri-europene-nord-est", "/investitii-modernizarea-microintreprinderilor-apel-2"]
  },
  "/investitii-modernizarea-microintreprinderilor-apel-2": {
    title: "Modernizarea microîntreprinderilor – Apel 2 | FABER",
    h1: "Investiții pentru modernizarea microîntreprinderilor – Apel 2 Nord-Est",
    intro: /Investiții pentru modernizarea microîntreprinderilor – Apel 2.*dedicată exclusiv/i,
    links: ["/fonduri-regionale", "/fonduri-europene-nord-est", "/por-adr-nord-est"]
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
  const intro = normalize($(".intro").first().text() || $("main p").first().text());
  const canonical = $("link[rel='canonical']").attr("href");
  const hrefs = new Set($("a[href]").map((_, element) => $(element).attr("href")).get());

  if (title !== spec.title) fail(`${route}: TITLE diferit: ${title}`);
  if ($("h1").length !== 1 || h1 !== spec.h1) fail(`${route}: H1 diferit sau multiplu: ${h1}`);
  if (!spec.intro.test(intro)) fail(`${route}: răspunsul introductiv nu exprimă intenția separată`);
  if (canonical !== `${SITE}${route}`) fail(`${route}: canonical incorect: ${canonical}`);
  if (!$(".breadcrumb").length) fail(`${route}: breadcrumb lipsește`);
  for (const requiredLink of spec.links) {
    if (!hrefs.has(requiredLink)) fail(`${route}: lipsește linkul intern ${requiredLink}`);
  }
  for (const href of hrefs) {
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

const porHtml = fs.readFileSync(path.join(ROOT, "por-adr-nord-est", "index.html"), "utf8");
const por$ = cheerio.load(porHtml, { decodeEntities: false });
const firstHundredWords = normalize(por$(".intro").first().text()).split(/\s+/).slice(0, 100).join(" ");
if (!firstHundredWords.includes("POR ADR Nord-Est")) fail("/por-adr-nord-est: expresia istorică lipsește din primele 100 de cuvinte");
for (const county of ["Bacău", "Botoșani", "Iași", "Neamț", "Suceava", "Vaslui"]) {
  if (!por$("main").text().includes(county)) fail(`/por-adr-nord-est: lipsește județul ${county}`);
}
for (const term of ["cod CAEN", "amplasament", "situații financiare", "cofinanțare", "Documente", "Întrebări frecvente", "Surse oficiale"]) {
  if (!por$("main").text().toLowerCase().includes(term.toLowerCase())) fail(`/por-adr-nord-est: lipsește ${term}`);
}

console.log("Regional intent separation PASS: 4 TITLE-uri, 4 H1-uri și 4 răspunsuri introductive distincte; linkarea și breadcrumburile sunt prezente.");
