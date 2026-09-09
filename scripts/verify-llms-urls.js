#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { sitemapUrls } = require("../tools/sitemap-utils");
const { isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const REQUIRED_PATHS = [
  "/dr12-afir",
  "/dr14",
  "/investitii-modernizarea-microintreprinderilor-apel-2",
  "/afir-autoconsum-agroalimentar",
  "/pro-infra",
  "/pocidif-21",
  "/fonduri-regionale",
  "/gal-afir",
  "/autoconsum-public-fotovoltaice-institutii-publice",
  "/programul-tranzitie-justa-intrebari-documente",
  "/metodologie-verificare-eligibilitate",
  "/surse-oficiale-fonduri-europene"
];

function localFile(pathname) {
  return pathname === "/" ? path.join(ROOT, "index.html") : path.join(ROOT, pathname.slice(1), "index.html");
}

function redirectSources() {
  const sources = new Set();
  for (const raw of fs.readFileSync(path.join(ROOT, "_redirects"), "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [source, , status = "302"] = line.split(/\s+/);
    if (/^3\d\d$/.test(status) && !/[*:]/.test(source)) sources.add(source.replace(/\/+$/, "") || "/");
  }
  return sources;
}

function main() {
  const errors = [];
  const llms = fs.readFileSync(path.join(ROOT, "llms.txt"), "utf8");
  const programs = loadProgramConfig().programs;
  const latestVerification = programs
    .filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget)
    .reduce((latest, program) => program.verifiedAt > latest ? program.verifiedAt : latest, "0000-00-00");
  const sitemap = new Set(sitemapUrls(ROOT));
  const redirects = redirectSources();
  const lines = llms.split(/\r?\n/);
  const urls = [];

  if (!llms.includes(`Ultima actualizare: ${latestVerification}`)) {
    errors.push(`Data llms.txt trebuie să urmeze ultima verificare publică din registry: ${latestVerification}.`);
  }
  if (!llms.includes(`Ultima verificare din registrul public: ${latestVerification}`)) {
    errors.push(`Blocul factual llms.txt trebuie să indice verificarea ${latestVerification}.`);
  }
  if (/<(?:html|head|body|main|article)\b/iu.test(llms)) errors.push("llms.txt nu trebuie să copieze documente HTML ale site-ului.");
  for (const [index, line] of lines.entries()) {
    const matches = line.match(/https:\/\/atelierdeconsultanta\.ro[^\s`)]+/g) || [];
    if (matches.length > 1) errors.push(`Linia ${index + 1} conține mai multe URL-uri.`);
    if (matches.length === 1 && !/^\s*-\s+\[[^\]]+\]\(https:\/\/atelierdeconsultanta\.ro[^\s)]+\)\s*$/.test(line)) {
      errors.push(`URL-ul de la linia ${index + 1} nu este un link Markdown pe o linie-bullet separată.`);
    }
    urls.push(...matches);
  }

  const unique = new Set();
  for (const raw of urls) {
    let url;
    try { url = new URL(raw); } catch { errors.push(`URL invalid: ${raw}`); continue; }
    const pathname = url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/, "");
    const canonical = `${SITE}${pathname === "/" ? "/" : pathname}`;
    if (raw !== canonical) errors.push(`URL necanonic în llms.txt: ${raw}`);
    if (/\.html$|\/index\.html$/.test(pathname) || url.search || url.hash) errors.push(`Alias sau parametri în llms.txt: ${raw}`);
    if (redirects.has(pathname)) errors.push(`URL redirectat în llms.txt: ${raw}`);
    if (!sitemap.has(canonical)) errors.push(`URL llms.txt absent din sitemap: ${raw}`);
    if (unique.has(canonical)) errors.push(`URL duplicat în llms.txt: ${canonical}`);
    unique.add(canonical);

    const file = localFile(pathname);
    if (!fs.existsSync(file)) { errors.push(`Lipsește pagina locală pentru ${canonical}`); continue; }
    const html = fs.readFileSync(file, "utf8");
    const canonicalMatch = html.match(/<link\b[^>]*rel=["'][^"']*canonical[^"']*["'][^>]*href=["']([^"']+)["']/i)
      || html.match(/<link\b[^>]*href=["']([^"']+)["'][^>]*rel=["'][^"']*canonical[^"']*["']/i);
    if (!canonicalMatch || canonicalMatch[1] !== canonical) errors.push(`Canonical local diferit pentru ${canonical}`);
    if (/<meta\b[^>]*name=["']robots["'][^>]*content=["'][^"']*noindex/i.test(html)) errors.push(`Pagină noindex în llms.txt: ${canonical}`);
  }

  for (const pathname of REQUIRED_PATHS) {
    if (!unique.has(`${SITE}${pathname}`)) errors.push(`URL prioritar lipsă din llms.txt: ${pathname}`);
  }
  if (unique.size >= sitemap.size) errors.push("llms.txt trebuie să rămână o selecție editorială, nu o duplicare a sitemap-ului.");

  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  console.log(`llms.txt valid: ${unique.size} URL-uri canonice, indexabile și fără redirect.`);
}

main();
