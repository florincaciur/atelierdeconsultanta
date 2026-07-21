"use strict";

const fs = require("fs");
const path = require("path");
const {
  hasOfficialSource,
  isPublicProgram,
  loadProgramConfig
} = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const HOME = path.join(ROOT, "index.html");
const STYLE_FILE = path.join(ROOT, "assets", "homepage-hero.css");
const CHECK_ONLY = process.argv.includes("--check");
const START = "<!-- HOMEPAGE_DECISION_HERO_START -->";
const END = "<!-- HOMEPAGE_DECISION_HERO_END -->";
const STYLE_ID = "homepage-hero-critical-css";
const MONTHS = ["ianuarie", "februarie", "martie", "aprilie", "mai", "iunie", "iulie", "august", "septembrie", "octombrie", "noiembrie", "decembrie"];

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDateRo(value) {
  const [year, month, day] = String(value).split("-").map(Number);
  return `${day} ${MONTHS[month - 1]} ${year}`;
}

function latestVerifiedProgram(programs) {
  return programs
    .filter((program) => isPublicProgram(program) && hasOfficialSource(program))
    .sort((left, right) => (
      right.verifiedAt.localeCompare(left.verifiedAt)
      || String(right.lastMeaningfulUpdate || "").localeCompare(String(left.lastMeaningfulUpdate || ""))
      || left.slug.localeCompare(right.slug, "ro")
    ))[0];
}

function renderHero(program, publicCount) {
  if (!program) throw new Error("Registrul nu conține niciun program public cu sursă oficială completă.");
  const verifiedLabel = formatDateRo(program.verifiedAt);
  return `${START}
    <!-- Copy P1.06 păstrat conform brief-ului; datele programului provin exclusiv din registrul unic. -->
    <section id="hero" class="homepage-decision-hero" data-section-id="hero" aria-labelledby="homepage-hero-title" data-homepage-hero-version="p1_06">
      <div class="homepage-hero__inner">
        <div class="homepage-hero__copy">
          <h1 class="hero-title" id="homepage-hero-title">Consultanță și proiectare pentru investiții finanțate</h1>
          <p class="hero-subtitle">Verificăm solicitantul, programul, punctajul, bugetul și documentele înainte de a începe dosarul. Concluzia poate fi: continuăm, ajustăm sau nu depunem acum.</p>
          <div class="hero-ctas" aria-label="Acțiuni principale">
            <a href="/contact" class="btn-primary" data-analytics-event="cta_click" data-analytics-component="homepage_hero" data-analytics-cta-id="homepage_hero_project_check" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_06">Începe verificarea proiectului</a>
            <a href="/metodologie-verificare-eligibilitate" class="btn-secondary" data-analytics-event="cta_click" data-analytics-component="homepage_hero" data-analytics-cta-id="homepage_hero_method" data-analytics-target="/metodologie-verificare-eligibilitate" data-analytics-cta-view="true" data-analytics-copy-variant="p1_06">Vezi cum lucrăm</a>
          </div>
          <p class="homepage-hero__microcopy">Prima etapă este o verificare orientativă. Nu promitem aprobarea.</p>
        </div>

        <aside class="homepage-hero__panel" aria-label="Metodă și informații verificate">
          <ol class="homepage-hero__facts">
            <li class="homepage-hero__fact" data-hero-proof="method">
              <span class="homepage-hero__index" aria-hidden="true">01</span>
              <div>
                <span class="homepage-hero__eyebrow">Metodă</span>
                <strong>Cinci pași înainte de dosar</strong>
                <p>Verificare prudentă, documentată și interdisciplinară — consultanță și proiectare — înainte de dosar. Traseu: solicitant → program → punctaj → buget și documente → decizie.</p>
              </div>
            </li>
            <li class="homepage-hero__fact" data-hero-proof="latest-program" data-homepage-hero-latest-program data-program-id="${escapeHtml(program.slug)}" data-program-status="${escapeHtml(program.status)}" data-status-label="${escapeHtml(program.statusLabel)}" data-verified-at="${escapeHtml(program.verifiedAt)}" data-source-url="${escapeHtml(program.sourceUrl)}">
              <span class="homepage-hero__index" aria-hidden="true">02</span>
              <div>
                <span class="homepage-hero__eyebrow">Program verificat recent</span>
                <strong><a href="${escapeHtml(program.pageUrl)}">${escapeHtml(program.shortName)}</a></strong>
                <p>${escapeHtml(program.statusLabel)} · verificat la <time datetime="${escapeHtml(program.verifiedAt)}">${verifiedLabel}</time>. Sursa: ${escapeHtml(program.sourceName)}, <a href="${escapeHtml(program.sourceUrl)}" target="_blank" rel="noopener noreferrer" data-analytics-event="source_document_click" data-analytics-component="homepage_hero" data-analytics-cta-id="homepage_hero_official_source" data-analytics-target="${escapeHtml(program.sourceUrl)}">documentul oficial</a>.</p>
              </div>
            </li>
            <li class="homepage-hero__fact" data-hero-proof="registry-update" data-public-program-count="${publicCount}" data-registry-verified-at="${escapeHtml(program.verifiedAt)}">
              <span class="homepage-hero__index" aria-hidden="true">03</span>
              <div>
                <span class="homepage-hero__eyebrow">Actualizare</span>
                <strong>Registru verificat la ${verifiedLabel}</strong>
                <p>Statusurile și datele sunt generate din registrul unic. <a href="/fonduri-europene">Vezi programele</a>.</p>
              </div>
            </li>
          </ol>
        </aside>
      </div>
    </section>
${END}`;
}

function syncHomepageHero(source, programs) {
  const latest = latestVerifiedProgram(programs);
  const publicCount = programs.filter(isPublicProgram).length;
  const hero = renderHero(latest, publicCount);
  const marked = new RegExp(`${START}[\\s\\S]*?${END}`);
  let output = marked.test(source)
    ? source.replace(marked, hero)
    : source.replace(/<!-- ✦ HERO ✦ -->[\s\S]*?<\/section>/, hero);
  if (output === source && !marked.test(source)) throw new Error("Nu am găsit hero-ul homepage pentru sincronizare.");
  const criticalCss = fs.readFileSync(STYLE_FILE, "utf8").trim();
  output = output
    .replace(/\s*<link rel="stylesheet" href="\/assets\/homepage-hero\.css[^>]*>/g, "")
    .replace(new RegExp(`\\s*<style id="${STYLE_ID}">[\\s\\S]*?<\\/style>`), "");
  output = output.replace(
    /(<style id="homepage-faq-expand-css">)/,
    `  <style id="${STYLE_ID}">\n${criticalCss}\n  </style>\n  $1`
  );
  return output;
}

function main() {
  const { programs } = loadProgramConfig();
  const before = fs.readFileSync(HOME, "utf8");
  const after = syncHomepageHero(before, programs);
  if (CHECK_ONLY) {
    if (after !== before) throw new Error("Hero-ul homepage nu este sincronizat. Rulează npm run sync:homepage-hero.");
    console.log("Homepage hero sync PASS.");
    return;
  }
  if (after !== before) fs.writeFileSync(HOME, after, "utf8");
  const latest = latestVerifiedProgram(programs);
  console.log(`Homepage hero sincronizat: ${latest.slug}, verificat la ${latest.verifiedAt}.`);
}

if (require.main === module) main();

module.exports = { formatDateRo, latestVerifiedProgram, renderHero, syncHomepageHero };
