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
  return `${START}
    <!-- Copy-ul și traseul vizual au fost restaurate din bannerul FABER anterior; CTA-ul urmează contractul contextual P1.15. -->
    <section id="hero" class="homepage-decision-hero" data-section-id="hero" aria-labelledby="homepage-hero-title" data-homepage-hero-version="p1_15">
      <div class="homepage-hero__inner">
        <div class="homepage-hero__copy">
          <div class="hero-badge"><span class="dot" aria-hidden="true"></span>FABER pentru firme, fermieri, start-up-uri și IMM-uri</div>
          <h1 class="hero-title" id="homepage-hero-title">Consultanță și proiectare pentru proiecte <span class="gradient-text">cu fonduri europene</span></h1>
          <p class="hero-subtitle">Verificare prudentă, documentată și interdisciplinară — consultanță și proiectare — înainte de dosar. Verificăm forma solicitantului, CAEN-ul sau exploatația, amplasamentul, bugetul și documentele înainte de alegerea programului. Pentru proiectele care continuă, corelăm cererea de finanțare cu anexele și documentația tehnică.</p>
          <div class="hero-ctas" aria-label="Acțiuni principale">
            <a href="/contact?source_page=%2F" class="btn-primary" data-contextual-hero-cta data-analytics-event="cta_click" data-analytics-component="homepage_hero" data-analytics-cta-id="homepage_hero_project_check" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_15">Începe verificarea proiectului</a>
            <a href="/verificare-eligibilitate-fonduri-europene" class="btn-secondary" data-analytics-event="cta_click" data-analytics-component="homepage_hero" data-analytics-cta-id="homepage_hero_prepare" data-analytics-target="/verificare-eligibilitate-fonduri-europene" data-analytics-cta-view="true" data-analytics-copy-variant="p1_15">Vezi ce date pregătești</a>
          </div>
          <p class="homepage-hero__microcopy">Spune-ne solicitantul, localitatea și investiția. Prima etapă este o verificare orientativă; nu promitem aprobarea.</p>
        </div>

        <aside class="homepage-hero__panel hero-flow" aria-label="Traseul unui proiect de finanțare" data-homepage-hero-latest-program data-program-id="${escapeHtml(program.slug)}" data-program-status="${escapeHtml(program.status)}" data-status-label="${escapeHtml(program.statusLabel)}" data-verified-at="${escapeHtml(program.verifiedAt)}" data-source-url="${escapeHtml(program.sourceUrl)}" data-public-program-count="${publicCount}">
          <svg class="hero-flow-svg" viewBox="0 0 520 240" role="img" aria-labelledby="hero-flow-title hero-flow-desc" focusable="false">
            <title id="hero-flow-title">Traseul unui proiect de finanțare</title>
            <desc id="hero-flow-desc">Etapele unui proiect: idee, verificare a eligibilității, pregătirea dosarului, finanțare și implementare.</desc>
            <path class="hf-line" d="M52 150 C 120 70, 180 70, 260 120 S 410 190, 468 96" fill="none" stroke="rgba(255,255,255,0.28)" stroke-width="2.5" stroke-dasharray="6 7" stroke-linecap="round"></path>
            <g><circle cx="52" cy="150" r="22" fill="rgba(245,166,35,0.16)" stroke="#f5a623" stroke-width="1.6"></circle><path d="M52 140 a7 7 0 0 1 4 12.6 v3.4 h-8 v-3.4 a7 7 0 0 1 4 -12.6 Z M49.5 159 h5" fill="none" stroke="#f5a623" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"></path><text x="52" y="192" text-anchor="middle" class="hf-label">Idee</text></g>
            <g><circle cx="156" cy="84" r="22" fill="rgba(255,255,255,0.07)" stroke="rgba(255,255,255,0.65)" stroke-width="1.6"></circle><path d="M148 84 l6 6 11 -12" fill="none" stroke="#f5a623" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"></path><text x="156" y="126" text-anchor="middle" class="hf-label">Verificare</text></g>
            <g><circle cx="260" cy="120" r="24" fill="rgba(255,255,255,0.07)" stroke="rgba(255,255,255,0.65)" stroke-width="1.6"></circle><rect x="252" y="109" width="16" height="21" rx="2.5" fill="none" stroke="#fff" stroke-width="1.6"></rect><path d="M256 115 h8 M256 120 h8 M256 125 h5" stroke="rgba(255,255,255,0.85)" stroke-width="1.4" stroke-linecap="round"></path><text x="260" y="164" text-anchor="middle" class="hf-label">Dosar</text></g>
            <g><circle cx="372" cy="158" r="22" fill="rgba(255,255,255,0.07)" stroke="rgba(255,255,255,0.65)" stroke-width="1.6"></circle><circle cx="372" cy="158" r="10.5" fill="none" stroke="#f5a623" stroke-width="1.7"></circle><path d="M376 154.5 c-1 -1.2 -2.4 -1.8 -4 -1.8 a5.3 5.3 0 0 0 0 10.6 c1.6 0 3 -.6 4 -1.8 M366.5 156.5 h6 M366.5 159.5 h6" fill="none" stroke="#f5a623" stroke-width="1.5" stroke-linecap="round"></path><text x="372" y="200" text-anchor="middle" class="hf-label">Finanțare</text></g>
            <g><circle cx="468" cy="96" r="22" fill="rgba(184,71,22,0.22)" stroke="#e8642a" stroke-width="1.6"></circle><path d="M459 104 v-7 h5 v7 M466 104 v-12 h5 v12 M473 104 v-9 h5 v9 M457 104 h23" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"></path><text x="468" y="138" text-anchor="middle" class="hf-label">Implementare</text></g>
          </svg>
          <p class="hero-flow-caption">Fiecare etapă trebuie susținută de documentele folosite în etapa următoare.</p>
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
  const criticalMarkup = `  <style id="${STYLE_ID}">\n${criticalCss}\n  </style>\n`;
  output = /<style id="homepage-faq-expand-css">/.test(output)
    ? output.replace(/(<style id="homepage-faq-expand-css">)/, `${criticalMarkup}  $1`)
    : output.replace(/<\/head>/i, `${criticalMarkup}</head>`);
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
