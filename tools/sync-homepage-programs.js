"use strict";

const fs = require("fs");
const path = require("path");
const { isPublicProgram, loadProgramConfig } = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const HOME = path.join(ROOT, "index.html");
const CONFIG = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "homepage-programs.json"), "utf8"));
const HUBS = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "program-family-hubs.json"), "utf8"));
const BANNERS = JSON.parse(fs.readFileSync(path.join(ROOT, "banners.json"), "utf8"));
const CHECK_ONLY = process.argv.includes("--check");
const PRIORITY_START = "<!-- P1_08_PRIORITY_CAROUSEL_START -->";
const PRIORITY_END = "<!-- P1_08_PRIORITY_CAROUSEL_END -->";
const GRID_START = "<!-- P1_08_PROGRAM_GRID_START -->";
const GRID_END = "<!-- P1_08_PROGRAM_GRID_END -->";
const COMPACT_HOME_START = "<!-- P1_21_HOMEPAGE_FLOW_START -->";
const CSS_LINK = '<link rel="stylesheet" href="/assets/homepage-program-explorer.css?v=20260809-2" data-homepage-program-explorer-style="p1_08">';
const JS_LINK = '<script src="/assets/homepage-program-explorer.js?v=20260809-2" defer data-homepage-program-explorer-script="p1_08"></script>';
const MONTHS = ["ianuarie", "februarie", "martie", "aprilie", "mai", "iunie", "iulie", "august", "septembrie", "octombrie", "noiembrie", "decembrie"];
const STATUS_FILTER_LABELS = {
  apel_deschis: "Apel deschis",
  ghid_aprobat_nedeschis: "Ghid aprobat, apel nedeschis",
  consultare_publica: "Consultare publică",
  calendar_estimativ: "Calendar estimativ",
  apel_inchis: "Apel închis",
  arhivat: "Arhivat"
};

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDateRo(value) {
  const [year, month, day] = String(value).split("-").map(Number);
  if (!year || !month || !day) throw new Error(`Dată invalidă: ${value}`);
  return `${day} ${MONTHS[month - 1]} ${year}`;
}

function statusSymbol(status) {
  if (status === "apel_deschis") return "●";
  if (status === "apel_inchis" || status === "arhivat") return "○";
  return "◐";
}

function hubForProgram(program) {
  return HUBS.hubs.find((hub) => hub.route === program.discovery?.parentHub);
}

function validateProgram(program, context) {
  if (!program) throw new Error(`${context}: program absent din registru.`);
  if (!isPublicProgram(program)) throw new Error(`${context}: ${program.slug} nu este publicabil.`);
  for (const field of ["slug", "shortName", "family", "status", "statusLabel", "verifiedAt", "sourceUrl", "sourceVersion", "pageUrl", "cardSummary"]) {
    if (!program[field]) throw new Error(`${context}: ${program.slug} nu are ${field}.`);
  }
  if (!program.discovery?.parentHub || !Array.isArray(program.discovery.applicantTypes)) {
    throw new Error(`${context}: ${program.slug} nu are taxonomia discovery completă.`);
  }
}

function renderPrioritySlide(program, banner, index, total) {
  const active = index === 0;
  const inert = active ? "" : " inert";
  const image = String(banner?.image || "/assets/hero/hero-business.webp").replace(/'/g, "%27");
  return `          <div class="priority-program-slide${active ? " is-active" : ""}" role="group" aria-roledescription="slide" aria-label="${index + 1} din ${total}" data-priority-slide data-program-id="${esc(program.slug)}" data-program-family="${esc(program.family)}" data-program-status="${esc(program.status)}" data-status-label="${esc(program.statusLabel)}" data-verified-at="${esc(program.verifiedAt)}" data-source-url="${esc(program.sourceUrl)}" aria-hidden="${active ? "false" : "true"}"${inert} style="--program-image:url('${image}')">
            <span class="priority-program-status"><span aria-hidden="true">${statusSymbol(program.status)}</span><span>${esc(program.statusLabel)}</span></span>
            <h3>${esc(program.shortName)}</h3>
            <p>${esc(program.cardSummary)}</p>
            <p class="priority-program-date">Verificat la <time datetime="${esc(program.verifiedAt)}">${formatDateRo(program.verifiedAt)}</time>.</p>
            <a class="priority-program-link" href="${esc(program.pageUrl)}"${active ? "" : ' tabindex="-1"'} data-analytics-event="program_card_click" data-analytics-cta-id="priority_program_${esc(program.slug)}" data-analytics-program-slug="${esc(program.slug)}" data-analytics-program-family="${esc(program.family)}" data-analytics-target="${esc(program.pageUrl)}">Vezi condițiile</a>
          </div>`;
}

function renderPriorityCarousel(programs, bannersByProgram) {
  const featured = CONFIG.featuredProgramSlugs.map((slug) => programs.find((program) => program.slug === slug));
  if (!featured.length || featured.length > CONFIG.carousel.maximumItems || featured.length > 24) {
    throw new Error(`Caruselul trebuie să conțină între 1 și 24 de programe; găsite ${featured.length}.`);
  }
  featured.forEach((program) => validateProgram(program, "carusel"));
  const total = featured.length;
  const slides = featured.map((program, index) => renderPrioritySlide(program, bannersByProgram.get(program.slug), index, total)).join("\n");
  return `${PRIORITY_START}
    <section id="priority-programs" aria-labelledby="priority-programs-title">
      <div class="program-explorer-header">
        <span class="section-label">Catalog public</span>
        <h2 id="priority-programs-title">Toate programele de finanțare urmărite</h2>
        <p>Fiecare program public are propriul banner, fără rotire automată. Statutul și data verificării provin din registrul unic.</p>
      </div>
      <div class="priority-program-carousel" data-priority-carousel data-carousel-count="${total}">
        <button class="priority-program-control priority-program-control--previous" type="button" aria-label="Programul anterior" data-priority-previous data-analytics-event="carousel_interaction" data-analytics-cta-id="priority_carousel_previous"><span aria-hidden="true">←</span></button>
        <div class="priority-program-viewport" tabindex="0" role="region" aria-roledescription="carusel" aria-label="Programe prioritare" data-priority-viewport>
          <div class="priority-program-track" data-priority-track>
${slides}
          </div>
        </div>
        <button class="priority-program-control priority-program-control--next" type="button" aria-label="Programul următor" data-priority-next data-analytics-event="carousel_interaction" data-analytics-cta-id="priority_carousel_next"><span aria-hidden="true">→</span></button>
        <div class="priority-program-meta">
          <p class="priority-program-counter" role="status" aria-live="polite" aria-atomic="true" data-priority-counter>1 din ${total}</p>
          <a class="priority-program-all" href="${esc(CONFIG.carousel.allProgramsUrl)}">Vezi toate programele</a>
        </div>
      </div>
    </section>
${PRIORITY_END}`;
}

function option(value, label) {
  return `<option value="${esc(value)}">${esc(label)}</option>`;
}

function renderGridCard(program) {
  validateProgram(program, "grid");
  const hub = hubForProgram(program);
  if (!hub) throw new Error(`grid: ${program.slug} nu are hub valid.`);
  const applicants = program.discovery.applicantTypes;
  const applicantLabels = applicants.map((key) => HUBS.filters.applicantTypes[key]).filter(Boolean);
  return `        <article class="program-directory-card" data-program-directory-card data-program-id="${esc(program.slug)}" data-program-family="${esc(program.family)}" data-filter-family="${esc(hub.id)}" data-filter-applicants="${esc(applicants.join(" "))}" data-program-status="${esc(program.status)}" data-status-label="${esc(program.statusLabel)}" data-verified-at="${esc(program.verifiedAt)}" data-source-url="${esc(program.sourceUrl)}">
          <span class="program-directory-status"><span aria-hidden="true">${statusSymbol(program.status)}</span><span>${esc(program.statusLabel)}</span></span>
          <h3>${esc(program.shortName)}</h3>
          <p>${esc(program.cardSummary)}</p>
          <p class="program-directory-audience"><strong>Beneficiar:</strong> ${esc(applicantLabels.join(", ") || "Categoria se confirmă în ghid")}</p>
          <p class="program-directory-date">Verificat la <time datetime="${esc(program.verifiedAt)}">${formatDateRo(program.verifiedAt)}</time>.</p>
          <a class="program-directory-link" href="${esc(program.pageUrl)}" data-analytics-event="program_card_click" data-analytics-cta-id="program_grid_${esc(program.slug)}" data-analytics-program-slug="${esc(program.slug)}" data-analytics-program-family="${esc(program.family)}" data-analytics-target="${esc(program.pageUrl)}">Vezi condițiile</a>
        </article>`;
}

function renderProgramGrid(programs) {
  const publicPrograms = programs
    .filter(isPublicProgram)
    .filter((program) => !CONFIG.grid.excludeWhenDiscoveryListedIsFalse || program.discovery?.listed !== false)
    .sort((left, right) => left.shortName.localeCompare(right.shortName, "ro"));
  publicPrograms.forEach((program) => validateProgram(program, "grid"));

  const usedHubIds = new Set(publicPrograms.map((program) => hubForProgram(program)?.id));
  const familyOptions = HUBS.hubs.filter((hub) => usedHubIds.has(hub.id)).map((hub) => option(hub.id, hub.label)).join("\n              ");
  const usedStatuses = new Set(publicPrograms.map((program) => program.status));
  const statusOptions = Object.entries(STATUS_FILTER_LABELS).filter(([status]) => usedStatuses.has(status)).map(([status, label]) => option(status, label)).join("\n              ");
  const usedApplicants = new Set(publicPrograms.flatMap((program) => program.discovery.applicantTypes));
  const applicantOptions = Object.entries(HUBS.filters.applicantTypes).filter(([key]) => usedApplicants.has(key)).map(([key, label]) => option(key, label)).join("\n              ");
  const cards = publicPrograms.map(renderGridCard).join("\n");

  return `${GRID_START}
    <section id="program-directory" aria-labelledby="program-directory-title" data-program-directory>
      <div class="program-explorer-header">
        <span class="section-label">Toate programele publicabile</span>
        <h2 id="program-directory-title">Filtrează după proiectul tău</h2>
        <p>Filtrele schimbă numai rezultatele din pagină și nu generează URL-uri indexabile. Condițiile se verifică pe pagina programului.</p>
      </div>
      <div class="program-directory-filters" data-program-filter-form role="group" aria-label="Filtre programe">
        <div class="program-directory-filter">
          <label for="program-filter-family">Familie</label>
          <select id="program-filter-family" name="family" aria-controls="program-directory-grid">
            <option value="all">Toate familiile</option>
              ${familyOptions}
          </select>
        </div>
        <div class="program-directory-filter">
          <label for="program-filter-status">Status</label>
          <select id="program-filter-status" name="status" aria-controls="program-directory-grid">
            <option value="all">Toate statusurile</option>
              ${statusOptions}
          </select>
        </div>
        <div class="program-directory-filter">
          <label for="program-filter-applicant">Beneficiar</label>
          <select id="program-filter-applicant" name="applicant" aria-controls="program-directory-grid">
            <option value="all">Toți beneficiarii</option>
              ${applicantOptions}
          </select>
        </div>
        <button class="program-directory-reset" type="button" data-program-filter-reset>Resetează filtrele</button>
      </div>
      <p class="program-directory-result" id="program-directory-result" role="status" aria-live="polite" aria-atomic="true" data-program-filter-result>${publicPrograms.length} programe afișate</p>
      <div class="program-directory-grid" id="program-directory-grid" aria-describedby="program-directory-result">
${cards}
      </div>
      <p class="program-directory-empty" data-program-filter-empty hidden>Nu există programe pentru combinația selectată. Resetează filtrele pentru a vedea toate opțiunile.</p>
    </section>
${GRID_END}`;
}

function replaceBlock(source, start, end, legacyPattern, markup, label) {
  const marked = new RegExp(`${start}[\\s\\S]*?${end}`);
  if (marked.test(source)) return source.replace(marked, markup);
  if (!legacyPattern.test(source)) throw new Error(`Nu am găsit secțiunea ${label}.`);
  return source.replace(legacyPattern, markup);
}

function synchronizeAssets(source) {
  let output = source
    .replace(/\s*<link\b[^>]*href=["']\/assets\/program-carousel\.css[^>]*>/gi, "")
    .replace(/\s*<link\b[^>]*data-homepage-program-explorer-style=["']p1_08["'][^>]*>/gi, "")
    .replace(/\s*<script\b[^>]*data-homepage-program-explorer-script=["']p1_08["'][^>]*><\/script>/gi, "");
  const insertion = `  ${CSS_LINK}\n  ${JS_LINK}\n`;
  if (/<script\b[^>]*src=["']\/assets\/lead-attribution\.js[^>]*>/i.test(output)) {
    return output.replace(/(<script\b[^>]*src=["']\/assets\/lead-attribution\.js[^>]*>)/i, `${insertion}  $1`);
  }
  return output.replace(/<\/head>/i, `${insertion}</head>`);
}

function removeLegacyCarouselRuntime(source) {
  return source.replace(
    /\n\s*var programCarouselState = \{[\s\S]*?\n\s*scheduleAfterFirstPaint\(loadProgramCarousel,\s*1200\);\s*/,
    "\n"
  );
}

function syncHomepage(source, programs) {
  const bannersByProgram = new Map(BANNERS.map((banner) => [banner.programId, banner]));
  let output = replaceBlock(
    source,
    PRIORITY_START,
    PRIORITY_END,
    /<section\s+id="carousel-section"[\s\S]*?<\/section>/,
    renderPriorityCarousel(programs, bannersByProgram),
    "carusel"
  );
  if (output.includes(COMPACT_HOME_START)) {
    output = output.replace(new RegExp(`${GRID_START}[\\s\\S]*?${GRID_END}`), "");
  } else {
    output = replaceBlock(
      output,
      GRID_START,
      GRID_END,
      /<section\s+id="finantare"[\s\S]*?<\/section>/,
      renderProgramGrid(programs),
      "grid programe"
    );
  }
  return synchronizeAssets(removeLegacyCarouselRuntime(output));
}

function main() {
  const { programs } = loadProgramConfig();
  const before = fs.readFileSync(HOME, "utf8");
  const after = syncHomepage(before, programs);
  if (CHECK_ONLY) {
    if (after !== before) throw new Error("Homepage program explorer nu este sincronizat. Rulează npm run sync:homepage-programs.");
    console.log("Homepage program explorer sync PASS.");
    return;
  }
  if (after !== before) fs.writeFileSync(HOME, after, "utf8");
  console.log(`Homepage program explorer sincronizat: ${CONFIG.featuredProgramSlugs.length} priorități editoriale.`);
}

if (require.main === module) main();

module.exports = { CONFIG, formatDateRo, renderPriorityCarousel, renderProgramGrid, syncHomepage };
