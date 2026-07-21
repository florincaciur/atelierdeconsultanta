#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { loadNextStepConfig, renderNextStepBlock } = require("./contextual-next-steps");
const { renderProgramContextualLinks } = require("./sync-program-contextual-links");
const { loadEditorialGovernance, renderEditorialGovernance } = require("./editorial-governance");
const {
  PROGRAM_STATUSES,
  hasOfficialSource,
  isPublicProgram,
  loadProgramConfig,
  renderProgramFactualStatus,
  statusStatement
} = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const HUB_CONFIG_FILE = path.join(ROOT, "config", "program-family-hubs.json");
const CHECK_ONLY = process.argv.includes("--check");
const ASSET_VERSION = "20260721-1";
const PROJECT_CHECK_URL = "/verificare-eligibilitate-fonduri-europene";
const HUB_ICONS = Object.freeze({
  "afir-agricultura": "ph-duotone ph-plant",
  "regional-adr": "ph-duotone ph-buildings",
  "digitalizare-inovare": "ph-duotone ph-cpu",
  energie: "ph-duotone ph-sun",
  "antreprenoriat-gal": "ph-duotone ph-briefcase"
});

function esc(value) {
  return String(value ?? "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function words(value) {
  return String(value || "").trim().split(/\s+/u).filter(Boolean).length;
}

function dateLabel(value) {
  const date = new Date(`${value}T00:00:00Z`);
  return new Intl.DateTimeFormat("ro-RO", {
    day: "numeric",
    month: "long",
    year: "numeric",
    timeZone: "UTC"
  }).format(date);
}

function routeFiles(route) {
  const slug = route.replace(/^\//u, "");
  // Variantele istorice `slug.html` sunt documente de redirect și nu sunt
  // suprafețe canonice de conținut. Hub-ul se sincronizează numai pe ruta 200.
  return [path.join(ROOT, slug, "index.html")].filter((file) => fs.existsSync(file));
}

function loadData() {
  const hubs = JSON.parse(fs.readFileSync(HUB_CONFIG_FILE, "utf8"));
  const registry = loadProgramConfig();
  return { hubs, ...registry };
}

function validate(data) {
  const errors = [];
  const { hubs, programs } = data;
  if (hubs.hubs.length !== 5) errors.push(`Sunt necesare exact 5 hub-uri, nu ${hubs.hubs.length}.`);
  const routes = new Set(hubs.hubs.map((hub) => hub.route));
  const ids = new Set(hubs.hubs.map((hub) => hub.id));
  if (routes.size !== hubs.hubs.length) errors.push("Rutele hub-urilor trebuie să fie unice.");
  if (ids.size !== hubs.hubs.length) errors.push("Identificatorii hub-urilor trebuie să fie unici.");

  for (const hub of hubs.hubs) {
    const count = words(hub.intro);
    if (count < 50 || count > 80) errors.push(`${hub.route}: introducerea are ${count} cuvinte; sunt necesare 50–80.`);
    if (hub.faqs.length < 5 || hub.faqs.length > 8) errors.push(`${hub.route}: sunt necesare 5–8 întrebări.`);
    if (!routeFiles(hub.route).length) errors.push(`${hub.route}: ruta canonică existentă nu are fișier HTML.`);
    for (const link of hub.relatedLinks) {
      if (!link.href.startsWith("/")) errors.push(`${hub.route}: link relevant necanonic ${link.href}.`);
    }
  }

  for (const program of programs) {
    const discovery = program.discovery;
    if (!discovery || !routes.has(discovery.parentHub)) {
      errors.push(`${program.slug}: lipsește un singur parentHub valid.`);
      continue;
    }
    for (const [field, dictionary] of [
      ["applicantTypes", hubs.filters.applicantTypes],
      ["regions", hubs.filters.regions],
      ["investmentTypes", hubs.filters.investmentTypes]
    ]) {
      if (!Array.isArray(discovery[field]) || !discovery[field].length) errors.push(`${program.slug}: ${field} trebuie să conțină cel puțin o valoare.`);
      for (const value of discovery[field] || []) {
        if (!dictionary[value]) errors.push(`${program.slug}: ${field} conține valoarea necontrolată ${value}.`);
      }
    }
    if (isPublicProgram(program) && discovery.listed !== false && !hasOfficialSource(program)) {
      errors.push(`${program.slug}: programul listat public nu are proveniență oficială completă.`);
    }
  }
  if (errors.length) throw new Error(`Configurația hub-urilor este invalidă:\n- ${errors.join("\n- ")}`);
}

function optionMarkup(values, dictionary, allLabel) {
  return [`<option value="">${esc(allLabel)}</option>`, ...values.map((value) => `<option value="${esc(value)}">${esc(dictionary[value])}</option>`)].join("");
}

function usedValues(programs, field, order) {
  const used = new Set(programs.flatMap((program) => program.discovery[field]));
  return Object.keys(order).filter((value) => used.has(value));
}

function beneficiaryText(program) {
  const values = (program.eligibleApplicants || []).map((value) => String(value).trim()).filter(Boolean);
  return values.length ? values.join("; ") : "Categoria de beneficiar se confirmă în ghidul oficial indicat.";
}

function renderCard(program) {
  const discovery = program.discovery;
  return `<article class="program-family-card" data-program-card data-program-id="${esc(program.slug)}" data-program-status="${esc(program.status)}" data-status-label="${esc(program.statusLabel)}" data-verified-at="${esc(program.verifiedAt)}" data-source-url="${esc(program.sourceUrl)}" data-applicant-types="${esc(discovery.applicantTypes.join(" "))}" data-regions="${esc(discovery.regions.join(" "))}" data-investment-types="${esc(discovery.investmentTypes.join(" "))}" data-status="${esc(program.status)}">
  <div class="program-family-card__body">
    <h3><a href="${esc(program.pageUrl)}">${esc(program.shortName || program.name)}</a></h3>
    <p class="program-family-card__status"><strong>${esc(statusStatement(program))}</strong> Verificat la <time datetime="${esc(program.verifiedAt)}">${esc(dateLabel(program.verifiedAt))}</time>.</p>
    <p><strong>Beneficiar:</strong> ${esc(beneficiaryText(program))}</p>
    <p>${esc(program.cardSummary)}</p>
  </div>
  <div class="program-family-card__footer">
    <a class="program-family-card__source" href="${esc(program.sourceUrl)}" target="_blank" rel="noopener noreferrer" data-analytics-event="source_document_click" data-analytics-component="program_family_card" data-analytics-cta-id="official_source" data-analytics-program-category="${esc(program.slug)}">Sursa oficială: ${esc(program.sourceName)}</a>
    <a class="btn btn-primary" href="${esc(program.pageUrl)}" data-analytics-event="cta_click" data-analytics-component="program_family_card" data-analytics-cta-id="program_conditions_${esc(program.slug)}" data-analytics-program-category="${esc(program.slug)}" data-analytics-target="${esc(program.pageUrl)}" data-analytics-copy-variant="family_hub" data-analytics-cta-view="true">Vezi condițiile</a>
  </div>
</article>`;
}

function renderHero(hub) {
  return `
    <span class="hero-icon" aria-hidden="true"><i class="${esc(HUB_ICONS[hub.id] || "ph-duotone ph-folders")}"></i></span>
    <span class="eyebrow design-badge">Programe · ${esc(hub.label)}</span>
    <h1>${esc(hub.h1)}</h1>
    <p>${esc(hub.intro)}</p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="${PROJECT_CHECK_URL}" data-analytics-event="cta_click" data-analytics-component="program_family_hub" data-analytics-cta-id="project_check" data-analytics-target="${PROJECT_CHECK_URL}" data-analytics-copy-variant="family_hub" data-analytics-cta-view="true">Începe verificarea proiectului</a>
      <a class="btn btn-secondary" href="#cum-alegi">Cum alegi programul</a>
    </div>`;
}

function renderMain(hub, programs, filters, hubRecord = null) {
  const applicantTypes = usedValues(programs, "applicantTypes", filters.applicantTypes);
  const regions = usedValues(programs, "regions", filters.regions);
  const investmentTypes = usedValues(programs, "investmentTypes", filters.investmentTypes);
  const statuses = PROGRAM_STATUSES.filter((status) => programs.some((program) => program.status === status));
  const statusLabels = Object.fromEntries(statuses.map((status) => [status, programs.find((program) => program.status === status).statusLabel]));
  const countLabel = programs.length === 1 ? "1 program afișat" : `${programs.length} programe afișate`;
  const factualContext = hubRecord
    ? `\n\n  <section class="program-family-hub-factual" aria-label="Context factual al hub-ului">${renderProgramFactualStatus(hubRecord)}</section>`
    : "";
  const nextStepConfig = loadNextStepConfig();
  const nextStepSlug = Object.keys(nextStepConfig.pages).find((slug) => nextStepConfig.pages[slug].route === hub.route);
  const contextualNextStep = !hubRecord && nextStepSlug ? `\n\n${renderNextStepBlock(nextStepSlug, nextStepConfig)}` : "";
  const programContextualLinks = hubRecord ? `\n${renderProgramContextualLinks(hubRecord)}` : "";
  const editorialRecord = loadEditorialGovernance().byRoute.get(hub.route);
  const editorialGovernance = editorialRecord ? `\n\n${renderEditorialGovernance(editorialRecord)}` : "";

  return `<main class="container program-family-hub" id="main-content" tabindex="-1" data-program-family-hub="${esc(hub.id)}">
  <section class="program-family-filter-panel" aria-labelledby="program-family-filter-title">
    <div class="program-family-filter-panel__heading">
      <div>
        <p class="program-family-kicker">Registru verificat</p>
        <h2 id="program-family-filter-title">Găsește programul potrivit investiției</h2>
      </div>
      <p>Filtrele schimbă numai lista vizibilă. Combinația este păstrată în URL-ul paginii, dar nu creează pagini indexabile separate.</p>
    </div>
    <div class="program-family-filters" data-program-hub-filters role="group" aria-label="Filtrează programele">
      <div class="program-family-filter">
        <label for="hub-filter-applicant">Tip solicitant</label>
        <select id="hub-filter-applicant" name="solicitant" aria-controls="hub-program-list">${optionMarkup(applicantTypes, filters.applicantTypes, "Toți solicitanții")}</select>
      </div>
      <div class="program-family-filter">
        <label for="hub-filter-region">Regiune</label>
        <select id="hub-filter-region" name="regiune" aria-controls="hub-program-list">${optionMarkup(regions, filters.regions, "Toate regiunile")}</select>
      </div>
      <div class="program-family-filter">
        <label for="hub-filter-investment">Tip investiție</label>
        <select id="hub-filter-investment" name="investitie" aria-controls="hub-program-list">${optionMarkup(investmentTypes, filters.investmentTypes, "Toate investițiile")}</select>
      </div>
      <div class="program-family-filter">
        <label for="hub-filter-status">Status</label>
        <select id="hub-filter-status" name="status" aria-controls="hub-program-list">${optionMarkup(statuses, statusLabels, "Toate statusurile")}</select>
      </div>
      <button class="btn btn-secondary program-family-filters__reset" type="button" data-program-filters-reset>Resetează filtrele</button>
    </div>
    <p class="program-family-results-status" id="hub-filter-results" role="status" aria-live="polite" aria-atomic="true" data-program-results-status>${esc(countLabel)}.</p>
  </section>${factualContext}

  <section class="program-family-results" aria-labelledby="program-family-results-title">
    <h2 id="program-family-results-title">Programe din familia ${esc(hub.label)}</h2>
    <div class="program-family-grid" id="hub-program-list" data-program-list>
      ${programs.map(renderCard).join("\n      ")}
    </div>
    <div class="program-family-empty" data-program-empty hidden>
      <h3>Niciun program nu corespunde filtrelor selectate</h3>
      <p>Resetează un filtru sau trimite contextul proiectului pentru o verificare inițială.</p>
    </div>
  </section>

  <section class="program-family-how" id="cum-alegi" aria-labelledby="program-family-how-title">
    <div>
      <p class="program-family-kicker">Verificare prudentă</p>
      <h2 id="program-family-how-title">Cum alegi</h2>
      <ol>${hub.howToChoose.map((item) => `<li>${esc(item)}</li>`).join("")}</ol>
    </div>
    <aside class="program-family-how__cta" aria-label="Verificarea proiectului">
      <h3>Ai un proiect concret?</h3>
      <p>Trimite tipul solicitantului, localitatea și investiția. Răspunsul inițial este orientativ și pornește de la documentele disponibile.</p>
      <a class="btn btn-primary" href="${PROJECT_CHECK_URL}" data-content-primary-cta data-analytics-event="cta_click" data-analytics-component="program_family_hub" data-analytics-cta-id="project_check_how" data-analytics-target="${PROJECT_CHECK_URL}" data-analytics-copy-variant="family_hub" data-analytics-cta-view="true">Începe verificarea proiectului</a>
    </aside>
  </section>${contextualNextStep}

  <section class="program-family-related" aria-labelledby="program-family-related-title">
    <h2 id="program-family-related-title">Ghiduri și instrumente relevante</h2>
    <div class="program-family-related__links">${hub.relatedLinks.map((link) => `<a href="${esc(link.href)}">${esc(link.label)}</a>`).join("")}</div>
  </section>

  <section class="program-family-faq" aria-labelledby="program-family-faq-title">
    <h2 id="program-family-faq-title">Întrebări frecvente despre ${esc(hub.label)}</h2>
    <div class="program-family-faq__list">${hub.faqs.map((item) => `<details class="faq-item"><summary><span>${esc(item.question)}</span></summary><p>${esc(item.answer)}</p></details>`).join("\n      ")}</div>
  </section>${editorialGovernance}${programContextualLinks}
</main>`;
}

function injectAsset(html, element, marker, closingTag) {
  if (html.includes(marker)) return html;
  return html.replace(closingTag, `${element}\n${closingTag}`);
}

function synchronizeHtml(html, hub, programs, filters) {
  const heroPattern = /(<header\b[^>]*\bclass=["'][^"']*\bhero\b[^"']*["'][^>]*>)[\s\S]*?<\/header>/iu;
  const mainPattern = /<main\b[^>]*>[\s\S]*?<\/main>/iu;
  if (!heroPattern.test(html)) throw new Error(`${hub.route}: nu a fost găsit hero-ul.`);
  if (!mainPattern.test(html)) throw new Error(`${hub.route}: nu a fost găsit elementul main.`);

  let next = html.replace(heroPattern, `$1${renderHero(hub)}\n  </header>`);
  const hubRecord = loadProgramConfig().programs.find((program) => program.pageUrl === hub.route && program.discovery?.listed === false) || null;
  next = next.replace(mainPattern, renderMain(hub, programs, filters, hubRecord));
  next = injectAsset(next, `  <link rel="stylesheet" href="/assets/program-family-hubs.css?v=${ASSET_VERSION}" />`, "/assets/program-family-hubs.css", "</head>");
  next = injectAsset(next, `<script src="/assets/program-family-hubs.js?v=${ASSET_VERSION}" defer></script>`, "/assets/program-family-hubs.js", "</body>");
  return next;
}

function main() {
  const data = loadData();
  validate(data);
  const changed = [];
  const counts = [];
  for (const hub of data.hubs.hubs) {
    const programs = data.programs
      .filter((program) => program.discovery.parentHub === hub.route && program.discovery.listed !== false && isPublicProgram(program))
      .sort((left, right) => (left.presentation?.order ?? 999) - (right.presentation?.order ?? 999) || left.name.localeCompare(right.name, "ro"));
    counts.push(`${hub.route}: ${programs.length}`);
    for (const file of routeFiles(hub.route)) {
      const html = fs.readFileSync(file, "utf8");
      const next = synchronizeHtml(html, hub, programs, data.hubs.filters);
      if (next === html) continue;
      changed.push(path.relative(ROOT, file).split(path.sep).join("/"));
      if (!CHECK_ONLY) fs.writeFileSync(file, next, "utf8");
    }
  }

  if (CHECK_ONLY && changed.length) {
    console.error(`Hub-uri nesincronizate în ${changed.length} fișiere:\n- ${changed.join("\n- ")}`);
    process.exitCode = 1;
    return;
  }
  console.log(`${CHECK_ONLY ? "Verificate" : "Sincronizate"} 5 hub-uri (${counts.join(", ")}); ${changed.length} ${CHECK_ONLY ? "fișiere neconforme" : "fișiere actualizate"}.`);
}

if (require.main === module) main();

module.exports = { loadData, renderMain, synchronizeHtml, validate };
