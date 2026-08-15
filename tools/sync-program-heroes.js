#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { sourcesForKeys } = require("./official-sources");
const { designFamilyForSlug } = require("./design-family-map");
const { isPublicProgram, loadProgramConfig, programForRoute } = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const BANNERS_PATH = path.join(ROOT, "banners.json");
const PROGRAM_HERO_CSS = "/assets/program-heroes.css";

const PROGRAM_ROUTES = Object.freeze([
  "/investitii-modernizarea-microintreprinderilor-apel-2",
  "/fonduri-regionale",
  "/dr12-afir",
  "/afir-autoconsum-agroalimentar",
  "/autoconsum-public-fotovoltaice-institutii-publice",
  "/dr14",
  "/digitalizare-imm",
  "/femeia-antreprenor-2026",
  "/gal-afir",
  "/e-move",
  "/pocidif-21",
  "/pro-infra",
  "/start-up-nation-2026"
]);

const PRIORITY_ROUTES = Object.freeze([
  "/dr12-afir",
  "/dr14",
  "/investitii-modernizarea-microintreprinderilor-apel-2",
  "/afir-autoconsum-agroalimentar",
  "/pro-infra",
  "/pocidif-21"
]);

const BANNER_ALIASES = Object.freeze({
  "/fonduri-regionale": "/investitii-modernizarea-microintreprinderilor-apel-2"
});

const FAMILY_BY_ROUTE = Object.freeze({
  "/por-adr-nord-est": "generic",
  "/fonduri-regionale": "generic",
  "/investitii-modernizarea-microintreprinderilor-apel-2": "generic",
  "/dr12-afir": "afir",
  "/afir-autoconsum-agroalimentar": "energy",
  "/autoconsum-public-fotovoltaice-institutii-publice": "energy",
  "/dr14": "afir",
  "/digitalizare-imm": "digital",
  "/femeia-antreprenor-2026": "startup",
  "/gal-afir": "gal",
  "/e-move": "energy",
  "/fondul-modernizare-energie-regenerabila-2026": "energy",
  "/pocidif-21": "digital",
  "/pro-infra": "energy",
  "/start-up-nation-2026": "startup"
});

const PRO_INFRA_REFERENCE = Object.freeze({
  tag: "Eficiență energetică | PRO INFRA | MTI",
  title: "PRO INFRA – eficiență energetică pentru producătorii din infrastructura de transport",
  description: "Înlocuirea instalațiilor, utilajelor și echipamentelor cu alternative eficiente energetic, electrificare și monitorizare prin EMS.",
  icon: "ph-duotone ph-factory",
  image: "/assets/hero/hero-solar.webp",
  family: "energy",
  primaryHref: "/verificare-eligibilitate-fonduri-europene",
  primaryText: "Verifică eligibilitatea PRO INFRA",
  guideHref: "https://legislatie.just.ro/Public/DetaliiDocumentAfis/306916",
  guideText: "Sursă oficială"
});

function normalizeCtaLink(value) {
  if (!value || typeof value !== "string") return "";
  let pathname;
  try {
    pathname = new URL(value.trim(), "https://atelierdeconsultanta.ro").pathname;
  } catch {
    pathname = value.trim().split(/[?#]/, 1)[0];
  }

  pathname = pathname.replace(/\\/g, "/");
  if (!pathname.startsWith("/")) pathname = `/${pathname}`;
  pathname = pathname.replace(/\/+$/g, "");
  pathname = pathname.replace(/\/index\.html$/i, "");
  pathname = pathname.replace(/\.html$/i, "");
  pathname = pathname.replace(/\/{2,}/g, "/");
  return pathname || "/";
}

function loadBanners(filePath = BANNERS_PATH) {
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const banners = Array.isArray(parsed) ? parsed : parsed.banners;
  if (!Array.isArray(banners)) throw new Error(`${filePath} must contain a banner array`);
  return banners;
}

function createBannerIndex(banners = loadBanners()) {
  const index = new Map();
  for (const banner of banners) {
    const route = normalizeCtaLink(banner.ctaLink || banner.href);
    if (!route || route === "/") continue;
    if (index.has(route)) throw new Error(`Duplicate banner route: ${route}`);
    index.set(route, banner);
  }
  return index;
}

function bannerForRoute(route, bannersOrIndex = loadBanners()) {
  const normalized = normalizeCtaLink(route);
  const sourceRoute = BANNER_ALIASES[normalized] || normalized;
  const index = bannersOrIndex instanceof Map ? bannersOrIndex : createBannerIndex(bannersOrIndex);
  return index.get(sourceRoute) || null;
}

function familyForRoute(route) {
  const normalized = normalizeCtaLink(route);
  const family = FAMILY_BY_ROUTE[normalized] || designFamilyForSlug(normalized.slice(1));
  if (!family) throw new Error(`No program hero family configured for ${normalized}`);
  return family;
}

function iconClass(icon) {
  const classes = String(icon || "ph-sparkle").trim().split(/\s+/).filter(Boolean);
  if (!classes.includes("ph-duotone")) classes.unshift("ph-duotone");
  return [...new Set(classes)].join(" ");
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderTitle(title) {
  return String(title || "")
    .split(/\r?\n/)
    .map((line) => escapeHtml(line.trim()))
    .filter(Boolean)
    .join("<br>");
}

function extractExistingHero(fragment) {
  const $ = cheerio.load(fragment, { decodeEntities: false }, false);
  const hero = $("header.hero").first();
  if (!hero.length) throw new Error("Hero header not found");
  const actions = hero.find(".hero-actions").first();
  if (!actions.length || actions.find("a").length < 2) {
    throw new Error("Program hero must retain eligibility and official-guide CTAs");
  }
  return {
    tag: hero.find(".design-badge").first().text().trim(),
    title: hero.find("h1").first().text().trim(),
    description: hero.find("p").first().text().trim(),
    actionsHtml: actions.html().trim()
  };
}

function ensureHeroActions(route, banner, actionsHtml) {
  const normalizedRoute = normalizeCtaLink(route);
  const $ = cheerio.load(`<div class="hero-actions">${String(actionsHtml || "")}</div>`, { decodeEntities: false }, false);
  const links = $(".hero-actions a");
  const eligibility = links.filter((_, element) => normalizeCtaLink($(element).attr("href")) === "/verificare-eligibilitate-fonduri-europene").first();
  const officialGuideKey = (banner.officialGuideKeys && banner.officialGuideKeys[normalizedRoute]) || banner.officialGuideKey;
  const officialSource = sourcesForKeys([officialGuideKey])[0];
  const officialUrl = officialSource?.isComplete && /^https?:\/\//i.test(officialSource.url)
    ? officialSource.url
    : String(banner.sourceUrl || "").trim();
  if (!/^https?:\/\//i.test(officialUrl)) {
    throw new Error(`No complete official guide configured for ${normalizedRoute}`);
  }
  const guide = links.filter((_, element) => $(element).attr("href") === officialUrl).first();
  const programName = String(banner.title || "programul").split(/\r?\n/, 1)[0].trim();
  const eligibilityHtml = eligibility.length
    ? $.html(eligibility)
    : `<a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">${escapeHtml(`Verifică eligibilitatea ${programName}`)}</a>`;
  const guideHtml = guide.length
    ? $.html(guide)
    : `<a class="btn btn-secondary" href="${escapeHtml(officialUrl)}" target="_blank" rel="noopener noreferrer">Sursă oficială</a>`;
  return `${eligibilityHtml}\n      ${guideHtml}`;
}

function renderProgramHero({ route, banner, existing = {}, actionsHtml }) {
  const normalizedRoute = normalizeCtaLink(route);
  if (!banner) throw new Error(`No banner found for ${normalizedRoute}`);
  const family = familyForRoute(normalizedRoute);
  const isProInfra = normalizedRoute === "/pro-infra";
  const content = isProInfra
    ? {
        tag: PRO_INFRA_REFERENCE.tag,
        title: PRO_INFRA_REFERENCE.title,
        description: PRO_INFRA_REFERENCE.description
      }
    : {
        tag: banner.tag || existing.tag || banner.subtitle || "Program de finanțare",
        title: (banner.pageTitles && banner.pageTitles[normalizedRoute]) || banner.pageTitle || banner.title || existing.title,
        description: (banner.pageDescriptions && banner.pageDescriptions[normalizedRoute]) || banner.description || banner.subtitle || existing.description
      };
  const finalActions = ensureHeroActions(normalizedRoute, banner, actionsHtml || existing.actionsHtml);
  if (!finalActions) throw new Error(`Missing hero actions for ${normalizedRoute}`);
  const image = banner.image;
  if (!image || !String(image).startsWith("/")) throw new Error(`Invalid banner image for ${normalizedRoute}`);
  const calendar = banner.calendar && banner.calendar.label
    ? `<aside class="program-hero__estimate program-hero__calendar" aria-label="Calendar oficial" data-program-calendar="official">
      <strong>${escapeHtml(banner.calendar.label)}</strong>
      ${banner.calendar.note ? `<span>${escapeHtml(banner.calendar.note)}</span>` : ""}
    </aside>`
    : banner.estimate && banner.estimate.label
      ? `<aside class="program-hero__estimate" aria-label="Calendar estimativ" data-program-estimate="true">
        <strong>${escapeHtml(banner.estimate.label)}</strong>
        ${banner.estimate.note ? `<span>${escapeHtml(banner.estimate.note)}</span>` : ""}
      </aside>`
      : "";

  return `<!-- PROGRAM_HERO_START -->
  <header class="hero hero--image hero--${escapeHtml(family)} program-hero" data-design-family="${escapeHtml(family)}" data-program-family="${escapeHtml(family)}" data-program-route="${escapeHtml(normalizedRoute)}" data-banner-id="${escapeHtml(banner.id)}" data-banner-image="${escapeHtml(image)}" style="--hero-image:url('${escapeHtml(image)}')">
    <span class="hero-icon" aria-hidden="true"><i class="${escapeHtml(iconClass(isProInfra ? PRO_INFRA_REFERENCE.icon : banner.icon))}"></i></span>
    <span class="eyebrow design-badge design-badge--${escapeHtml(family)}">${escapeHtml(content.tag)}</span>
    <h1>${isProInfra ? escapeHtml(content.title) : renderTitle(content.title)}</h1>
    <p>${escapeHtml(content.description)}</p>
    ${calendar}
    <div class="hero-actions">
      ${finalActions}
    </div>
  </header>
  <!-- PROGRAM_HERO_END -->`;
}

function findHeroBlock(html) {
  const marked = html.match(/<!-- PROGRAM_HERO_START -->[\s\S]*?<!-- PROGRAM_HERO_END -->/);
  if (marked) return marked[0];
  const hero = html.match(/<header\b[^>]*class="[^"]*\bhero\b[^"]*"[^>]*>[\s\S]*?<\/header>/i);
  return hero ? hero[0] : null;
}

function ensureProgramHeroCss(html) {
  if (html.includes(`href="${PROGRAM_HERO_CSS}"`) || html.includes(`href='${PROGRAM_HERO_CSS}'`)) return html;
  if (!/<\/head>/i.test(html)) throw new Error("Missing </head>");
  return html.replace(/<\/head>/i, `  <link rel="stylesheet" href="${PROGRAM_HERO_CSS}">\n</head>`);
}

function syncPage(route, bannerIndex, { check = false, program = null } = {}) {
  const normalizedRoute = normalizeCtaLink(route);
  const filePath = path.join(ROOT, normalizedRoute.slice(1), "index.html");
  if (!fs.existsSync(filePath)) throw new Error(`Missing public page: ${filePath}`);
  const before = fs.readFileSync(filePath, "utf8");
  // P1.11 owns the complete hero/status composition for pages migrated to the
  // compact program template. Re-injecting the legacy hero actions here would
  // be removed later by sync-program-page-template and make the build
  // permanently non-idempotent.
  if (/data-program-template(?:-version)?=/i.test(before)) {
    return { route: normalizedRoute, filePath, bannerId: "program-page-template", changed: false, skipped: true };
  }
  const banner = bannerForRoute(normalizedRoute, bannerIndex);
  if (!banner) throw new Error(`Missing banners.json mapping for ${normalizedRoute}`);
  const pageBanner = program
    ? {
        ...banner,
        title: program.name || banner.title,
        tag: program.statusLabel || banner.tag,
        description: program.cardSummary || banner.description,
        officialGuideKey: program.officialGuideKeys?.[0] || banner.officialGuideKey,
        sourceUrl: program.sourceUrl || banner.sourceUrl,
        sourceVersion: program.sourceVersion || banner.sourceVersion,
        calendar: program.presentation?.calendar || banner.calendar,
        estimate: program.presentation?.estimate || banner.estimate
      }
    : banner;
  const oldHero = findHeroBlock(before);
  const existing = oldHero ? extractExistingHero(oldHero) : { tag: "", title: "", description: "", actionsHtml: "" };
  const newHero = renderProgramHero({ route: normalizedRoute, banner: pageBanner, existing });
  const withHero = oldHero
    ? before.replace(oldHero, newHero)
    : before.replace(/(<main\b[^>]*>)/iu, `$1\n${newHero}`);
  if (!oldHero && withHero === before) throw new Error(`Could not insert the page hero for ${normalizedRoute}`);
  const after = ensureProgramHeroCss(withHero);
  const changed = after !== before;
  if (changed && !check) fs.writeFileSync(filePath, after, "utf8");
  return { route: normalizedRoute, filePath, bannerId: banner.id, changed };
}

function selectedRoutes(argv = process.argv.slice(2)) {
  if (argv.includes("--priority")) return [...PRIORITY_ROUTES];
  const routeArg = argv.find((arg) => arg.startsWith("--routes="));
  if (!routeArg) return [...PROGRAM_ROUTES];
  return routeArg.slice("--routes=".length).split(",").map(normalizeCtaLink).filter(Boolean);
}

function main() {
  const argv = process.argv.slice(2);
  const check = argv.includes("--check");
  const bannerIndex = createBannerIndex();
  const programs = loadProgramConfig().programs;
  const routes = selectedRoutes(argv).filter((route) => {
    const program = programForRoute(route, programs);
    return !program || isPublicProgram(program);
  });
  const results = routes.map((route) => syncPage(route, bannerIndex, {
    check,
    program: programForRoute(route, programs)
  }));
  const changed = results.filter((result) => result.changed);
  for (const result of results) {
    console.log(`${result.skipped ? "SKIPPED_TEMPLATE" : result.changed ? (check ? "OUTDATED" : "UPDATED") : "OK"} ${result.route} <- ${result.bannerId}`);
  }
  console.log(`${results.length} program heroes checked; ${changed.length} ${check ? "outdated" : "updated"}.`);
  if (check && changed.length) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = {
  BANNER_ALIASES,
  FAMILY_BY_ROUTE,
  PRIORITY_ROUTES,
  PROGRAM_ROUTES,
  PRO_INFRA_REFERENCE,
  bannerForRoute,
  createBannerIndex,
  familyForRoute,
  iconClass,
  ensureHeroActions,
  loadBanners,
  normalizeCtaLink,
  renderProgramHero
};
