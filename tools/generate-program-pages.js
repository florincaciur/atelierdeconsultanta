#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const GLOBAL_HEADER = fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8").trim();
const CONFIG_PATH = path.join(ROOT, "config", "seo-programs.json");
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const REDIRECTS_PATH = path.join(ROOT, "_redirects");
const BLOG_JSON_PATH = path.join(ROOT, "blog.json");
const BANNERS_PATH = path.join(ROOT, "banners.json");
const LLMS_PATH = path.join(ROOT, "llms.txt");
const CANONICAL_DIRECTORY_ONLY_SLUGS = new Set([
  "dr12-afir",
  "dr14",
  "por-adr-nord-est",
  "afir-autoconsum-agroalimentar",
  "pro-infra",
  "pocidif-21"
]);
const {
  bannerForRoute,
  createBannerIndex,
  loadBanners,
  renderProgramHero
} = require("./sync-program-heroes");
const { renderPocidifContent } = require("./pocidif-content");
const { applyPriorityAeo } = require("./priority-aeo");
const PROGRAM_BANNER_INDEX = createBannerIndex(loadBanners(BANNERS_PATH));
const {
  editorialSchemaProperties,
  getEditorialMetadata,
  renderEditorialSection
} = require("./editorial-metadata");
const {
  officialSourceCitations,
  renderOfficialSources,
  sourcesForKeys
} = require("./official-sources");
const { designFamilyForSlug } = require("./design-family-map");
const {
  SITE,
  buildPageMetadata,
  breadcrumbItemsForPath,
  breadcrumbSchema,
  canonicalUrl,
  faqPageSchema,
  jsonLdGraph,
  normalizeCanonicalPath,
  organizationSchema,
  serviceSchema,
  standardInternalLinksForPath,
  webApplicationSchema,
  webPageSchema,
  websiteSchema
} = require("./schema-helpers");
const {
  normalizeHtmlCopy,
  normalizeRomanianCopy
} = require("./normalize-copy-ro");
const CLARITY_TRACKING_CODE = `  <script type="text/javascript">
    (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
    })(window, document, "clarity", "script", "wnvzyco6rq");
  </script>`;

const PILLAR_SLUGS = new Set([
  "consultanta-fonduri-europene",
  "verificare-eligibilitate-fonduri-europene",
  "fonduri-europene",
  "fonduri-europene-nerambursabile-2026",
  "dr12-afir",
  "dr14",
  "digitalizare-imm",
  "femeia-antreprenor-2026",
  "start-up-nation-2026",
  "fonduri-europene-imm",
  "investitii-modernizarea-microintreprinderilor-apel-2",
  "pocidif-21",
  "pro-infra",
  "fondul-modernizare-energie-regenerabila-2026",
  "e-move",
  "gal-afir"
]);

const SECONDARY_SLUGS = new Set([
  "start-up-nation-2026-conditii",
  "start-up-nation-2026-cheltuieli-eligibile",
  "start-up-nation-2026-idei-afaceri",
  "start-up-nation-2026-plan-de-afaceri",
  "cod-caen-start-up-nation-2026",
  "consultanta-start-up-nation-2026",
  "consultant-fonduri-europene-imm",
  "firma-consultanta-fonduri-europene",
  "consultanta-afir",
  "consultanta-pnrr-digitalizare",
  "digitalizare-imm-pnrr",
  "granturi-digitalizare-imm",
  "fonduri-europene-femei-antreprenor",
  "femeia-antreprenor-2026-conditii-idei-afaceri"
]);

const KEYWORDS_BY_SLUG = {
  "consultanta-fonduri-europene": ["consultanță fonduri europene", "firmă consultanță fonduri europene", "consultant fonduri europene", "verificare eligibilitate fonduri europene", "cost consultanță fonduri europene", "dosar fonduri europene"],
  "verificare-eligibilitate-fonduri-europene": ["verificare eligibilitate fonduri europene", "eligibilitate fonduri europene 2026", "eligibilitate DR12", "eligibilitate DR14", "verificare cod CAEN fonduri europene"],
  "fonduri-europene-nerambursabile-2026": ["fonduri europene nerambursabile 2026", "fonduri europene 2026 pentru tineri", "fonduri europene 2026 rural non agricol", "program fonduri europene 2026", "fonduri europene 2026 pentru femei"],
  "dr12-afir": ["dr 12 afir lansare", "dr 12 ghid final", "dr12 afir", "afir dr 12", "ghid dr 12 afir"],
  "dr14": ["dr14", "dr14 afir", "dr14 afir 2026", "dr 14 conditii", "când se lansează dr 14", "ghidul solicitantului dr 14"],
  "dr14-afir-ferme-mici": ["DR14 AFIR ferme mici", "conditii DR14 ferme mici", "documente DR14 AFIR", "eligibilitate ferme mici"],
  "digitalizare-imm": ["Digitalizare IMM 2026", "PNRR digitalizare IMM", "grant digitalizare IMM 2026", "echipamente digitalizare IMM"],
  "femeia-antreprenor-2026": ["Femeia Antreprenor 2026", "fonduri europene femei antreprenor 2026", "grant Femeia Antreprenor 2026", "cheltuieli eligibile Femeia Antreprenor 2026"],
  "start-up-nation-2026": ["Start Up Nation 2026", "Start Up Nation 2026 conditii", "cheltuieli eligibile Start Up Nation 2026", "cod CAEN Start Up Nation 2026", "idei afaceri Start Up Nation 2026", "plan de afaceri Start Up Nation 2026"],
  "fonduri-europene-imm": ["fonduri europene IMM 2026", "program IMM 2026", "granturi IMM 2026", "fonduri pentru IMM"],
  "investitii-modernizarea-microintreprinderilor-apel-2": ["fonduri microintreprinderi 2026", "program microintreprinderi 2026", "conditii microintreprinderi 2026"],
  "pocidif-21": ["PoCIDIF 2.1", "inovare digitală IMM TIC", "finanțare PoCIDIF", "servicii aplicații produse digitale"],
  "eligibilitate-pocidif-21": ["eligibilitate PoCIDIF 2.1", "coduri CAEN PoCIDIF", "IMM TIC PoCIDIF", "parteneriat PoCIDIF"],
  "cheltuieli-eligibile-pocidif-21": ["cheltuieli eligibile PoCIDIF 2.1", "hardware PoCIDIF", "software PoCIDIF", "buget PoCIDIF"],
  "documente-punctaj-pocidif-21": ["documente PoCIDIF 2.1", "punctaj PoCIDIF", "plan de afaceri PoCIDIF", "indicatori PoCIDIF"],
  "pro-infra": ["PRO INFRA", "eficiență energetică industrială", "echipamente eficiente energetic", "sistem EMS", "audit energetic"],
  "fondul-modernizare-energie-regenerabila-2026": ["program energie 2026", "fonduri energie regenerabile 2026", "granturi energie verde 2026", "Fondul pentru Modernizare energie regenerabila"],
  "e-move": ["e-MOVE RO", "program e-MOVE RO 2026", "finantare statii incarcare electrice", "mobilitate electrica fonduri europene", "statii incarcare masini electrice finantare"],
  "gal-afir": ["GAL AFIR", "apeluri GAL 2026", "finantari LEADER beneficiari publici", "finantari GAL beneficiari privati", "preluare proiecte GAL implementare"],
  "calculator-soc": ["calculator SOC", "calculator DR12 AFIR", "calculator cofinantare"],
  "cod-caen-start-up-nation-2026": ["cod CAEN Start Up Nation 2026", "verificare cod CAEN fonduri europene", "cod CAEN eligibil Start Up Nation"],
  "start-up-nation-2026-conditii": ["Start Up Nation 2026 conditii", "eligibilitate Start Up Nation 2026", "cod CAEN Start Up Nation 2026"],
  "start-up-nation-2026-cheltuieli-eligibile": ["cheltuieli eligibile Start Up Nation 2026", "buget Start Up Nation 2026", "achizitii Start Up Nation 2026"],
  "start-up-nation-2026-idei-afaceri": ["idei afaceri Start Up Nation 2026", "afaceri eligibile Start Up Nation", "program IMM 2026"],
  "start-up-nation-2026-plan-de-afaceri": ["plan de afaceri Start Up Nation 2026", "buget plan de afaceri", "consultanta Start Up Nation 2026"],
  "firma-consultanta-fonduri-europene": ["firma consultanta fonduri europene", "servicii fonduri europene", "alegere consultant fonduri europene"],
  "consultant-fonduri-europene-imm": ["consultant fonduri europene IMM", "fonduri europene IMM 2026", "verificare eligibilitate IMM"]
};

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function publicText(value, fallback = "") {
  const text = String(value ?? "").trim();
  if (!text || /^TODO_/i.test(text)) return fallback;
  return normalizeRomanianCopy(text
    .replace(/TODO_CLIENT_[A-Z0-9_ -]*/gi, fallback)
    .replace(/TODO_SURSA_OFICIALA[A-Z0-9_ -]*/gi, "Se confirma in ghidul activ")
    .replace(/TODO_DATA_ACCESARII/gi, "")
    .replace(/TODO_VERIFICARE_GHID[A-Z0-9_ -]*/gi, "Se verifica in ghidul activ"));
}

function hasPublicPlaceholder(value) {
  const text = normalizeRomanianCopy(String(value ?? "").trim()).toLowerCase();
  return !text || /todo_|in curs de validare|în curs de validare|date in curs|date în curs|de completat dupa|de completat după|validare interna|validare internă|program confirmat intern|valoare anonimizata|valoare anonimizată|status anonimizat|rezultat publicabil dupa acord|rezultat publicabil după acord/.test(text);
}

function esc(value) {
  return publicText(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escAttr(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pageText(page) {
  return `${page.slug || ""} ${page.type || ""} ${page.category || ""} ${page.programName || ""} ${page.h1 || ""}`.toLowerCase();
}

function shortProgramName(page) {
  return publicText(page.programName || page.h1 || "proiectul")
    .replace(/\s*\|\s*.*$/g, "")
    .replace(/\s*-\s*ghid.*$/gi, "")
    .trim();
}

function designFamilyFor(page) {
  if (page.designFamily) return page.designFamily;
  const mappedFamily = designFamilyForSlug(page.slug || "");
  if (mappedFamily) return mappedFamily;
  if (page.type === "trust") return "trust";
  if (page.includeTools || /calculator|instrumente/.test(pageText(page))) return "tool";
  if (/apeluri-gal|gal-afir|leader/.test(pageText(page))) return "gal";
  if (/dr12|dr14|afir|agricultur|ferme|fermieri|utilaje/.test(pageText(page))) return "afir";
  if (/digitalizare|pnrr|software|cloud|crm|erp|cyber|granturi-digitalizare/.test(pageText(page))) return "digital";
  if (/start-up|startup|femeia antreprenor|antreprenor 2026|cod-caen-start/.test(pageText(page))) return "startup";
  if (/energie|fotovoltaic|modernizare|autoconsum|e-move|infra|panouri/.test(pageText(page))) return "energy";
  if (/consultanta|consultant|eligibilitate|metodologie|servici/.test(pageText(page))) return "service";
  if (/blog|ghid|resurse|glosar|acte|documente|calendar|surse/.test(pageText(page))) return "editorial";
  if (/fonduri europene|fonduri nerambursabile|imm|nord-est|regional|cluster/.test(pageText(page))) return "cluster";
  return "generic";
}

const DESIGN_FAMILY_PROFILES = {
  afir: {
    badge: "AFIR | status apel | verificare documente",
    icon: "ph-duotone ph-plant",
    image: "/assets/hero/hero-agriculture.webp",
    cards: ["Solicitant", "Investitie", "Documente", "Punctaj"],
    primary: "Verifica eligibilitatea",
    secondary: "Vezi sursa oficiala"
  },
  gal: {
    badge: "GAL/LEADER | ghid local | teritoriu",
    icon: "ph-duotone ph-map-pin",
    image: "/assets/hero/hero-local.webp",
    cards: ["Beneficiar public", "Beneficiar privat", "DR36", "Implementare"],
    primary: "Verifica eligibilitatea GAL",
    secondary: "Vezi sursa oficiala"
  },
  digital: {
    badge: "PNRR/MIPE | digitalizare | ghid verificat",
    icon: "ph-duotone ph-desktop",
    image: "/assets/hero/hero-digital.webp",
    cards: ["Hardware", "Software", "Cloud", "Cybersecurity"],
    primary: "Verifica eligibilitatea",
    secondary: "Vezi sursa oficiala"
  },
  startup: {
    badge: "Antreprenoriat | ghid | status oficial",
    icon: "ph-duotone ph-rocket-launch",
    image: "/assets/hero/hero-business.webp",
    cards: ["Eligibilitate", "CAEN", "Buget", "Plan afaceri"],
    primary: "Verifica eligibilitatea",
    secondary: "Vezi sursa oficiala"
  },
  energy: {
    badge: "Energie | autoconsum | avize",
    icon: "ph-duotone ph-sun",
    image: "/assets/hero/hero-solar.webp",
    cards: ["Consum", "Avize", "Capacitate", "Buget"],
    primary: "Verifica proiectul energetic",
    secondary: "Vezi sursa oficiala"
  },
  cluster: {
    badge: "FABER | resursa | actualizare",
    icon: "ph-duotone ph-info",
    image: "/assets/hero/hero-business.webp",
    cards: ["Program", "Solicitant", "Documente", "Riscuri"],
    primary: "Verifica eligibilitatea",
    secondary: "Vezi documentele"
  },
  service: {
    badge: "Serviciu FABER | proces | livrabile",
    icon: "ph-duotone ph-magnifying-glass",
    image: "/assets/hero/hero-business.webp",
    cards: ["Verificare", "Strategie", "Dosar", "Clarificari"],
    primary: "Solicita analiza",
    secondary: "Vezi documentele"
  },
  editorial: {
    badge: "Ghid editorial | actualizat | surse citate",
    icon: "ph-duotone ph-file-text",
    image: "/assets/hero/hero-business.webp",
    cards: ["Pe scurt", "Ce verifici", "Greseli", "Pasi"],
    primary: "Verifica situatia ta",
    secondary: "Citeste ghidul"
  },
  trust: {
    badge: "Dovada sociala | caz anonimizat | rezultat",
    icon: "ph-duotone ph-bank",
    image: "/assets/hero/hero-business.webp",
    cards: ["Beneficiar", "Problema", "Interventie", "Rezultat"],
    primary: "Solicita o analiza similara",
    secondary: "Vezi portofoliul"
  },
  tool: {
    badge: "Instrument FABER | calcul | verificare",
    icon: "ph-duotone ph-calculator",
    image: "/assets/hero/hero-digital.webp",
    cards: ["Date", "Calcul", "Rezultat", "Avertizare"],
    primary: "Foloseste instrumentul",
    secondary: "Vezi metodologia"
  },
  generic: {
    badge: "FABER | resursa | actualizare",
    icon: "ph-duotone ph-info",
    image: "/assets/hero/hero-business.webp",
    cards: ["Context", "Verificare", "Resurse", "Urmator pas"],
    primary: "Solicita consultanta",
    secondary: "Vezi documentele"
  }
};

function designProfileFor(page) {
  return DESIGN_FAMILY_PROFILES[designFamilyFor(page)] || DESIGN_FAMILY_PROFILES.generic;
}

function slugPath(page) {
  return `/${page.slug}`;
}

function canonical(page) {
  return canonicalUrl(slugPath(page));
}

function cleanUrl(value) {
  if (!value || value === "/") return "/";
  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      if (url.origin === SITE) return normalizeCanonicalPath(url.pathname);
    } catch {
      return value;
    }
    return value;
  }
  return normalizeCanonicalPath(value);
}

function metadataForPage(page) {
  return buildPageMetadata({
    title: page.title,
    description: page.description,
    pathname: slugPath(page),
    fallbackTitle: page.h1 || page.slug,
    fallbackDescription: page.quickAnswer || page.summary || page.h1
  });
}

function breadcrumbItemsForPage(page) {
  return breadcrumbItemsForPath(slugPath(page), page.h1 || page.title);
}

function renderBreadcrumb(items) {
  return `<div class="breadcrumb">${items.map((item, index) => {
    const label = esc(item.name);
    if (index === items.length - 1) return label;
    return `<a href="${cleanUrl(item.item)}">${label}</a>`;
  }).join(" / ")}</div>`;
}

let bannerHeroImageByRoute = null;

function bannerHeroImageForPage(page) {
  if (!bannerHeroImageByRoute) {
    bannerHeroImageByRoute = new Map();
    if (fs.existsSync(BANNERS_PATH)) {
      for (const banner of readJson(BANNERS_PATH)) {
        const route = cleanUrl(banner.ctaLink || "");
        const image = String(banner.image || "").trim();
        if (route && image) bannerHeroImageByRoute.set(route, image);
      }
    }
  }
  return bannerHeroImageByRoute.get(slugPath(page)) || "";
}

function fallbackHeroImageFor(page) {
  const profile = designProfileFor(page);
  if (profile.image) return profile.image;
  const text = pageText(page);
  if (page.slug === "e-move") return "/assets/hero/hero-solar.webp";
  if (page.slug === "gal-afir") return "/assets/hero/hero-local.webp";
  if (/afir|dr12|dr14|agricultur|ferme|utilaje/.test(text)) return "/assets/hero/hero-agriculture.webp";
  if (/fotovoltaic|energie|modernizare|autoconsum|infra/.test(text)) return "/assets/hero/hero-solar.webp";
  if (/digitalizare|pnrr|software|instrumente/.test(text)) return "/assets/hero/hero-digital.webp";
  if (/local|nord-est|bacau|iasi|suceava|bucuresti/.test(text)) return "/assets/hero/hero-local.webp";
  return "/assets/hero/hero-business.webp";
}

function heroImageFor(page) {
  return page.heroImage || bannerHeroImageForPage(page) || fallbackHeroImageFor(page);
}

function heroAttrs(page) {
  const family = designFamilyFor(page);
  return `class="hero hero--image hero--${esc(family)}" data-design-family="${esc(family)}" style="--hero-image:url('${heroImageFor(page)}')"`;
}

function heroIconFor(page) {
  if (page.heroIcon) return page.heroIcon;
  const profile = designProfileFor(page);
  if (profile.icon) return profile.icon;
  if (page.slug === "e-move") return "ph-duotone ph-battery-charging";
  if (page.slug === "gal-afir") return "ph-duotone ph-map-pin";
  const text = pageText(page);
  if (/dr12|dr14|afir|agricultur|ferme|utilaje/.test(text)) return "ph-duotone ph-plant";
  if (/digitalizare|pnrr|software|instrumente/.test(text)) return "ph-duotone ph-desktop";
  if (/energie|fotovoltaic|modernizare|autoconsum/.test(text)) return "ph-duotone ph-sun";
  if (/start-up|startup/.test(text)) return "ph-duotone ph-rocket-launch";
  if (/femeia|antreprenor/.test(text)) return "ph-duotone ph-user-circle";
  if (/infra|productie|microintreprinderi/.test(text)) return "ph-duotone ph-factory";
  if (/gal|leader|local|nord-est|regional/.test(text)) return "ph-duotone ph-map-pin";
  if (/contact|consultanta|eligibilitate|verificare/.test(text)) return "ph-duotone ph-magnifying-glass";
  return "ph-duotone ph-info";
}

function heroBadgeFor(page) {
  return page.heroBadge || designProfileFor(page).badge || page.category;
}

function guideSourceForPage(page) {
  const keys = [
    page.officialGuideKey,
    page.guideSourceKey,
    page.secondaryCtaSourceKey,
    ...(Array.isArray(page.sourceKeys) ? page.sourceKeys : [])
  ].filter(Boolean);
  const seen = new Set();
  for (const key of keys) {
    if (seen.has(key)) continue;
    seen.add(key);
    const source = sourcesForKeys([key])[0];
    if (source && source.isComplete && /^https?:\/\//i.test(source.url)) return source;
  }
  return null;
}

function heroSecondaryCta(page) {
  if (page.secondaryCtaHref && page.secondaryCtaLabel) {
    return {
      href: cleanUrl(page.secondaryCtaHref),
      label: page.secondaryCtaLabel,
      external: /^https?:\/\//i.test(page.secondaryCtaHref)
    };
  }
  const guide = guideSourceForPage(page);
  if (guide) {
    return {
      href: guide.url,
      label: page.guideCtaLabel || designProfileFor(page).secondary || "Vezi sursa oficiala",
      external: true
    };
  }
  if (page.slug === "consultanta-fonduri-europene") {
    return {
      href: "/metodologie-verificare-eligibilitate",
      label: "Vezi metodologia",
      external: false
    };
  }
  if (designFamilyFor(page) === "trust") {
    return {
      href: "/portofoliu",
      label: "Vezi portofoliul",
      external: false
    };
  }
  if (designFamilyFor(page) === "tool") {
    return {
      href: "/metodologie-verificare-eligibilitate",
      label: "Vezi metodologia",
      external: false
    };
  }
  return {
    href: designFamilyFor(page) === "editorial" ? "/surse-oficiale-fonduri-europene" : "/contact",
    label: designProfileFor(page).secondary || "Discuta cu un consultant",
    external: false
  };
}

function renderCtaLink(cta, className = "btn btn-secondary") {
  const href = cta.external ? cta.href : cleanUrl(cta.href);
  const attrs = cta.external ? ` target="_blank" rel="noopener noreferrer"` : "";
  return `<a class="${className}" href="${escAttr(href)}"${attrs}>${esc(cta.label)}</a>`;
}

function configuredCta(item) {
  if (!item || typeof item !== "object") return null;
  if (item.sourceKey) {
    const guide = sourcesForKeys([item.sourceKey])[0];
    if (guide && guide.isComplete && /^https?:\/\//i.test(guide.url)) {
      return {
        href: guide.url,
        label: item.label || "Sursa oficiala",
        external: true,
        className: item.className
      };
    }
  }

  const href = item.href || item.fallbackHref;
  if (!href) return null;
  return {
    href,
    label: item.label || item.fallbackLabel || "Detalii",
    external: /^https?:\/\//i.test(href),
    className: item.className
  };
}

function renderHeroActions(page, primaryCta, secondaryCta) {
  if (Array.isArray(page.heroCtas) && page.heroCtas.length) {
    return page.heroCtas
      .map(configuredCta)
      .filter(Boolean)
      .map((cta, index) => renderCtaLink(cta, cta.className || (index === 0 ? "btn btn-primary" : "btn btn-secondary")))
      .join("\n      ");
  }

  return `<a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">${esc(primaryCta)}</a>
      ${renderCtaLink(secondaryCta)}`;
}

function heroPrimaryCtaFor(page) {
  if (page.heroPrimaryCta) return page.heroPrimaryCta;
  const family = designFamilyFor(page);
  const profile = designProfileFor(page);
  const name = shortProgramName(page);
  if (family === "service") return `Solicita analiza pentru ${name}`;
  if (family === "trust") return profile.primary;
  if (family === "tool") return profile.primary;
  if (["afir", "gal", "digital", "startup", "energy"].includes(family)) return `${profile.primary} pentru ${name}`;
  if (family === "editorial") return profile.primary;
  return profile.primary || "Solicita verificare eligibilitate";
}

function renderHeroSummary(page) {
  const family = designFamilyFor(page);
  const program = shortProgramName(page);
  const audience = compactTextList(page.audience, family === "trust" ? "caz anonimizat" : "solicitant de verificat", 1);
  const status = family === "legal"
    ? "informare"
    : (page.funding || page.category || "se confirma in ghidul activ");
  const docs = compactTextList(page.mandatory || page.documentRows?.map((row) => row && row[0]), "documente si buget", 2);
  const risk = compactTextList(page.ineligibleExpenses || page.commonMistakes, "eligibilitatea depinde de apelul activ", 1);
  const items = [
    ["Beneficiar", audience],
    ["Status", status],
    ["Documente", docs],
    ["Risc", risk]
  ];
  return `<div class="hero-summary" aria-label="Rezumat vizual pentru ${esc(program)}">
      ${items.map(([label, value]) => `<span class="hero-summary__item"><strong>${esc(label)}</strong><em>${esc(value)}</em></span>`).join("\n      ")}
    </div>`;
}

function renderFamilyCards(page) {
  const profile = designProfileFor(page);
  const family = designFamilyFor(page);
  const labels = page.designCards || profile.cards || DESIGN_FAMILY_PROFILES.generic.cards;
  const program = shortProgramName(page);
  const detailByLabel = {
    Solicitant: compactTextList(page.audience, "profilul solicitantului", 2),
    Investitie: compactTextList(page.eligibleExpenses, "investitia propusa", 2),
    Documente: compactTextList(page.mandatory, "documente, oferte si buget", 2),
    Punctaj: compactTextList(page.scoring, "criterii si grila activa", 2),
    Hardware: "echipamente justificate prin procesul firmei",
    Software: "ERP, CRM, aplicatii si automatizari utile",
    Cloud: "servicii digitale si infrastructura scalabila",
    Cybersecurity: "securitate, backup si continuitate",
    CAEN: "activitate, autorizare si legatura cu investitia",
    Buget: page.funding || "grant, cofinantare si costuri neeligibile",
    "Plan afaceri": "obiective, achizitii, calendar si riscuri",
    Consum: "consum, amplasament si dimensionare",
    Avize: "documente tehnice si aprobari necesare",
    Capacitate: "puterea instalata sau dimensiunea investitiei",
    Verificare: "date primite si incadrare initiala",
    Strategie: "program, punctaj, buget si calendar",
    Dosar: "documente, anexe, oferte si formulare",
    Clarificari: "raspunsuri si ajustari dupa evaluare",
    "Pe scurt": page.quickAnswer || `rezumat pentru ${program}`,
    "Ce verifici": compactTextList(page.mandatory, "program, documente si investitie", 2),
    Greseli: compactTextList(page.commonMistakes || page.ineligibleExpenses, "presupuneri neverificate", 2),
    Pasi: compactTextList(page.steps, "verificare, buget, depunere", 2),
    Beneficiar: compactTextList(page.audience, "beneficiar anonimizat", 2),
    Problema: "incadrare, documente sau buget de clarificat",
    Interventie: "analiza FABER pe documente si surse oficiale",
    Rezultat: "decizie prudenta, ajustare sau pas urmator",
    Date: "completeaza valorile de lucru",
    Calcul: "scenariu orientativ, nu promisiune",
    Avertizare: "confirma rezultatul in ghidul activ",
    Program: page.programName || page.h1,
    Riscuri: compactTextList(page.ineligibleExpenses || page.commonMistakes, "riscuri la evaluare", 2),
    Context: page.category || "resursa FABER",
    Resurse: "linkuri interne si surse oficiale",
    "Urmator pas": "verificare concreta pe cazul tau"
  };
  return `<section class="design-card-grid design-card-grid--${esc(family)}" aria-label="Repere vizuale ${esc(program)}">
        ${labels.map((label) => `<article class="mini-card design-card"><span class="design-card__badge">${esc(label)}</span><h3>${esc(label)}</h3><p>${esc(detailByLabel[label] || `Verificare pentru ${program}`)}</p></article>`).join("\n        ")}
      </section>`;
}

function stripTags(html) {
  return html.replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function wordCount(html) {
  const text = stripTags(html);
  const words = text.match(/[\p{L}\p{N}]+(?:[-''][\p{L}\p{N}]+)*/gu);
  return words ? words.length : 0;
}

function textWordCount(value) {
  const words = String(value || "").match(/[\p{L}\p{N}]+(?:[-''][\p{L}\p{N}]+)*/gu);
  return words ? words.length : 0;
}

function isEditorialProgram(page) {
  return page.template === "editorial-program";
}

function li(items) {
  return (items || []).map((item) => `<li>${esc(item)}</li>`).join("\n");
}

function links(items) {
  return (items || [])
    .map((item) => {
      const href = typeof item === "string" ? item : (Array.isArray(item) ? item[0] : item.href);
      const label = typeof item === "string"
        ? labelForHref(href)
        : (Array.isArray(item) ? (item[1] || labelForHref(href)) : (item.label || item.name || item.title || labelForHref(href)));
      return `<a href="${cleanUrl(href)}">${esc(label)}</a>`;
    })
    .join("\n");
}

const POCIDIF_DISCOVERY_COPY = Object.freeze({
  "digitalizare-imm": [
    "PoCIDIF 2.1 pentru IMM din sectorul TIC",
    "Dacă întreprinderea dezvoltă un produs, o aplicație sau un serviciu digital inovator pentru piață, nu doar își digitalizează procesele interne, verifică separat eligibilitatea în PoCIDIF 2.1."
  ],
  "fonduri-europene-digitalizare": [
    "Inovare digitală prin PoCIDIF 2.1",
    "Pentru microîntreprinderi și IMM-uri TIC care fac cercetare, dezvoltare și inovare și introduc pe piață un rezultat digital, traseul relevant este pagina PoCIDIF 2.1."
  ],
  "pnrr": [
    "PoCIDIF 2.1 este un program distinct de PNRR",
    "Un IMM TIC care dezvoltă un produs digital inovator trebuie să compare apelurile PNRR cu PoCIDIF 2.1 și să evite suprapunerea aceleiași investiții sau a acelorași costuri."
  ],
  "fonduri-europene-imm": [
    "PoCIDIF 2.1 pentru IMM-uri TIC",
    "PoCIDIF 2.1 este ruta specializată pentru IMM-urile din sectorul TIC care dezvoltă servicii, aplicații sau produse inovatoare folosind tehnologii avansate."
  ],
  "consultanta-fonduri-europene": [
    "Verificare specializată PoCIDIF 2.1",
    "Proiectele CDI ale IMM-urilor TIC cer verificarea separată a CAEN-ului, produsului inovator, echipei, tipurilor de ajutor, indicatorilor și grilei PoCIDIF 2.1."
  ],
  "ghiduri": [
    "Ghidul aprobat PoCIDIF 2.1",
    "Pentru inovare digitală în IMM-uri TIC, consultă sinteza ghidului aprobat, schema, anexele și articolele despre eligibilitate, cheltuieli, documente și punctaj."
  ]
});

function renderPocidifDiscoveryLink(page) {
  const copy = POCIDIF_DISCOVERY_COPY[page.slug];
  if (!copy) return "";
  return `<aside class="source-note" aria-label="Resursă contextuală PoCIDIF 2.1">
        <h2>${esc(copy[0])}</h2>
        <p>${esc(copy[1])} <a href="/pocidif-21">Vezi pagina PoCIDIF 2.1</a>.</p>
      </aside>`;
}

function labelForHref(href) {
  const labels = {
    "/calculator-soc": "Calculator SO AFIR",
    "/dr12-afir": "DR 12 AFIR",
    "/dr14": "DR 14 AFIR",
    "/consultanta-afir": "Consultanta AFIR",
    "/fonduri-europene-agricultura": "Fonduri europene agricultura",
    "/verificare-eligibilitate-fonduri-europene": "Verificare eligibilitate",
    "/start-up-nation-2026-conditii": "Conditii Start-Up Nation",
    "/start-up-nation-2026-cheltuieli-eligibile": "Cheltuieli eligibile Start-Up Nation",
    "/cod-caen-start-up-nation-2026": "Cod CAEN Start-Up Nation",
    "/consultanta-start-up-nation-2026": "Consultanta Start-Up Nation",
    "/fonduri-europene-femei-antreprenor": "Fonduri pentru femei antreprenor",
    "/femeia-antreprenor-2026-conditii-idei-afaceri": "Conditii si idei Femeia Antreprenor",
    "/fonduri-europene-imm": "Fonduri europene IMM",
    "/digitalizare-imm-pnrr": "Digitalizare IMM / PNRR",
    "/pnrr-digitalizare-imm-cheltuieli-eligibile": "Cheltuieli Digitalizare IMM",
    "/fonduri-europene-digitalizare": "Fonduri europene digitalizare",
    "/consultanta-pnrr-digitalizare": "Consultanta PNRR digitalizare",
    "/investitii-modernizarea-microintreprinderilor-apel-2": "Modernizarea microintreprinderilor - Apel 2",
    "/pocidif-21": "PoCIDIF 2.1",
    "/fonduri-europene-nord-est": "Fonduri europene Nord-Est",
    "/por-adr-nord-est": "POR ADR Nord-Est",
    "/eligibilitate-fonduri-europene": "Eligibilitate fonduri europene",
    "/consultanta-fonduri-europene": "Consultanta fonduri europene",
    "/instrumente": "Instrumente",
    "/resurse": "Resurse descarcabile",
    "/fondul-modernizare-energie-regenerabila-2026": "Energie regenerabila 2026",
    "/fondul-de-modernizare": "Fondul de Modernizare",
    "/e-move": "e-MOVE RO",
    "/gal-afir": "GAL-AFIR / LEADER",
    "/finantari-panouri-fotovoltaice": "Finantari panouri fotovoltaice",
    "/afir-autoconsum-agroalimentar": "AFIR autoconsum agroalimentar",
    "/fonduri-pentru-ferme": "Fonduri pentru ferme",
    "/fonduri-pentru-utilaje-agricole": "Fonduri pentru utilaje agricole",
    "/fonduri-europene": "Fonduri europene",
    "/ghiduri": "Ghiduri",
    "/contact": "Contact",
    "/portofoliu": "Portofoliu",
    "/testimoniale": "Testimoniale",
    "/studii-de-caz": "Studii de caz",
    "/studii-de-caz-fonduri-europene": "Studii de caz fonduri europene",
    "/webinarii": "Webinarii",
    "/apeluri-gal": "Apeluri GAL"
  };
  const clean = cleanUrl(href);
  if (labels[clean]) return labels[clean];
  return clean.replace(/^\/+/, "").replace(/-/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function minWordsForPage(page) {
  if (isEditorialProgram(page)) return Number(page.minWords || 1200);
  if (Number(page.minWords) > 0) return Number(page.minWords);
  if (PILLAR_SLUGS.has(page.slug)) return 1200;
  if (SECONDARY_SLUGS.has(page.slug)) return 1100;
  if (page.type === "program" || page.type === "hub" || page.type === "service") return 1100;
  return 900;
}

function minFaqForPage(page) {
  if (isEditorialProgram(page)) {
    if (Number(page.minFaq) > 0) return Number(page.minFaq);
    if (PILLAR_SLUGS.has(page.slug)) return 10;
    return Math.min(6, Math.max(2, (page.faq || []).length || 2));
  }
  if (Number(page.minFaq) > 0) return Number(page.minFaq);
  if (PILLAR_SLUGS.has(page.slug)) return 10;
  if (SECONDARY_SLUGS.has(page.slug)) return 6;
  if (page.type === "program" || page.type === "hub" || page.type === "service") return 8;
  return 4;
}

function keywordsForPage(page) {
  return page.keywords || KEYWORDS_BY_SLUG[page.slug] || [];
}

function faqsForPage(page) {
  const faq = Array.isArray(page.faq) ? [...page.faq] : [];
  const programName = page.programName || page.h1 || "program";
  const keyword = keywordsForPage(page)[0] || programName;
  const minimumFaq = minFaqForPage(page);
  const additions = [
    [`Cum verific daca ${programName} este potrivit pentru proiectul meu?`, `Porneste de la solicitant, cod CAEN, localitate, investitie, buget si documentele disponibile. Daca una dintre aceste piese nu se potriveste cu apelul activ, proiectul trebuie ajustat inainte de depunere.`],
    [`Cand nu merita sa aplic pentru ${programName}?`, `Nu merita sa aplici cand nu poti dovedi eligibilitatea, cand cheltuielile principale nu sunt permise, cand cofinantarea nu este acoperita sau cand calendarul nu permite documente complete si verificabile.`],
    [`Ce documente trebuie pregatite pentru ${programName}?`, "De regula sunt necesare documente de firma sau solicitant, documente pentru activitate si locatie, date financiare, oferte, descrierea investitiei si informatii despre cofinantare."],
    [`Cum se verifica un cod CAEN pentru ${programName}?`, "Codul CAEN se verifica prin certificatul constatator, activitatea reala, autorizarea necesara, lista de coduri eligibile a apelului si legatura directa dintre investitie si activitatea finantata."],
    [`Ce cheltuieli sunt sensibile la evaluare pentru ${programName}?`, "Sunt sensibile cheltuielile greu de justificat, activele supradimensionate, serviciile descrise vag, achizitiile incepute prea devreme si costurile care nu au legatura directa cu obiectivele proiectului."],
    [`Cum tratez cofinantarea si cheltuielile neeligibile pentru ${programName}?`, "Cofinantarea si cheltuielile neeligibile trebuie estimate separat de grant. Include rezerve pentru TVA, diferente de pret, costuri neacoperite si intarzieri in rambursare."],
    [`Ce greseli duc frecvent la respingere sau clarificari pentru ${programName}?`, "Apar probleme cand documentele sunt expirate, ofertele sunt incomplete, bugetul nu se leaga de activitate, punctajul este estimat optimist sau solicitantul nu poate sustine implementarea."],
    [`Cum folosesc informatiile despre ${programName} in 2026?`, "Foloseste informatiile ca filtru initial si confirma intotdeauna regulile in apelul activ. Programele pot schimba praguri, documente, punctaje si termene de la o sesiune la alta."],
    [`Ce rol are consultanta pentru ${keyword}?`, `Consultanta ajuta la trierea programului, verificarea documentelor, structurarea bugetului, pregatirea raspunsurilor la clarificari si reducerea riscurilor, dar nu poate garanta aprobarea finantarii.`],
    [`Cat de repede trebuie inceputa pregatirea dosarului pentru ${programName}?`, "Pregatirea trebuie inceputa inainte de deschiderea efectiva a apelului, mai ales daca sunt necesare oferte, documente pentru spatiu, autorizatii, calcule de punctaj sau clarificari privind solicitantul."]
  ];
  if (faq.length >= minimumFaq) return faq;
  const seen = new Set(faq.map(([question]) => String(question).toLowerCase()));
  for (const item of additions) {
    const key = item[0].toLowerCase();
    if (!seen.has(key)) {
      faq.push(item);
      seen.add(key);
    }
    if (faq.length >= minimumFaq) break;
  }
  return faq;
}

function renderKeywordIntent(page) {
  const keywords = keywordsForPage(page);
  if (!keywords.length) return "";
  const chunks = keywords.slice(0, 6).map((keyword) => `<li>${esc(keyword)}</li>`).join("\n");
  return `<h2>Situatii frecvente cautate de beneficiari</h2>
      <p>Pagina raspunde natural intrebarilor pe care le au beneficiarii cand compara programe, documente, bugete si servicii de consultanta. Formularea ramane orientativa si trebuie verificata cu ghidul apelului activ.</p>
      <ul>${chunks}</ul>`;
}

function hasNumericClaim(page) {
  return [page.funding, page.description, page.quickAnswer].some((value) => /\d/.test(String(value || "")));
}

function validatePage(page) {
  if (!page.slug || !page.output || !page.title || !page.h1) {
    throw new Error(`Pagina incompleta in config: ${JSON.stringify(page)}`);
  }
  if (hasNumericClaim(page) && (!Array.isArray(page.sourceKeys) || page.sourceKeys.length === 0)) {
    throw new Error(`${page.slug} contine valori numerice si nu are sourceKeys interne.`);
  }
  if (isEditorialProgram(page)) {
    const quickAnswerWords = textWordCount(page.quickAnswer);
    if (quickAnswerWords < 100 || quickAnswerWords > 150) {
      throw new Error(`${page.slug} trebuie sa aiba raspuns scurt intre 100 si 150 cuvinte; are ${quickAnswerWords}.`);
    }
    if ((page.commonMistakes || []).length < 6) {
      throw new Error(`${page.slug} trebuie sa aiba cel putin 6 greseli frecvente.`);
    }
  }
}

function schemaGraph(page, config, metadata = metadataForPage(page)) {
  const faq = faqsForPage(page);
  const editorial = getEditorialMetadata(page.slug);
  const pageNode = webPageSchema({
    type: page.schemaType === "CollectionPage" ? "CollectionPage" : "WebPage",
    url: metadata.canonicalUrl,
    name: metadata.title,
    description: metadata.description,
    dateModified: page.updatedAt || config.updatedAt
  });

  if (editorial) {
    Object.assign(pageNode, editorialSchemaProperties(editorial));
  }

  if (Array.isArray(page.sourceKeys) && page.sourceKeys.length) {
    pageNode.citation = officialSourceCitations(page.sourceKeys);
  }
  if (isEditorialProgram(page)) {
    pageNode.mainEntity = { "@id": `${canonical(page)}#service` };
    pageNode.about = {
      "@type": page.schemaType === "GovernmentService" ? "GovernmentService" : "Service",
      name: page.programName || page.h1,
      serviceType: page.category
    };
  }

  const graph = [
    organizationSchema(),
    websiteSchema(),
    pageNode,
    breadcrumbSchema(breadcrumbItemsForPage(page)),
    faqPageSchema(faq, { minItems: 2 })
  ];

  if (page.type !== "tools") {
    const articleNode = {
      "@type": "Article",
      "@id": `${canonical(page)}#article`,
      "mainEntityOfPage": { "@id": pageNode["@id"] },
      "headline": publicText(page.h1 || page.title),
      "description": publicText(metadata.description),
      "inLanguage": "ro-RO",
      "author": { "@id": `${SITE}/#organization` },
      "publisher": { "@id": `${SITE}/#organization` },
      "dateModified": page.updatedAt || config.updatedAt
    };
    if (editorial) Object.assign(articleNode, editorialSchemaProperties(editorial));
    if (Array.isArray(page.sourceKeys) && page.sourceKeys.length) {
      articleNode.citation = officialSourceCitations(page.sourceKeys);
    }
    graph.push(articleNode);
  }

  if (page.type === "program" || page.type === "service" || page.schemaType === "Service" || page.schemaType === "GovernmentService") {
    const serviceNode = serviceSchema({
      type: page.schemaType === "GovernmentService" ? "GovernmentService" : "Service",
      url: metadata.canonicalUrl,
      name: page.programName || page.h1,
      description: metadata.description,
      serviceType: page.category
    });
    if (isEditorialProgram(page)) {
      serviceNode.audience = (page.audience || []).slice(0, 4).map((item) => ({
        "@type": "Audience",
        audienceType: item
      }));
      serviceNode.potentialAction = {
        "@type": "CommunicateAction",
        name: "Trimite date pentru verificarea eligibilitatii",
        target: `${SITE}/contact`
      };
    }
    graph.push(serviceNode);
  }

  if (page.type === "tools") {
    graph.push(webApplicationSchema({
      url: metadata.canonicalUrl,
      name: "Instrumente fonduri europene",
      description: metadata.description,
      applicationCategory: "FinanceApplication"
    }));
  }

  if (page.slug === "portofoliu") {
    graph.push({
      "@type": "CreativeWorkSeries",
      "@id": `${canonical(page)}#portfolio-series`,
      "name": "Portofoliu FABER - studii de caz anonimizate",
      "description": publicText(metadata.description),
      "publisher": { "@id": `${SITE}/#organization` },
      "inLanguage": "ro-RO"
    });
  }

  return jsonLdGraph(graph);
}

function renderChecklist(title, items) {
  return `<section class="mini-card"><h3>${esc(title)}</h3><ul>${li(items)}</ul></section>`;
}

function renderSimpleTable(rows) {
  if (!Array.isArray(rows) || !rows.length) return "";
  return `<div class="table-wrap">
    <table class="program-table">
    <tbody>
      ${rows.map((row) => `<tr><th>${esc(row[0])}</th><td>${esc(row[1])}</td></tr>`).join("\n")}
    </tbody>
  </table>
  </div>`;
}

function renderContentSections(sections) {
  if (!Array.isArray(sections) || !sections.length) return "";
  return sections.map((section) => {
    const title = section.title ? `<h2>${esc(section.title)}</h2>` : "";
    const body = Array.isArray(section.paragraphs)
      ? section.paragraphs.map((paragraph) => `<p>${esc(paragraph)}</p>`).join("\n")
      : (section.body ? `<p>${esc(section.body)}</p>` : "");
    const table = renderSimpleTable(section.tableRows);
    const list = Array.isArray(section.items) && section.items.length ? `<ul>${li(section.items)}</ul>` : "";
    const linksHtml = Array.isArray(section.links) && section.links.length
      ? `<div class="related-links">${section.links.map((link) => `<a href="${cleanUrl(link.href)}">${esc(link.label || labelForHref(link.href))}</a>`).join("\n")}</div>`
      : "";
    return `${title}
      ${body}
      ${table}
      ${list}
      ${linksHtml}`;
  }).join("\n");
}

function renderDr12AfirContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <p class="intro">Ce finan&#539;eaz&#259; DR12 AFIR? DR12 AFIR sprijin&#259; investi&#539;iile &#238;n fermele tinerilor fermieri, astfel &#238;nc&#226;t exploata&#539;iile s&#259; poat&#259; cump&#259;ra utilaje, echipamente, dot&#259;ri sau s&#259; preg&#259;teasc&#259; moderniz&#259;ri legate direct de activitatea agricol&#259;. Pagina este scris&#259; pentru o prim&#259; orientare, &#238;n limbaj practic, nu ca &#238;nlocuitor pentru ghidul oficial. Pragurile, documentele, calendarul &#537;i condi&#539;iile finale trebuie verificate &#238;ntotdeauna &#238;n forma activ&#259; publicat&#259; de AFIR, inclusiv anexele &#537;i eventualele clarific&#259;ri ale sesiunii.</p>

      <section aria-labelledby="dr12-finantare-intensitate">
        <h2 id="dr12-finantare-intensitate">Finan&#539;are &#537;i intensitate</h2>
        <p>Finan&#539;area trebuie privit&#259; ca parte dintr-un plan de ferm&#259;, nu ca o list&#259; de achizi&#539;ii. Grantul poate reduce presiunea pe investi&#539;ie, dar beneficiarul trebuie s&#259; aib&#259; cofinan&#539;are, documente coerente &#537;i capacitate de implementare.</p>
        <ul>
          <li><strong>Grant orientativ:</strong> forma consultativ&#259; analizat&#259; men&#539;ioneaz&#259; p&#226;n&#259; la 200.000 euro/proiect; valoarea final&#259; se confirm&#259; &#238;n ghidul activ.</li>
          <li><strong>Intensitate:</strong> sprijinul poate ajunge orientativ la 80% pentru tineri fermieri &#537;i la 65% pentru alte categorii eligibile, dac&#259; apelul activ p&#259;streaz&#259; aceste condi&#539;ii.</li>
          <li><strong>Partea proprie:</strong> cofinan&#539;area, TVA-ul, diferen&#539;ele de pre&#539; &#537;i cheltuielile neeligibile trebuie calculate separat de grant.</li>
          <li><strong>Investi&#539;ie propor&#539;ional&#259;:</strong> utilajele, dot&#259;rile sau construc&#539;iile trebuie s&#259; fie potrivite cu suprafa&#539;a, efectivele, fluxul de lucru &#537;i obiectivul exploata&#539;iei.</li>
          <li><strong>Reguli finale:</strong> contractarea, cererile de plat&#259;, rambursarea &#537;i monitorizarea se fac dup&#259; regulile AFIR publicate pentru sesiunea deschis&#259;.</li>
        </ul>
        <p>&#206;n practic&#259;, t&#226;n&#259;rul fermier trebuie s&#259; compare valoarea dorit&#259; a investi&#539;iei cu produc&#539;ia real&#259;, utilajele existente &#537;i veniturile fermei. O achizi&#539;ie util&#259; pentru o ferm&#259; mare poate fi greu de justificat pentru o exploata&#539;ie aflat&#259; la &#238;nceput. De aceea, bugetul trebuie s&#259; explice nu doar ce se cump&#259;r&#259;, ci &#537;i de ce acea achizi&#539;ie este necesar&#259; acum, cum va fi folosit&#259; &#537;i ce rezultate poate sus&#539;ine dup&#259; implementare.</p>
      </section>

      <section aria-labelledby="dr12-solicitanti-eligibili">
        <h2 id="dr12-solicitanti-eligibili">Solicitan&#539;i eligibili</h2>
        <p>DR12 se adreseaz&#259; fermierilor tineri care pot demonstra c&#259; au un rol real &#238;n exploata&#539;ie &#537;i c&#259; investi&#539;ia propus&#259; ajut&#259; activitatea agricol&#259;. Verificarea porne&#537;te de la solicitant, apoi continu&#259; cu ferma, documentele &#537;i bugetul.</p>
        <ul>
          <li>solicitantul trebuie s&#259; se &#238;ncadreze &#238;n categoria de t&#226;n&#259;r fermier la data stabilit&#259; de ghid;</li>
          <li>forma juridic&#259;, controlul asupra exploata&#539;iei &#537;i istoricul instal&#259;rii trebuie s&#259; poat&#259; fi dovedite;</li>
          <li>exploata&#539;ia poate fi vegetal&#259;, zootehnic&#259; sau mixt&#259;, dac&#259; activitatea este documentat&#259; &#537;i legat&#259; de investi&#539;ie;</li>
          <li>terenurile, animalele, spa&#539;iile sau cl&#259;dirile trebuie s&#259; aib&#259; documente valabile pe perioada cerut&#259;;</li>
          <li>solicitantul trebuie s&#259; poat&#259; sus&#539;ine partea proprie &#537;i s&#259; respecte obliga&#539;iile de implementare &#537;i monitorizare;</li>
          <li>investi&#539;ia trebuie s&#259; aib&#259; o leg&#259;tur&#259; clar&#259; cu activitatea agricol&#259;, nu doar cu o inten&#539;ie general&#259; de dezvoltare.</li>
        </ul>
        <p>Dac&#259; ferma include terenuri arendate, animale &#238;nregistrate, spa&#539;ii &#238;nchiriate sau activit&#259;&#539;i derulate prin mai multe documente, toate trebuie citite &#238;mpreun&#259;. Un dosar solid arat&#259; continuitate: cine lucreaz&#259; ferma, ce produce, unde se face investi&#539;ia, ce documente sus&#539;in activitatea &#537;i cum r&#259;m&#226;n valabile obliga&#539;iile pe perioada cerut&#259; de program. Aceast&#259; verificare este important&#259; mai ales pentru fermele tinere, unde istoricul poate fi scurt &#537;i fiecare dovad&#259; conteaz&#259;.</p>
      </section>

      <section aria-labelledby="dr12-pasi-verificare">
        <h2 id="dr12-pasi-verificare">Pa&#537;i de verificare</h2>
        <p>O verificare bun&#259; reduce riscul de clarific&#259;ri, respingere sau buget imposibil de sus&#539;inut. Ordinea de mai jos ajut&#259; tinerii fermieri s&#259; decid&#259; dac&#259; proiectul merit&#259; preg&#259;tit pentru DR12.</p>
        <ol>
          <li><strong>Solicitantul:</strong> verific&#259; forma juridic&#259;, calitatea de fermier, controlul asupra exploata&#539;iei &#537;i eventualele condi&#539;ii legate de instalare.</li>
          <li><strong>V&#226;rsta:</strong> confirm&#259; &#238;ncadrarea ca t&#226;n&#259;r fermier exact la momentul cerut de ghidul activ.</li>
          <li><strong>Suprafa&#539;a &#537;i efectivele:</strong> centralizeaz&#259; terenurile, culturile, animalele &#537;i documentele care sus&#539;in dimensiunea economic&#259;.</li>
          <li><strong>Documentele APIA/ANSVSA:</strong> preg&#259;te&#537;te adeverin&#539;e, extrase, registre, autoriza&#539;ii sau dovezi echivalente, dup&#259; specificul fermei.</li>
          <li><strong>Dreptul de folosin&#539;&#259;:</strong> verific&#259; proprietatea, arenda, concesiunea, &#238;nchirierea sau alte documente pentru terenuri, spa&#539;ii &#537;i amplasamente.</li>
          <li><strong>Investi&#539;ia:</strong> compar&#259; fiecare utilaj, dotare sau lucrare cu activitatea fermei, nu doar cu bugetul disponibil.</li>
          <li><strong>Cofinan&#539;area:</strong> separ&#259; grantul de contribu&#539;ia proprie, TVA, costuri neeligibile, diferen&#539;e de pre&#539; &#537;i rezerve pentru &#238;nt&#226;rzieri.</li>
          <li><strong>Calendarul:</strong> confirm&#259; perioada de depunere, implementare, plat&#259; &#537;i monitorizare &#238;nainte de a angaja cheltuieli.</li>
        </ol>
        <p>La finalul verific&#259;rii, proiectul ar trebui s&#259; poat&#259; fi explicat &#238;n c&#226;teva propozi&#539;ii simple: cine aplic&#259;, ce ferm&#259; exist&#259;, ce problem&#259; rezolv&#259; investi&#539;ia, ce costuri r&#259;m&#226;n la beneficiar &#537;i ce documente dovedesc fiecare afirma&#539;ie. Dac&#259; r&#259;spunsurile sunt neclare, este mai sigur s&#259; ajustezi proiectul &#238;nainte de depunere dec&#226;t s&#259; r&#259;spunzi gr&#259;bit la clarific&#259;ri.</p>
      </section>

      <section aria-labelledby="dr12-sfaturi-succes">
        <h2 id="dr12-sfaturi-succes">Sfaturi pentru succes</h2>
        <p>Cele mai multe probleme apar atunci c&#226;nd proiectul pare bun pe h&#226;rtie, dar documentele nu sus&#539;in aceea&#537;i poveste. Preg&#259;tirea trebuie s&#259; arate c&#259; ferma exist&#259;, investi&#539;ia este necesar&#259;, iar bugetul poate fi dus p&#226;n&#259; la cap&#259;t.</p>
        <ul>
          <li><strong>Fragmentarea exploata&#539;iei:</strong> evit&#259; &#238;mp&#259;r&#539;iri artificiale ale terenurilor, efectivelor sau activit&#259;&#539;ilor doar pentru a intra &#238;n program. Preg&#259;te&#537;te documente care arat&#259; traseul real al fermei.</li>
          <li><strong>Buget nerealist:</strong> cere oferte clare, verific&#259; pre&#539;urile, explic&#259; de ce sunt necesare achizi&#539;iile &#537;i p&#259;streaz&#259; o rezerv&#259; pentru TVA, diferen&#539;e de curs sau costuri neeligibile.</li>
          <li><strong>Documente expirate:</strong> verific&#259; din timp valabilitatea contractelor de folosin&#539;&#259;, adeverin&#539;elor APIA, documentelor ANSVSA, certificatelor fiscale &#537;i actelor societ&#259;&#539;ii.</li>
          <li><strong>Active supradimensionate:</strong> un utilaj prea mare pentru suprafa&#539;a lucrat&#259; sau pentru efectivele existente poate ridica &#238;ntreb&#259;ri la evaluare. Justificarea tehnic&#259; trebuie scris&#259; pe date concrete.</li>
          <li><strong>Cofinan&#539;are incert&#259;:</strong> stabile&#537;te sursa banilor pentru partea proprie &#238;nainte de depunere. Include scenarii pentru ramburs&#259;ri &#238;nt&#226;rziate &#537;i cheltuieli respinse.</li>
        </ul>
        <p>Pentru o analiz&#259; realist&#259;, preg&#259;te&#537;te date despre solicitant, v&#226;rst&#259;, localitate, suprafe&#539;e, efective, documente APIA/ANSVSA, investi&#539;ia dorit&#259;, ofertele disponibile &#537;i sursa cofinan&#539;&#259;rii.</p>
      </section>

${officialSourcesHtml}
      <section aria-labelledby="dr12-faq-title">
        <h2 id="dr12-faq-title">&#206;ntreb&#259;ri frecvente</h2>
        ${faqHtml}
      </section>`;
}

function renderPocidif21Content(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <p class="intro">${esc(page.quickAnswer)}</p>
      <p>Programul nu este g&#226;ndit pentru digitalizare de rutin&#259;, website-uri simple sau cump&#259;r&#259;ri IT f&#259;r&#259; leg&#259;tur&#259; cu un produs nou. Un proiect potrivit explic&#259; problema rezolvat&#259;, utilizatorii viza&#539;i, tehnologia folosit&#259;, noutatea fa&#539;&#259; de solu&#539;iile existente, echipa care poate livra &#537;i modul &#238;n care bugetul duce la un rezultat comercial verificabil. Dac&#259; aceste elemente sunt clare, finan&#539;area poate accelera dezvoltarea, validarea, lansarea &#537;i scalarea unui serviciu digital cu valoare real&#259; pentru clien&#539;i.</p>

      <section aria-labelledby="pocidif-criterii-title">
        <h2 id="pocidif-criterii-title">Criterii de eligibilitate</h2>
        <p>Eligibilitatea se verific&#259; &#238;nainte de arhitectur&#259;, buget sau oferte. PoCIDIF 2.1 este relevant c&#226;nd solicitantul, activitatea TIC &#537;i solu&#539;ia propus&#259; formeaz&#259; un proiect coerent, nu doar o inten&#539;ie general&#259; de modernizare.</p>
        <ul>
          <li><strong>Statut IMM:</strong> solicitantul trebuie s&#259; se &#238;ncadreze ca IMM conform regulilor apelului, cu documente financiare &#537;i juridice care sus&#539;in aceast&#259; &#238;ncadrare.</li>
          <li><strong>Coduri CAEN TIC:</strong> codurile autorizate trebuie s&#259; fie compatibile cu activitatea finan&#539;at&#259; &#537;i cu veniturile sau proiectele dezvoltate de firm&#259;.</li>
          <li><strong>Inova&#539;ie:</strong> solu&#539;ia trebuie s&#259; arate ce aduce nou pentru clien&#539;i, proces, pia&#539;&#259; sau tehnologie, nu doar faptul c&#259; este software.</li>
          <li><strong>Produs propriu:</strong> proiectul trebuie s&#259; aib&#259; un rezultat digital identificabil: serviciu, aplica&#539;ie, platform&#259; sau produs cu func&#539;ionalit&#259;&#539;i descrise clar.</li>
          <li><strong>Capacitate de implementare:</strong> echipa, furnizorii, calendarul, proprietatea asupra solu&#539;iei &#537;i cofinan&#539;area trebuie s&#259; fie credibile pentru dimensiunea grantului.</li>
        </ul>
        <p>Un test util este s&#259; po&#539;i descrie proiectul &#238;ntr-o propozi&#539;ie concret&#259;: cine folose&#537;te solu&#539;ia, ce problem&#259; rezolv&#259;, ce component&#259; tehnic&#259; se dezvolt&#259; &#537;i de ce produsul nu poate fi redus la o simpl&#259; achizi&#539;ie de licen&#539;e sau echipamente. Dac&#259; r&#259;spunsul r&#259;m&#226;ne vag, descrierea tehnic&#259; trebuie rescris&#259; &#238;nainte de depunere.</p>
      </section>

      <section aria-labelledby="pocidif-valoare-title">
        <h2 id="pocidif-valoare-title">Valoarea &#537;i intensitatea finan&#539;&#259;rii</h2>
        <p>Ghidul aprobat stabile&#537;te minimum 200.000 euro, maximum 1.500.000 euro pentru solu&#539;ii software &#537;i maximum 3.000.000 euro pentru produse hardware inovatoare. Intensitatea se stabile&#537;te separat dup&#259; tipul ajutorului, dimensiunea firmei &#537;i regiune.</p>
        <div class="table-wrap">
          <svg role="img" aria-labelledby="pocidif-grant-svg-title pocidif-grant-svg-desc" viewBox="0 0 920 250" width="100%" height="250">
            <title id="pocidif-grant-svg-title">Interval de grant &#537;i intensit&#259;&#539;i PoCIDIF 2.1</title>
            <desc id="pocidif-grant-svg-desc">Grafic cu finan&#539;are aprobat&#259; &#238;ntre 200.000 &#537;i 3.000.000 euro &#537;i rate diferen&#539;iate dup&#259; tipul ajutorului.</desc>
            <rect x="52" y="62" width="560" height="30" rx="15" fill="#f8f9fb"></rect>
            <rect x="142" y="62" width="390" height="30" rx="15" fill="#b84716"></rect>
            <line x1="142" y1="48" x2="142" y2="112" stroke="#1a2540" stroke-width="2"></line>
            <line x1="532" y1="48" x2="532" y2="112" stroke="#1a2540" stroke-width="2"></line>
            <text x="52" y="38" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="18" font-weight="700">Grant aprobat</text>
            <text x="142" y="140" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="16" text-anchor="middle">200.000 &#8364;</text>
            <text x="532" y="140" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="16" text-anchor="middle">3.000.000 &#8364;</text>
            <rect x="650" y="42" width="220" height="72" rx="16" fill="#fff7ed" stroke="#b84716" stroke-width="2"></rect>
            <text x="760" y="72" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="16" font-weight="700" text-anchor="middle">Ajutor regional</text>
            <text x="760" y="102" fill="#b84716" font-family="Inter, Arial, sans-serif" font-size="22" font-weight="800" text-anchor="middle">rate diferen&#539;iate</text>
            <rect x="650" y="136" width="220" height="72" rx="16" fill="#f8f9fb" stroke="#1a2540" stroke-width="2"></rect>
            <text x="760" y="166" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="16" font-weight="700" text-anchor="middle">Minimis</text>
            <text x="760" y="196" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="30" font-weight="800" text-anchor="middle">p&#226;n&#259; la 100%</text>
            <text x="52" y="205" fill="#334155" font-family="Inter, Arial, sans-serif" font-size="15">Bugetul se verific&#259; pe tipuri de ajutor, dimensiunea firmei, regiune &#537;i categoria rezultatului.</text>
          </svg>
        </div>
        <p>Bugetul trebuie construit pe activit&#259;&#539;i, nu pe dorin&#539;e de achizi&#539;ie. Separ&#259; dezvoltarea, testarea, infrastructura, licen&#539;ele, serviciile, partea proprie, TVA-ul &#537;i costurile neeligibile. Pentru fiecare linie trebuie s&#259; existe o justificare: ce rezultat produce, de ce este necesar&#259; pentru produs &#537;i cum se &#238;ncadreaz&#259; &#238;n tipul de ajutor permis.</p>
      </section>

      <section aria-labelledby="pocidif-activitati-title">
        <h2 id="pocidif-activitati-title">Activit&#259;&#539;i eligibile</h2>
        <p>Activit&#259;&#539;ile eligibile trebuie legate direct de dezvoltarea serviciului, aplica&#539;iei sau produsului digital. O list&#259; bun&#259; arat&#259; traseul de la cerin&#539;e la versiune testat&#259;, lansare &#537;i exploatare comercial&#259;.</p>
        <ul>
          <li>analiz&#259; de produs, definirea cerin&#539;elor, arhitectur&#259; tehnic&#259; &#537;i proiectare func&#539;ional&#259;;</li>
          <li>dezvoltare software, integrarea modulelor, automatizarea fluxurilor &#537;i construirea componentelor digitale proprii;</li>
          <li>testare, validare, securizare, documentare tehnic&#259; &#537;i preg&#259;tirea pentru lansare;</li>
          <li>infrastructur&#259;, servicii cloud, licen&#539;e sau echipamente necesare produsului, dac&#259; au leg&#259;tur&#259; direct&#259; cu proiectul;</li>
          <li>activit&#259;&#539;i de validare comercial&#259;, pilotare, demonstrare sau intrare pe pia&#539;&#259;, unde ghidul le permite;</li>
          <li>servicii de consultan&#539;&#259;, management de proiect sau documenta&#539;ii, &#238;n limitele &#537;i condi&#539;iile apelului.</li>
        </ul>
        <p>Diferen&#539;a dintre eligibil &#537;i riscant st&#259; &#238;n leg&#259;tura cu produsul. Un server, o licen&#539;&#259; sau un serviciu extern pot fi justificate doar dac&#259; sus&#539;in direct dezvoltarea &#537;i operarea solu&#539;iei propuse. Dac&#259; o cheltuial&#259; poate fi folosit&#259; la fel de bine pentru orice activitate administrativ&#259;, trebuie explicat&#259; mai atent sau eliminat&#259;.</p>
      </section>

      <section aria-labelledby="pocidif-pasi-title">
        <h2 id="pocidif-pasi-title">Pa&#537;i de preg&#259;tire</h2>
        <ol>
          <li><strong>Verific&#259; solicitantul:</strong> confirm&#259; statutul IMM, codurile CAEN, situa&#539;iile financiare, istoricul firmei &#537;i eventualele ajutoare primite.</li>
          <li><strong>Define&#537;te produsul:</strong> descrie utilizatorii, problema rezolvat&#259;, func&#539;ionalit&#259;&#539;ile, noutatea &#537;i rezultatul care va fi livrat.</li>
          <li><strong>Scrie arhitectura:</strong> clarific&#259; modulele, fluxurile de date, integr&#259;rile, securitatea, infrastructura &#537;i rolurile echipei.</li>
          <li><strong>Construie&#537;te bugetul:</strong> &#238;mparte costurile pe activit&#259;&#539;i, categorii de ajutor, cofinan&#539;are, TVA, costuri neeligibile &#537;i rezerve.</li>
          <li><strong>Preg&#259;te&#537;te dovezile:</strong> str&#226;nge oferte, CV-uri, documente de proprietate intelectual&#259;, descrieri tehnice, date de pia&#539;&#259; &#537;i documente financiare.</li>
          <li><strong>Verific&#259; sursa oficial&#259;:</strong> compar&#259; proiectul cu ghidul activ, anexele, grila de evaluare &#537;i clarific&#259;rile publicate &#238;nainte de depunere.</li>
        </ol>
        <p>O preg&#259;tire bun&#259; las&#259; c&#226;t mai pu&#539;ine presupuneri deschise. Antreprenorul trebuie s&#259; poat&#259; ar&#259;ta ce se dezvolt&#259; &#238;n fiecare etap&#259;, cine livreaz&#259;, ce se testeaz&#259;, c&#226;t cost&#259; &#537;i cum se m&#259;soar&#259; rezultatul. Aceast&#259; claritate ajut&#259; at&#226;t la scrierea cererii, c&#226;t &#537;i la implementare.</p>
      </section>

      <section aria-labelledby="pocidif-riscuri-title">
        <h2 id="pocidif-riscuri-title">Riscuri comune</h2>
        <p>Riscurile apar mai ales c&#226;nd proiectul este descris comercial, dar nu este sus&#539;inut tehnic &#537;i financiar. Un grant mare cere o documenta&#539;ie propor&#539;ional&#259;: produs clar, echip&#259; credibil&#259;, buget argumentat &#537;i calendar realist.</p>
        <ul>
          <li><strong>Inova&#539;ie descris&#259; vag:</strong> expresii precum digitalizare, platform&#259; modern&#259; sau solu&#539;ie integrat&#259; nu sunt suficiente f&#259;r&#259; func&#539;ionalit&#259;&#539;i, utilizatori &#537;i diferen&#539;iere.</li>
          <li><strong>Cod CAEN necorelat:</strong> activitatea firmei, codurile autorizate &#537;i produsul propus trebuie s&#259; spun&#259; aceea&#537;i poveste.</li>
          <li><strong>Buget generic:</strong> costurile mari pentru dezvoltare, cloud, licen&#539;e sau echipamente trebuie legate de module, rezultate &#537;i livrabile.</li>
          <li><strong>Drepturi neclare:</strong> proprietatea asupra codului, licen&#539;elor, datelor, m&#259;rcii sau componentelor dezvoltate trebuie clarificat&#259; &#238;nainte de depunere.</li>
          <li><strong>Cofinan&#539;are incert&#259;:</strong> partea proprie, TVA-ul, cheltuielile neeligibile &#537;i eventualele decalaje de rambursare trebuie acoperite realist.</li>
          <li><strong>Calendar optimist:</strong> dezvoltarea, testarea, achizi&#539;iile, contractarea &#537;i lansarea trebuie planificate cu rezerve pentru clarific&#259;ri &#537;i aprob&#259;ri.</li>
        </ul>
        <p>Consultan&#539;a ajut&#259; prin verificarea cadrului de finan&#539;are, traducerea ideii tehnice &#238;ntr-o logic&#259; de proiect, structurarea bugetului &#537;i identificarea punctelor care pot genera clarific&#259;ri. Nu poate garanta aprobarea, dar poate reduce riscul ca un proiect bun s&#259; fie pierdut prin documente neclare.</p>
      </section>

${officialSourcesHtml}
      <section aria-labelledby="pocidif-faq-title">
        <h2 id="pocidif-faq-title">&#206;ntreb&#259;ri frecvente</h2>
        ${faqHtml}
      </section>`;
}

function renderFondModernizareRegenerabilaContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <p class="intro">Fondul pentru Modernizare 2026 pentru energie regenerabil&#259; vizeaz&#259; cre&#537;terea capacit&#259;&#539;ii de produc&#539;ie a energiei electrice din surse regenerabile. Pentru investitori, pagina trebuie citit&#259; ca un filtru de preg&#259;tire: verifici solicitantul, codul CAEN, amplasamentul, racordarea, solu&#539;ia tehnic&#259; &#537;i cofinan&#539;area care pot sus&#539;ine un proiect bancabil. Ghidul oficial, anexele &#537;i calendarul apelului se public&#259; de Ministerul Energiei, iar regulile finale trebuie confirmate &#238;n documentele active.</p>

      <section aria-labelledby="fm-eligibilitate-title">
        <h2 id="fm-eligibilitate-title">Eligibilitate &#537;i condi&#539;ii</h2>
        <p>Eligibilitatea porne&#537;te de la solicitant, activitatea economic&#259; &#537;i locul unde se construie&#537;te capacitatea nou&#259;. Un proiect poate avea tehnologie bun&#259;, dar s&#259; devin&#259; riscant dac&#259; terenul, racordarea sau dreptul de folosin&#539;&#259; nu sunt clare.</p>
        <ul>
          <li><strong>Tipul de solicitant:</strong> firma trebuie s&#259; se &#238;ncadreze &#238;n categoria de beneficiar permis&#259; de ghid, cu situa&#539;ii financiare, documente juridice &#537;i capacitate de implementare verificabile.</li>
          <li><strong>Cod CAEN:</strong> activitatea finan&#539;at&#259; trebuie corelat&#259; cu certificatul constatator, modelul de afaceri, veniturile estimate &#537;i modul de valorificare a energiei.</li>
          <li><strong>Amplasament:</strong> terenul sau acoperi&#537;ul trebuie s&#259; aib&#259; drept de folosin&#539;&#259; valabil, acces, posibilitate de autorizare, condi&#539;ii de mediu &#537;i o logic&#259; de racordare realist&#259;.</li>
          <li><strong>Capacitate nou&#259;:</strong> investi&#539;ia trebuie s&#259; adauge produc&#539;ie nou&#259; din surse regenerabile, nu s&#259; acopere doar &#238;nlocuiri sau cheltuieli de exploatare curent&#259;.</li>
          <li><strong>Stocare:</strong> bateriile sau alte solu&#539;ii de stocare se trateaz&#259; ca eligibile doar dac&#259; ghidul activ le permite expres &#537;i dac&#259; dimensionarea este justificat&#259; tehnic.</li>
        </ul>
      </section>

      <section aria-labelledby="fm-valoare-title">
        <h2 id="fm-valoare-title">Valoarea &#537;i intensitatea grantului</h2>
        <p>Valoarea grantului, intensitatea sprijinului, pragurile de capacitate, costurile standard &#537;i regula de selec&#539;ie se confirm&#259; &#238;n ghidul activ al Ministerului Energiei. Pentru decizia de investi&#539;ie conteaz&#259; mai mult bugetul total dec&#226;t procentul nerambursabil afi&#537;at.</p>
        <ul>
          <li>separ&#259; costurile eligibile de TVA, costuri neeligibile, avize, taxe, proiectare, diferen&#539;e de curs &#537;i rezerve;</li>
          <li>calculeaz&#259; contribu&#539;ia proprie &#537;i sursa finan&#539;&#259;rii pentru perioadele dintre achizi&#539;ii, cereri de plat&#259; &#537;i rambursare;</li>
          <li>verific&#259; dac&#259; valoarea investi&#539;iei este propor&#539;ional&#259; cu puterea instalat&#259;, solu&#539;ia tehnic&#259;, racordarea &#537;i veniturile estimate;</li>
          <li>trateaz&#259; separat costurile pentru produc&#539;ie, racordare, monitorizare, proiectare, consultan&#539;&#259; &#537;i, unde este permis, stocare;</li>
          <li>nu porni achizi&#539;ii, comenzi sau lucr&#259;ri &#238;nainte de momentul permis de apel.</li>
        </ul>
      </section>

      <section aria-labelledby="fm-etape-title">
        <h2 id="fm-etape-title">Etapele proiectului</h2>
        <p>Un proiect regenerabil trebuie preg&#259;tit &#238;n ordinea real&#259; a investi&#539;iei: idee, studiu, avize, racordare, execu&#539;ie &#537;i punere &#238;n func&#539;iune. Dac&#259; sari direct la lista de echipamente, ri&#537;ti s&#259; bugetezi active care nu pot fi autorizate sau racordate la timp.</p>
        <div class="table-wrap">
          <svg role="img" aria-labelledby="fm-flow-title fm-flow-desc" viewBox="0 0 960 210" width="100%" height="210">
            <title id="fm-flow-title">Flux proiect Fondul pentru Modernizare energie regenerabil&#259;</title>
            <desc id="fm-flow-desc">Flux cu cinci etape: Idee, Studiu, Avize, Racordare, Execu&#539;ie &#537;i punere &#238;n func&#539;iune.</desc>
            <defs>
              <marker id="fm-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
                <path d="M0,0 L0,6 L9,3 z" fill="#b84716"></path>
              </marker>
            </defs>
            <g fill="#fff7ed" stroke="#b84716" stroke-width="2">
              <rect x="28" y="58" width="132" height="80" rx="12"></rect>
              <rect x="205" y="58" width="132" height="80" rx="12"></rect>
              <rect x="382" y="58" width="132" height="80" rx="12"></rect>
              <rect x="559" y="58" width="132" height="80" rx="12"></rect>
              <rect x="736" y="58" width="170" height="80" rx="12"></rect>
            </g>
            <g stroke="#b84716" stroke-width="3" marker-end="url(#fm-arrow)">
              <line x1="170" y1="98" x2="195" y2="98"></line>
              <line x1="347" y1="98" x2="372" y2="98"></line>
              <line x1="524" y1="98" x2="549" y2="98"></line>
              <line x1="701" y1="98" x2="726" y2="98"></line>
            </g>
            <g fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="17" font-weight="700" text-anchor="middle">
              <text x="94" y="104">Idee</text>
              <text x="271" y="104">Studiu</text>
              <text x="448" y="104">Avize</text>
              <text x="625" y="104">Racordare</text>
              <text x="821" y="93">Execu&#539;ie</text>
              <text x="821" y="116">PIF</text>
            </g>
            <text x="28" y="172" fill="#334155" font-family="Inter, Arial, sans-serif" font-size="15">Stocarea se include doar dac&#259; este permis&#259; de ghid &#537;i sus&#539;inut&#259; de solu&#539;ia tehnic&#259;.</text>
          </svg>
        </div>
        <ol>
          <li><strong>Studiu:</strong> verifici resursa, puterea instalat&#259;, produc&#539;ia estimat&#259;, solu&#539;ia de amplasare &#537;i scenariul de valorificare a energiei.</li>
          <li><strong>Avize:</strong> clarifici urbanismul, mediul, accesul, regimul terenului, acordurile necesare &#537;i eventualele limit&#259;ri locale.</li>
          <li><strong>Racordare:</strong> verifici solu&#539;ia de racordare, capacitatea re&#539;elei, termenele operatorului &#537;i costurile asociate.</li>
          <li><strong>Execu&#539;ie:</strong> planifici achizi&#539;iile, contractele, livrarea echipamentelor, lucr&#259;rile, testele &#537;i raportarea c&#259;tre finan&#539;ator.</li>
          <li><strong>Punere &#238;n func&#539;iune:</strong> preg&#259;te&#537;ti recep&#539;ia, probele, autoriz&#259;rile finale, m&#259;surarea produc&#539;iei &#537;i obliga&#539;iile de monitorizare.</li>
        </ol>
      </section>

      <section aria-labelledby="fm-cheltuieli-title">
        <h2 id="fm-cheltuieli-title">Cheltuieli sensibile</h2>
        <p>Cheltuielile sensibile sunt cele care pot bloca evaluarea dac&#259; nu au documente tehnice sau justificare economic&#259;. Pentru o prim&#259; analiz&#259;, preg&#259;te&#537;te cel pu&#539;in urm&#259;toarele piese:</p>
        <ul>
          <li>solu&#539;ie tehnic&#259; preliminar&#259;, inclusiv tehnologie, putere instalat&#259;, produc&#539;ie estimat&#259;, scheme &#537;i echipamente principale;</li>
          <li>certificat de urbanism, PUZ sau alte documente urbanistice, dac&#259; amplasamentul le cere;</li>
          <li>studii geotehnice, topografice, structurale sau de amplasament, mai ales pentru proiecte la sol sau acoperi&#537;uri cu risc structural;</li>
          <li>documente pentru teren, cl&#259;dire, drept de folosin&#539;&#259;, acces, servitu&#539;i &#537;i eventuale acorduri ale proprietarilor;</li>
          <li>documente de mediu, avize, acorduri sau analize necesare &#238;n func&#539;ie de localizare &#537;i tehnologie;</li>
          <li>oferta de racordare, studiu de solu&#539;ie sau coresponden&#539;&#259; cu operatorul de distribu&#539;ie/transport;</li>
          <li>oferte tehnice comparabile pentru echipamente, montaj, proiectare, monitorizare, mentenan&#539;&#259; &#537;i, dac&#259; ghidul permite, stocare.</li>
        </ul>
      </section>

      <section aria-labelledby="fm-sfaturi-title">
        <h2 id="fm-sfaturi-title">Sfaturi pentru succes</h2>
        <p>Riscurile tipice sunt amplasamentul nepotrivit, activele supradimensionate &#537;i cofinan&#539;area incert&#259;. Un teren cu regim juridic neclar, o putere instalat&#259; care nu poate fi racordat&#259; sau un buget construit f&#259;r&#259; rezerv&#259; poate transforma un proiect promi&#539;&#259;tor &#238;ntr-un dosar greu de aprobat &#537;i implementat.</p>
        <ul>
          <li>confirm&#259; amplasamentul &#238;nainte de dimensionarea final&#259; a parcului sau instala&#539;iei;</li>
          <li>dimensioneaz&#259; activele dup&#259; resurs&#259;, re&#539;ea, model de venit &#537;i termene, nu doar dup&#259; grantul maxim;</li>
          <li>preg&#259;te&#537;te cofinan&#539;area, garan&#539;iile, TVA-ul &#537;i rezervele de pre&#539; &#238;nainte de depunere;</li>
          <li>verific&#259; dac&#259; stocarea, monitorizarea, lucr&#259;rile conexe &#537;i costurile de racordare sunt permise explicit;</li>
          <li>p&#259;streaz&#259; o trasabilitate clar&#259; &#238;ntre ghid, solu&#539;ia tehnic&#259;, devize, oferte, contracte &#537;i cererile de plat&#259;.</li>
        </ul>
        <p>Consultan&#539;a poate ajuta prin ordonarea documentelor, identificarea riscurilor tehnice, verificarea bugetului, corelarea amplasamentului cu racordarea &#537;i preg&#259;tirea explica&#539;iilor pentru evaluare. Rolul ei nu este s&#259; promit&#259; aprobarea, ci s&#259; reduc&#259; zonele neclare &#238;nainte s&#259; apar&#259; costuri mari.</p>
      </section>

${officialSourcesHtml}
      <section aria-labelledby="fm-faq-title">
        <h2 id="fm-faq-title">&#206;ntreb&#259;ri frecvente</h2>
        ${faqHtml}
      </section>`;
}

function renderAfirAutoconsumAgroalimentarContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <section aria-labelledby="afir-raspuns-rapid">
        <h2 id="afir-raspuns-rapid">Răspuns rapid</h2>
        <p class="intro">${esc(page.quickAnswer)}</p>
        <p class="source-note"><strong>Status document:</strong> Ghidul Solicitantului – Schema ENERGIE, Versiunea 7, este ghidul aprobat prin Ordinul MADR nr. 180/09.06.2026 și aplicabil sesiunii deschise între 15 iunie și 14 august 2026. Nu este prezentat ca simplă versiune consultativă. Ghidul și anexele pot primi rectificări, astfel că înainte de depunere se verifică forma disponibilă pe pagina AFIR și eventualele clarificări ulterioare. <strong>Ultima verificare:</strong> <time datetime="2026-07-13">13 iulie 2026</time>.</p>
        <div class="table-wrap">
          <table class="program-table">
            <thead><tr><th>Reper din Ghidul V7</th><th>Condiție</th></tr></thead>
            <tbody>
              <tr><td>Tip investiție</td><td>capacitate nouă de producere a energiei electrice din sursă solară, cu sau fără stocare</td></tr>
              <tr><td>Autoconsum</td><td>minimum 70% din producția anuală a centralei finanțate</td></tr>
              <tr><td>Până la 1 MW inclusiv</td><td>100% din costurile eligibile, în limita a 650.000 euro/MW</td></tr>
              <tr><td>Peste 1 MW</td><td>100% din costurile eligibile, în limita a 550.000 euro/MW</td></tr>
              <tr><td>Plafon beneficiar</td><td>maximum 20 milioane euro, inclusiv pentru mai multe proiecte cumulate</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="afir-beneficiari">
        <h2 id="afir-beneficiari">Beneficiari: agricultură, industrie alimentară și OUAI/FOUAI</h2>
        <p>Ghidul V7 separă trei categorii de solicitanți. Prima include întreprinderile din sectorul agricol — microîntreprinderi, întreprinderi mici, mijlocii și mari, inclusiv PFA, II și IF — precum și cooperative agricole, societăți cooperative agricole și societăți agricole care dețin active fizice de producție și/sau procesare a produselor agroalimentare. A doua categorie cuprinde întreprinderile din industria alimentară, legal constituite și înregistrate la ONRC.</p>
        <p>A treia categorie este formată din organizațiile și federațiile de organizații din domeniul îmbunătățirilor funciare, <strong>OUAI/FOUAI</strong>, constituite conform Legii nr. 138/2004. Proiectele se depun individual. Un beneficiar poate depune mai multe proiecte numai pentru locuri de producție diferite, cu respectarea plafonului cumulat de 20 milioane euro; același proiect nu poate conține mai multe puncte de producție a energiei.</p>
        <p>Pentru activitățile agricole de stocare sau păstrare, consumul este eligibil când aceste etape fac parte din fluxul activității agricole proprii. Consumul destinat numai stocării sau păstrării produselor agricole, fără activitatea agricolă proprie care generează acel flux, nu este eligibil.</p>
      </section>

      <section aria-labelledby="afir-caen">
        <h2 id="afir-caen">Codurile CAEN relevante</h2>
        <p>La depunere, întreprinderile din agricultură și industria alimentară trebuie să aibă în statut, ca activități principale sau secundare, activități din grupele eligibile. Energia produsă și autoconsumată trebuie legată exclusiv de aceste activități sau de activitatea eligibilă a OUAI/FOUAI.</p>
        <ul>
          <li><strong>CAEN 01</strong> — Agricultură, vânătoare și servicii anexe;</li>
          <li><strong>CAEN 10</strong> — Industria alimentară;</li>
          <li><strong>CAEN 11</strong> — Fabricarea băuturilor.</li>
        </ul>
        <p>La contractare, solicitantul trebuie să aibă înscrisă și activitatea de producere a energiei electrice din resurse regenerabile, clasa CAEN 3512, după caz. Ghidul menționează tranziția dintre CAEN Rev.2 și Rev.3 și acceptarea codului 3511 în perioada de tranziție până la 25 septembrie 2026, dacă reflectă activitatea reală și scopul investiției. Încadrarea nu se verifică doar după numărul codului: activitatea finanțată, locul de consum și documentele solicitantului trebuie să fie coerente.</p>
      </section>

      <section aria-labelledby="afir-autoconsum-dimensionare">
        <h2 id="afir-autoconsum-dimensionare">Autoconsum și dimensionare</h2>
        <p>Autoconsumul înseamnă energia produsă, livrată și utilizată de solicitant pentru activitățile eligibile. V7 impune ca aceasta să reprezinte minimum 70% din producția anuală a centralei finanțate. Procentul nu se estimează arbitrar: studiul de fezabilitate corelează capacitatea instalată, producția medie anuală și cantitatea de energie consumată.</p>
        <p>În monitorizare, ghidul urmărește producția înregistrată de contor sau SCADA, energia injectată în rețea și energia consumată din rețea. Dimensionarea trebuie să poată demonstra că surplusul net nu depășește limita compatibilă cu autoconsumul minim. Capacitatea operațională se determină prin puterea nominală a invertoarelor în curent alternativ; dacă puterea invertoarelor este mai mare decât cea a panourilor, la indicator și la ajutorul solicitat se folosește valoarea mai mică.</p>
        <p>Plafonul financiar nu este ținta tehnică. O instalație construită după valoarea maximă, fără profil de consum, sezonalitate și consumatori dovediți, poate rata atât eligibilitatea, cât și procentul de autoconsum declarat.</p>
      </section>

      <section aria-labelledby="afir-stocare">
        <h2 id="afir-stocare">Sistem fotovoltaic cu sau fără stocare</h2>
        <p>Schema finanțează numai capacități <strong>noi</strong> de producere a energiei electrice din sursă solară, sub sau peste 1 MW, cu sau fără stocare. Nu sunt eligibile înlocuirea unor capacități vechi, extinderea unei capacități existente care nu poate fi contorizată și monitorizată separat sau o investiție alcătuită numai din baterii.</p>
        <p>Dacă proiectul include stocare, minimum 75% din energia stocată trebuie să provină din instalația solară proprie. Capacitatea de stocare în baterii nu poate fi mai mare decât capacitatea totală de producere a centralei propuse. Pentru punctajul specific stocării, V7 cere o capacitate care poate stoca energia produsă la puterea nominală timp de cel puțin 12 minute; de exemplu, pentru 1 MW, reperul indicat este 0,2 MWh.</p>
      </section>

      <section aria-labelledby="afir-puncte">
        <h2 id="afir-puncte">Punct de consum și punct de producție</h2>
        <p><strong>Punctul de consum</strong> este locul și activitatea eligibilă în care energia produsă va fi utilizată. El trebuie legat de facturile istorice sau de documentele care susțin consumatorii viitori. <strong>Punctul de producție</strong> este amplasamentul centralei solare și al echipamentelor proiectului. Descrierea investiției trebuie să arate localizarea, puterea instalată, consumatorul, stocarea, dacă există, și modul de funcționare.</p>
        <p>Același proiect nu poate include mai multe puncte de producție a energiei. Dacă un beneficiar pregătește mai multe proiecte, acestea trebuie să privească locuri de producție diferite și să rămână împreună sub plafonul de 20 milioane euro. În toate cazurile, traseul dintre producție, măsurare și consum trebuie să fie clar și verificabil.</p>
      </section>

      <section aria-labelledby="afir-consum-istoric">
        <h2 id="afir-consum-istoric">Datele istorice de consum</h2>
        <p>Pentru un consumator activ care își menține nivelul de consum, studiul de fezabilitate trebuie să analizeze autoconsumul pe baza <strong>ultimelor 12 facturi de energie</strong> emise până la întocmirea studiului. Facturile folosite în analiză se încarcă în secțiunea „Alte documente” a cererii de finanțare. Unele facturi omise din motive independente de solicitant pot fi prezentate la solicitarea de informații suplimentare, dar aceasta nu trebuie tratată ca o regulă de amânare a documentării.</p>
        <p>Când activitatea sau consumatorii sunt noi, ori consumul existent urmează să crească, V7 permite o estimare detaliată susținută prin contracte de finanțare sau execuție, facturi și extrase pentru echipamente comandate, intabularea investiției, contracte de furnizare, memoriu cu lista echipamentelor, bilanț energetic sau alte dovezi. Estimarea trebuie să arate de unde apare consumul viitor, nu doar să repete puterea propusă de furnizor.</p>
      </section>

      <section aria-labelledby="afir-amplasament">
        <h2 id="afir-amplasament">Amplasamentul</h2>
        <p>Solicitantul trebuie să dovedească dreptul de folosință asupra terenului și/sau clădirii: proprietate, concesiune, superficie, administrare, închiriere, comodat sau alt drept acceptat. Dreptul trebuie să fie valabil cel puțin cinci ani de la data estimată a plății finale. Când solicitantul nu este proprietar, se prezintă și acordul proprietarului dacă acesta nu rezultă deja din contract.</p>
        <p>Dosarul include extrasul de carte funciară și planul de amplasament cu imobilele și poziția exactă a investiției. Planul nu trebuie să aibă viza OCPI, dar trebuie asumat de proiectant și solicitant. Ghidul interzice modificarea amplasamentului proiectului. Pentru imobile ipotecate este necesar acordul creditorului la contractare, iar pentru terenurile agricole din extravilan se aplică regulile privind scoaterea din circuitul agricol până la etapa stabilită de V7.</p>
      </section>

      <section aria-labelledby="afir-racordare-off-grid">
        <h2 id="afir-racordare-off-grid">Racordare versus off-grid</h2>
        <p>V7 permite descrierea unei soluții conectate la rețea sau a funcționării <strong>off-grid</strong>. Varianta aleasă trebuie justificată prin studiul de fezabilitate, schema electrică, profilul de consum și capacitatea de stocare, dacă este cazul. Pentru proiectele on-grid, certificatul de racordare confirmă îndeplinirea condițiilor din avizul tehnic și permite punerea sub tensiune a instalației.</p>
        <p>Poziția echipamentelor contează în buget: un transformator aflat în instalația de utilizare, care rămâne în proprietatea beneficiarului, poate fi eligibil; dacă se află în instalația de racordare și se cedează operatorului de distribuție, costul nu este eligibil. Cheltuielile cu branșamentul sunt enumerate de ghid între costurile neeligibile. Pentru off-grid, proiectul trebuie să demonstreze că soluția poate alimenta consumatorii declarați și poate măsura separat producția și consumul.</p>
      </section>

      <section aria-labelledby="afir-studiu-fezabilitate">
        <h2 id="afir-studiu-fezabilitate">Studiul de fezabilitate</h2>
        <p>Studiul de fezabilitate se elaborează conform HG nr. 907/2016, se aprobă prin hotărârea organului competent al solicitantului și nu poate fi mai vechi de doi ani. Din echipa de elaborare trebuie să facă parte personal autorizat ANRE în proiectarea instalațiilor electrice. Studiul compară soluțiile alternative și justifică alegerea eficientă din punctul de vedere al costurilor.</p>
        <p>Documentul trebuie să lege într-o singură analiză: activitatea eligibilă, consumul istoric sau viitor, capacitatea solară, producția estimată, autoconsumul, stocarea, racordarea ori funcționarea off-grid, amplasamentul, indicatorii, bugetul și analiza cost-beneficiu. Lucrările pregătitoare, inclusiv studiul și avizele, nu sunt considerate demararea lucrărilor, dar costurile lor sunt tratate conform listelor de eligibilitate ale V7.</p>
      </section>

      <section aria-labelledby="afir-actiuni-cheltuieli">
        <h2 id="afir-actiuni-cheltuieli">Acțiuni și cheltuieli eligibile</h2>
        <p>Sunt eligibile achiziția instalațiilor și echipamentelor pentru capacități solare noi, cu sau fără stocare, construcțiile care fac obiectul investiției și montajul plus punerea în funcțiune. Lista indicativă include amenajarea terenului, protecția mediului, utilitățile obiectivului, dirigenția de șantier, construcții și instalații, utilaje și echipamente cu sau fără montaj, active necorporale, organizarea de șantier, cheltuieli diverse și neprevăzute, probe, teste și pregătirea personalului de exploatare, în limitele bugetului și ale ghidului.</p>
        <p>Cheltuielile trebuie să fie indispensabile proiectului, incluse și defalcate în cererea de finanțare, efectuate după depunere și în perioada contractului. Activele corporale trebuie să fie noi. Sunt neeligibile, între altele, TVA-ul, terenurile, leasingul, imobilele existente, mijloacele de transport, echipamentele second-hand, operarea și mentenanța, managementul proiectului, publicitatea și auditul financiar, branșamentul, avizele, autorizațiile și studiul de fezabilitate. Lista exactă și încadrarea fiecărui cost se verifică înainte de bugetare.</p>
      </section>

      <section aria-labelledby="afir-documente">
        <h2 id="afir-documente">Documentele obligatorii</h2>
        <p>Dosarul se depune online și trebuie să conțină documente complete, lizibile, valabile și semnate electronic. Setul de bază prevăzut de V7 include:</p>
        <ul>
          <li>cererea de finanțare și declarația unică;</li>
          <li>studiul de fezabilitate, analiza autoconsumului și ultimele 12 facturi sau justificarea consumatorilor viitori;</li>
          <li>bugetul solicitantului și hotărârea AGA/CA ori documentul echivalent pentru aprobarea proiectului și a costurilor neacoperite de ajutor;</li>
          <li>certificatul constatator ONRC sau adeverința din Registrul Național al Organizațiilor de Îmbunătățiri Funciare pentru OUAI;</li>
          <li>actul constitutiv, actul de înființare, statutul sau documentele echivalente;</li>
          <li>extrasul de carte funciară, dreptul de folosință, acordul proprietarului și planul de amplasament;</li>
          <li>actul de identitate al reprezentantului, documentele de insolvență și, dacă există datorii, graficul de eșalonare;</li>
          <li>avizele, documentele de mediu, racordare și orice alte dovezi cerute de investiție și de grila de verificare.</li>
        </ul>
        <p>O neconcordanță între facturi, studiu, CAEN, amplasament, buget și cerere poate duce la neconformitate sau neeligibilitate chiar dacă fiecare document există separat.</p>
      </section>

      <section aria-labelledby="afir-selectie">
        <h2 id="afir-selectie">Selecție</h2>
        <p>Schema folosește o procedură de ofertare concurențială. Evaluarea administrativă și de eligibilitate este urmată de evaluarea tehnico-economică. Proiectele primesc între 0 și 100 de puncte și sunt ordonate descrescător până la epuizarea bugetului. La egalitate, departajarea se face după valoarea eligibilă a proiectului, în euro, în ordine crescătoare.</p>
        <ul>
          <li><strong>Ajutorul solicitat pe MW</strong> — până la 70 de puncte; valoarea cea mai mică primește punctajul maxim, iar valorile intermediare sunt calculate raportat la populația eligibilă;</li>
          <li><strong>Procentul de autoconsum</strong> — punctaj conform Anexei 3;</li>
          <li><strong>Capacitatea de stocare</strong> — punctaj dacă respectă pragul tehnic prevăzut;</li>
          <li><strong>Domeniul solicitantului</strong> — OUAI 10 puncte, CAEN 01 șapte puncte, CAEN 10 cinci puncte și CAEN 11 două puncte.</li>
        </ul>
        <p>A solicita automat plafonul maxim pe MW poate reduce punctajul. Reducerea ajutorului cerut trebuie însă susținută printr-un buget finanțabil și prin contribuția proprie necesară, nu doar printr-un calcul de scor.</p>
      </section>

      <section aria-labelledby="afir-supradimensionare">
        <h2 id="afir-supradimensionare">Riscul supradimensionării</h2>
        <p>Supradimensionarea apare când producția estimată este prea mare față de consumul justificat sau când consumatorii viitori nu sunt dovediți. Consecințele pot fi pierderea eligibilității pentru nerespectarea autoconsumului minim de 70%, reducerea costurilor acceptate, imposibilitatea respectării indicatorilor în monitorizare ori recuperarea ajutorului.</p>
        <p>Riscul se controlează prin cele 12 facturi, modelarea pe luni, estimarea producției, analiza sezonalității, verificarea activității CAEN, documentarea fiecărui consumator viitor și alegerea realistă a stocării. La ultima cerere de plată sau rambursare, consumatorul declarat trebuie să fie activ, iar echipamentele prevăzute ca viitori consumatori trebuie achiziționate și puse în funcțiune.</p>
      </section>

      <section aria-labelledby="afir-achizitii">
        <h2 id="afir-achizitii">Achiziții</h2>
        <p>Achizițiile beneficiarilor privați se derulează conform Îndrumarului metodologic aprobat prin Ordinul MADR nr. 142/2026 și anexat contractului. Procedurile trebuie să respecte transparența, tratamentul egal, nediscriminarea, utilizarea eficientă a fondurilor și evitarea conflictelor de interese. Nerespectarea regulilor poate transforma costul în cheltuială neeligibilă și poate atrage corecții sau recuperarea sprijinului.</p>
        <p>Primul angajament juridic obligatoriu de comandă ori începerea lucrărilor înainte de depunerea cererii poate încălca efectul stimulativ. Modificările contractelor se fac numai în condițiile îndrumarului și ale contractului de finanțare. Echipamentele pot fi înlocuite numai în situații justificate, cu soluții echivalente sau superioare, fără creșterea prețului; subcontractarea totală nu este permisă.</p>
      </section>

      <section aria-labelledby="afir-plati">
        <h2 id="afir-plati">Mecanisme de plată</h2>
        <p>V7 descrie trei trasee financiare care se folosesc conform contractului și graficului de eșalonare:</p>
        <ul>
          <li><strong>Prefinanțare:</strong> maximum 30% din ajutorul solicitat, condiționată de o garanție irevocabilă și necondiționată reprezentând 100% din prefinanțare; utilizarea se justifică prin documente;</li>
          <li><strong>Cerere de plată:</strong> AFIR virează sumele necesare pentru facturi și alte documente care atestă achiziția și recepția; cererea de rambursare aferentă se depune în maximum 10 zile lucrătoare de la încasare;</li>
          <li><strong>Rambursare:</strong> beneficiarul plătește cheltuielile eligibile și solicită ulterior rambursarea pe baza documentelor justificative și a raportului auditorului financiar independent.</li>
        </ul>
        <p>Ultima cerere de rambursare se depune după punerea în funcțiune și, pentru proiectele on-grid, conectarea la rețea. Ghidul limitează la cinci numărul total al cererilor de plată și rambursare, fără cererea de prefinanțare, și cere respectarea termenului maxim al schemei. Cheltuielile neeligibile, diferența până la costul total și contribuția proprie rămân în sarcina beneficiarului.</p>
      </section>

      <section aria-labelledby="afir-faq">
        <h2 id="afir-faq">FAQ</h2>
        ${faqHtml}
      </section>

${officialSourcesHtml}

      <section aria-labelledby="afir-resurse-corelate">
        <h2 id="afir-resurse-corelate">Fondul pentru Modernizare și finanțări fotovoltaice</h2>
        <p>Schema ENERGIE este finanțată prin Fondul pentru Modernizare și administrată de MADR prin AFIR. Pentru orientare între apelurile de energie consultă <a href="/fondul-de-modernizare">hubul Fondul pentru Modernizare</a>, iar pentru comparația dintre soluții și programe vezi pagina despre <a href="/finantari-panouri-fotovoltaice">finanțări pentru panouri fotovoltaice</a> și ghidul aplicat pentru <a href="/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum">fotovoltaice și autoconsum</a>.</p>
      </section>

      <section aria-labelledby="afir-cta">
        <h2 id="afir-cta">CTA: verifică proiectul înainte de depunere</h2>
        <p>Trimite forma juridică, codurile CAEN, punctul de consum, ultimele 12 facturi, consumatorii viitori, amplasamentul, puterea propusă, soluția de stocare și racordare, bugetul și sursa contribuției proprii. Verificarea urmărește Ghidul V7 și documentele oficiale active, fără promisiunea aprobării.</p>
        <p><a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Solicită verificarea eligibilității</a></p>
      </section>`;
}

function renderProInfraEfficiencyContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <p class="intro">${esc(page.quickAnswer)}</p>
      <p class="source-note"><strong>Status document:</strong> pagina folosește Schema de ajutor de stat PRO INFRA aprobată prin Ordinul MTI nr. 2.292/29.12.2025, publicată în Monitorul Oficial nr. 20/14.01.2026, în forma consolidată la 12 februarie 2026. Condițiile concrete ale unei proceduri de ofertare, calendarul și anexele de depunere se confirmă în Ghidul solicitantului aferent apelului. <strong>Ultima verificare:</strong> <time datetime="2026-07-13">13 iulie 2026</time>.</p>

      <section aria-labelledby="pro-infra-scop">
        <h2 id="pro-infra-scop">Scopul schemei</h2>
        <p>PRO INFRA sprijină investițiile care cresc eficiența energetică a capacităților industriale folosite pentru producerea materiilor prime, materialelor și produselor necesare proiectelor de infrastructură de transport. Schema face parte din programul-cheie 9 al Fondului pentru Modernizare — eficiență energetică în transporturi — și urmărește reducerea consumului de energie și a emisiilor de gaze cu efect de seră în procesele de producție.</p>
        <p>Ajutorul nu finanțează o extindere industrială generică și nici o linie generală de „energie verde”. Investiția trebuie să înlocuiască active existente cu tehnologii moderne, eficiente energetic și cu emisii reduse, iar beneficiarul trebuie să măsoare rezultatul energetic pe conturul proiectului. Schema consolidată prevede granturi de maximum 15 milioane euro pe beneficiar și o intensitate de maximum 100% din cheltuielile eligibile, acordate prin procedură de ofertare concurențială.</p>
      </section>

      <section aria-labelledby="pro-infra-legatura-productie">
        <h2 id="pro-infra-legatura-productie">Legătura directă cu producția necesară infrastructurii de transport</h2>
        <p>Solicitantul trebuie să producă materii prime, materiale sau produse care susțin implementarea proiectelor de infrastructură de transport, în activitățile din lista CAEN eligibilă anexată schemei. Lista include, între altele, extracția pietrei, pietrișului, nisipului și argilei, fabricarea unor produse din plastic, produse refractare, cărămizi, var și ipsos, beton, mortar, produse din beton, prelucrarea pietrei, profile și fire metalice, metale neferoase, construcții metalice, elemente de fixare și cabluri electrice.</p>
        <p>Înscrierea unui cod CAEN în anexă nu este suficientă singură. Cererea, auditul și analiza de oportunitate trebuie să explice ce resursă rezultă, unde intră în lanțul de producție pentru infrastructura de transport, ce instalație existentă este înlocuită și cum noua soluție reduce consumul energetic. Sunt eligibile microîntreprinderi, întreprinderi mici și mijlocii și întreprinderi mari, în condițiile schemei. În fiecare procedură concurențială poate fi depus un singur proiect, care poate include mai multe locații sau puncte de lucru.</p>
      </section>

      <section aria-labelledby="pro-infra-inlocuire">
        <h2 id="pro-infra-inlocuire">Înlocuirea instalațiilor, utilajelor și echipamentelor</h2>
        <p>Proiectul trebuie să vizeze <strong>înlocuirea</strong> instalațiilor de producție, utilajelor și echipamentelor existente cu alternative noi, de generație nouă și eficiente energetic. Logica proiectului pornește de la situația existentă: consum, performanță, emisii, capacitate și rol în flux. Pentru fiecare activ înlocuit se descrie alternativa propusă și economia de energie demonstrabilă.</p>
        <p>Schema nu tratează drept eligibilă simpla cumpărare a unei linii suplimentare fără legătură cu activele înlocuite și cu economia de energie. Echipamentele noi trebuie să fie instalate pe teritoriul României, în locațiile asupra cărora beneficiarul dovedește dreptul de folosință. Investițiile destinate respectării unor standarde UE deja în vigoare nu primesc ajutor; excepția privește standarde adoptate, dar încă neintrate în vigoare, dacă investiția este finalizată cu cel puțin 18 luni înainte de aplicarea lor.</p>
      </section>

      <section aria-labelledby="pro-infra-electrificare">
        <h2 id="pro-infra-electrificare">Înlocuirea echipamentelor cu combustie internă cu echipamente electrice</h2>
        <p>Electrificarea este una dintre direcțiile explicite ale schemei. Utilajele și echipamentele aferente producției pot fi înlocuite cu alternative electrice eficiente energetic. Pentru echipamentele existente bazate pe combustie internă, proiectul trebuie să arate consumul de referință, soluția electrică, necesarul de putere, adaptările instalației și energia economisită pe conturul analizat.</p>
        <p>PRO INFRA nu finanțează instalații, echipamente sau utilaje noi care utilizează combustibili fosili, inclusiv gaze naturale, și nici componente suplimentare pentru asemenea active. De aceea, o soluție tehnică mixtă trebuie separată riguros: partea care păstrează sau adaugă consum fosil nu poate fi prezentată drept cost eligibil doar pentru că restul liniei este eficient energetic.</p>
      </section>

      <section aria-labelledby="pro-infra-ems">
        <h2 id="pro-infra-ems">Obligativitatea sistemului EMS</h2>
        <p>Proiectele finanțate includ instalarea și operaționalizarea unui <strong>sistem de management al energiei — EMS</strong> integrat în instalațiile și echipamentele investiției. EMS-ul trebuie să monitorizeze complet și în timp real consumul de energie pe conturul proiectului și să furnizeze rapoarte periodice care arată reducerea consumului și performanțele energetice.</p>
        <p>Schema admite o excepție numai când solicitantul demonstrează că EMS-ul nu este necesar pentru a proba eficiența energetică și furnizează alte documente adecvate. Excepția nu este automată. O afirmație generală că utilajul nou „consumă mai puțin” nu înlocuiește măsurarea. Când EMS-ul este instalat, datele sale sunt integrate și validate prin auditul energetic.</p>
      </section>

      <section aria-labelledby="pro-infra-audit">
        <h2 id="pro-infra-audit">Auditul energetic</h2>
        <p>Proiectul se fundamentează prin audit energetic realizat pe conturul proiectului pentru ultimul an calendaristic încheiat la momentul deschiderii apelului. Auditul stabilește situația de referință, identifică măsurile de eficiență, cuantifică economia estimată și leagă instalațiile înlocuite de indicatorii asumați.</p>
        <p>Documentul este realizat și semnat de un auditor energetic sau manager energetic autorizat ori atestat de Ministerul Energiei, în conformitate cu Legea nr. 121/2014. Auditul nu este doar anexă de depunere: la finalul fiecărui an din perioada de monitorizare a indicatorilor de rezultat, beneficiarul prezintă un nou audit pe conturul proiectului și/sau al beneficiarului. Acolo unde există EMS, auditul integrează și validează datele sistemului.</p>
      </section>

      <section aria-labelledby="pro-infra-oportunitate">
        <h2 id="pro-infra-oportunitate">Analiza de oportunitate</h2>
        <p>Analiza de oportunitate este documentul tehnico-economic care dovedește necesitatea și fezabilitatea investiției. Ea descrie beneficiarul, situația existentă și motivele înlocuirii, apoi compară cel puțin două scenarii tehnico-economice independente. Dacă limitările tehnice sau de mediu permit un singur scenariu, documentul trebuie să justifice explicit această situație.</p>
        <p>Analiza cuprinde evaluarea impactului economic, social și de mediu, o analiză cost-eficacitate, reducerea estimată a consumului și emisiilor, economiile de resurse și costurile evitate. Ea tratează schimbările climatice, reziliența la dezastre, dimensionarea proiectului, durabilitatea și respectarea condițiilor privind standardele UE. Costul minim nu este singurul criteriu; opțiunea aleasă trebuie să producă economia energetică asumată și să poată fi implementată în amplasament.</p>
      </section>

      <section aria-labelledby="pro-infra-efect-stimulativ">
        <h2 id="pro-infra-efect-stimulativ">Efectul stimulativ și interdicția demarării premature</h2>
        <p>Ajutorul are efect stimulativ numai dacă solicitarea scrisă este transmisă furnizorului în cadrul procedurii concurențiale <strong>înainte de demararea lucrărilor</strong>. Demararea înseamnă fie începerea construcțiilor, fie primul angajament juridic obligatoriu pentru comandarea echipamentelor, fie orice alt angajament care face investiția ireversibilă, în funcție de momentul care apare primul.</p>
        <p>Cumpărarea terenului, obținerea avizelor și autorizațiilor, studiile tehnice pregătitoare și analiza de oportunitate nu sunt considerate demararea lucrărilor. În schimb, o comandă fermă, un contract executoriu sau lucrări începute prea devreme pot face <strong>întregul proiect neeligibil</strong>, nu doar factura respectivă. Calendarul achizițiilor trebuie verificat înainte de orice semnare.</p>
      </section>

      <section aria-labelledby="pro-infra-casare">
        <h2 id="pro-infra-casare">Casarea echipamentelor înlocuite</h2>
        <p>Beneficiarul trebuie să dovedească, în termen de 30 de zile de la recepția noii instalații de producție, a utilajului sau echipamentului, casarea activului pentru care a solicitat înlocuirea. Casarea presupune dezmembrare, demontare, tăiere, spargere sau alte operațiuni prin care bunul își pierde forma inițială și nu mai poate fi folosit potrivit destinației pentru care a fost creat.</p>
        <p>Proiectul trebuie să păstreze trasabilitatea dintre activul vechi identificat în audit, activul nou din buget și dovada finală a casării. Lipsa seriilor, a proceselor-verbale, a documentelor de predare sau a unei corespondențe clare între bunuri poate crea un risc de neîndeplinire a condiției de înlocuire.</p>
      </section>

      <section aria-labelledby="pro-infra-excluderi">
        <h2 id="pro-infra-excluderi">Sectoarele și situațiile excluse</h2>
        <p>Schema nu acordă ajutor pentru activități legate direct de export, ajutoare condiționate de folosirea preferențială a produselor naționale, pescuit și acvacultură, producția agricolă primară, anumite activități de prelucrare și comercializare a produselor agricole, închiderea minelor de cărbune necompetitive sau măsuri care încalcă nedisociabil dreptul Uniunii.</p>
        <p>Nu sunt eligibile întreprinderile încadrate în activitățile din anexa I la Directiva ETS 2003/87/CE, chiar dacă folosesc un CAEN din anexa PRO INFRA. Schema nu se aplică nici întreprinderilor care au beneficiat de sprijin în temeiul OUG nr. 138/2022 privind compensarea costurilor indirecte ale emisiilor. Dacă firma desfășoară și activități excluse, acestea trebuie separate de activitățile eligibile prin organizare și distincție între costuri, astfel încât ajutorul să nu le finanțeze.</p>
      </section>

      <section aria-labelledby="pro-infra-dificultate">
        <h2 id="pro-infra-dificultate">Întreprinderea în dificultate</h2>
        <p>PRO INFRA nu acordă ajutor unei întreprinderi în dificultate. Verificarea acoperă pierderea a mai mult de jumătate din capitalul social sau capitalurile proprii în situațiile definite de Regulamentul (UE) nr. 651/2014, procedurile colective de insolvență, ajutoarele de salvare nerambursate, planurile de restructurare încă active și, pentru întreprinderile care nu sunt IMM, indicatorii financiari specifici.</p>
        <p>Pentru o întreprindere non-IMM, raportul datorii/capitaluri proprii mai mare de 7,5 și capacitatea de acoperire a dobânzilor pe baza EBITDA sub 1,0, în ultimii doi ani, fac parte din testul legal. Separat, la depunere se verifică solvabilitatea: raportul dintre datoriile totale și capitalurile proprii trebuie să fie pozitiv și sub 7,5 în ultimul an financiar. Dacă acest criteriu nu este îndeplinit sau trebuie susținute contribuția proprie și cheltuielile neeligibile, schema prevede prezentarea unei scrisori de bonitate ori de confort bancar.</p>
      </section>

      <section aria-labelledby="pro-infra-cheltuieli">
        <h2 id="pro-infra-cheltuieli">Cheltuieli eligibile</h2>
        <p>Cheltuielile eligibile sunt strict costurile pentru achiziționarea și instalarea instalațiilor de producție, utilajelor și echipamentelor eficiente energetic care nu utilizează combustibili fosili sau gaze naturale, precum și costurile EMS-ului integrat, după caz. Activele trebuie să fie noi și de generație nouă la solicitarea finanțării.</p>
        <p>Costurile care nu intră în aceste categorii sunt, ca regulă generală, neeligibile. TVA-ul nu este eligibil. Documentele justificative trebuie să fie clare, specifice și contemporane faptelor. Aceleași cheltuieli nu pot primi o altă finanțare publică, inclusiv ajutor de minimis. Diferența până la valoarea totală, contribuția necesară în urma ofertei concurențiale și toate costurile neeligibile sunt suportate de beneficiar.</p>
        <p>Schema nu enumeră panourile fotovoltaice sau alte instalații de producere a energiei regenerabile ca obiect direct al cheltuielilor eligibile. Energia regenerabilă produsă la nivelul beneficiarului apare în criteriul secundar de selecție; acest criteriu nu transformă automat o instalație fotovoltaică într-un cost PRO INFRA eligibil.</p>
      </section>

      <section aria-labelledby="pro-infra-documente">
        <h2 id="pro-infra-documente">Documente tehnice</h2>
        <p>Solicitarea include denumirea și dimensiunea întreprinderii, descrierea proiectului și calendarul, obiectivele și rezultatele, localizarea, bugetul, lista costurilor eligibile și neeligibile, valoarea ajutorului solicitat și analiza de oportunitate cu analiza cost-eficacitate. Pentru verificarea tehnică sunt necesare cel puțin:</p>
        <ul>
          <li>auditul energetic de referință, semnat de specialist autorizat sau atestat;</li>
          <li>analiza de oportunitate și scenariile tehnico-economice;</li>
          <li>inventarul instalațiilor și echipamentelor înlocuite, cu identificare și consumuri;</li>
          <li>specificațiile, ofertele și documentația pentru instalațiile și utilajele noi;</li>
          <li>arhitectura EMS, conturul de măsurare, punctele de monitorizare și raportarea propusă;</li>
          <li>calculul economiei de energie, al reducerii emisiilor și al costului ajutorului per MWh economisit;</li>
          <li>documentele pentru locație, dreptul de folosință, utilități, avize și autorizații;</li>
          <li>documentele CAEN, financiare, fiscale, de capacitate tehnică și declarațiile privind ajutoarele și sectoarele excluse.</li>
        </ul>
        <p>Ghidul solicitantului al fiecărei proceduri poate detalia formatele, anexele și documentele suplimentare. Dosarul tehnic trebuie să spună aceeași poveste în audit, analiza de oportunitate, buget, oferte și indicatori.</p>
      </section>

      <section aria-labelledby="pro-infra-indicatori">
        <h2 id="pro-infra-indicatori">Indicatorii de eficiență energetică</h2>
        <p>Indicatorul central este energia economisită în procesul de producție, exprimată în MWh și demonstrată față de situația de referință din audit. Proiectul urmărește și reducerea consumului pe contur, reducerea emisiilor de gaze cu efect de seră și performanța instalațiilor noi. EMS-ul furnizează date în timp real, iar auditurile ulterioare confirmă rezultatul.</p>
        <p>Selecția reflectă această logică. 90% din criteriile de clasificare se bazează pe ajutorul solicitat pentru fiecare MWh economisit: cu cât valoarea EUR/MWh este mai mică, cu atât punctajul este mai mare. Restul de 10% privește utilizarea energiei regenerabile produse la nivelul beneficiarului în proces sau pentru alimentarea utilajelor. Nu există punctaj intermediar pentru acest al doilea criteriu.</p>
      </section>

      <section aria-labelledby="pro-infra-monitorizare">
        <h2 id="pro-infra-monitorizare">Monitorizare</h2>
        <p>Beneficiarul respectă o perioadă de durabilitate de cinci ani de la finalizarea implementării. În această perioadă nu poate înceta activitatea desfășurată cu bunul finanțat, nu poate înstrăina activele și nu poate face o modificare substanțială care afectează natura, obiectivele sau condițiile proiectului.</p>
        <p>La finalul fiecărui an din perioada de monitorizare a indicatorilor se prezintă auditul energetic; acesta validează datele EMS unde sistemul este instalat. Beneficiarul furnizează MTI informațiile cerute pentru raportare și monitorizare și păstrează cel puțin 10 ani evidența ajutorului primit și documentele care demonstrează respectarea condițiilor. Nerealizarea indicatorilor sau încălcarea obligațiilor poate conduce la stoparea ori recuperarea ajutorului, inclusiv cu dobândă.</p>
      </section>

      <section aria-labelledby="pro-infra-riscuri">
        <h2 id="pro-infra-riscuri">Riscuri</h2>
        <ul class="warning-list">
          <li>proiectul descrie o modernizare industrială generală, fără legătură demonstrată cu resursele necesare infrastructurii de transport;</li>
          <li>codul CAEN apare în anexă, dar activitatea intră într-un sector exclus sau în anexa I ETS;</li>
          <li>auditul nu delimitează conturul, nu folosește un an de referință complet ori nu susține economia declarată;</li>
          <li>analiza de oportunitate nu compară scenarii și nu explică dimensionarea ori cost-eficacitatea;</li>
          <li>EMS-ul nu este integrat, nu măsoară toate punctele relevante sau excepția este insuficient justificată;</li>
          <li>echipamentele noi folosesc combustibili fosili ori gaze naturale;</li>
          <li>contractele, comenzile sau lucrările încep înainte de depunerea solicitării;</li>
          <li>activele înlocuite nu pot fi identificate sau casarea nu este dovedită în termen;</li>
          <li>solicitantul este întreprindere în dificultate, are indicatori financiari neconformi sau nu poate acoperi costurile proprii;</li>
          <li>beneficiarul tratează criteriul energiei regenerabile ca finanțare directă pentru fotovoltaice;</li>
          <li>economia de energie și valoarea EUR/MWh sunt supraestimate, reducând credibilitatea și punctajul proiectului.</li>
        </ul>
      </section>

      <section aria-labelledby="pro-infra-faq">
        <h2 id="pro-infra-faq">FAQ</h2>
        ${faqHtml}
      </section>

${officialSourcesHtml}

      <section aria-labelledby="pro-infra-cta">
        <h2 id="pro-infra-cta">CTA: verifică investiția PRO INFRA</h2>
        <p>Trimite codul CAEN, produsele realizate pentru infrastructura de transport, inventarul instalațiilor și utilajelor existente, consumurile energetice, auditul disponibil, soluția de înlocuire, documentele locației, bugetul și sursa contribuției proprii. Verificarea urmărește legătura cu schema, riscul de demarare prematură, costurile eligibile și indicatorii EUR/MWh înainte de depunere.</p>
        <p><a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Solicită verificarea eligibilității PRO INFRA</a></p>
      </section>`;
}

function renderPorAdrNordEstContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <p class="intro">Programul Regional Nord-Est 2021–2027 este cadrul regional pentru apelurile administrate de ADR Nord-Est în județele Bacău, Botoșani, Iași, Neamț, Suceava și Vaslui. Expresia istorică „POR ADR Nord-Est” este încă folosită de antreprenori, însă această pagină oferă orientare la nivel de program pentru IMM și microîntreprinderi, nu regulile unei singure sesiuni. Eligibilitatea, bugetele și termenele se confirmă în ghidul activ al fiecărui apel.</p>

      <section aria-labelledby="por-ne-judete-apeluri">
        <h2 id="por-ne-judete-apeluri">Județele regiunii și tipurile de apeluri</h2>
        <p>Regiunea Nord-Est cuprinde cele șase județe <strong>Bacău, Botoșani, Iași, Neamț, Suceava și Vaslui</strong>. Pentru încadrare contează locul în care se implementează investiția și documentele care dovedesc dreptul asupra amplasamentului, nu doar adresa sediului social.</p>
        <p>Programul Regional poate publica tipuri diferite de apeluri, în funcție de prioritățile și calendarul activ: competitivitate și investiții productive pentru IMM, inovare și digitalizare, eficiență energetică, dezvoltare urbană, mobilitate, educație, sănătate, turism sau patrimoniu. Fiecare apel are beneficiari, cheltuieli și documente proprii; această pagină nu declară un apel deschis fără confirmarea sursei oficiale.</p>
      </section>

      <section aria-labelledby="por-ne-diferenta-rute">
        <h2 id="por-ne-diferenta-rute">Diferența dintre hub, program și Apelul 2</h2>
        <div class="table-wrap">
          <table class="program-table">
            <thead><tr><th>Pagină</th><th>Intenție</th><th>Când o folosești</th></tr></thead>
            <tbody>
              <tr><td><a href="/fonduri-regionale">Fonduri regionale</a></td><td>Hub național pentru toate programele regionale și ADR-urile din România.</td><td>Când nu ai stabilit încă regiunea sau vrei să compari autoritățile regionale.</td></tr>
              <tr><td><a href="/fonduri-europene-nord-est">Fonduri europene Nord-Est</a></td><td>Hub regional pentru programe regionale, AFIR, scheme naționale, digitalizare și energie.</td><td>Când investiția este în Nord-Est, dar programul potrivit nu este încă stabilit.</td></tr>
              <tr><td>Programul Regional Nord-Est</td><td>Orientare privind programul regional și apelurile sale pentru IMM și microîntreprinderi.</td><td>Când știi că ruta regională este relevantă, dar nu analizezi încă o singură sesiune.</td></tr>
              <tr><td><a href="/investitii-modernizarea-microintreprinderilor-apel-2">Investiții pentru modernizarea microîntreprinderilor – Apel 2</a></td><td>Condițiile și pregătirea exclusiv pentru Apelul 2.</td><td>Când vrei analiza detaliată a solicitantului, CAEN-ului, amplasamentului, bugetului și documentelor pentru această sesiune.</td></tr>
            </tbody>
          </table>
        </div>
        <p><a class="btn btn-secondary" href="/investitii-modernizarea-microintreprinderilor-apel-2">Vezi pagina detaliată pentru Apelul 2</a></p>
      </section>

      <section aria-labelledby="por-ne-cine-poate-aplica">
        <h2 id="por-ne-cine-poate-aplica">Cine poate aplica</h2>
        <p>Programul este gândit pentru firme mici din regiunea Nord-Est care vor să își îmbunătățească activitatea curentă, nu pentru idei fără legătură cu activitatea reală. Înainte de buget, antreprenorul trebuie să confirme dacă solicitantul și locul investiției se potrivesc cu apelul activ.</p>
        <ul>
          <li>microîntreprindere cu sediu sau punct de lucru relevant pentru investiție în regiunea Nord-Est;</li>
          <li>activitate desfășurată într-unul dintre județele Bacău, Botoșani, Iași, Neamț, Suceava sau Vaslui;</li>
          <li>solicitant cu istoric verificabil, vechime minimă și situații financiare conforme cu cerințele ghidului activ;</li>
          <li>cod CAEN eligibil și autorizat conform regulilor publicate de ADR Nord-Est;</li>
          <li>investiție legată de activitatea firmei: utilaje, echipamente, dotări, software, servicii sau amenajări permise;</li>
          <li>capacitate de a acoperi cofinanțarea, TVA-ul, costurile neeligibile și eventualele decalaje de rambursare.</li>
        </ul>
      </section>

      <section aria-labelledby="por-ne-conditii">
        <h2 id="por-ne-conditii">Condiții de eligibilitate</h2>
        <p>Eligibilitatea nu se verifică dintr-o singură condiție. Un proiect poate părea potrivit la prima vedere, dar poate avea probleme dacă amplasamentul investiției, codul CAEN, istoricul firmei sau lista de achiziții nu se potrivesc cu ghidul.</p>
        <ul>
          <li>solicitantul trebuie să se încadreze ca microîntreprindere la momentul cerut de apel;</li>
          <li>investiția trebuie implementată în regiunea Nord-Est, nu doar declarată prin sediul social;</li>
          <li>codul CAEN trebuie să fie eligibil, autorizat și conectat direct cu bunurile sau serviciile cumpărate;</li>
          <li>solicitantul trebuie să poată prezenta situații financiare, declarații și documente fără contradicții;</li>
          <li>spațiul investiției trebuie să fie disponibil pe perioada cerută, prin proprietate, închiriere, concesiune sau altă formă acceptată;</li>
          <li>achizițiile propuse trebuie să fie noi, necesare și justificate prin activitatea firmei, dacă ghidul nu permite altfel;</li>
          <li>proiectul nu trebuie să înceapă achiziții sau lucrări înainte de momentul permis de apel.</li>
        </ul>
        <p>O verificare corectă pune împreună certificatul constatator, bilanțurile, locația, ofertele și obiectivul de investiție. Dacă una dintre piese nu se potrivește, proiectul trebuie ajustat înainte de depunere.</p>
      </section>

      <section aria-labelledby="por-ne-sume">
        <h2 id="por-ne-sume">Sume și intensitate</h2>
        <p>Valoarea grantului, procentul nerambursabil și limitele de cheltuieli se confirmă numai în ghidul activ. Pentru antreprenor, partea importantă este să înțeleagă bugetul total, nu doar suma care poate fi obținută.</p>
        <ul>
          <li>grantul maxim și minim se verifică în apelul publicat de ADR Nord-Est;</li>
          <li>intensitatea sprijinului poate depinde de tipul firmei, localizare, regulile de ajutor de stat sau minimis și categoria de cheltuială;</li>
          <li>cofinanțarea trebuie acoperită din surse proprii, credit, leasing sau alte surse acceptate de program;</li>
          <li>TVA-ul, costurile neeligibile, diferențele de preț și cheltuielile respinse pot rămâne în sarcina firmei;</li>
          <li>ofertele prea generale sau rotunjite artificial pot crea întrebări la evaluare;</li>
          <li>bugetul trebuie să arate clar ce se cumpără, de ce este necesar și cum ajută afacerea după implementare.</li>
        </ul>
        <p>Nu porni de la ideea că proiectul este bun doar pentru că există finanțare. Dacă solicitantul nu poate susține partea proprie sau dacă achizițiile nu sunt bine explicate, riscul rămâne ridicat chiar și pentru un proiect eligibil.</p>
      </section>

      <section aria-labelledby="por-ne-documente">
        <h2 id="por-ne-documente">Documente necesare</h2>
        <p>Lista finală de documente se ia din ghid și anexe. Totuși, antreprenorii pot pregăti din timp un set de bază pentru discuția inițială și pentru verificarea riscurilor evidente.</p>
        <ul>
          <li>certificat constatator actualizat, cu activitatea si punctul de lucru relevante;</li>
          <li>situatii financiare, balante sau alte documente contabile cerute de apel;</li>
          <li>documente pentru spatiul investitiei: proprietate, contract de inchiriere, acorduri sau alte dovezi acceptate;</li>
          <li>lista de echipamente, utilaje, software, servicii si lucrari propuse;</li>
          <li>oferte sau estimari de pret suficient de clare pentru fiecare achizitie importanta;</li>
          <li>descrierea activitatii firmei si a modului in care investitia modernizeaza procesul curent;</li>
          <li>date despre cofinantare, credite, leasing sau alte surse de bani pentru partea proprie;</li>
          <li>declaratii si formulare specifice apelului, completate conform modelelor oficiale.</li>
        </ul>
        <p>Documentele trebuie să spună aceeași poveste. Dacă o ofertă descrie o activitate, certificatul constatator alta, iar planul de investiții nu le leagă clar, apar clarificări sau riscuri de respingere.</p>
      </section>

      <section aria-labelledby="por-ne-pasi">
        <h2 id="por-ne-pasi">Pașii de pregătire</h2>
        <p>O pregatire buna inseamna sa elimini intrebarile importante inainte de depunere. Fluxul de mai jos arata ordinea fireasca pentru o microintreprindere care vrea sa verifice POR ADR Nord-Est fara sa piarda timp cu un dosar nepotrivit.</p>
        <div class="table-wrap">
          <svg role="img" aria-labelledby="por-ne-flow-title por-ne-flow-desc" viewBox="0 0 920 170" width="100%" height="170">
            <title id="por-ne-flow-title">Flux de pregatire POR ADR Nord-Est</title>
            <desc id="por-ne-flow-desc">Patru etape: Verificare eligibilitate, Pregatire documente, Depunere si Implementare.</desc>
            <defs>
              <marker id="por-ne-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
                <path d="M0,0 L0,6 L9,3 z" fill="#b84716"></path>
              </marker>
            </defs>
            <g fill="#fff7ed" stroke="#b84716" stroke-width="2">
              <rect x="24" y="42" width="180" height="82" rx="12"></rect>
              <rect x="266" y="42" width="180" height="82" rx="12"></rect>
              <rect x="508" y="42" width="180" height="82" rx="12"></rect>
              <rect x="750" y="42" width="146" height="82" rx="12"></rect>
            </g>
            <g stroke="#b84716" stroke-width="3" marker-end="url(#por-ne-arrow)">
              <line x1="214" y1="83" x2="254" y2="83"></line>
              <line x1="456" y1="83" x2="496" y2="83"></line>
              <line x1="698" y1="83" x2="738" y2="83"></line>
            </g>
            <g fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="18" font-weight="700" text-anchor="middle">
              <text x="114" y="78">Verificare</text>
              <text x="114" y="102">eligibilitate</text>
              <text x="356" y="78">Pregatire</text>
              <text x="356" y="102">documente</text>
              <text x="598" y="91">Depunere</text>
              <text x="823" y="91">Implementare</text>
            </g>
          </svg>
        </div>
        <ol>
          <li><strong>Verificare eligibilitate:</strong> confirmi firma, judetul, codul CAEN, vechimea, istoricul financiar si ideea de investitie.</li>
          <li><strong>Pregatire documente:</strong> strangi documentele firmei, actele pentru spatiu, ofertele, bugetul si explicatia investitiei.</li>
          <li><strong>Depunere:</strong> completezi cererea si anexele in forma ceruta de apel, fara informatii contradictorii.</li>
          <li><strong>Implementare:</strong> respecti achizitiile, termenele, raportarile si dovezile cerute pentru rambursare.</li>
        </ol>
      </section>

${officialSourcesHtml}
      <h2>Întrebări frecvente</h2>
      ${faqHtml}`;
}

function renderMicroApel2Content(page) {
  const officialUrl = "https://adrnordest.ro/comentariiGhid/P1Microintreprinderi/Apel2/";
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <p class="intro"><strong>Investiții pentru modernizarea microîntreprinderilor – Apel 2</strong> este pagina dedicată exclusiv acestei sesiuni din Programul Regional Nord-Est. Ea urmărește solicitantul, localizarea, codul CAEN, amplasamentul, situațiile financiare, cheltuielile și cofinanțarea necesare proiectului. În forma consultativă analizată, granturile sunt între 100.000 și 300.000 euro, cu intensitate maximă de 90%; valorile și condițiile se reconfirmă în documentele active ADR Nord-Est.</p>
      <p class="note">Pentru cadrul general, celelalte apeluri și rolul autorității regionale, consultă <a href="/por-adr-nord-est">Programul Regional Nord-Est – finanțări pentru IMM și microîntreprinderi</a>. Pagina curentă nu este un hub general și rămâne limitată la Apelul 2.</p>

      <section aria-labelledby="apel2-beneficii-title">
        <h2 id="apel2-beneficii-title">De ce merită analizat Apelul 2</h2>
        <p>Pentru antreprenor, beneficiul principal nu este doar grantul, ci posibilitatea de a moderniza o activitate existentă fără să blocheze tot bugetul firmei. Un dosar bine pregătit arată cum investiția crește capacitatea, calitatea serviciilor, viteza de lucru sau eficiența procesului.</p>
        <ul>
          <li>poți planifica achiziții mai mari decât ai putea susține rapid doar din resurse proprii;</li>
          <li>poți corela echipamentele cu un cod CAEN și cu o activitate clară din regiunea Nord-Est;</li>
          <li>poți separa din timp grantul, cofinanțarea, TVA-ul și cheltuielile neeligibile;</li>
          <li>poți decide responsabil dacă proiectul merită depus sau dacă trebuie ajustat înainte de apel.</li>
        </ul>
      </section>

      <section aria-labelledby="apel2-finantare-title">
        <h2 id="apel2-finantare-title">Finanțare: grant și intensitate</h2>
        <p>Intervalul de finanțare menționat în forma consultativă este 100.000-300.000 euro, iar intensitatea maximă este 90%. Ghidul final poate modifica detalii, plafoane, condiții sau documente, așa că decizia de depunere trebuie luată după verificarea sursei oficiale.</p>
        <div class="table-wrap">
          <svg role="img" aria-labelledby="apel2-finantare-svg-title apel2-finantare-svg-desc" viewBox="0 0 860 230" width="100%" height="230">
            <title id="apel2-finantare-svg-title">Interval de finanțare și intensitate Apel 2 Nord-Est</title>
            <desc id="apel2-finantare-svg-desc">Grafic cu bară pentru granturi între 100.000 și 300.000 euro și intensitate maximă de 90%.</desc>
            <rect x="48" y="62" width="540" height="28" rx="14" fill="#f3f4f6"></rect>
            <rect x="168" y="62" width="360" height="28" rx="14" fill="#b84716"></rect>
            <line x1="168" y1="52" x2="168" y2="104" stroke="#1a2540" stroke-width="2"></line>
            <line x1="528" y1="52" x2="528" y2="104" stroke="#1a2540" stroke-width="2"></line>
            <text x="48" y="40" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="17" font-weight="700">Grant orientativ</text>
            <text x="168" y="130" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="16" text-anchor="middle">100.000 €</text>
            <text x="528" y="130" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="16" text-anchor="middle">300.000 €</text>
            <rect x="640" y="48" width="166" height="94" rx="16" fill="#fff7ed" stroke="#b84716" stroke-width="2"></rect>
            <text x="723" y="82" fill="#1a2540" font-family="Inter, Arial, sans-serif" font-size="18" font-weight="700" text-anchor="middle">Intensitate</text>
            <text x="723" y="122" fill="#b84716" font-family="Inter, Arial, sans-serif" font-size="34" font-weight="800" text-anchor="middle">max. 90%</text>
            <text x="48" y="180" fill="#334155" font-family="Inter, Arial, sans-serif" font-size="15">Valorile sunt orientative și trebuie reconfirmate în ghidul final ADR Nord-Est.</text>
          </svg>
        </div>
        <p class="note">Sursa oficială ADR Nord-Est pentru acest apel: <a href="${officialUrl}" target="_blank" rel="noopener noreferrer">pagina programului Modernizarea microîntreprinderilor - Apel 2</a>. Pagina oficială indică faptul că sesiunea de comentarii a expirat; forma finală și clarificările se verifică înainte de depunere.</p>
      </section>

      <section aria-labelledby="apel2-eligibilitate-title">
        <h2 id="apel2-eligibilitate-title">Eligibilitate: solicitant, regiune, cod CAEN</h2>
        <p>Eligibilitatea se verifică înainte de lista de cumpărături. Un proiect bun începe cu firma, locul investiției și activitatea finanțată.</p>
        <ul>
          <li><strong>Solicitant:</strong> microîntreprindere care respectă condițiile ghidului activ, inclusiv istoricul financiar și limitele de ajutor aplicabile.</li>
          <li><strong>Regiune:</strong> investiția trebuie realizată în regiunea Nord-Est, nu doar declarată printr-un sediu fără legătură cu proiectul.</li>
          <li><strong>Cod CAEN:</strong> activitatea trebuie să fie eligibilă, autorizată și legată direct de echipamentele sau serviciile propuse.</li>
          <li><strong>Spațiu:</strong> punctul de lucru, contractul de închiriere, proprietatea sau alt drept de folosință trebuie să acopere perioada cerută.</li>
          <li><strong>Cofinanțare:</strong> firma trebuie să poată susține partea proprie, TVA-ul, costurile neeligibile și decalajele de plată.</li>
        </ul>
      </section>

      <section aria-labelledby="apel2-cheltuieli-title">
        <h2 id="apel2-cheltuieli-title">Cheltuieli eligibile</h2>
        <p>Cheltuielile trebuie să susțină modernizarea reală a activității. Nu este suficient ca achizițiile să fie dorite de firmă; ele trebuie să fie permise de apel și justificate în proiect.</p>
        <ul>
          <li>echipamente, utilaje și dotări folosite în activitatea eligibilă;</li>
          <li>software, licențe sau componente digitale, dacă apelul le permite;</li>
          <li>amenajări sau lucrări legate de spațiul investiției, în limitele ghidului;</li>
          <li>servicii, documentații, proiectare sau consultanță, doar dacă sunt permise și încadrate corect;</li>
          <li>cheltuieli auxiliare care pot fi explicate prin obiectivul investiției și prin rezultatele asumate.</li>
        </ul>
        <p>O listă de cheltuieli bună este ușor de urmărit: fiecare achiziție are o funcție, o ofertă, un loc de utilizare și o legătură cu rezultatul proiectului. Această logică ajută antreprenorul să evite bugete supradimensionate, echipamente greu de justificat sau costuri care ar putea fi tăiate la evaluare.</p>
      </section>

      <section aria-labelledby="apel2-proces-title">
        <h2 id="apel2-proces-title">Proces și calendar</h2>
        <p>Calendarul real este cel publicat de ADR Nord-Est. Până la forma finală, pregătirea poate avansa pe datele firmei, buget, oferte și documente care nu depind de ultima versiune a ghidului.</p>
        <ol class="process-list">
          <li><strong>Verificare inițială.</strong> Confirmăm solicitantul, regiunea, CAEN-ul, spațiul și ideea de investiție.</li>
          <li><strong>Buget și oferte.</strong> Separăm cheltuielile eligibile, cheltuielile neeligibile, TVA-ul, cofinanțarea și rezervele.</li>
          <li><strong>Documente.</strong> Pregătim actele firmei, situațiile financiare, documentele pentru spațiu și anexele cerute.</li>
          <li><strong>Depunere.</strong> Completăm cererea și anexele conform ghidului final și platformei indicate.</li>
          <li><strong>Evaluare și implementare.</strong> Răspundem la clarificări, apoi urmărim achizițiile, plățile și raportările.</li>
        </ol>
      </section>

      <section aria-labelledby="apel2-documente-title">
        <h2 id="apel2-documente-title">Documente necesare</h2>
        <p>Documentele finale se iau din ghid și anexe. Pentru o evaluare rapidă a șanselor, merită pregătite din timp următoarele:</p>
        <ul>
          <li>certificat constatator actualizat, cu activitatea și punctul de lucru relevante;</li>
          <li>situații financiare și documente contabile cerute pentru încadrare;</li>
          <li>documente pentru spațiul investiției: proprietate, închiriere, acorduri, planuri sau autorizații;</li>
          <li>lista achizițiilor propuse, cu rolul fiecărei cheltuieli în activitatea firmei;</li>
          <li>oferte comparabile, devize, specificații tehnice sau estimări documentate;</li>
          <li>date despre cofinanțare, surse proprii, credit, leasing sau alte surse acceptate;</li>
          <li>declarații și formulare specifice apelului, completate în forma publicată de ADR Nord-Est.</li>
        </ul>
      </section>

      <section aria-labelledby="apel2-riscuri-title">
        <h2 id="apel2-riscuri-title">Riscuri și recomandări</h2>
        <p>Cele mai multe probleme apar când proiectul pornește de la achiziții, nu de la eligibilitate și logică de modernizare. Recomandarea practică este să verifici întâi dacă fiecare document susține aceeași poveste.</p>
        <ul class="warning-list">
          <li>nu trata apelul ca program național; localizarea în Nord-Est este filtru de bază;</li>
          <li>nu include echipamente fără legătură clară cu codul CAEN și activitatea finanțată;</li>
          <li>nu construi bugetul la plafon fără justificare operațională;</li>
          <li>nu ignora TVA-ul, cheltuielile neeligibile și decalajele până la rambursare;</li>
          <li>nu depune cu documente pentru spațiu incomplete sau cu durată insuficientă;</li>
          <li>nu folosi forma consultativă ca regulă finală; verifică ghidul activ, anexele și clarificările.</li>
        </ul>
      </section>

${officialSourcesHtml}
      <h2>Întrebări frecvente</h2>
      ${faqHtml}`;
}

function renderTable(page) {
  const rows = [
    ["Program", page.programName || page.h1],
    ["Pentru cine", (page.audience || []).slice(0, 3).join("; ")],
    ["Finantare", page.funding],
    ["Ce verifici intai", (page.mandatory || []).slice(0, 4).join("; ")],
    ["CTA", "verificare eligibilitate si discutie de consultanta"]
  ];
  return `<div class="table-wrap table-wrap--summary">
    <table class="program-table">
    <tbody>
      ${rows.map(([key, value]) => `<tr><th>${esc(key)}</th><td>${esc(value)}</td></tr>`).join("\n")}
    </tbody>
  </table>
  </div>`;
}

function renderCalendarTable(page) {
  const rows = Array.isArray(page.calendarRows) && page.calendarRows.length
    ? page.calendarRows
    : [
      ["Pregatire", "Inainte de lansarea apelului", "eligibilitate, documente, oferte si buget"],
      ["Depunere", "Conform calendarului oficial", "cerere, anexe si documente in platforma"],
      ["Evaluare", "Dupa inchiderea apelului", "clarificari, punctaj si selectie in limita bugetului"],
      ["Contractare si implementare", "Dupa selectie", "contract, achizitii, plati si raportari"]
    ];
  return renderEditorialTable("Calendar orientativ", ["Etapa", "Perioada", "Ce pregatesti"], rows);
}

function renderCofinancingExample(page) {
  const rows = Array.isArray(page.cofinancingRows) && page.cofinancingRows.length
    ? page.cofinancingRows
    : [
      ["Investitie eligibila", "100.000 EUR", "valoare folosita doar pentru calcul orientativ"],
      ["Sprijin nerambursabil estimat", "70%", "procentul real se confirma in ghidul activ"],
      ["Grant orientativ", "70.000 EUR", "100.000 EUR x 70%"],
      ["Contributie proprie", "30.000 EUR", "la care se pot adauga TVA, costuri neeligibile sau rezerve"]
    ];
  return renderEditorialTable(page.cofinancingTitle || "Exemplu numeric de cofinantare", ["Element", "Valoare", "Observatie"], rows);
}

function compactTextList(items, fallback, limit = 4) {
  const values = (items || [])
    .filter(Boolean)
    .slice(0, limit)
    .map((item) => String(item).trim())
    .filter(Boolean);
  return values.length ? values.join("; ") : fallback;
}

function renderDecisionMatrix(page) {
  const programName = page.programName || page.h1 || "programul";
  const audience = compactTextList(page.audience, "solicitantul si forma juridica");
  const mandatory = compactTextList(page.mandatory, "documentele solicitantului, bugetul si ofertele");
  const expenses = compactTextList(page.eligibleExpenses, "cheltuielile propuse prin proiect");
  const risks = compactTextList(page.ineligibleExpenses, "cheltuieli nepermise sau insuficient justificate");
  const steps = compactTextList(page.steps, "verificare, documentare, bugetare si depunere", 5);
  const decisionIntro = page.decisionIntro ||
    `${programName} se verifica prin elemente concrete: cine aplica, ce documente exista, ce investitie se propune si ce riscuri pot aparea la evaluare sau implementare.`;
  const decisionClose = page.decisionClose ||
    "Daca datele, documentele sau bugetul nu sustin proiectul, recomandarea prudenta este ajustarea sau amanarea depunerii. Regulile finale se confirma in ghidul activ, anexele apelului si sursele oficiale.";

  return `<h2>Ce verifici concret pentru ${esc(programName)}</h2>
      <p>${esc(decisionIntro)}</p>
      <table class="program-table">
        <tbody>
          <tr><th>Potrivirea solicitantului</th><td>${esc(audience)}</td></tr>
          <tr><th>Documente sensibile</th><td>${esc(mandatory)}</td></tr>
          <tr><th>Investitii de argumentat</th><td>${esc(expenses)}</td></tr>
          <tr><th>Riscuri de verificat</th><td>${esc(risks)}</td></tr>
          <tr><th>Ordinea pregatirii</th><td>${esc(steps)}</td></tr>
        </tbody>
      </table>
      <p>${esc(decisionClose)}</p>`;
}

function renderEditorialTable(title, columns, rows) {
  const safeRows = Array.isArray(rows) ? rows : [];
  return `<h2>${esc(title)}</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead>
            <tr>${columns.map((column) => `<th>${esc(column)}</th>`).join("")}</tr>
          </thead>
          <tbody>
            ${safeRows.map((row) => `<tr>${columns.map((_, index) => `<td>${esc(Array.isArray(row) ? row[index] : "")}</td>`).join("")}</tr>`).join("\n")}
          </tbody>
        </table>
      </div>`;
}

function renderPreparationSteps(steps) {
  const safeSteps = Array.isArray(steps) ? steps : [];
  return `<ol class="process-list">
        ${safeSteps.map((step) => {
    const title = Array.isArray(step) ? step[0] : "";
    const detail = Array.isArray(step) ? step[1] : step;
    return `<li><strong>${esc(title)}</strong>${detail ? ` ${esc(detail)}` : ""}</li>`;
  }).join("\n")}
      </ol>`;
}

function renderCaseExample(example) {
  const item = example || {};
  const requiredFields = ["beneficiary", "investmentObjective", "challenges", "checked"];
  const hasApprovedFields = requiredFields.every((field) => !hasPublicPlaceholder(item[field]));
  const noteText = String(item.note ?? "").trim();
  if (!hasApprovedFields || (noteText && hasPublicPlaceholder(noteText))) return "";

  const rows = [
    ["Tip beneficiar", publicText(item.beneficiary)],
    ["Obiectiv investi\u021bie", publicText(item.investmentObjective)],
    ["Provoc\u0103ri", publicText(item.challenges)],
    ["Ce s-a verificat", publicText(item.checked)]
  ];
  return `${item.note ? `<p class="note">${esc(item.note)}</p>` : ""}
      <div class="table-wrap">
        <table class="program-table">
          <tbody>
            ${rows.map(([key, value]) => `<tr><th>${esc(key)}</th><td>${esc(value)}</td></tr>`).join("\n")}
          </tbody>
        </table>
      </div>`;
}

function renderEditorialNotes(notes) {
  if (!Array.isArray(notes) || !notes.length) return "";
  return `<h2>Note de verificare</h2>
      ${notes.map((note) => `<p>${esc(note)}</p>`).join("\n")}`;
}

function renderEditorialProgramContent(page) {
  const editorialHtml = renderEditorialSection(getEditorialMetadata(page.slug));
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");
  const caseExampleHtml = renderCaseExample(page.caseExample);
  const dr14ScoreHtml = page.slug === "dr14" ? `\n${renderDr14Score()}` : "";

  return `
${editorialHtml}
      <h2>R\u0103spuns scurt</h2>
      <p class="intro">${esc(page.quickAnswer)}</p>
      ${renderContentSections(page.contentSections)}
      ${renderEditorialTable("Cine poate aplica", ["Tip solicitant", "Eligibilitate posibil\u0103", "Ce trebuie verificat", "Observa\u021bii"], page.applicantRows)}
      ${renderEditorialTable("Ce investi\u021bii pot fi eligibile", ["Categorie cheltuial\u0103", "Exemple", "Aten\u021bie la", "Sursa"], page.eligibleInvestmentRows)}
      ${renderCalendarTable(page)}
      ${renderCofinancingExample(page)}
      ${dr14ScoreHtml}
      ${renderEditorialTable("Documente necesare", ["Document", "Cine \u00eel preg\u0103te\u0219te", "C\u00e2nd este necesar", "Risc dac\u0103 lipse\u0219te"], page.documentRows)}
      <h2>Pa\u0219i de preg\u0103tire</h2>
      ${renderPreparationSteps(page.preparationSteps)}
      <h2>Gre\u0219eli frecvente</h2>
      <ul class="warning-list">${li(page.commonMistakes)}</ul>
      ${caseExampleHtml ? `<h2>Exemplu realist anonimizat</h2>
      ${caseExampleHtml}` : ""}
      ${renderEditorialNotes(page.editorialNotes)}
${officialSourcesHtml}
      <h2>FAQ</h2>
      ${faqHtml}
      <h2>${esc(page.inlineCtaTitle || "Urmatorul pas")}</h2>
      <p>${esc(page.inlineCtaText || "Trimite datele principale despre solicitant, localitate, activitate, investitie si buget. FABER poate verifica incadrarea initiala si riscurile, fara sa promita aprobarea finantarii.")}</p>`;
}

function renderTools() {
  return `<section class="tool-suite" aria-label="Calculatoare fonduri europene">
    <div class="tool-panel">
      <h3>Calculator cofinantare proiect</h3>
      <div class="tool-grid">
        <div class="tool-field"><label for="cofinantare-total">Valoare totala estimata (EUR)</label><input id="cofinantare-total" type="number" value="50000" min="0"></div>
        <div class="tool-field"><label for="cofinantare-procent">Procent nerambursabil estimat</label><input id="cofinantare-procent" type="number" value="70" min="0" max="100"></div>
        <div class="tool-field"><label for="cofinantare-neeligibil">Cheltuieli neeligibile (EUR)</label><input id="cofinantare-neeligibil" type="number" value="0" min="0"></div>
      </div>
      <div id="cofinantare-result" class="tool-result" aria-live="polite"></div>
      <p class="tool-note">Rezultatul este orientativ. Procentul real si tratamentul TVA se verifica in apelul activ.</p>
    </div>
    <div class="tool-panel">
      <h3>Buget Digitalizare IMM</h3>
      <div class="tool-grid">
        <div class="tool-field"><label for="digitalizare-software">Software</label><input id="digitalizare-software" type="number" value="15000" min="0"></div>
        <div class="tool-field"><label for="digitalizare-hardware">Hardware</label><input id="digitalizare-hardware" type="number" value="10000" min="0"></div>
        <div class="tool-field"><label for="digitalizare-servicii">Implementare si instruire</label><input id="digitalizare-servicii" type="number" value="5000" min="0"></div>
        <div class="tool-field"><label for="digitalizare-security">Securitate si backup</label><input id="digitalizare-security" type="number" value="3000" min="0"></div>
      </div>
      <div id="digitalizare-result" class="tool-result" aria-live="polite"></div>
    </div>
    <div class="tool-panel">
      <h3>Punctaj initial Start-Up Nation</h3>
      <div class="tool-grid">
        <div class="tool-field"><label for="startup-caen">Cod CAEN propus</label><input id="startup-caen" type="text" placeholder="ex: 6201"></div>
        <div class="tool-field"><label for="startup-budget">Buget estimat (EUR)</label><input id="startup-budget" type="number" value="30000" min="0"></div>
        <div class="tool-field"><label for="startup-cofinantare">Cofinantare disponibila (EUR)</label><input id="startup-cofinantare" type="number" value="3000" min="0"></div>
        <div class="tool-field"><label for="startup-jobs">Locuri de munca planificate</label><input id="startup-jobs" type="number" value="1" min="0"></div>
      </div>
      <div id="startup-result" class="tool-result" aria-live="polite"></div>
    </div>
    <div class="tool-panel">
      <h3>Eligibilitate rapida</h3>
      <label><input class="eligibility-check" type="checkbox"> Stiu forma juridica si codul CAEN</label><br>
      <label><input class="eligibility-check" type="checkbox"> Am localitatea si spatiul investitiei</label><br>
      <label><input class="eligibility-check" type="checkbox"> Am buget si cofinantare estimata</label><br>
      <label><input class="eligibility-check" type="checkbox"> Am lista de cheltuieli si oferte orientative</label>
      <div id="eligibility-result" class="tool-result" aria-live="polite"></div>
    </div>
  </section>`;
}

function renderDownloads() {
  const downloads = [
    ["Checklist documente fonduri europene", "/resurse/descarcari/checklist-documente-fonduri-europene.pdf", "PDF"],
    ["Buget Digitalizare IMM", "/resurse/descarcari/buget-digitalizare-imm.xlsx", "Excel"],
    ["Calendar pregatire depunere", "/resurse/descarcari/calendar-pregatire-depunere.xlsx", "Excel"],
    ["Checklist DR12 DR14", "/resurse/descarcari/checklist-afir-dr12-dr14.pdf", "PDF"]
  ];
  return `<div class="download-list">
    ${downloads.map(([title, href, type]) => `<a class="download-card" href="${href}" download><strong>${esc(title)}</strong><span>${esc(type)} descarcabil</span></a>`).join("\n")}
  </div>
  <div class="newsletter-box">
    <strong>Vrei actualizari cand se schimba ghidurile?</strong>
    <p>Trimite un mesaj prin pagina de contact si mentioneaza programul urmarit. Nu promitem aprobari, dar putem semnala ce documente trebuie revizuite.</p>
    <a class="btn btn-primary" href="/contact">Cere actualizari pentru program</a>
  </div>`;
}

function renderConsultantaPillarContent(page) {
  const editorialHtml = renderEditorialSection(getEditorialMetadata(page.slug));
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <h2>Raspuns scurt</h2>
      <p class="intro">FABER ajută firmele, fermierii și antreprenorii să decidă dacă un proiect merită pregătit pentru finanțare, ce program poate fi potrivit și ce riscuri trebuie clarificate înainte de dosar. Analiza pornește de la datele solicitantului, documente, buget și regulile apelului activ.</p>
${editorialHtml}

      <h2>Ce face o firmă de consultanță fonduri europene?</h2>
      <p>O firmă de consultanță pentru fonduri europene verifică dacă solicitantul, activitatea, investiția și documentele disponibile se potrivesc cu un program de finanțare. Rolul ei nu este să promită aprobarea, ci să reducă riscurile înainte ca beneficiarul să investească timp și bani într-un dosar. În practică, consultantul analizează codul CAEN, localitatea, forma juridică, istoricul firmei sau fermei, bugetul, cofinanțarea, cheltuielile propuse și grila de punctaj. Apoi recomandă programul potrivit, structurează strategia de depunere, pregătește documentația, răspunde la clarificări și poate sprijini etapa de contractare sau implementare. O colaborare bună începe cu date minime clare și cu o concluzie prudentă: proiect potrivit, proiect cu riscuri de clarificat sau proiect care nu ar trebui depus în forma actuală.</p>

      <h2>Pentru cine lucrăm</h2>
      <div class="grid">
        <section class="mini-card"><h3>Solicitanți</h3><ul>
          <li>firme existente;</li>
          <li>start-up-uri;</li>
          <li>fermieri;</li>
          <li>microîntreprinderi.</li>
        </ul></section>
        <section class="mini-card"><h3>Tipuri de proiecte</h3><ul>
          <li>proiecte de digitalizare;</li>
          <li>investiții agricole;</li>
          <li>producție și servicii;</li>
          <li>investiții regionale sau energetice, dacă apelul permite.</li>
        </ul></section>
      </div>

      <h2>Ce verificăm înainte de dosar</h2>
      <p>Verificarea inițială separă ideile promițătoare de dosarele riscante. Tabelul de mai jos arată informațiile cerute înainte de recomandarea unui program sau a unei strategii de punctaj.</p>
      <div class="table-wrap">
        <table class="program-table">
          <thead>
            <tr>
              <th>Element verificat</th>
              <th>De ce contează</th>
              <th>Documente/date necesare</th>
              <th>Risc dacă este ignorat</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Solicitant și formă juridică</td>
              <td>Programul poate accepta doar anumite categorii de beneficiari.</td>
              <td>CUI, certificat constatator, formă juridică, vechime.</td>
              <td>Dosar respins administrativ sau eligibilitate interpretată greșit.</td>
            </tr>
            <tr>
              <td>Cod CAEN și activitate reală</td>
              <td>Investiția trebuie să fie legată de activitatea finanțată.</td>
              <td>Coduri CAEN, autorizări, descriere activitate, punct de lucru.</td>
              <td>Cheltuieli neeligibile sau punctaj supraestimat.</td>
            </tr>
            <tr>
              <td>Localizare și spațiu</td>
              <td>Multe apeluri depind de regiune, rural/urban sau dreptul de folosință.</td>
              <td>Adresă proiect, contract spațiu, acte teren/clădire, durată folosință.</td>
              <td>Blocaj la contractare, clarificări sau imposibilitate de implementare.</td>
            </tr>
            <tr>
              <td>Buget și cofinanțare</td>
              <td>Grantul nu acoperă toate costurile și nu elimină presiunea de cash-flow.</td>
              <td>Buget estimativ, oferte, sursă cofinanțare, tratament TVA.</td>
              <td>Proiect aprobat pe hârtie, dar greu de susținut financiar.</td>
            </tr>
            <tr>
              <td>Cheltuieli propuse</td>
              <td>Fiecare achiziție trebuie să fie permisă și justificată prin obiective.</td>
              <td>Listă echipamente/servicii, specificații, oferte, justificare necesitate.</td>
              <td>Tăieri de buget, corecții sau respingere la evaluare.</td>
            </tr>
            <tr>
              <td>Punctaj și priorități</td>
              <td>Eligibilitatea nu înseamnă automat selecție la finanțare.</td>
              <td>Grilă de evaluare, criterii aplicabile, documente care susțin punctajul.</td>
              <td>Depunere cu șanse slabe sau strategie construită pe presupuneri.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2>Programe, CAEN si exemple numerice 2026</h2>
      <p>Exemplele de mai jos sunt orientative si folosesc procente simple ca exercitiu de buget. Pragurile, intensitatea sprijinului, punctajul si calendarul se confirma in ghidul activ al fiecarui apel.</p>
      <div class="table-wrap">
        <table class="program-table">
          <thead>
            <tr>
              <th>Program</th>
              <th>CAEN sau profil potrivit</th>
              <th>Buget / sprijin orientativ</th>
              <th>Exemplu numeric prudent</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>AFIR DR12</td>
              <td>Tineri fermieri si investitii agricole, conform ghidului activ.</td>
              <td>Pragurile se confirma in documentele AFIR pentru sesiunea activa.</td>
              <td>La o investitie eligibila de 100.000 EUR si contributie proprie de 30%, beneficiarul pregateste 30.000 EUR contributie si verifica documentele pentru diferenta finantata.</td>
            </tr>
            <tr>
              <td>AFIR DR14</td>
              <td>Ferme mici, modernizare si investitii direct legate de exploatatie.</td>
              <td>Sprijinul si intensitatea se confirma in ghidul DR14 activ.</td>
              <td>La 40.000 EUR cheltuieli eligibile si sprijin estimat de 85%, analiza bugetului porneste de la 34.000 EUR grant si 6.000 EUR contributie.</td>
            </tr>
            <tr>
              <td>Digitalizare IMM</td>
              <td>CAEN 6201, servicii, productie sau comert cu nevoie reala de software, hardware si securitate.</td>
              <td>Bugetul maxim si procentul se confirma in apelul activ.</td>
              <td>Un proiect de 60.000 EUR poate include software, echipamente si instruire; la 90% sprijin orientativ, contributia proprie estimata este 6.000 EUR.</td>
            </tr>
            <tr>
              <td>Program Regional Nord-Est</td>
              <td>Microintreprinderi si IMM-uri cu investitii productive sau modernizare, in functie de regiune si CAEN.</td>
              <td>Intervalele si cofinantarea depind de ghidul ADR activ.</td>
              <td>La 150.000 EUR cheltuieli eligibile si 80% sprijin orientativ, grantul estimat este 120.000 EUR, iar contributia 30.000 EUR.</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="table-wrap">
        <table class="program-table">
          <thead>
            <tr><th>Cod CAEN</th><th>Exemplu de investitie</th><th>Program de verificat</th><th>Risc frecvent</th></tr>
          </thead>
          <tbody>
            <tr><td>0111</td><td>utilaje pentru culturi de camp</td><td>AFIR / agricultura</td><td>dimensiune economica sau documente agricole incomplete</td></tr>
            <tr><td>4321</td><td>echipamente pentru instalatii electrice</td><td>regional, energie, digitalizare</td><td>legatura slaba intre achizitie si activitatea autorizata</td></tr>
            <tr><td>5610</td><td>dotari restaurant si eficienta operationala</td><td>regional / IMM</td><td>cheltuieli care nu sustin punctajul apelului</td></tr>
            <tr><td>6201</td><td>software, echipamente IT, securitate cibernetica</td><td>Digitalizare IMM / programe regionale</td><td>buget IT prea general sau indicatori neclar formulati</td></tr>
          </tbody>
        </table>
      </div>

      <h2>Cum decurge procesul</h2>
      <ol class="process-list">
        <li><strong>Discuție inițială.</strong> Clarificăm solicitantul, investiția, bugetul și termenul dorit.</li>
        <li><strong>Analiză eligibilitate.</strong> Verificăm datele minime, documentele disponibile și riscurile evidente.</li>
        <li><strong>Alegere program.</strong> Comparăm apelurile relevante și eliminăm programele nepotrivite.</li>
        <li><strong>Strategie punctaj.</strong> Estimăm prudent criteriile care pot fi susținute prin documente.</li>
        <li><strong>Dosar.</strong> Pregătim cererea, bugetul, anexele și justificările necesare.</li>
        <li><strong>Depunere.</strong> Verificăm forma finală și încărcarea documentelor în platforma programului.</li>
        <li><strong>Clarificări.</strong> Răspundem solicitărilor primite de la autoritate, pe baza documentelor.</li>
        <li><strong>Contractare.</strong> Verificăm condițiile de semnare, termenele și obligațiile beneficiarului.</li>
        <li><strong>Implementare.</strong> Sprijinim achizițiile, raportările și cererile de plată/rambursare dacă serviciul este inclus.</li>
      </ol>

      <h2>Ce NU promitem</h2>
      <ul class="warning-list">
        <li>Nu promitem finanțare garantată.</li>
        <li>Nu recomandăm programe nepotrivite doar pentru a depune un dosar.</li>
        <li>Nu estimăm șanse fără date minime despre solicitant, investiție, buget și documente.</li>
      </ul>
      <p>Un răspuns responsabil poate fi uneori „nu acum” sau „nu pe acest program”. Este mai util să oprești un dosar slab înainte de depunere decât să consumi resurse într-un proiect care nu poate fi susținut.</p>

      <h2>Cost consultanță fonduri europene</h2>
      <p>Costul consultanței depinde de program, complexitatea investiției, documentele existente, etapa în care se află proiectul și suportul cerut după depunere. Un dosar simplu, cu documente pregătite, nu se estimează la fel ca un proiect cu investiții tehnice, achiziții complexe, clarificări sau implementare pe termen lung.</p>
      <p>Nu introducem prețuri standard dacă ele nu există deja în proiect. Pentru o estimare prudentă, trimite datele de bază și programul vizat, iar FABER poate indica ce trebuie verificat înainte de ofertare.</p>
      <p><a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Solicită evaluare pentru cost</a></p>

      <h2>Programe relevante</h2>
      <p>Pagina aceasta funcționează ca punct de intrare. Pentru reguli, documente și condiții specifice, verifică pagina programului potrivit și sursa oficială a apelului activ.</p>
      <div class="related-links">
        <a href="/consultanta-afir">Consultanță AFIR</a>
        <a href="/dr12-afir">DR 12 AFIR</a>
        <a href="/dr14">DR 14 AFIR</a>
        <a href="/start-up-nation-2026">Start-Up Nation</a>
        <a href="/digitalizare-imm">Digitalizare IMM</a>
        <a href="/por-adr-nord-est">POR / ADR Nord-Est</a>
        <a href="/fonduri-europene-agricultura">Fonduri europene agricultură</a>
        <a href="/fondul-de-modernizare">Fondul de Modernizare</a>
      </div>

      <h2>Ce intră, de regulă, într-un dosar</h2>
      <p>Un dosar pentru fonduri europene nu este doar un formular completat. El trebuie să lege solicitantul, investiția, bugetul și documentele suport într-o explicație coerentă. Documentele diferă de la program la program, dar de obicei includ informații despre firmă sau fermă, situații financiare, acte pentru spațiu, oferte, descrierea investiției, buget, declarații și anexe specifice apelului.</p>
      <p>Înainte de depunere, verificarea internă trebuie să urmărească dacă fiecare afirmație poate fi susținută prin documente. Dacă bugetul include echipamente, serviciile sau lucrările trebuie să fie justificate prin nevoia proiectului. Dacă se solicită punctaj pentru o condiție, acea condiție trebuie să poată fi demonstrată. Această disciplină reduce clarificările și riscul de respingere.</p>

      <h2>Responsabilități în colaborare</h2>
      <p>Consultanța funcționează bine atunci când responsabilitățile sunt clare de la început. Beneficiarul cunoaște activitatea, investiția și constrângerile reale ale afacerii. Consultantul cunoaște logica programului, documentele cerute, riscurile frecvente și modul în care informațiile trebuie așezate în dosar. Niciuna dintre părți nu poate înlocui complet rolul celeilalte.</p>
      <ul>
        <li>Clientul furnizează date corecte despre firmă, fermă, localizare, buget și documentele disponibile.</li>
        <li>FABER verifică potrivirea cu programele relevante și semnalează riscurile înainte de depunere.</li>
        <li>Bugetul se construiește pe oferte și justificări, nu pe estimări optimiste.</li>
        <li>Decizia de depunere se ia după verificarea ghidului activ și a documentelor minime.</li>
      </ul>
      <p>Această împărțire este importantă mai ales când proiectul trece din etapa de idee în etapa de implementare. După contractare, apar termene, achiziții, raportări și obligații de menținere a investiției. Un dosar pregătit corect ar trebui să poată fi implementat, nu doar depus.</p>

      <h2>Riscuri frecvente înainte de depunere</h2>
      <p>Cele mai multe probleme apar când proiectul este construit prea repede sau când programul este ales doar pentru că pare popular. Un cod CAEN nealiniat cu investiția, un spațiu fără documente suficiente, o ofertă prea generală sau o cofinanțare neclară pot transforma o idee bună într-un dosar vulnerabil. De aceea, verificarea eligibilității trebuie făcută înainte de achiziții, contracte ferme sau promisiuni către furnizori.</p>
      <p>Un alt risc este supraestimarea punctajului. Dacă un criteriu nu poate fi susținut prin documente, el nu ar trebui tratat ca punctaj sigur. La fel, dacă un program cere condiții de vechime, localizare, dimensiune economică sau activitate autorizată, aceste elemente trebuie confirmate înainte de a investi în documentație completă.</p>

      <h2>Când recomandăm să nu depui imediat</h2>
      <p>Există situații în care o amânare este mai sănătoasă decât o depunere rapidă. Dacă documentele pentru spațiu nu acoperă perioada cerută, dacă ofertele nu descriu suficient cheltuielile, dacă solicitantul nu poate susține cofinanțarea sau dacă activitatea nu este clar legată de investiție, dosarul trebuie corectat înainte de depunere. Aceeași prudență se aplică atunci când programul este încă în consultare, când ghidul nu este final sau când informațiile publice nu permit o estimare serioasă a punctajului. În aceste cazuri, rolul consultanței este să protejeze beneficiarul de decizii costisitoare, nu să forțeze un dosar doar pentru a respecta un calendar comercial. Concluzia trebuie documentată și revizuită când apar reguli noi.</p>
      <p>Pentru proiectele aflate la limită, recomandarea poate fi pregătirea documentelor lipsă, ajustarea investiției, schimbarea calendarului sau urmărirea unui apel viitor. Această etapă nu blochează proiectul; îl face mai ușor de apărat la evaluare.</p>

      <section class="faq" aria-labelledby="consultanta-faq">
        <h2 id="consultanta-faq">Intrebari frecvente</h2>
        ${faqHtml}
      </section>

      <h2>Surse și metodologie</h2>
      <p>Metodologia FABER pornește de la verificarea eligibilității, a documentelor, a grilei de punctaj și a riscurilor de implementare. Pentru decizii finale se verifică întotdeauna ghidul oficial, anexele, corrigendumurile și comunicările autorității.</p>
      <div class="related-links">
        <a href="/metodologie-verificare-eligibilitate">Metodologia FABER</a>
        <a href="/surse-oficiale-fonduri-europene">Surse oficiale fonduri europene</a>
        <a href="/glosar-fonduri-europene">Glosar fonduri europene</a>
        <a href="/verificare-eligibilitate-fonduri-europene">Verificare eligibilitate</a>
      </div>
      ${officialSourcesHtml}
      <p class="note">Data actualizării: <time datetime="2026-05-20">20 mai 2026</time>. Indicatorii comerciali precum număr de proiecte, valoare atrasă sau rată de aprobare trebuie publicați doar dacă există documente interne, portofoliu sau metodologie care îi susțin.</p>
`;
}

function renderDr14Score() {
  return `<section class="mini-card dr14-score-tool" aria-labelledby="dr14-score-title">
      <h2 id="dr14-score-title">Estimator rapid punctaj DR14</h2>
      <p>Acest estimator este orientativ si ajuta la discutia initiala. Punctajul real se confirma doar prin grila apelului activ si documentele solicitantului.</p>
      <label><input type="checkbox" name="dr14-mountain" data-score-input data-score-value="10"> Exploatatia este in zona montana sau intr-o zona cu constrangeri specifice.</label>
      <label><input type="checkbox" name="dr14-young" data-score-input data-score-value="5"> Solicitantul are profil agricol cu experienta sau pregatire relevanta.</label>
      <label><input type="checkbox" name="dr14-investment" data-score-input data-score-value="5"> Investitia sustine modernizarea directa a fermei mici.</label>
      <p><strong>Punctaj orientativ:</strong> <span data-score-total>0</span></p>
      <script>
        (function(){
          var inputs = document.querySelectorAll('[data-score-input]');
          var total = document.querySelector('[data-score-total]');
          function updateScore(){
            var score = 0;
            inputs.forEach(function(input){ if(input.checked){ score += Number(input.getAttribute('data-score-value') || 0); } });
            if(total){ total.textContent = String(score); }
          }
          inputs.forEach(function(input){ input.addEventListener('change', updateScore); });
          updateScore();
        })();
      </script>
    </section>`;
}

function renderTrustMethodology() {
  return `
      <h2>Metodologie de anonimizare si actualizare</h2>
      <p>Inainte ca un exemplu sa fie publicat, FABER elimina datele care pot identifica direct beneficiarul: nume, adresa exacta, furnizori, contracte, documente financiare si detalii comerciale sensibile. Daca proiectul poate fi recunoscut usor prin combinatia dintre localitate, domeniu si valoare, informatia este agregata sau transformata intr-un interval orientativ.</p>
      <p>Actualizarea se face cand exista un motiv real: ghid schimbat, apel nou, acord de publicare, rezultat documentat sau lectie relevanta pentru alti beneficiari. Nu completam paginile cu rezultate inventate si nu transformam feedbackul in promisiuni comerciale. Acolo unde o cifra nu poate fi dovedita, informatia ramane nepublicata sau este explicata ca scenariu orientativ.</p>
      <h2>Ce poti invata din aceste exemple</h2>
      <p>Cel mai important lucru este ordinea verificarii. Un proiect solid incepe cu eligibilitatea solicitantului si continua cu documentele, investitia, bugetul si punctajul. Daca se porneste direct de la suma maxima sau de la o lista de cumparaturi, apar frecvent blocaje: cheltuieli greu de justificat, cofinantare insuficienta, documente pentru spatiu incomplete sau criterii de punctaj care nu pot fi sustinute.</p>
      <p>Exemplele trebuie folosite ca punct de orientare pentru discutia initiala. Pentru decizia finala, FABER verifica ghidul activ, anexele, clarificarile autoritatii si documentele concrete ale beneficiarului. Aceasta separare mentine pagina utila fara sa creeze asteptari false.</p>
      <p>Un beneficiar poate folosi aceste pagini pentru a pregati intrebari mai bune: ce document lipseste, ce cheltuiala este sensibila, ce suma trebuie acoperita din surse proprii si ce criteriu de selectie merita verificat primul.</p>`;
}

function renderTrustContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  if (page.slug === "portofoliu") {
    return `
      <p class="snippet-box">Portofoliul FABER include doar proiecte anonimizate si aprobate pentru publicare. Cand lipsesc acordul, dovezile sau nivelul corect de anonimizare, exemplul nu este afisat public.</p>
      <h2>Criterii pentru un exemplu publicabil</h2>
      <div class="case-grid">
        <article class="case-card">
          <h3>Acord explicit</h3>
          <p>Exemplul poate fi publicat doar dupa acceptul beneficiarului pentru informatiile folosite si pentru nivelul de anonimizare ales.</p>
        </article>
        <article class="case-card">
          <h3>Date verificabile</h3>
          <p>Programul, tipul solicitantului, provocarea si concluzia trebuie sustinute de documente interne sau surse publice.</p>
        </article>
        <article class="case-card">
          <h3>Anonimizare suficienta</h3>
          <p>Numele, adresa exacta, furnizorii, contractele si detaliile financiare sensibile sunt eliminate sau agregate.</p>
        </article>
        <article class="case-card">
          <h3>Lectie utila</h3>
          <p>Un caz publicabil trebuie sa explice o decizie, un risc sau o lectie practica, nu doar sa afiseze o suma sau un rezultat.</p>
        </article>
      </div>
      <h2>Cum interpretezi portofoliul</h2>
      <p>Un portofoliu de consultanta pentru fonduri europene trebuie citit ca o harta de experienta, nu ca o garantie. Pentru fiecare exemplu conteaza tipul solicitantului, programul urmarit, documentele disponibile, nivelul de cofinantare si riscurile aparute inainte de depunere. Doua proiecte cu aceeasi valoare pot avea dificultati complet diferite daca unul depinde de acte pentru teren, iar altul depinde de software, indicatori digitali sau avize tehnice.</p>
      <p>FABER publica exemple anonimizate pentru a proteja datele comerciale ale clientilor. Numele, localitatea exacta, furnizorii si documentele interne nu sunt afisate fara acord explicit. In schimb, pagina arata ce tip de gandire este utila: buget verificat, eligibilitate documentata, punctaj estimat prudent si clarificari pregatite pe dovezi.</p>
      <h2>Ce ar trebui sa intre intr-un caz publicabil</h2>
      <ul>
        <li>programul sau familia de programe urmarita;</li>
        <li>valoarea proiectului sau un interval orientativ aprobat pentru publicare;</li>
        <li>cofinantarea si cheltuielile neeligibile explicate separat;</li>
        <li>provocarea principala: CAEN, SO, locatie, documente, avize, buget sau punctaj;</li>
        <li>rezultatul publicabil: dosar pregatit, buget ajustat, risc clarificat sau decizie de amanare.</li>
      </ul>
      <p>In practica, un studiu de caz util nu ascunde blocajele. Daca o investitie a fost ajustata, acest lucru poate fi mai valoros pentru un beneficiar decat o prezentare lucioasa. Arata unde se pierd puncte, ce documente trebuie obtinute mai devreme si de ce un proiect trebuie uneori restrans pentru a ramane implementabil.</p>
      <p>Cat timp lipsesc acordul, dovada sau anonimizarea suficienta, portofoliul ramane un cadru editorial. Echipa poate adauga un caz doar dupa ce confirma sursa informatiei, formularea valorilor si nivelul de anonimizare. Daca una dintre aceste conditii lipseste, exemplul ramane intern si nu este folosit pentru promovare.</p>
      <h2>Cand actualizam exemplele</h2>
      <p>Exemplele sunt revizuite cand se modifica ghidurile, cand apar dovezi publicabile sau cand clientul permite folosirea unor detalii suplimentare. Daca un rezultat nu poate fi sustinut prin documente, el nu este transformat in claim comercial. Aceeasi prudenta se aplica valorilor totale, ratelor de succes sau sumelor atrase: ele trebuie sa aiba baza clara inainte de publicare.</p>
      ${renderTrustMethodology()}
      <p class="note">Portofoliul nu garanteaza rezultate viitoare. Exemplele sunt anonimizate si se publica doar cand exista acord si dovada.</p>
      ${officialSourcesHtml}
      <h2>Intrebari frecvente</h2>
      ${faqHtml}`;
  }

  if (page.slug === "testimoniale") {
    return `
      <p class="snippet-box">Testimonialele FABER se publica doar dupa acord explicit si fara date care pot identifica beneficiarul, daca acesta cere anonimizare. Pana la confirmarea citatelor reale, pagina descrie metodologia de colectare si criteriile pentru feedback publicabil.</p>
      <h2>Ce trebuie sa contina un testimonial aprobat</h2>
      <div class="case-grid">
        <article class="case-card">
          <h3>Claritate documente</h3>
          <p>Clientul poate confirma ce documente au fost clarificate si daca informatia poate fi publicata cu nume, initiale sau anonim.</p>
        </article>
        <article class="case-card">
          <h3>Buget si cheltuieli</h3>
          <p>Feedbackul poate mentiona separarea costurilor doar daca nu dezvaluie valori confidentiale sau detalii comerciale sensibile.</p>
        </article>
        <article class="case-card">
          <h3>Riscuri explicate</h3>
          <p>Un testimonial util descrie prudent ce risc a fost inteles mai bine, fara sa promita aprobare sau punctaj.</p>
        </article>
        <article class="case-card">
          <h3>Acord de publicare</h3>
          <p>Citatul final se adauga doar dupa confirmarea clientului si dupa eliminarea datelor personale sau confidentiale.</p>
        </article>
      </div>
      <h2>Cum colectam si verificam feedbackul</h2>
      <p>Feedbackul este util doar daca descrie o etapa reala de lucru. Pentru FABER, un testimonial publicabil trebuie sa raspunda la intrebari simple: ce a fost clarificat, ce documente au fost mai bine organizate, ce risc a fost observat si cum a ajutat comunicarea in proces. Nu publicam citate care promit aprobare, sugereaza rezultate garantate sau contin date pe care clientul nu le-a aprobat.</p>
      <p>Clientul poate alege publicarea cu nume, initiale sau anonimizare completa. Cand exista informatii sensibile, preferam anonimizarea. Aceasta decizie protejeaza proiectul, furnizorii, datele financiare si documentele depuse. Testimonialul ramane valoros chiar si fara nume complet daca explica o experienta concreta: claritate in eligibilitate, buget mai coerent, lista de documente mai buna sau raspunsuri la clarificari pregatite metodic.</p>
      <h2>Ce nu inseamna un testimonial</h2>
      <p>Un testimonial nu este dovada ca un program va aproba proiecte similare. El arata modul de lucru si calitatea colaborarii, nu decizia autoritatii finantatoare. De aceea, fiecare citat este insotit de context si de limitari: programul se poate schimba, ghidul activ poate cere alte documente, iar punctajul depinde de grila si de dovezile solicitantului.</p>
      <p>Pentru beneficiari, testimonialele pot fi folosite ca filtru de incredere: daca feedbackul vorbeste despre prudenta, documente si claritate, colaborarea are sanse mai bune sa fie realista. Daca un consultant promite doar sume, procente sau aprobare sigura, merita cerute explicatii suplimentare si surse oficiale.</p>
      <p>Cand citesti feedbackul, urmareste detaliile verificabile: etapa proiectului, tipul investitiei, documentele clarificate si modul in care au fost tratate riscurile. Un citat scurt, dar concret, este mai util decat o lauda generala, pentru ca arata ce se intampla in colaborare: intrebari puse la timp, bugete explicate, decizii prudente si comunicare clara inainte de termenele limita.</p>
      <h2>Cum poate fi trimis un testimonial</h2>
      <p>Dupa o etapa de lucru, beneficiarul poate trimite feedback prin email sau prin pagina de contact. FABER poate propune o forma scurta, iar clientul confirma ce poate fi publicat. Fara acord, feedbackul ramane intern si nu este folosit in pagina.</p>
      ${renderTrustMethodology()}
      <p class="note">Nu publicam nume, valori sau rezultate financiare fara acord explicit. Cand clientul permite publicarea numelui, pagina poate fi actualizata cu cite complete.</p>
      ${officialSourcesHtml}
      <h2>Intrebari frecvente</h2>
      ${faqHtml}`;
  }

  if (page.slug === "studii-de-caz") {
    return `
      <p class="snippet-box">Studiile de caz FABER se publica doar cand exista materiale reale, anonimizare si acord pentru detaliile folosite. Pana atunci, pagina stabileste structura unui caz publicabil: problema, analiza, documente, decizie si rezultat dovedit.</p>
      <h2>Format pentru studii de caz validate</h2>
      <div class="case-grid">
        <article class="case-card">
          <h3>Context</h3>
          <p>Tip solicitant, domeniu, regiune si program vizat, fara nume, CUI, adresa exacta sau date care pot identifica beneficiarul.</p>
        </article>
        <article class="case-card">
          <h3>Problema verificata</h3>
          <p>Documente lipsa, CAEN, SO, locatie, buget, cofinantare sau cheltuieli sensibile, descrise fara informatii confidentiale.</p>
        </article>
        <article class="case-card">
          <h3>Ce a verificat FABER</h3>
          <p>Eligibilitate, documente, buget, punctaj, surse oficiale si riscuri, cu mentiunea clara ca analiza nu garanteaza finantarea.</p>
        </article>
        <article class="case-card">
          <h3>Rezultat publicabil</h3>
          <p>Doar rezultate aprobate pentru publicare: decizie de depunere, amanare, ajustare de buget, risc clarificat sau lectie invatata.</p>
        </article>
      </div>
      <h2>Cum sunt construite studiile de caz</h2>
      <p>Un studiu de caz bun porneste de la problema, nu de la suma. Inainte de a discuta grantul, trebuie vazut daca solicitantul poate demonstra eligibilitatea, daca investitia are legatura cu activitatea si daca documentele pot sustine bugetul. Aceasta abordare ajuta beneficiarul sa inteleaga ce trebuie rezolvat inainte de depunere.</p>
      <p>In fiecare caz, FABER urmareste aceeasi logica: solicitant, activitate, locatie, buget, cofinantare, cheltuieli, punctaj, documente si calendar. Daca una dintre aceste piese este slaba, proiectul poate fi ajustat sau amanat. Un rezultat bun poate fi inclusiv decizia de a nu depune imediat, pentru ca evita costuri si asteptari nerealiste.</p>
      <p>Un caz nu este publicat doar pentru ca seamana cu o situatie frecventa. Trebuie sa existe o baza verificabila: ce program a fost analizat, ce documente au existat, ce decizie a fost luata si ce detalii pot fi facute publice. Aceasta regula pastreaza pagina utila pentru cititori fara sa transforme exemplele in reclame sau promisiuni.</p>
      <h2>Lectii care se repeta in proiecte</h2>
      <ul>
        <li>un cod CAEN potrivit nu ajuta daca investitia nu este justificata operational;</li>
        <li>o oferta generica poate slabi un buget altfel bun;</li>
        <li>cofinantarea trebuie confirmata inainte de depunere, nu dupa selectie;</li>
        <li>punctajul se estimeaza doar pe criterii care pot fi dovedite;</li>
        <li>clarificarile sunt mai usor de gestionat cand dosarul a fost documentat ordonat.</li>
      </ul>
      <p>Aceste lectii sunt valabile pentru agricultura, digitalizare, energie si proiecte regionale. Diferenta este data de documentele specifice: o ferma are nevoie de date agricole si calcul SO, un IMM de digitalizare are nevoie de justificarea proceselor, iar un proiect energetic are nevoie de consum, avize si dimensionare.</p>
      <h2>Ce trimiti pentru un studiu aplicat pe cazul tau</h2>
      <p>Pentru o discutie initiala, sunt utile datele solicitantului, codul CAEN sau descrierea fermei, localitatea investitiei, bugetul estimat, lista de cheltuieli dorite, cofinantarea disponibila si documentele deja pregatite. Cu aceste informatii, FABER poate indica ce program merita verificat si ce lipseste inainte de dosarul complet.</p>
      <p>Daca informatiile sunt incomplete, studiul de caz se opreste la nivel de lectie generala. Publicarea se face doar dupa ce forma finala nu mai expune date personale, contracte, furnizori sau cifre care pot identifica beneficiarul.</p>
      ${renderTrustMethodology()}
      ${officialSourcesHtml}
      <h2>Intrebari frecvente</h2>
      ${faqHtml}`;
  }

  return "";
}

function renderAfirHubContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");
  const programRows = [
    ["Consultanta AFIR", "beneficiari care au nevoie de verificarea traseului, documentelor si bugetului", "solicitant, exploatatie, SO/SOC, investitie, cofinantare si riscuri", "/consultanta-afir"],
    ["Calculator SO/SOC", "solicitanti care cauta calcul SO AFIR, calculator SO AFIR sau incadrare economica", "date actuale despre culturi, animale si exploatatie", "/calculator-soc"],
    ["DR 12 AFIR", "tineri fermieri si exploatatii care trebuie sa dovedeasca rolul solicitantului", "profil solicitant, exploatatie, calcul SO/SOC, documente de folosinta", "/dr12-afir"],
    ["DR 14 AFIR", "ferme mici care urmaresc modernizare proportionala cu activitatea reala", "incadrare ferma mica, documente exploatatie, buget si grila activa", "/dr14"],
    ["Autoconsum agroalimentar", "beneficiari care verifica investitii in energie pentru activitatea agroalimentara", "consum, amplasament, avize, capacitate si costuri neeligibile", "/afir-autoconsum-agroalimentar"],
    ["Fonduri pentru utilaje agricole", "ferme care vor echipamente legate direct de productie", "necesitate, dimensiune, oferte si corelare cu activitatea", "/fonduri-pentru-utilaje-agricole"],
    ["GAL-AFIR / LEADER", "beneficiari care verifica apeluri locale prin GAL si proceduri AFIR", "localitate in teritoriul GAL, ghid local, criterii si documente", "/gal-afir"]
  ];

  return `
      <p class="intro">${esc(page.quickAnswer)} Hub-ul AFIR este punctul de intrare pentru fermieri care vor sa aleaga intre interventii, sa verifice documentele exploatatiei si sa pregateasca o discutie realista despre eligibilitate.</p>
      <p class="snippet-box">Pe scurt: foloseste aceasta pagina pentru trierea initiala AFIR. Porneste de la solicitant, ferma, SO/SOC, documente, investitie si cofinantare. Apoi mergi in pagina programului potrivit si confirma regulile in ghidul oficial activ, pentru ca sumele, pragurile, grilele si termenele pot fi diferite de la un apel la altul.</p>
      ${renderTable(page)}
      <h2>Ce problema rezolva hub-ul AFIR</h2>
      <p>Multe cautari despre AFIR pornesc de la o intrebare prea larga: ce bani pot lua pentru ferma. O analiza utila incepe mai precis. Intai se verifica solicitantul, apoi exploatatia, dimensiunea economica, dreptul de folosinta asupra terenurilor sau animalelor, investitia propusa, capacitatea de cofinantare si documentele care pot sustine fiecare afirmatie.</p>
      <p>Hub-ul grupeaza paginile agricole principale si explica ordinea verificarii. Nu inlocuieste ghidul solicitantului, nu stabileste praguri finale si nu promite aprobare. Rolul sau este sa reduca riscul de a pregati un dosar pe programul gresit sau cu documente care se contrazic.</p>
${renderDecisionMatrix(page)}
      <h2>Harta programelor AFIR si a paginilor utile</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Resursa</th><th>Cand o folosesti</th><th>Ce verifici inainte de buget</th><th>Pagina</th></tr></thead>
          <tbody>
            ${programRows.map(([name, use, check, href]) => `<tr><td>${esc(name)}</td><td>${esc(use)}</td><td>${esc(check)}</td><td><a href="${href}">${esc(labelForHref(href))}</a></td></tr>`).join("\n")}
          </tbody>
        </table>
      </div>
      <h2>Calcul SO AFIR si calculator SO AFIR</h2>
      <p>Cautarile de tip calcul SO AFIR, calculator SO AFIR, AFIR SO sau AFIR calcul SO au o intentie practica: beneficiarul vrea sa afle daca exploatatia poate fi incadrata economic in programul potrivit. Hub-ul explica ordinea verificarii, iar calculul efectiv se face in pagina <a href="/calculator-soc">Calculator SO/SOC</a>, pe date care pot fi sustinute prin documente.</p>
      <p>Rezultatul calculatorului nu decide singur programul. Dupa calcul se verifica solicitantul, forma juridica, dreptul de folosinta, documentele APIA sau ANSVSA, investitia si cofinantarea. Daca datele sunt incomplete sau mai multe interventii par posibile, urmatorul pas este <a href="/consultanta-afir">consultanta AFIR</a>, nu blocarea bugetului pe o presupunere.</p>
      <h2>GAL-AFIR in hub: cand mergi la pagina LEADER</h2>
      <p>Cautarile pentru GAL-AFIR trebuie separate de programele AFIR nationale. Daca proiectul depinde de un Grup de Actiune Locala, verificarea se muta pe teritoriul GAL, ghidul local, criteriile locale si fluxul AFIR aplicabil. Pentru acest traseu, consult? <a href="/gal-afir">GAL-AFIR / LEADER</a> ?i apoi confirm? sursa local?.</p>
      <h2>DR12, DR14 si alegerea programului potrivit</h2>
      <p>DR12 si DR14 sunt adesea comparate pentru ca ambele pot fi relevante in agricultura, dar criteriile nu trebuie amestecate. DR12 se analizeaza cand profilul solicitantului si logica de instalare sau consolidare a unui tanar fermier sunt centrale. DR14 se analizeaza cand punctul de plecare este ferma mica si dezvoltarea ei proportionala cu activitatea existenta.</p>
      <p>Daca o familie lucreaza terenuri impreuna, daca actele sunt impartite intre mai multe persoane sau daca investitia a fost aleasa inaintea calculului SO/SOC, decizia trebuie amanata pana cand documentele spun aceeasi poveste. O pagina de program ajuta doar dupa ce datele fermei sunt ordonate.</p>
      <p>Pentru o comparatie aplicata intre cele doua interventii, foloseste si pagina <a href="/dr12-vs-dr14">DR12 vs DR14</a>. Pentru o analiza specifica fermei mici, mergi in pagina <a href="/dr14">DR14 AFIR ferme mici</a>. Ambele pagini pastreaza formularea prudenta: concluzia finala depinde de ghidul activ si de documentele solicitantului.</p>
      <h2>Documente care trebuie pregatite devreme</h2>
      <p>In proiectele agricole, documentele nu sunt o formalitate de final. Ele decid daca investitia poate fi sustinuta. Daca dreptul de folosinta, calculul SO/SOC, ofertele sau anexele nu se potrivesc, proiectul poate intra in clarificari sau poate deveni greu de aparat.</p>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Document / informatie</th><th>De ce conteaza</th><th>Risc daca lipseste</th></tr></thead>
          <tbody>
            <tr><td>Date despre exploatatie</td><td>Arata ce culturi, animale sau activitati exista in prezent.</td><td>Dimensiune economica neclara sau incadrare gresita.</td></tr>
            <tr><td>Documente de folosinta</td><td>Dovedesc terenul, spatiul, adaposturile sau punctul de lucru.</td><td>Blocaj la eligibilitate, contractare sau implementare.</td></tr>
            <tr><td>Calcul SO/SOC</td><td>Leaga ferma reala de interventia potrivita.</td><td>Alegerea unui program nepotrivit sau punctaj supraestimat.</td></tr>
            <tr><td>Oferte si specificatii</td><td>Explica achizitiile si legatura lor cu activitatea agricola.</td><td>Buget slab justificat sau cheltuieli taiate la evaluare.</td></tr>
            <tr><td>Cofinantare si cash-flow</td><td>Arata daca proiectul poate fi sustinut dupa selectie.</td><td>Proiect aprobat pe hartie, dar greu de implementat.</td></tr>
          </tbody>
        </table>
      </div>
      <h2>Buget, cofinantare si valori nepresupuse</h2>
      <p>Bugetul AFIR trebuie construit dupa verificarea eligibilitatii, nu inainte. Un utilaj sau o lucrare poate fi utila comercial, dar trebuie sa fie permisa de ghid, proportionala cu ferma si justificata prin obiectivele proiectului. Diferenta dintre cheltuieli eligibile si costuri suportate separat trebuie explicata de la inceput.</p>
      <p>Pe hub-ul AFIR nu folosim procente, plafoane sau calendare ca si cum ar fi reguli finale. Fiecare valoare se confirma in pagina programului si in ghidul aplicabil. Rolul hub-ului este sa arate ce trebuie verificat inainte de oferte, contracte sau decizia de depunere.</p>
      ${renderCofinancingExample(page)}
      ${renderCalendarTable(page)}
      <h2>Cum folosesti calculatorul SO/SOC</h2>
      <p>Calculatorul SO/SOC este util cand datele introduse sunt actuale si pot fi dovedite. Nu este suficient sa obtii o cifra; trebuie pastrata legatura dintre calcul, documentele exploatatiei si programul analizat. Daca datele despre culturi sau efective nu sunt stabile, concluzia de eligibilitate trebuie tratata ca provizorie.</p>
      <p>Inainte de o discutie cu FABER, pregateste tipul fermei, localitatea, suprafetele, efectivele, forma juridica, documentele de folosinta si investitia dorita. Cu aceste informatii se poate decide daca merita analizat DR12, DR14, o pagina despre utilaje, o interventie de energie sau un alt apel.</p>
      <h2>Riscuri frecvente la proiecte AFIR</h2>
      <ul>
        <li>program ales dupa denumire, fara verificarea ghidului activ;</li>
        <li>calcul SO/SOC facut pe date incomplete sau greu de dovedit;</li>
        <li>terenuri, animale sau puncte de lucru cu documente nealiniate;</li>
        <li>investitie aleasa inainte de analiza activitatii reale;</li>
        <li>oferte generale, fara specificatii tehnice si fara justificare;</li>
        <li>cofinantare tratata superficial, fara rezerva pentru costuri neeligibile;</li>
        <li>punctaj estimat pe criterii care nu pot fi demonstrate;</li>
        <li>calendar strans, fara timp pentru clarificari sau completari;</li>
        <li>amestecarea informatiilor din ghiduri consultative cu regulile apelului activ;</li>
        <li>promisiuni comerciale facute inainte de confirmarea documentelor.</li>
      </ul>
      <h2>Scenarii orientative de folosire a hub-ului</h2>
      <p>Un tanar fermier care preia treptat o exploatatie ar trebui sa porneasca de la rolul sau real, documentele care dovedesc exploatatia si planul de dezvoltare. Abia dupa aceea compara investitiile si bugetul. Un fermier cu exploatatie mica, dar stabila, poate avea o discutie mai utila pornind de la DR14, cu accent pe proportia dintre activitate, investitie si capacitatea de implementare.</p>
      <p>O ferma care vrea energie pentru autoconsum are nevoie de alta ordine de verificare: consum, amplasament, avize, dimensionare si legatura cu activitatea agroalimentara. O ferma care vrea utilaje trebuie sa arate de ce utilajul este necesar, nu doar ca este eligibil in principiu. Aceste scenarii sunt diferite, iar hub-ul exista tocmai pentru a le separa.</p>
      <h2>Cand are sens consultanta AFIR</h2>
      <p><a href="/consultanta-afir">Consultanta AFIR</a> are sens cand proiectul nu poate fi decis dintr-o lista simpla de conditii. Daca solicitantul are mai multe suprafete, exploatatia este impartita intre membri ai familiei, investitia include utilaje si lucrari, cofinantarea trebuie confirmata sau ghidul este inca in consultare, este mai sigur sa faci o verificare structurata inainte de a comanda documente scumpe.</p>
      <p>Un consultant nu transforma un proiect nepotrivit intr-un proiect eligibil. Rolul sau este sa puna intrebarile corecte, sa identifice documentele lipsa, sa compare interventiile relevante si sa opreasca scenariile care nu pot fi sustinute. In agricultura, aceasta prudenta conteaza pentru ca multe decizii luate devreme afecteaza implementarea: achizitii, drepturi de folosinta, contracte, termene, plati si obligatii de mentinere.</p>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Profil beneficiar</th><th>Intrebare de pornire</th><th>Pagina recomandata</th><th>Ce trimiti pentru analiza</th></tr></thead>
          <tbody>
            <tr><td>Tanar fermier</td><td>Poate solicitantul demonstra rolul real si exploatatia?</td><td><a href="/dr12-afir">DR 12 AFIR</a></td><td>date solicitant, documente ferma, SO/SOC, plan investitie.</td></tr>
            <tr><td>Ferma mica</td><td>Investitia este proportionala si documentele sunt coerente?</td><td><a href="/dr14">DR 14 AFIR</a></td><td>acte exploatatie, calcul SO/SOC, lista achizitii, buget.</td></tr>
            <tr><td>Ferma care compara programe</td><td>DR12 si DR14 sunt ambele posibile sau doar par similare?</td><td><a href="/dr12-vs-dr14">DR12 vs DR14</a></td><td>profil solicitant, varsta, forma juridica, documente si investitie.</td></tr>
            <tr><td>Agroalimentar / energie</td><td>Consumul si amplasamentul justifica investitia?</td><td><a href="/afir-autoconsum-agroalimentar">AFIR autoconsum</a></td><td>consum, locatie, avize, capacitate, buget si sursa cofinantarii.</td></tr>
          </tbody>
        </table>
      </div>
      <h2>Ce informatii sunt utile in primul mesaj</h2>
      <p>Pentru o verificare initiala, nu este nevoie sa trimiti tot dosarul. Sunt utile cateva date de baza: forma juridica, localitatea, tipul fermei, suprafetele sau efectivele, calculul SO/SOC daca exista, investitia dorita, bugetul estimat, cofinantarea disponibila si documentele pe care le ai deja. Cu aceste informatii se poate spune daca analiza trebuie sa continue pe DR12, DR14, utilaje, energie sau alta directie.</p>
      <p>Daca datele lipsesc, raspunsul corect este o lista de completari, nu o concluzie fortata. Aceasta abordare poate parea mai lenta, dar previne alegerea unui program gresit. In practica, un dosar respins sau imposibil de implementat costa mai mult decat o verificare facuta inainte de buget.</p>
      <h2>Cum citesti raspunsul primit dupa verificare</h2>
      <p>Un raspuns bun pentru AFIR trebuie sa fie specific. Ar trebui sa spuna ce program ramane in analiza, ce document lipseste, ce risc trebuie clarificat si ce nu poate fi concluzionat pana la ghidul activ. Daca raspunsul contine doar o incurajare generala, beneficiarul nu are inca baza pentru buget sau depunere.</p>
      <p>De aceea, FABER prefera concluzii operationale: pregateste calculul SO/SOC, corecteaza actele de folosinta, verifica alta interventie, separa TVA si cheltuielile neeligibile, ajusteaza investitia sau asteapta documentele oficiale. Aceste indicatii transforma hub-ul AFIR intr-un instrument de decizie, nu intr-o simpla lista de programe.</p>
      <h2>Concluzie pentru paginile AFIR</h2>
      <p>AFIR trebuie privit ca o familie de reguli, nu ca o singura oportunitate. Fiecare interventie are logica ei, iar fermierul trebuie sa poata demonstra incadrarea prin documente. Hub-ul acesta trimite catre paginile unde analiza devine specifica si pastreaza aceeasi regula editoriala: fara sume finale neverificate, fara promisiuni de aprobare si fara recomandari care ignora ghidul activ.</p>
      <h2>Linkuri interne pentru urmatorul pas</h2>
      <div class="related-links">
        <a href="/consultanta-afir">Consultanta AFIR pentru alegerea programului</a>
        <a href="/calculator-soc">Calculator SO AFIR</a>
        <a href="/dr12-afir">DR 12 AFIR</a>
        <a href="/dr14">DR 14 AFIR</a>
        <a href="/dr12-vs-dr14">DR12 vs DR14</a>
        <a href="/dr14">DR14 ferme mici</a>
        <a href="/gal-afir">GAL-AFIR / LEADER</a>
        <a href="/fonduri-pentru-ferme">Fonduri pentru ferme</a>
        <a href="/surse-oficiale-fonduri-europene">Surse oficiale</a>
      </div>
${officialSourcesHtml}
      <h2>Intrebari frecvente</h2>
      ${faqHtml}`;
}

function renderGuidesHubContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <p class="intro">${esc(page.quickAnswer)} Pagina strange resursele care ajuta beneficiarul sa treaca de la idee la verificare: program, documente, buget, calendar, riscuri si surse oficiale.</p>
      <p class="snippet-box">Pe scurt: ghidurile FABER sunt puncte de orientare, nu inlocuitori pentru apelurile active. Foloseste-le pentru a intelege ce informatii trebuie pregatite, ce documente lipsesc si ce intrebari trebuie clarificate inainte de depunere.</p>
      ${renderTable(page)}
      <h2>Cum alegi ghidul potrivit</h2>
      <p>O pagina de ghiduri este utila doar daca te ajuta sa alegi urmatorul pas. Inainte sa descarci un checklist sau sa citesti un articol, noteaza programul urmarit, tipul solicitantului, localitatea proiectului, codul CAEN sau profilul fermei, investitia dorita si bugetul estimat. Aceste date separa ghidurile relevante de materialele care par utile, dar nu se aplica proiectului tau.</p>
      <p>Ghidurile de pe site sunt scrise prudent. Ele explica ordinea verificarii si riscurile frecvente, dar nu publica rezultate, testimoniale, statistici sau valori finale fara baza verificabila. Daca un apel nu are inca ghid final, textul ramane orientativ si trimite la sursa oficiala.</p>
${renderDecisionMatrix(page)}
      <h2>Biblioteca rapida de ghiduri si instrumente</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Subiect</th><th>Ce clarifica</th><th>Resursa interna</th></tr></thead>
          <tbody>
            <tr><td>Consultanta fonduri europene</td><td>procesul de verificare, documentele minime si riscurile inainte de dosar</td><td><a href="/consultanta-fonduri-europene">pagina de consultanta</a></td></tr>
            <tr><td>AFIR si agricultura</td><td>DR12, DR14, ferme, utilaje, SO/SOC si documente agricole</td><td><a href="/afir">hub AFIR</a></td></tr>
            <tr><td>Digitalizare IMM</td><td>software, hardware, securitate, indicatori si buget IT</td><td><a href="/digitalizare-imm">Digitalizare IMM</a></td></tr>
            <tr><td>Start-Up Nation</td><td>CAEN, plan de afaceri, cheltuieli si pregatire prudent verificata</td><td><a href="/start-up-nation-2026">Start-Up Nation 2026</a></td></tr>
            <tr><td>Documente si checklisturi</td><td>liste de verificare, calendar si fisiere descarcabile pentru pregatire</td><td><a href="/resurse">Resurse descarcabile</a></td></tr>
            <tr><td>Calculatoare</td><td>scenarii orientative pentru cofinantare, digitalizare si eligibilitate initiala</td><td><a href="/instrumente">Instrumente</a></td></tr>
          </tbody>
        </table>
      </div>
      <h2>Metoda de lucru cu un ghid</h2>
      <p>Primul pas este citirea scopului. Un ghid despre eligibilitate nu iti spune automat ce cumperi; un ghid despre buget nu decide daca solicitantul este eligibil. Separarea aceasta previne multe greseli, mai ales cand proiectul pare simplu la inceput.</p>
      <ol>
        <li>Alege programul sau familia de programe care se potriveste solicitantului.</li>
        <li>Verifica daca exista ghid oficial activ, anexe, grila si calendar.</li>
        <li>Noteaza documentele pe care le ai deja si documentele care lipsesc.</li>
        <li>Construieste bugetul dupa eligibilitate, nu invers.</li>
        <li>Verifica riscurile: cofinantare, TVA, oferte, autorizari, punctaj si implementare.</li>
        <li>Revizuieste concluzia cand apare un corrigendum, o versiune noua de ghid sau o clarificare oficiala.</li>
      </ol>
      <h2>Checklist minim inainte de depunere</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Zona verificata</th><th>Intrebare practica</th><th>Ce document cauti</th></tr></thead>
          <tbody>
            <tr><td>Solicitant</td><td>Forma juridica si istoricul permit aplicarea?</td><td>CUI, certificat constatator, situatii financiare, date de reprezentare.</td></tr>
            <tr><td>Activitate</td><td>Codul CAEN sau profilul fermei are legatura cu investitia?</td><td>Coduri autorizate, descriere activitate, punct de lucru, documente agricole.</td></tr>
            <tr><td>Locatie</td><td>Proiectul se implementeaza intr-un spatiu dovedit?</td><td>Contracte, acte teren/cladire, durata folosintei, avize daca sunt necesare.</td></tr>
            <tr><td>Buget</td><td>Cheltuielile sunt permise si pot fi justificate?</td><td>Oferte, specificatii, devize, justificare operationala, tratament TVA.</td></tr>
            <tr><td>Punctaj</td><td>Criteriile estimate pot fi dovedite?</td><td>Grila, anexe, declaratii, documente suport pentru fiecare criteriu.</td></tr>
            <tr><td>Implementare</td><td>Beneficiarul poate sustine proiectul dupa selectie?</td><td>Cash-flow, cofinantare, calendar achizitii, responsabilitati si obligatii.</td></tr>
          </tbody>
        </table>
      </div>
      <h2>Cum eviti folosirea informatiilor expirate</h2>
      <p>Ghidurile se schimba. O informatie corecta intr-o versiune consultativa poate deveni incompleta sau irelevanta dupa publicarea ghidului final. De aceea, fiecare pagina trebuie citita impreuna cu data actualizarii, sursa oficiala si mentiunile despre caracterul orientativ al exemplelor.</p>
      <p>Inainte sa iei o decizie, verifica daca pagina trimite la AFIR, MIPE, ADR, PNRR sau alta institutie relevanta. Daca sursa oficiala nu este completa, nu trata butonul de ghid ca dovada finala. In proiectele cu bani publici, sursa de adevar ramane documentul apelului activ, nu un rezumat comercial.</p>
      <h2>Exemple de folosire responsabila</h2>
      <p>Un antreprenor care cauta digitalizare poate porni din ghidul Digitalizare IMM, dar trebuie sa ajunga rapid la lista de procese digitalizate, buget IT, securitate, indicatori si documente. Un fermier care cauta utilaje are nevoie de hub-ul AFIR, de calcul SO/SOC si de justificarea investitiei in ferma. Un start-up are nevoie de CAEN, cheltuieli eligibile, cofinantare si plan de afaceri, nu doar de lista cu idei.</p>
      <p>Daca un ghid nu raspunde direct la cazul tau, foloseste-l ca lista de intrebari pentru discutia de eligibilitate. O intrebare buna economiseste timp: ce lipseste, ce program trebuie eliminat, ce document trebuie obtinut inainte de buget si ce criteriu nu poate fi sustinut prin dovezi.</p>
      <h2>Ghiduri pe profil de beneficiar</h2>
      <p>Un fermier are nevoie de documente diferite fata de un IMM din servicii sau fata de un start-up. De aceea, resursele trebuie citite prin filtrul beneficiarului, nu doar prin titlul programului. O pagina despre agricultura trebuie sa ajunga la SO/SOC, acte de folosinta si investitii agricole. O pagina despre digitalizare trebuie sa ajunga la procese, hardware, software, securitate si indicatori. O pagina despre programe regionale trebuie sa verifice regiunea, codul CAEN, punctul de lucru si cheltuielile productive.</p>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Beneficiar</th><th>Ghiduri de pornire</th><th>Intrebarea care decide urmatorul pas</th></tr></thead>
          <tbody>
            <tr><td>Fermier sau exploatatie agricola</td><td><a href="/afir">AFIR</a>, <a href="/dr12-afir">DR12</a>, <a href="/dr14">DR14</a>, <a href="/calculator-soc">calculator SO/SOC</a></td><td>Exploatatia si investitia pot fi dovedite prin documente coerente?</td></tr>
            <tr><td>IMM existent</td><td><a href="/fonduri-europene-imm">fonduri IMM</a>, <a href="/digitalizare-imm">digitalizare</a>, <a href="/por-adr-nord-est">regional</a></td><td>Codul CAEN, localizarea si bugetul se potrivesc cu apelul activ?</td></tr>
            <tr><td>Start-up</td><td><a href="/start-up-nation-2026">Start-Up Nation</a>, <a href="/cod-caen-start-up-nation-2026">cod CAEN</a>, <a href="/start-up-nation-2026-plan-de-afaceri">plan de afaceri</a></td><td>Activitatea, cofinantarea si cheltuielile pot fi sustinute realist?</td></tr>
            <tr><td>Proiect energetic</td><td><a href="/fondul-de-modernizare">Fondul de Modernizare</a>, <a href="/finantari-panouri-fotovoltaice">fotovoltaice</a>, <a href="/afir-autoconsum-agroalimentar">autoconsum agroalimentar</a></td><td>Consumul, amplasamentul, avizele si dimensionarea sunt documentate?</td></tr>
          </tbody>
        </table>
      </div>
      <h2>Plan de verificare inainte sa ceri oferta</h2>
      <p>Inainte sa ceri o oferta de consultanta, strange informatiile care permit o concluzie. Pentru o firma, sunt utile CUI-ul, codurile CAEN, localitatea proiectului, activitatea reala, bugetul estimat, lista de achizitii si documentele pentru spatiu. Pentru o ferma, sunt utile datele exploatatiei, SO/SOC, documentele de folosinta si investitia dorita. Pentru un proiect energetic, sunt utile consumul, amplasamentul, puterea estimata si stadiul avizelor.</p>
      <p>Acest plan reduce raspunsurile vagi. Un consultant poate raspunde mai clar cand vede daca programul este posibil, ce lipseste si ce trebuie verificat in sursa oficiala. Daca informatiile sunt incomplete, prima etapa devine completarea datelor, nu redactarea dosarului.</p>
      <h2>Ce inseamna concluzie buna dupa citirea ghidurilor</h2>
      <p>O concluzie buna nu este doar "aplica" sau "nu aplica". Poate fi "aplica doar daca se confirma ghidul final", "corecteaza documentele pentru spatiu", "restrange bugetul", "schimba programul", "asteapta o sesiune viitoare" sau "pregateste intai cofinantarea". Aceste raspunsuri sunt mai utile decat un optimism general pentru ca arata ce trebuie facut concret.</p>
      <p>Ghidurile FABER incearca sa duca cititorul spre acest tip de concluzie. Fiecare pagina foloseste rezumat scurt, tabele, intrebari frecvente, linkuri interne si surse oficiale pentru a face informatia usor de verificat. Cand o informatie nu este finala, textul pastreaza formularea orientativa.</p>
      <h2>Cum se actualizeaza si cum se pastreaza prudenta</h2>
      <p>O biblioteca de ghiduri pentru fonduri europene trebuie sa fie utila si cand regulile se schimba. De aceea, paginile nu ar trebui sa depinda de promisiuni comerciale sau de cifre fara sursa. Cand exista o valoare oficiala clara, ea poate fi citata cu sursa. Cand sursa nu este completa, pagina explica doar scenariul de verificare si trimite cititorul catre documentul activ.</p>
      <p>Actualizarea responsabila inseamna si eliminarea informatiilor care pot induce in eroare. Daca un apel s-a inchis, daca un ghid consultativ a fost inlocuit sau daca un program are conditii noi, concluziile trebuie revizuite. Pentru utilizator, semnul bun este existenta surselor oficiale, a datei de actualizare si a unor avertismente clare acolo unde informatia este orientativa.</p>
      <h2>Ce ar trebui sa rezulte dupa 15 minute de lucru cu pagina</h2>
      <p>Dupa ce folosesti pagina Ghiduri, ar trebui sa ai o lista scurta de actiuni: programul pe care il verifici, documentele pe care le ai, documentele lipsa, riscurile evidente si intrebarile pentru consultant. Daca nu poti completa aceste puncte, proiectul este inca prea neclar pentru buget final.</p>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Rezultat asteptat</th><th>Exemplu de formulare utila</th><th>Urmatorul pas</th></tr></thead>
          <tbody>
            <tr><td>Program probabil</td><td>Analizam DR14, dar comparam cu DR12 pentru ca solicitantul este tanar fermier.</td><td>Verifica pagina programului si calculul SO/SOC.</td></tr>
            <tr><td>Document lipsa</td><td>Lipseste actul de folosinta pentru spatiul investitiei.</td><td>Obtine documentul inainte de oferta finala.</td></tr>
            <tr><td>Risc de buget</td><td>TVA si costurile neeligibile nu sunt separate.</td><td>Refa scenariul de cofinantare.</td></tr>
            <tr><td>Intrebare pentru consultant</td><td>Codul CAEN si investitia propusa se potrivesc cu apelul activ?</td><td>Trimite datele prin pagina de contact.</td></tr>
          </tbody>
        </table>
      </div>
      <h2>Cand pagina trebuie completata cu analiza individuala</h2>
      <p>Ghidurile generale nu pot decide cazurile cu mai multi solicitanti, ferme cu documente impartite, investitii tehnice, cofinantare sensibila, punctaje la limita sau apeluri in consultare. In aceste cazuri, pagina este doar punctul de pornire. Analiza individuala trebuie sa citeasca documentele si sa compare regulile cu situatia reala.</p>
      <p>Aceasta limita este intentionata. Un site bun nu ar trebui sa creeze impresia ca orice situatie poate fi rezolvata printr-un text standard. Pentru proiecte cu bani publici, concluzia corecta se construieste pe documente, surse oficiale si verificari repetate.</p>
      <h2>Cum transformi ghidul intr-o cerere de verificare</h2>
      <p>Cand scrii catre FABER dupa ce ai citit ghidurile, include programul vizat, de ce crezi ca se potriveste, ce documente ai, ce lipseste si ce investitie vrei sa faci. Un mesaj scurt, dar structurat, permite un raspuns mai concret decat o intrebare generala despre "ce fonduri sunt disponibile".</p>
      <p>Exemplu de mesaj util: "Sunt IMM cu CAEN autorizat, investitie in software si echipamente, buget estimat, punct de lucru in regiune, dar nu stiu daca TVA si securitatea cibernetica sunt tratate corect". Pentru agricultura, mesajul poate include SO/SOC, suprafete, efective, documente de folosinta si utilajul dorit. Pentru energie, include consumul si amplasamentul.</p>
      <p>Cu cat mesajul este mai clar, cu atat verificarea poate separa mai repede programele potrivite de cele care trebuie eliminate. Aceasta economie de timp conteaza mai ales cand apelul are termen scurt, documentele trebuie actualizate sau bugetul depinde de oferte noi, anexe revizuite sau conditii publicate recent.</p>
      <h2>Concluzie pentru biblioteca de ghiduri</h2>
      <p>Pagina Ghiduri trebuie folosita ca masa de lucru: alegi programul, verifici documentele, notezi riscurile si mergi catre sursa oficiala. Nu este o lista de promisiuni si nu inlocuieste analiza pe cazul concret. Daca ai deja date despre solicitant, investitie si buget, urmatorul pas este verificarea eligibilitatii, nu cautarea unui rezumat mai lung sau a unei valori care nu poate fi confirmata oficial, public. Pentru proiectele neclare, revino la lista scurta de intrebari inainte sa continui.</p>
      <h2>Linkuri interne utile</h2>
      <div class="related-links">
        <a href="/resurse">Resurse descarcabile</a>
        <a href="/instrumente">Instrumente</a>
        <a href="/afir">Hub AFIR</a>
        <a href="/dr12-vs-dr14">DR12 vs DR14</a>
        <a href="/digitalizare-imm">Digitalizare IMM</a>
        <a href="/start-up-nation-2026">Start-Up Nation</a>
        <a href="/metodologie-verificare-eligibilitate">Metodologie</a>
        <a href="/surse-oficiale-fonduri-europene">Surse oficiale</a>
        <a href="/contact">Contact</a>
      </div>
${officialSourcesHtml}
      <h2>Intrebari frecvente</h2>
      ${faqHtml}`;
}

function renderDr12SearchIntentContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <section aria-labelledby="dr12-raspuns-rapid">
        <h2 id="dr12-raspuns-rapid">Răspuns rapid</h2>
        <p class="intro">DR12 AFIR 2026 este intervenția pentru investiții în consolidarea exploatațiilor tinerilor fermieri instalați și ale fermierilor instalați cu vârsta de până la 45 de ani. Ghidul DR 12 AFIR disponibil în documentația proiectului este o versiune consultativă, nu ghidul final. El indică o dimensiune economică de minimum 12.000 euro SO, un sprijin public de maximum 200.000 euro/proiect și două intensități maxime: 80% pentru tinerii fermieri care îndeplinesc condițiile specifice și 65% pentru celelalte categorii eligibile. O dată de lansare nu se deduce din consultare. Sesiunea, etapele lunare, alocarea și termenele se confirmă exclusiv prin ghidul activ și nota oficială de lansare.</p>
        <p>Căutările „dr12 afir”, „afir dr 12”, „ghid dr 12 afir”, „dr 12 ghid final” și „dr 12 afir lansare” se referă la aceeași intervenție; răspunsurile de mai jos separă explicit informațiile consultative de regulile care vor fi confirmate în apelul activ.</p>
      </section>

      <section aria-labelledby="dr12-status-ghid">
        <h2 id="dr12-status-ghid">Statusul ghidului: consultativ sau final</h2>
        <p>Documentul analizat poartă explicit mențiunea de versiune consultativă și a fost publicat pentru dezbatere. Prin urmare, expresiile „dr 12 ghid final” și „ghid DR 12 AFIR” trebuie tratate prudent: pagina descrie regulile din varianta consultativă, iar forma finală poate modifica praguri, documente, punctaje, alocări sau termene.</p>
        <p>Înainte de orice depunere se verifică versiunea activă publicată de AFIR, ordinul de aprobare, anexele, cererea de finanțare, grila de selecție și eventualele erate. Nicio regulă consultativă nu este prezentată aici drept regulă definitivă.</p>
      </section>

      <section aria-labelledby="dr12-lansare">
        <h2 id="dr12-lansare">Când se lansează DR12</h2>
        <p>Pentru query-ul „dr 12 afir lansare”, răspunsul corect este că versiunea consultativă nu fixează o dată certă de deschidere. Ghidul arată că sesiunea se organizează în două etape lunare, stabilite prin nota de lansare. Pentru prima etapă este indicat un prag de calitate de 75 de puncte, iar pentru etapa a doua pragul minim consultativ este de 45 de puncte.</p>
        <p>Data, ora deschiderii, durata fiecărei etape, alocarea și condițiile de oprire anticipată trebuie preluate numai din anunțul oficial al sesiunii active. Pregătirea documentelor poate începe înainte, dar depunerea nu trebuie planificată pe o dată nepublicată.</p>
      </section>

      <section aria-labelledby="dr12-solicitanti">
        <h2 id="dr12-solicitanti">Cine poate aplica</h2>
        <p>Varianta consultativă enumeră trei categorii: tineri fermieri instalați cu vârsta de până la 40 de ani, înainte de împlinirea vârstei de 41 de ani; fermieri care au finalizat planul de afaceri prin submăsura 6.1 din PNDR 2014-2022, indiferent de vârsta de la depunere; și fermieri instalați cu vârsta de până la 45 de ani, înainte de împlinirea vârstei de 46 de ani.</p>
        <p>Solicitantul trebuie să fie șef al exploatației și să exercite controlul efectiv. Persoanele fizice neautorizate nu sunt eligibile. Ghidul include PFA, întreprindere individuală, întreprindere familială și SRL în condițiile detaliate pentru asociat, administrator și control. Încadrarea juridică și profesională se reconfirmă în ghidul activ.</p>
      </section>

      <section aria-labelledby="dr12-so-minim">
        <h2 id="dr12-so-minim">Pragul minim SO</h2>
        <p>Investiția trebuie realizată într-o fermă cu dimensiunea economică de minimum 12.000 euro SO la momentul depunerii. Calculul folosește coeficienții SOC 2020 din cererea de finanțare și datele documentabile pentru suprafețe, culturi și efective.</p>
        <p>Suprafețele se corelează cu IACS-APIA, iar efectivele care nu pot fi înregistrate acolo se verifică în registrele ANSVSA/DSVSA, ANZ sau prin documentele circumscripției veterinare, după caz. Un calcul realizat fără aceleași date în documentele oficiale poate schimba eligibilitatea și punctajul.</p>
      </section>

      <section aria-labelledby="dr12-componente">
        <h2 id="dr12-componente">Sector zootehnic versus alte sectoare</h2>
        <p>DR12 are două componente distincte: <strong>sector zootehnic</strong> și <strong>alte sectoare</strong>. Solicitantul poate depune un singur proiect pe una dintre cele două componente. Încadrarea pornește de la structura exploatației și de la sectorul relevant descris în ghid.</p>
        <p>Pentru componenta alte sectoare pot exista investiții și în sectoare diferite de cel predominant, însă proiectul trebuie să includă investiții în sectorul vegetal care determină încadrarea. Alegerea componentei influențează alocarea, criteriile aplicabile și riscul de neconformitate dacă proiectul este încadrat greșit.</p>
      </section>

      <section aria-labelledby="dr12-intensitate">
        <h2 id="dr12-intensitate">Intensitatea sprijinului</h2>
        <div class="table-wrap">
          <table class="program-table">
            <thead><tr><th>Categorie</th><th>Intensitate maximă consultativă</th><th>Condiție-cheie</th></tr></thead>
            <tbody>
              <tr><td>Tineri fermieri</td><td>80% din costurile eligibile</td><td>Până la 40 de ani înainte de împlinirea vârstei de 41 de ani, competențe profesionale și calitatea de șef al exploatației.</td></tr>
              <tr><td>Celelalte categorii eligibile</td><td>65% din costurile eligibile</td><td>Îndeplinirea condițiilor specifice categoriei și ale proiectului.</td></tr>
              <tr><td>Plafon proiect</td><td>Maximum 200.000 euro</td><td>Sprijin public nerambursabil per proiect, conform variantei consultative.</td></tr>
            </tbody>
          </table>
        </div>
        <p>Procentele se aplică numai cheltuielilor eligibile. Contribuția privată, cheltuielile neeligibile și tratamentul TVA se calculează separat și se confirmă în documentele sesiunii active.</p>
      </section>

      <section aria-labelledby="dr12-investitii">
        <h2 id="dr12-investitii">Investiții eligibile</h2>
        <p>Lista indicativă din ghid cuprinde construcții noi și modernizări, spații protejate cu dotări și utilități, înființarea sau modernizarea fermelor pomicole, unități de condiționare și depozitare, precum și procesare la nivelul fermei ca parte secundară a proiectului.</p>
        <p>Pot fi analizate utilaje agricole noi, remorci și semiremorci tehnologice, echipamente pentru furajare, soluții digitale și agricultură de precizie, facilități de igienă și biosecuritate, căi de acces și irigații la nivel de fermă ca părți secundare. Energia regenerabilă este prevăzută ca parte secundară pentru consum propriu, fără livrarea surplusului în rețea. Fiecare investiție trebuie corelată cu producția și capacitatea reală a fermei.</p>
      </section>

      <section aria-labelledby="dr12-documente">
        <h2 id="dr12-documente">Documente APIA, ANSVSA, ANZ și ONRC</h2>
        <ul>
          <li><strong>APIA:</strong> forma de organizare, codul exploatației, suprafețele și culturile declarate trebuie să susțină calculul SO și proiectul.</li>
          <li><strong>ANSVSA/DSVSA:</strong> registrele exploatației și efectivele sunt verificate pentru fermele cu animale; pentru anumite animale se folosesc și adeverințe veterinare.</li>
          <li><strong>ANZ:</strong> documentele sunt relevante, între altele, pentru familiile de albine, vatra stupinei și situațiile prevăzute de ghid.</li>
          <li><strong>ONRC:</strong> forma juridică, reprezentantul, asociații și controlul efectiv se verifică inclusiv prin RECOM online.</li>
        </ul>
        <p>Contractele de proprietate sau folosință trebuie să fie în numele solicitantului și să acopere perioada cerută. Datele din toate registrele trebuie să descrie aceeași exploatație; diferențele pot genera clarificări sau neeligibilitate.</p>
      </section>

      <section aria-labelledby="dr12-cofinantare">
        <h2 id="dr12-cofinantare">Cofinanțare</h2>
        <p>Beneficiarul adaugă contribuția privată la sprijinul public și suportă integral cheltuielile neeligibile. Pentru proiectele cu intensitate de 80%, diferența eligibilă pornește de la 20%; pentru intensitatea de 65%, diferența pornește de la 35%. Calculul real include și TVA-ul după regimul fiscal aplicabil, diferențe de preț și rezerva de numerar pentru implementare.</p>
        <p>Ghidul consultativ cere dovada cofinanțării private prin extras de cont și/sau contract de credit. Dacă se folosește extrasul de cont, acesta este însoțit de angajamentul privind destinația a minimum 50% din disponibilul prezentat, conform regulilor descrise în document. Cerința exactă se reconfirmă la contractare în versiunea activă.</p>
      </section>

      <section aria-labelledby="dr12-punctaj">
        <h2 id="dr12-punctaj">Pragul de calitate și riscul de suprascore</h2>
        <p>Varianta consultativă stabilește un prag de 75 de puncte pentru prima etapă lunară și 45 de puncte pentru etapa a doua, atât pentru sectorul zootehnic, cât și pentru alte sectoare. Cererea nu poate fi depusă într-o etapă dacă prescoringul este sub pragul lunii respective.</p>
        <p>Suprascore-ul nu este o rezervă de siguranță. Punctele trebuie susținute de documente încă de la depunere. Dacă evaluatorul reduce punctajul sub pragul etapei sau constată o încadrare greșită pe componentă, proiectul poate fi declarat neconform. Se punctează numai ceea ce poate fi demonstrat, nu o investiție ori o situație viitoare nesusținută.</p>
      </section>

      <section aria-labelledby="dr12-greseli">
        <h2 id="dr12-greseli">Greșeli</h2>
        <ul class="warning-list">
          <li>prezentarea ghidului consultativ ca ghid final sau presupunerea unei date de lansare;</li>
          <li>calcul SO sub 12.000 sau necorelat cu APIA, ANSVSA, ANZ și documentele de folosință;</li>
          <li>confundarea limitei de vârstă pentru categoria solicitantului cu limita pentru intensitatea de 80%;</li>
          <li>alegerea greșită între sector zootehnic și alte sectoare;</li>
          <li>utilaje supradimensionate față de suprafețe, efective și parcul existent;</li>
          <li>prescoring optimist, fără documente pentru fiecare criteriu;</li>
          <li>cofinanțare, TVA și cheltuieli neeligibile neacoperite;</li>
          <li>contracte de folosință sau înregistrări oficiale care nu acoperă perioada și forma solicitantului.</li>
        </ul>
      </section>

      <section aria-labelledby="dr12-faq">
        <h2 id="dr12-faq">FAQ</h2>
        ${faqHtml}
      </section>

${officialSourcesHtml}

      <section aria-labelledby="dr12-cta">
        <h2 id="dr12-cta">CTA: verifică eligibilitatea DR12</h2>
        <p>Pregătește vârsta și forma solicitantului, situația APIA/ANSVSA/ANZ, calculul SO, componenta proiectului, lista investițiilor și sursa cofinanțării. Verificarea pornește de la documente și de la ghidul activ, nu de la plafonul maxim.</p>
        <p><a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Solicită verificarea eligibilității DR12</a></p>
      </section>`;
}

function renderDr14SearchIntentContent(page) {
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <section aria-labelledby="dr14-raspuns-rapid">
        <h2 id="dr14-raspuns-rapid">Răspuns rapid</h2>
        <p class="intro">DR14 AFIR 2026 este intervenția pentru investiții în fermele de mici dimensiuni. Ghidul solicitantului DR 14 folosit în documentația proiectului este varianta consultativă, nu forma finală. Documentul prevede un sprijin public de maximum 50.000 euro/proiect și o intensitate de până la 85% din costurile eligibile. Condițiile DR14 pornesc de la dimensiunea economică și SO majoritar: intervalul general este 4.000-11.999 SO, cu praguri minime distincte de 2.000 SO pentru rase autohtone și anumite subsectoare floricole, respectiv 2.300 SO pentru sectorul legumicol. Solicitantul depune pe o singură componentă dintre legumicol, zootehnic, achiziții simple și național-alte sectoare. Lansarea și regulile finale se confirmă numai în documentele oficiale active.</p>
        <p>Căutările „dr14”, „dr14 afir”, „dr14 afir 2026”, „dr 14 conditii”, „când se lansează dr 14” și „ghidul solicitantului dr 14” sunt tratate distinct în secțiunile următoare, fără a prezenta varianta consultativă drept formă finală.</p>
      </section>

      <section aria-labelledby="dr14-status">
        <h2 id="dr14-status">Status apel</h2>
        <p>Pagina oficială și ghidul disponibile în proiect sunt marcate explicit „versiunea consultativă”. Acest statut nu echivalează cu un apel deschis și nici cu un ghid final aprobat. Pentru întrebarea „când se lansează DR 14”, sursa consultată nu oferă o dată certă de depunere.</p>
        <p>Perioada apelului, bugetul, cele două etape lunare, pragurile aplicabile și anexele obligatorii se verifică în nota de lansare și în versiunea activă a ghidului. Până atunci pot fi pregătite datele fermei și documentele, fără a transforma regulile consultative în promisiuni finale.</p>
      </section>

      <section aria-labelledby="dr14-so">
        <h2 id="dr14-so">Intervalele SO pe sectoare</h2>
        <div class="table-wrap">
          <table class="program-table">
            <thead><tr><th>Încadrare</th><th>Interval consultativ</th><th>Regulă de verificare</th></tr></thead>
            <tbody>
              <tr><td>Ferme mici - regulă generală</td><td>4.000-11.999 euro SO</td><td>Dimensiunea trebuie dovedită la depunere.</td></tr>
              <tr><td>Zootehnic cu rase autohtone</td><td>2.000-11.999 euro SO</td><td>SO majoritar și minimum 2.000 SO trebuie să provină din animalele din rase autohtone.</td></tr>
              <tr><td>Flori, plante aromatice, medicinale și ornamentale</td><td>2.000-11.999 euro SO</td><td>Subsectorul trebuie să determine SO majoritar și să atingă pragul minim.</td></tr>
              <tr><td>Ferme legumicole</td><td>2.300-11.999 euro SO</td><td>Legumicolul trebuie să determine SO majoritar și să atingă minimum 2.300 SO.</td></tr>
            </tbody>
          </table>
        </div>
        <p>Calculul folosește coeficienții SOC 2020 și înregistrările APIA, ANSVSA/DSVSA și ANZ, după caz. Nu este suficient ca totalul fermei să depășească pragul redus; sectorul care justifică pragul trebuie să fie majoritar în condițiile ghidului.</p>
      </section>

      <section aria-labelledby="dr14-componente">
        <h2 id="dr14-componente">Cele patru componente</h2>
        <ol>
          <li><strong>Legumicol:</strong> încadrarea se bazează pe SO majoritar și proiectul trebuie să includă investiții în sectorul care determină componenta.</li>
          <li><strong>Zootehnic:</strong> se verifică efectivele, documentele sanitar-veterinare și legătura investiției cu activitatea zootehnică.</li>
          <li><strong>Achiziții simple:</strong> proiectele care propun numai achiziții simple intră pe alocarea distinctă, indiferent de sector.</li>
          <li><strong>Național - alte sectoare:</strong> reunește proiectele încadrate în celelalte sectoare conform SO majoritar și investiției.</li>
        </ol>
        <p>Un solicitant poate depune proiect pe o singură componentă. Încadrarea greșită poate afecta evaluarea, alocarea și pragul de calitate aplicabil.</p>
      </section>

      <section aria-labelledby="dr14-solicitanti">
        <h2 id="dr14-solicitanti">Solicitanți eligibili</h2>
        <p>Ghidul consultativ se adresează fermierilor organizați în forme eligibile și înregistrați în România, care acționează în nume propriu și pot asigura surse financiare stabile și suficiente. Sunt enumerate forme precum PFA, întreprindere individuală, întreprindere familială și mai multe tipuri de societăți, inclusiv SRL, cu condițiile juridice din ghid.</p>
        <p>Solicitantul trebuie să figureze anterior depunerii în sistemele APIA și/sau ANSVSA pe forma de organizare cu care cere sprijinul. Exploatația, activitatea, drepturile de folosință și investiția trebuie să aparțină aceleiași structuri eligibile. Situațiile de lichidare, insolvență sau faliment și regulile privind numărul de proiecte se verifică separat.</p>
      </section>

      <section aria-labelledby="dr14-investitii">
        <h2 id="dr14-investitii">Investiții eligibile</h2>
        <p>Ghidul permite investiții corporale și necorporale legate direct de producția agricolă a fermei. În funcție de componentă pot fi analizate construcții și modernizări, spații protejate, dotări, utilaje și echipamente, facilități de condiționare sau depozitare, soluții digitale, servicii tehnice și alte cheltuieli descrise în lista eligibilă.</p>
        <p>Investițiile se fac numai în sectoarele pentru care solicitantul are SO la depunere. O fermă exclusiv zootehnică poate investi în vegetal numai pentru baza furajeră, iar o fermă exclusiv vegetală rămâne în sectorul vegetal. Depozitarea, condiționarea și procesarea urmează aceeași corelare cu sectoarele documentate.</p>
      </section>

      <section aria-labelledby="dr14-achizitii-simple">
        <h2 id="dr14-achizitii-simple">Achiziții simple</h2>
        <p>Componenta „achiziții simple” este o alocare distinctă pentru proiectele care propun numai astfel de achiziții, indiferent de sectorul agricol în care activează ferma. Ea nu înseamnă că orice utilaj este automat eligibil sau că justificarea tehnică dispare.</p>
        <p>Echipamentele trebuie să fie noi, eligibile, dimensionate pentru exploatație și legate de activitatea documentată. Costurile generale aferente proiectelor cu achiziții simple au, în varianta consultativă, limita specifică de 3% din totalul cheltuielilor eligibile. Definiția și lista finală se reconfirmă în ghidul activ.</p>
      </section>

      <section aria-labelledby="dr14-documente">
        <h2 id="dr14-documente">Documente</h2>
        <ul>
          <li>înregistrările APIA din anul depunerii pentru suprafețe, culturi, codul exploatației și calculul SO;</li>
          <li>înregistrările ANSVSA/DSVSA și ANZ pentru animale, păsări, familii de albine și situațiile speciale prevăzute de ghid;</li>
          <li>certificate de origine pentru rasele autohtone, emise de organizațiile acreditate, când se folosește pragul specific;</li>
          <li>documentele ONRC/RECOM pentru forma juridică, reprezentare și situația solicitantului;</li>
          <li>documente de proprietate sau folosință, oferte, devize, documentații tehnice, avize și autorizații potrivit investiției;</li>
          <li>dovada sursei de cofinanțare la momentul cerut de regulile de contractare.</li>
        </ul>
        <p>Documentele nu se verifică izolat. Totalul SO, SO majoritar, componenta, investiția și forma solicitantului trebuie să fie coerente în toate bazele și anexele.</p>
      </section>

      <section aria-labelledby="dr14-cofinantare">
        <h2 id="dr14-cofinantare">Cofinanțare</h2>
        <p>Varianta consultativă prevede un sprijin public de maximum 50.000 euro/proiect și o intensitate de maximum 85% din costurile eligibile. Diferența eligibilă de minimum 15%, cheltuielile neeligibile, TVA-ul după regimul fiscal și eventualele depășiri de preț rămân în sarcina beneficiarului.</p>
        <p>Documentele bancare sau de trezorerie care dovedesc capacitatea și sursa cofinanțării se prezintă în termenul descris de ghidul consultativ după aprobarea raportului de selecție sau de contestații. Termenul și forma documentelor se confirmă în versiunea activă înainte de contractare.</p>
      </section>

      <section aria-labelledby="dr14-selectie">
        <h2 id="dr14-selectie">Selecție și punctaj</h2>
        <p>Ghidul consultativ organizează sesiunea în două etape lunare. Pentru zootehnic, achiziții simple și național-alte sectoare este indicat un prag de 85 de puncte în prima etapă și 40 de puncte în etapa a doua. Pentru componenta legumicolă sunt indicate 60 de puncte în prima etapă și 40 de puncte în etapa a doua.</p>
        <p>Prescoringul trebuie calculat obiectiv și susținut cu documente. O bifă fără dovadă nu protejează proiectul; scăderea sub pragul lunii poate duce la neconformitate. Grila finală, alocările și criteriile se verifică în apelul activ.</p>
      </section>

      <section aria-labelledby="dr14-conditii-artificiale">
        <h2 id="dr14-conditii-artificiale">Condiții artificiale</h2>
        <p>Nu este permisă crearea artificială a condițiilor pentru obținerea sau creșterea sprijinului. Fragmentarea exploatației, mutarea formală a animalelor sau suprafețelor, schimbarea aparentă a formei de control ori construirea unui SO majoritar numai pentru pragul redus pot declanșa verificări și pot conduce la neacordarea sprijinului.</p>
        <p>Ferma trebuie să existe economic și documentar în forma prezentată. Relațiile dintre solicitanți, grupuri, asociați, exploatații și alte proiecte publice se declară și se verifică potrivit ghidului și instrucțiunii privind evitarea condițiilor artificiale.</p>
      </section>

      <section aria-labelledby="dr14-calculator-so">
        <h2 id="dr14-calculator-so">Calculator SO</h2>
        <p>Calculatorul SO este punctul de pornire, nu decizia finală. Introdu numai culturi și efective care pot fi susținute prin APIA, ANSVSA/DSVSA și ANZ. Verifică atât totalul exploatației, cât și sectorul care generează SO majoritar, deoarece pragul minim și componenta DR14 depind de această structură.</p>
        <p><a class="btn btn-secondary" href="/calculator-soc">Calculează SO pentru ferma ta</a></p>
      </section>

      <section aria-labelledby="dr14-greseli">
        <h2 id="dr14-greseli">Greșeli</h2>
        <ul class="warning-list">
          <li>tratarea variantei consultative drept ghid final sau anunț de lansare;</li>
          <li>aplicarea pragului de 2.000 ori 2.300 SO fără ca subsectorul să determine SO majoritar;</li>
          <li>alegerea unei componente care nu corespunde structurii fermei și investiției;</li>
          <li>confundarea achizițiilor simple cu o eligibilitate automată a utilajelor;</li>
          <li>diferențe între APIA, ANSVSA/ANZ, calculul SO și cererea de finanțare;</li>
          <li>prescoring nesusținut de documente sau condiții create artificial;</li>
          <li>investiție supradimensionată pentru o fermă mică;</li>
          <li>lipsa cofinanțării, a TVA-ului și a rezervei pentru cheltuieli neeligibile.</li>
        </ul>
      </section>

      <section aria-labelledby="dr14-faq">
        <h2 id="dr14-faq">FAQ</h2>
        ${faqHtml}
      </section>

${officialSourcesHtml}

      <section aria-labelledby="dr14-cta">
        <h2 id="dr14-cta">CTA: verifică eligibilitatea DR14</h2>
        <p>Trimite forma solicitantului, culturile și efectivele, calculul SO, documentele APIA/ANSVSA/ANZ, componenta dorită, lista achizițiilor și sursa cofinanțării. Analiza se raportează la ghidul activ înainte de orice concluzie finală.</p>
        <p><a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Solicită verificarea eligibilității DR14</a></p>
      </section>`;
}

function renderMainContent(page) {
  const pocidifHtml = renderPocidifContent(page);
  if (pocidifHtml) return pocidifHtml;
  if (page.slug === "dr12-afir") {
    return renderDr12SearchIntentContent(page);
  }
  if (page.slug === "dr14") {
    return renderDr14SearchIntentContent(page);
  }
  if (page.slug === "fondul-modernizare-energie-regenerabila-2026") {
    return renderFondModernizareRegenerabilaContent(page);
  }
  if (page.slug === "afir-autoconsum-agroalimentar") {
    return renderAfirAutoconsumAgroalimentarContent(page);
  }
  if (page.slug === "pro-infra") {
    return renderProInfraEfficiencyContent(page);
  }
  if (page.slug === "investitii-modernizarea-microintreprinderilor-apel-2") {
    return renderMicroApel2Content(page);
  }
  if (page.slug === "por-adr-nord-est") {
    return renderPorAdrNordEstContent(page);
  }
  if (page.slug === "consultanta-fonduri-europene") {
    return renderConsultantaPillarContent(page);
  }
  if (page.slug === "afir") {
    return renderAfirHubContent(page);
  }
  if (page.slug === "ghiduri") {
    return renderGuidesHubContent(page);
  }
  if (page.type === "trust") {
    const trustHtml = renderTrustContent(page);
    if (trustHtml) return trustHtml;
  }
  if (isEditorialProgram(page)) {
    return renderEditorialProgramContent(page);
  }

  const editorialHtml = renderEditorialSection(getEditorialMetadata(page.slug));
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");
  const dr14ScoreHtml = page.slug === "dr14" ? `\n${renderDr14Score()}` : "";
  const toolsHtml = page.includeTools ? `\n${renderTools()}` : "";
  const downloadsHtml = page.includeDownloads ? `\n${renderDownloads()}` : "";
  const keywordHtml = renderKeywordIntent(page);

  let html = `
      <p class="intro">${esc(page.quickAnswer)}</p>
      ${renderTable(page)}
${editorialHtml}
      <h2>Pe scurt</h2>
      <p>${esc(page.programName)} trebuie analizat ca o decizie de investitie, nu doar ca o oportunitate de finantare. Inainte de orice buget, solicitantul trebuie sa verifice incadrarea, documentele, calendarul, costurile eligibile si riscurile care pot aparea la evaluare sau implementare.</p>
      <p>Informatiile de pe aceasta pagina sunt construite pentru orientare practica. Ele nu promit aprobare si nu inlocuiesc verificarea apelului activ, a anexelor si a grilei de selectie. Scopul este sa poti pregati o discutie serioasa despre eligibilitate si dosar.</p>
${renderDecisionMatrix(page)}
${keywordHtml}
      ${renderContentSections(page.contentSections)}
      <div class="grid">
        ${renderChecklist("Cui se adreseaza", page.audience)}
        ${renderChecklist("Conditii de eligibilitate", page.eligibility)}
      </div>
      <h2>Eligibilitatea se verifica prin solicitant, activitate, documente si investitie.</h2>
      <p>${esc(page.policyContribution)} Aceasta contributie conteaza pentru modul in care este scris proiectul: obiectivele trebuie sa fie clare, cheltuielile sa fie explicate, iar rezultatele sa poata fi urmarite dupa contractare.</p>
      <p>O eroare frecventa este pornirea de la lista de cumparaturi. Ordinea mai sigura este inversa: intai se verifica solicitantul, apoi activitatea, apoi locatia si documentele, iar abia dupa aceea se confirma echipamentele, serviciile sau lucrarile care pot intra in buget.</p>
      <div class="grid">
        ${renderChecklist("Conditii obligatorii", page.mandatory)}
        ${renderChecklist("Investitii si cheltuieli eligibile", page.eligibleExpenses)}
      </div>
      <h2>Cheltuieli neeligibile si riscuri</h2>
      <p>Cheltuielile neeligibile sunt importante pentru cash-flow. Chiar daca un proiect primeste sprijin, beneficiarul poate ramane responsabil pentru costuri care nu se deconteaza, diferente de pret, TVA tratat separat sau cheltuieli respinse la verificare.</p>
      <ul>${li(page.ineligibleExpenses)}</ul>
      <p>Riscurile apar mai ales cand documentele nu spun aceeasi poveste: codul CAEN descrie o activitate, oferta descrie alta activitate, iar planul de afaceri nu explica legatura dintre ele. De aceea, toate documentele trebuie citite impreuna, nu separat.</p>
      <h2>Finantare, cofinantare si buget</h2>
      <p>${esc(page.funding)} Pentru o decizie realista, bugetul trebuie impartit in cheltuieli eligibile, cheltuieli neeligibile, contributie proprie, posibile diferente de curs, costuri de implementare si rezerva pentru intarzieri.</p>
      <p>Cand pregatesti bugetul, evita rotunjirile agresive si ofertele prea generale. Un evaluator trebuie sa poata intelege ce cumperi, de ce este necesar, cum contribuie la obiective si cum va fi folosit dupa finalizarea proiectului.</p>
      ${renderCofinancingExample(page)}
      ${renderCalendarTable(page)}
      <h2>Criterii de selectie si punctaj</h2>
      <p>Grila de selectie transforma conditiile programului in prioritati concrete. Un proiect eligibil poate pierde daca nu are punctaj suficient, iar un proiect cu punctaj bun poate fi vulnerabil daca documentele de baza sunt incomplete.</p>
      <ul>${li(page.scoring)}</ul>
${dr14ScoreHtml}
      <p>In practica, punctajul se estimeaza inainte de depunere si se revizuieste dupa fiecare modificare de buget, investitie sau document. Daca o cheltuiala importanta nu sustine criteriile de selectie, ea trebuie justificata foarte clar sau eliminata.</p>
      <h2>Pasi pentru pregatirea cererii</h2>
      <ol>${li(page.steps)}</ol>
      <p>Pregatirea buna inseamna timp pentru clarificari, nu doar completarea formularelor. Documentele expirate, semnaturile lipsa, ofertele incomplete si fisierele incarcate gresit pot bloca proiecte care altfel ar avea o logica solida.</p>
      <h2>Evaluare, contractare si plata</h2>
      <p>Fluxul de dupa depunere trebuie inteles inainte de semnarea contractului. Evaluarea poate cere clarificari, contractarea poate impune termene stricte, iar plata depinde de documentele de achizitie, livrare, receptie si raportare.</p>
      <ol>${li(page.evaluation)}</ol>
      <p>Un proiect bun pastreaza trasabilitate de la cerere pana la plata: cerinta din ghid, cheltuiala din buget, oferta, contractul de achizitie, factura, dovada platii si rezultatul implementat trebuie sa fie coerente.</p>
      <h2>Exemple de situatii aplicate</h2>
      <p>Exemplele de mai jos sunt anonime si orientative. Ele arata tipul de rationament necesar, nu rezultate promise sau cazuri publicate cu date comerciale.</p>
      <ul>${li(page.examples)}</ul>
      <p>In fiecare exemplu, decizia corecta depinde de documente. Aceeasi investitie poate fi potrivita pentru un solicitant si nepotrivita pentru altul, in functie de activitate, locatie, istoric, buget si calendar.</p>
${toolsHtml}
${downloadsHtml}
${officialSourcesHtml}
      <h2>Intrebari frecvente</h2>
      ${faqHtml}
      <h2>Pentru o verificare initiala, trimite date despre solicitant, investitie, buget si programul urmarit.</h2>
      <p>Daca proiectul implica sume, cheltuieli tehnice, conditii de varsta, cod CAEN, amplasament sau cofinantare, merita verificat inainte de depunere. O analiza initiala poate identifica rapid documentele lipsa si riscurile evidente.</p>`;

  return html;
}

function pageHtml(page, config) {
  const metadata = metadataForPage(page);
  const family = designFamilyFor(page);
  const route = slugPath(page);
  const programBanner = bannerForRoute(route, PROGRAM_BANNER_INDEX);
  const relatedCss = (page.related || []).length ? `\n  <link rel="stylesheet" href="/assets/see-also.css" />` : "";
  const toolCss = page.includeTools || page.includeDownloads ? `\n  <link rel="stylesheet" href="/assets/seo-tools.css" />` : "";
  const sourcesCss = (page.sourceKeys || []).length ? `\n  <link rel="stylesheet" href="/assets/official-sources.css" />` : "";
  const extraCss = `${relatedCss}${toolCss}${sourcesCss}`;
  const extraJs = page.includeTools ? `\n  <script src="/assets/seo-tools.js" defer></script>` : "";
  const primaryCta = heroPrimaryCtaFor(page);
  const secondaryCta = heroSecondaryCta(page);
  const heroActionsHtml = renderHeroActions(page, primaryCta, secondaryCta);
  const programHeroHtml = programBanner
    ? renderProgramHero({
        route,
        banner: programBanner,
        existing: {
          tag: heroBadgeFor(page),
          title: page.h1,
          description: page.description
        },
        actionsHtml: heroActionsHtml
      })
    : `<header ${heroAttrs(page)}>
    <span class="hero-icon" aria-hidden="true"><i class="${esc(heroIconFor(page))}"></i></span>
    <span class="eyebrow design-badge design-badge--${esc(family)}">${esc(heroBadgeFor(page))}</span>
    <h1>${esc(page.h1)}</h1>
    <p>${esc(page.description)}</p>
    <div class="hero-actions">
      ${heroActionsHtml}
    </div>
    ${page.hideHeroSummary ? "" : renderHeroSummary(page)}
  </header>`;
  const finalCtaTitle = page.finalCtaTitle || (family === "editorial" ? "Verificare discreta pe cazul tau" : family === "trust" ? "Ai un caz asemanator?" : "Urmatorul pas");
  const finalCtaText = page.finalCtaText || (isEditorialProgram(page)
    ? "Trimite-ne codul CAEN / tipul fermei / investi\u021bia dorit\u0103 pentru verificarea eligibilit\u0103\u021bii."
    : "Trimite cateva detalii despre solicitant, localitate, cod CAEN, investitie si buget. Raspunsul initial este orientativ si nu reprezinta promisiune de finantare.");
  const finalPrimaryCta = page.finalPrimaryCta || designProfileFor(page).primary || "Solicita verificare eligibilitate";
  const finalSecondaryHref = page.finalSecondaryHref || "/consultanta-fonduri-europene";
  const finalSecondaryLabel = page.finalSecondaryLabel || "Vezi serviciile";
  const hasTrustApprovalGate = page.type === "trust" && Object.prototype.hasOwnProperty.call(page, "approvedItemsCount");
  const robots = page.robots || (hasTrustApprovalGate && Number(page.approvedItemsCount) < 3 ? "noindex, follow" : "index, follow");
  const html = `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(metadata.title)}</title>
  <meta name="description" content="${esc(metadata.description)}" />
  <meta name="robots" content="${escAttr(robots)}" />
  <meta name="seo-depth" content="true" />
  <meta name="seo-min-words" content="${minWordsForPage(page)}" />
  <meta name="seo-min-faq" content="${minFaqForPage(page)}" />
  <link rel="canonical" href="${metadata.canonicalUrl}" />
  <link rel="icon" type="image/png" href="/favicon.png" />
  <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
  <meta property="og:title" content="${esc(metadata.title)}" />
  <meta property="og:description" content="${esc(metadata.description)}" />
  <meta property="og:url" content="${metadata.ogUrl}" />
  <meta property="og:type" content="website" />
  <meta property="og:image" content="${SITE}/og-image.jpg" />
  <meta name="twitter:card" content="summary_large_image" />
  <link rel="preload" as="style" href="https://unpkg.com/@phosphor-icons/web@2.1.1/src/duotone/style.css" onload="this.onload=null;this.rel='stylesheet'" />
  <noscript><link rel="stylesheet" href="https://unpkg.com/@phosphor-icons/web@2.1.1/src/duotone/style.css" /></noscript>
  <link rel="stylesheet" href="/assets/seo-hub.css" />${extraCss}
  <script type="application/ld+json">${schemaGraph(page, config, metadata)}</script>${extraJs}
${CLARITY_TRACKING_CODE}
  <link rel="stylesheet" href="/assets/design-profiles.css">
${programBanner ? "  <link rel=\"stylesheet\" href=\"/assets/program-heroes.css\">" : ""}
</head>
<body class="page-family-${esc(family)}">
  ${GLOBAL_HEADER}
  ${renderBreadcrumb(breadcrumbItemsForPage(page))}
  ${programHeroHtml}
  <main class="container">
    <article class="panel">
${page.hideFamilyCards ? "" : renderFamilyCards(page)}
${renderMainContent(page)}
${renderPocidifDiscoveryLink(page)}
      <div class="related-links">${links(standardInternalLinksForPath(slugPath(page), page.related))}</div>
    </article>
    <section class="cta-box">
      <h2>${esc(finalCtaTitle)}</h2>
      <p>${esc(finalCtaText)}</p>
      <div class="cta-actions">
        <a class="btn btn-primary" href="/contact">${esc(finalPrimaryCta)}</a>
        <a class="btn btn-secondary" href="${escAttr(cleanUrl(finalSecondaryHref))}">${esc(finalSecondaryLabel)}</a>
      </div>
    </section>
  </main>
  <footer class="footer">© 2026 FABER - Atelier de Consultanta · <a href="/fonduri-europene">Fonduri europene</a> · <a href="/contact">Contact</a></footer>
</body>
</html>
`;
  return applyPriorityAeo(html, page.slug);
}

function redirectFallbackHtml(page) {
  const target = slugPath(page);
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Redirectionare | ${esc(page.h1 || page.title)}</title>
  <meta name="robots" content="noindex, follow" />
  <link rel="canonical" href="${canonical(page)}" />
  <meta http-equiv="refresh" content="0; url=${target}" />
  <script>window.location.replace('${target}');</script>
${CLARITY_TRACKING_CODE}
</head>
<body>
  <main style="font-family: Arial, sans-serif; max-width: 720px; margin: 12vh auto; padding: 32px; line-height: 1.6; color: #1a2540;">
    <h1>Ești redirecționat către o nouă adresă</h1>
    <p>Pagina veche a fost mutată. Dacă redirecționarea nu pornește automat, deschide <a href="${target}">${target}</a>.</p>
  </main>
</body>
</html>
`;
}

function ensureFile(page, html, { writeLegacy = true } = {}) {
  const normalizedHtml = normalizeHtmlCopy(html);
  const canonicalFile = path.join(ROOT, slugPath(page).slice(1), "index.html");
  fs.mkdirSync(path.dirname(canonicalFile), { recursive: true });
  fs.writeFileSync(canonicalFile, normalizedHtml, "utf8");

  const legacyFile = path.join(ROOT, page.output);
  if (CANONICAL_DIRECTORY_ONLY_SLUGS.has(page.slug) && fs.existsSync(legacyFile)) {
    fs.rmSync(legacyFile);
  } else if (writeLegacy && /\.html$/i.test(page.output) && !/\/index\.html$/i.test(page.output.replace(/\\/g, "/"))) {
    fs.mkdirSync(path.dirname(legacyFile), { recursive: true });
    fs.writeFileSync(legacyFile, normalizedHtml, "utf8");
  }
}

function parseSitemapUrls() {
  if (!fs.existsSync(SITEMAP_PATH)) return [];
  const xml = fs.readFileSync(SITEMAP_PATH, "utf8");
  return [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
}

function htmlCandidatesForRoute(route) {
  if (route === "/") return ["index.html"];
  const clean = route.replace(/^\/+/, "");
  return [`${clean}.html`, path.posix.join(clean, "index.html")];
}

function routeIsIndexable(route) {
  const clean = cleanUrl(route);
  if (!clean || clean.includes("/admin") || clean.includes("herambursabile") || clean.includes("/index")) return false;
  if (clean === "/") return true;
  const candidates = htmlCandidatesForRoute(clean);
  for (const candidate of candidates) {
    const file = path.join(ROOT, candidate);
    if (!fs.existsSync(file)) continue;
    const html = fs.readFileSync(file, "utf8");
    const robots = (html.match(/<meta\s+name=["']robots["']\s+content=["']([^"']+)/i) || [])[1] || "";
    if (!/noindex/i.test(robots)) return true;
  }
  return false;
}

function updateSitemap(pages, config) {
  require("child_process").execFileSync(process.execPath, [path.join(__dirname, "generate-sitemap.js")], {
    cwd: ROOT,
    stdio: "inherit"
  });
}

function updateRedirects(pages) {
  let text = fs.existsSync(REDIRECTS_PATH) ? fs.readFileSync(REDIRECTS_PATH, "utf8") : "";
  const additions = [];
  const queued = new Set();
  for (const page of pages) {
    const clean = slugPath(page);
    const customRedirects = Array.isArray(page.redirects) ? page.redirects : [];
    for (const source of customRedirects) {
      if (normalizeCanonicalPath(source) === clean) continue;
      const line = `${source} ${canonicalUrl(clean)} 301`;
      if (source === clean || queued.has(line) || text.includes(line)) continue;
      queued.add(line);
      additions.push(line);
    }
  }
  if (additions.length) {
    text = `${text.replace(/\s+$/g, "")}\n\n# SEO and AI Search canonical routes.\n${additions.join("\n")}\n`;
    fs.writeFileSync(REDIRECTS_PATH, text, "utf8");
  }
}

function updateBlogJson(pages, config) {
  if (!fs.existsSync(BLOG_JSON_PATH)) return;
  const data = readJson(BLOG_JSON_PATH);
  data.posts = Array.isArray(data.posts) ? data.posts : [];
  const retiredSlugs = new Set((config.pages || []).filter((page) => page.redirectTo).map((page) => page.slug));
  data.posts = data.posts.filter((post) => !retiredSlugs.has(post.id) && !retiredSlugs.has(post.slug));
  const byId = new Map(data.posts.map((post) => [post.id, post]));
  for (const page of pages.filter((item) => item.type === "program" && !byId.has(item.slug))) {
    const editorial = getEditorialMetadata(page.slug);
    data.posts.push({
      id: page.slug,
      title: page.h1,
      slug: page.slug,
      metaTitle: page.title,
      metaDescription: page.description,
      excerpt: page.quickAnswer,
      content: `<p>Pagina statica publicata la /${page.slug}.</p>`,
      status: "published",
      published: true,
      primaryKeyword: page.programName,
      secondaryKeywords: [page.category, "fonduri europene", "eligibilitate"],
      bannerImage: "",
      bannerAlt: "",
      author: editorial?.author || config.defaults.author,
      reviewer: editorial?.reviewer,
      officialSources: editorial?.officialSources || sourcesForKeys(page.sourceKeys).map((source) => ({
        url: source.url,
        title: source.title,
        institution: source.institution,
        documentType: source.documentType,
        accessedAt: source.accessedAt,
        note: source.note
      })),
      editorialStatus: editorial?.status || "in_curs_de_verificare",
      lastVerifiedAt: editorial?.lastVerifiedAt,
      createdAt: config.updatedAt,
      updatedAt: editorial?.updatedAt || config.updatedAt,
      publishedAt: editorial?.publishedAt || config.updatedAt,
      date: config.updatedAt,
      dateFormatted: "19 mai 2026",
      category: page.category,
      readTime: 12,
      readingTime: editorial?.readingTime || 12,
      icon: "",
      canonicalUrl: canonical(page),
      internalLinks: page.related || [],
      faq: faqsForPage(page).map(([question, answer]) => ({ question, answer }))
    });
  }
  writeJson(BLOG_JSON_PATH, data);
}

function updateBanners() {
  if (!fs.existsSync(BANNERS_PATH)) return;
  const banners = readJson(BANNERS_PATH);
  const wanted = [
    {
      id: "slide-micro-apel-2",
      tag: "Microîntreprinderi",
      title: "Modernizarea microîntreprinderilor\nApel 2",
      description: "Pregătire pentru microîntreprinderi: regiune, CAEN, documente, buget, cheltuieli și punctaj.",
      amount: "Finanțare: conform apelului activ",
      ctaText: "Detalii program →",
      ctaLink: "/investitii-modernizarea-microintreprinderilor-apel-2",
      image: "",
      altText: "Banner modernizarea microîntreprinderilor Apel 2",
      icon: "ph-buildings",
      order: 10,
      active: true,
      officialGuideKey: "por-ne"
    },
    {
      id: "slide-fond-modernizare-regenerabila",
      tag: "Energie regenerabilă",
      title: "Fondul pentru Modernizare\nEnergie regenerabilă",
      description: "Pagina pentru capacități noi de producere a energiei regenerabile: amplasament, avize, buget și depunere.",
      amount: "Finanțare: conform ghidului apelului activ",
      ctaText: "Detalii program →",
      ctaLink: "/fondul-modernizare-energie-regenerabila-2026",
      image: "",
      altText: "Banner Fondul pentru Modernizare energie regenerabilă",
      icon: "ph-sun",
      order: 11,
      active: true,
      officialGuideKey: "fondul-modernizare"
    },
    {
      id: "slide-apeluri-gal",
      tag: "LEADER / GAL",
      title: "Apeluri GAL\nFinanțări locale",
      description: "Orientare prudentă pentru identificarea GAL-ului local, verificarea ghidului, a documentelor și a criteriilor locale.",
      amount: "Finanțare: conform ghidului GAL activ",
      ctaText: "Detalii GAL →",
      ctaLink: "/apeluri-gal",
      image: "",
      altText: "Banner apeluri GAL LEADER",
      icon: "ph-map-pin",
      order: 12,
      active: true,
      officialGuideKey: "dr36-leader"
    },
    {
      id: "slide-e-move",
      tag: "Mobilitate electrică",
      title: "e-MOVE RO\nStații de încărcare și energie regenerabilă",
      description: "Program pentru infrastructura de mobilitate electrică. Verifică beneficiarul, amplasamentul, avizele, sursa de energie și ghidul activ înainte de depunere.",
      amount: "Finanțare: conform ghidului oficial al apelului activ",
      ctaText: "Detalii e-MOVE →",
      ctaLink: "/e-move",
      image: "",
      altText: "Banner program e-MOVE RO stații de încărcare și energie regenerabilă",
      icon: "ph-battery-charging",
      order: 13,
      active: true,
      officialGuideKey: "emove"
    },
    {
      id: "slide-gal-afir",
      tag: "LEADER / GAL / AFIR",
      title: "GAL-AFIR\nApeluri pentru beneficiari publici și privați",
      description: "Finanțări locale prin Grupuri de Acțiune Locală. FABER scrie proiecte noi și poate prelua proiecte aflate în implementare.",
      amount: "Finanțare: conform ghidului GAL activ",
      ctaText: "Detalii GAL-AFIR →",
      ctaLink: "/gal-afir",
      image: "",
      altText: "Banner GAL AFIR apeluri LEADER pentru beneficiari publici și privați",
      icon: "ph-map-pin",
      order: 14,
      active: true,
      officialGuideKey: "leader-gal"
    }
  ];
  for (const banner of wanted) {
    if (!banners.some((item) => item.id === banner.id)) banners.push(banner);
  }
  writeJson(BANNERS_PATH, banners);
}

function updateLlms(pages) {
  if (!fs.existsSync(LLMS_PATH)) return;
  let text = fs.readFileSync(LLMS_PATH, "utf8");
  const llmsSlugs = new Set(["instrumente", "resurse", "webinarii", "apeluri-gal", "e-move", "gal-afir", "investitii-modernizarea-microintreprinderilor-apel-2", "pocidif-21", "eligibilitate-pocidif-21", "cheltuieli-eligibile-pocidif-21", "documente-punctaj-pocidif-21", "pro-infra", "fondul-modernizare-energie-regenerabila-2026"]);
  const block = `\n## Pagini noi pentru vizibilitate AI si cautare vocala\n${pages
    .filter((page) => llmsSlugs.has(page.slug) && !/noindex/i.test(page.robots || ""))
    .map((page) => `- ${page.h1}: ${SITE}/${page.slug}`)
    .join("\n")}\n\n## Structura pentru asistenti AI\n- Paginile importante includ intrebari in limbaj natural, raspunsuri scurte vizibile si schema FAQPage doar cand intrebarile sunt vizibile in pagina.\n- Pentru sume, procente, punctaje si conditii finale, informatia trebuie verificata in apelul activ.\n`;
  if (text.includes("Pagini noi pentru vizibilitate AI")) {
    text = text.replace(/\n## Pagini noi pentru vizibilitate AI si cautare vocala[\s\S]*?\n## Structura pentru asistenti AI[\s\S]*$/m, block);
    fs.writeFileSync(LLMS_PATH, text, "utf8");
  } else {
    text = `${text.replace(/\s+$/g, "")}\n${block}`;
    fs.writeFileSync(LLMS_PATH, text, "utf8");
  }
}

function main() {
  const config = readJson(CONFIG_PATH);
  const onlyArgument = process.argv.slice(2).find((argument) => argument.startsWith("--only="));
  const onlySlugs = onlyArgument
    ? new Set(onlyArgument.slice("--only=".length).split(",").map((slug) => slug.trim()).filter(Boolean))
    : null;
  const pages = (config.pages || []).filter((page) => !page.redirectTo && (!onlySlugs || onlySlugs.has(page.slug)));
  if (onlySlugs && pages.length !== onlySlugs.size) {
    const found = new Set(pages.map((page) => page.slug));
    const missing = [...onlySlugs].filter((slug) => !found.has(slug));
    throw new Error(`Unknown or redirected --only slug(s): ${missing.join(", ")}`);
  }
  for (const page of pages) {
    validatePage(page);
    ensureFile(page, pageHtml(page, config), { writeLegacy: !onlySlugs });
  }
  if (onlySlugs) {
    console.log(`Generated ${pages.length} selected canonical SEO page(s): ${[...onlySlugs].join(", ")}.`);
    return;
  }
  updateSitemap(pages, config);
  updateRedirects(pages);
  updateBlogJson(pages, config);
  updateBanners();
  updateLlms(pages);
  console.log(`Generated ${pages.length} SEO program, hub and resource pages.`);
}

if (require.main === module) main();

module.exports = { pageHtml };
