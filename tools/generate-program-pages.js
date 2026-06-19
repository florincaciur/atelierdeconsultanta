#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "seo-programs.json");
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const REDIRECTS_PATH = path.join(ROOT, "_redirects");
const BLOG_JSON_PATH = path.join(ROOT, "blog.json");
const BANNERS_PATH = path.join(ROOT, "banners.json");
const LLMS_PATH = path.join(ROOT, "llms.txt");
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
const { brandLogoLink } = require("./brand-logo");
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
  "dr14-afir-ferme-mici",
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
  "dr12-afir": ["DR12 AFIR", "program DR12 investitii tineri fermieri", "investitii tineri fermieri 2026", "ghid DR12 AFIR"],
  "dr14": ["DR14 AFIR", "investitii ferme mici", "program fonduri ferme mici 2026", "conditii DR14", "SO ferma mica"],
  "dr14-afir-ferme-mici": ["DR14 AFIR ferme mici", "conditii DR14 ferme mici", "documente DR14 AFIR", "eligibilitate ferme mici"],
  "digitalizare-imm": ["Digitalizare IMM 2026", "PNRR digitalizare IMM", "grant digitalizare IMM 2026", "echipamente digitalizare IMM"],
  "femeia-antreprenor-2026": ["Femeia Antreprenor 2026", "fonduri europene femei antreprenor 2026", "grant Femeia Antreprenor 2026", "cheltuieli eligibile Femeia Antreprenor 2026"],
  "start-up-nation-2026": ["Start Up Nation 2026", "Start Up Nation 2026 conditii", "cheltuieli eligibile Start Up Nation 2026", "cod CAEN Start Up Nation 2026", "idei afaceri Start Up Nation 2026", "plan de afaceri Start Up Nation 2026"],
  "fonduri-europene-imm": ["fonduri europene IMM 2026", "program IMM 2026", "granturi IMM 2026", "fonduri pentru IMM"],
  "investitii-modernizarea-microintreprinderilor-apel-2": ["fonduri microintreprinderi 2026", "program microintreprinderi 2026", "conditii microintreprinderi 2026"],
  "pocidif-21": ["PoCIDIF 2.1", "inovare digitala IMM TIC", "granturi PoCIDIF", "servicii aplicatii produse digitale"],
  "pro-infra": ["PRO INFRA 2026", "program energie 2026", "granturi energie verde 2026", "fonduri energie regenerabile 2026"],
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
    if (PILLAR_SLUGS.has(page.slug)) return 10;
    if (Number(page.minFaq) > 0) return Number(page.minFaq);
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
  const seen = new Set(faq.map(([question]) => String(question).toLowerCase()));
  for (const item of additions) {
    const key = item[0].toLowerCase();
    if (!seen.has(key)) {
      faq.push(item);
      seen.add(key);
    }
    if (faq.length >= minFaqForPage(page)) break;
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
      <p>Pentru o comparatie aplicata intre cele doua interventii, foloseste si pagina <a href="/dr12-vs-dr14">DR12 vs DR14</a>. Pentru o analiza specifica fermei mici, mergi in pagina <a href="/dr14-afir-ferme-mici">DR14 AFIR ferme mici</a>. Ambele pagini pastreaza formularea prudenta: concluzia finala depinde de ghidul activ si de documentele solicitantului.</p>
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
        <a href="/dr14-afir-ferme-mici">DR14 ferme mici</a>
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

function renderMainContent(page) {
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
  const relatedCss = (page.related || []).length ? `\n  <link rel="stylesheet" href="/assets/see-also.css" />` : "";
  const toolCss = page.includeTools || page.includeDownloads ? `\n  <link rel="stylesheet" href="/assets/seo-tools.css" />` : "";
  const sourcesCss = (page.sourceKeys || []).length ? `\n  <link rel="stylesheet" href="/assets/official-sources.css" />` : "";
  const extraCss = `${relatedCss}${toolCss}${sourcesCss}`;
  const extraJs = page.includeTools ? `\n  <script src="/assets/seo-tools.js" defer></script>` : "";
  const primaryCta = heroPrimaryCtaFor(page);
  const secondaryCta = heroSecondaryCta(page);
  const finalCtaTitle = page.finalCtaTitle || (family === "editorial" ? "Verificare discreta pe cazul tau" : family === "trust" ? "Ai un caz asemanator?" : "Urmatorul pas");
  const finalCtaText = page.finalCtaText || (isEditorialProgram(page)
    ? "Trimite-ne codul CAEN / tipul fermei / investi\u021bia dorit\u0103 pentru verificarea eligibilit\u0103\u021bii."
    : "Trimite cateva detalii despre solicitant, localitate, cod CAEN, investitie si buget. Raspunsul initial este orientativ si nu reprezinta promisiune de finantare.");
  const finalPrimaryCta = page.finalPrimaryCta || designProfileFor(page).primary || "Solicita verificare eligibilitate";
  const finalSecondaryHref = page.finalSecondaryHref || "/consultanta-fonduri-europene";
  const finalSecondaryLabel = page.finalSecondaryLabel || "Vezi serviciile";
  const hasTrustApprovalGate = page.type === "trust" && Object.prototype.hasOwnProperty.call(page, "approvedItemsCount");
  const robots = page.robots || (hasTrustApprovalGate && Number(page.approvedItemsCount) < 3 ? "noindex, follow" : "index, follow");
  return `<!DOCTYPE html>
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
</head>
<body class="page-family-${esc(family)}">
  <nav class="navbar" aria-label="Navigare principala">
    ${brandLogoLink()}
    <div class="navbar-links">
      <a href="/fonduri-europene">Fonduri europene</a>
      <a href="/ghiduri">Ghiduri</a>
      <a href="/instrumente">Instrumente</a>
      <a href="/resurse">Resurse</a>
      <a class="nav-cta btn-primary" href="/contact">Solicita verificare eligibilitate</a>
    </div>
  </nav>
  ${renderBreadcrumb(breadcrumbItemsForPage(page))}
  <header ${heroAttrs(page)}>
    <span class="hero-icon" aria-hidden="true"><i class="${esc(heroIconFor(page))}"></i></span>
    <span class="eyebrow design-badge design-badge--${esc(family)}">${esc(heroBadgeFor(page))}</span>
    <h1>${esc(page.h1)}</h1>
    <p>${esc(page.description)}</p>
    <div class="hero-actions">
      ${renderHeroActions(page, primaryCta, secondaryCta)}
    </div>
    ${renderHeroSummary(page)}
  </header>
  <main class="container">
    <article class="panel">
${renderFamilyCards(page)}
${renderMainContent(page)}
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

function ensureFile(page, html) {
  const normalizedHtml = normalizeHtmlCopy(html);
  const canonicalFile = path.join(ROOT, slugPath(page).slice(1), "index.html");
  fs.mkdirSync(path.dirname(canonicalFile), { recursive: true });
  fs.writeFileSync(canonicalFile, normalizedHtml, "utf8");

  if (/\.html$/i.test(page.output) && !/\/index\.html$/i.test(page.output.replace(/\\/g, "/"))) {
    const legacyFile = path.join(ROOT, page.output);
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
  const llmsSlugs = new Set(["instrumente", "resurse", "webinarii", "apeluri-gal", "e-move", "gal-afir", "investitii-modernizarea-microintreprinderilor-apel-2", "pocidif-21", "pro-infra", "fondul-modernizare-energie-regenerabila-2026"]);
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
  const pages = config.pages || [];
  for (const page of pages) {
    validatePage(page);
    ensureFile(page, pageHtml(page, config));
  }
  updateSitemap(pages, config);
  updateRedirects(pages);
  updateBlogJson(pages, config);
  updateBanners();
  updateLlms(pages);
  console.log(`Generated ${pages.length} SEO program, hub and resource pages.`);
}

main();
