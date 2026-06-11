"use strict";

const SITE = "https://atelierdeconsultanta.ro";
const BRAND_NAME = "FABER - Atelier de Consultanță";
const BRAND_ALTERNATE_NAMES = [
  "FABER",
  "Atelier de Consultanță",
  "Atelier de Consultanță FABER",
  "atelierdeconsultanta.ro"
];
const BRAND_DESCRIPTION = "FABER - Atelier de Consultanță ajută firme, fermieri, start-up-uri și IMM-uri să verifice eligibilitatea și să pregătească proiecte pentru fonduri europene și finanțări nerambursabile.";
const ORGANIZATION_ID = `${SITE}/#organization`;
const LOCAL_BUSINESS_ID = `${SITE}/#localbusiness`;
const WEBSITE_ID = `${SITE}/#website`;
const LOGO_URL = `${SITE}/favicon-192.png`;
const IMAGE_URL = `${SITE}/og-image.jpg`;
const EMAIL = "atelier.consultanta@gmail.com";
const TELEPHONES = ["+40769828338", "+40753326229"];
const KNOWS_ABOUT = [
  "fonduri europene",
  "finanțări nerambursabile",
  "AFIR",
  "PNRR",
  "Start-Up Nation",
  "Digitalizare IMM",
  "consultanță IMM"
];

function cleanText(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function normalizeCanonicalPath(pathname) {
  const raw = String(pathname ?? "").trim();
  if (!raw || raw === "/") return "/";

  let pathValue = raw;
  try {
    pathValue = new URL(raw, SITE).pathname || "/";
  } catch {
    const hashIndex = raw.indexOf("#");
    const queryIndex = raw.indexOf("?");
    const suffixIndex = [hashIndex, queryIndex].filter((index) => index >= 0).sort((a, b) => a - b)[0];
    pathValue = suffixIndex >= 0 ? raw.slice(0, suffixIndex) : raw;
  }

  pathValue = `/${String(pathValue).replace(/^\/+/, "")}`;
  pathValue = pathValue.replace(/\/index\.html$/i, "");
  pathValue = pathValue.replace(/\.html$/i, "");
  pathValue = pathValue.length > 1 ? pathValue.replace(/\/+$/g, "") : pathValue;
  return pathValue || "/";
}

function canonicalUrl(pathname) {
  const canonicalPath = normalizeCanonicalPath(pathname);
  return `${SITE}${canonicalPath}`;
}

function buildPageMetadata(options = {}) {
  const fallbackTitle = cleanText(options.fallbackTitle || BRAND_NAME);
  const fallbackDescription = cleanText(options.fallbackDescription || BRAND_DESCRIPTION);
  const title = cleanText(options.title) || fallbackTitle;
  let description = cleanText(options.description) || fallbackDescription;

  if (!description || description === title) {
    description = fallbackDescription && fallbackDescription !== title
      ? fallbackDescription
      : BRAND_DESCRIPTION;
  }

  const canonicalPath = normalizeCanonicalPath(options.pathname || options.route || options.url || "/");
  const absoluteCanonicalUrl = canonicalUrl(canonicalPath);
  return {
    title,
    description,
    canonicalPath,
    canonicalUrl: absoluteCanonicalUrl,
    ogUrl: absoluteCanonicalUrl
  };
}

const ROUTE_LABELS = new Map([
  ["/", "Acasa"],
  ["/fonduri-europene", "Fonduri europene"],
  ["/consultanta-fonduri-europene", "Consultanta fonduri europene"],
  ["/verificare-eligibilitate-fonduri-europene", "Verificare eligibilitate"],
  ["/fonduri-europene-imm", "Fonduri europene IMM"],
  ["/fonduri-europene-agricultura", "Fonduri europene agricultura"],
  ["/fonduri-europene-digitalizare", "Fonduri europene digitalizare"],
  ["/fonduri-regionale", "Fonduri regionale"],
  ["/programul-tranzitie-justa", "Programul Tranzitie Justa"],
  ["/fonduri-nerambursabile", "Fonduri nerambursabile"],
  ["/afir", "AFIR"],
  ["/consultanta-afir", "Consultanta AFIR"],
  ["/dr12-afir", "DR 12 AFIR"],
  ["/dr14", "DR 14 AFIR"],
  ["/calculator-soc", "Calculator SO AFIR"],
  ["/start-up-nation-2026", "Start-Up Nation 2026"],
  ["/consultanta-start-up-nation-2026", "Consultanta Start-Up Nation"],
  ["/fonduri-europene-femei-antreprenor", "Fonduri pentru femei antreprenor"],
  ["/digitalizare-imm", "Digitalizare IMM"],
  ["/digitalizare-imm-pnrr", "Digitalizare IMM / PNRR"],
  ["/pnrr", "PNRR"],
  ["/consultanta-pnrr-digitalizare", "Consultanta PNRR digitalizare"],
  ["/pocidif-21", "PoCIDIF 2.1"],
  ["/fondul-de-modernizare", "Fondul de Modernizare"],
  ["/fondul-modernizare-energie-regenerabila-2026", "Energie regenerabila 2026"],
  ["/finantari-panouri-fotovoltaice", "Finantari panouri fotovoltaice"],
  ["/despre-faber", "Despre FABER"],
  ["/metodologie-verificare-eligibilitate", "Metodologie eligibilitate"],
  ["/surse-oficiale-fonduri-europene", "Surse oficiale"],
  ["/studii-de-caz-fonduri-europene", "Studii de caz"],
  ["/glosar-fonduri-europene", "Glosar fonduri europene"],
  ["/blog", "Blog"],
  ["/ghiduri", "Ghiduri"],
  ["/contact", "Contact"]
]);

const CLUSTER_RULES = [
  { href: "/afir", label: "AFIR", pattern: /\/(?:afir|dr12|dr14|calculator-soc|fonduri-pentru-ferme|fonduri-pentru-utilaje-agricole|gal-afir)/i },
  { href: "/start-up-nation-2026", label: "Start-Up Nation 2026", pattern: /\/(?:start-up-nation|cod-caen-start-up-nation|consultanta-start-up-nation)/i },
  { href: "/fonduri-europene-digitalizare", label: "Digitalizare", pattern: /\/(?:digitalizare|pnrr|pocidif|granturi-digitalizare|cheltuieli-eligibile-digitalizare)/i },
  { href: "/fondul-de-modernizare", label: "Energie", pattern: /\/(?:fondul-de-modernizare|fondul-modernizare|finantari-panouri|autoconsum|pro-infra|e-move)/i },
  { href: "/fonduri-regionale", label: "Fonduri regionale", pattern: /\/(?:programul-tranzitie-justa|fonduri-europene-nord-est|fonduri-europene-bucuresti|consultanta-fonduri-europene-bucuresti|por-adr-nord-est|investitii-modernizarea-microintreprinderilor)/i },
  { href: "/consultanta-fonduri-europene", label: "Consultanta", pattern: /\/(?:consultanta|consultant-fonduri|firma-consultanta|cat-costa-consultanta|cum-alegi-consultant)/i },
  { href: "/despre-faber", label: "Incredere si metodologie", pattern: /\/(?:despre-faber|metodologie|surse-oficiale|studii-de-caz|testimoniale|portofoliu|glosar)/i },
  { href: "/ghiduri", label: "Ghiduri", pattern: /\/(?:blog|ghiduri|resurse|intrebari|acte-necesare|greseli|cum-se|ce-acte|cand-merita|idei-afaceri)/i },
  { href: "/fonduri-europene-imm", label: "Fonduri europene IMM", pattern: /\/(?:fonduri-europene-imm|fonduri-europene-femei-antreprenor|femeia-antreprenor|fonduri-europene-nerambursabile-2026)/i },
  { href: "/fonduri-europene-agricultura", label: "Agricultura", pattern: /\/(?:fonduri-europene-agricultura|fonduri-europene-caen\/0111)/i }
];

const INTERNAL_LINK_GROUPS = [
  {
    pattern: /\/(?:start-up-nation|cod-caen-start-up-nation|consultanta-start-up-nation)/i,
    links: [
      "/consultanta-start-up-nation-2026",
      "/start-up-nation-2026",
      "/start-up-nation-2026-conditii",
      "/start-up-nation-2026-cheltuieli-eligibile",
      "/start-up-nation-2026-plan-de-afaceri",
      "/cod-caen-start-up-nation-2026"
    ]
  },
  {
    pattern: /\/(?:afir|dr12|dr14|calculator-soc|fonduri-pentru-ferme|fonduri-pentru-utilaje-agricole|gal-afir)/i,
    links: ["/consultanta-afir", "/afir", "/dr12-afir", "/dr14", "/calculator-soc", "/fonduri-pentru-ferme"]
  },
  {
    pattern: /\/(?:digitalizare|pnrr|pocidif|granturi-digitalizare|cheltuieli-eligibile-digitalizare)/i,
    links: ["/consultanta-pnrr-digitalizare", "/fonduri-europene-digitalizare", "/digitalizare-imm", "/digitalizare-imm-pnrr", "/pocidif-21", "/pnrr"]
  },
  {
    pattern: /\/(?:fondul-de-modernizare|fondul-modernizare|finantari-panouri|autoconsum|pro-infra|e-move)/i,
    links: ["/fondul-de-modernizare", "/fondul-modernizare-energie-regenerabila-2026", "/finantari-panouri-fotovoltaice", "/consultanta-fonduri-europene"]
  },
  {
    pattern: /\/(?:consultanta|consultant-fonduri|firma-consultanta|cat-costa-consultanta|cum-alegi-consultant)/i,
    links: ["/consultanta-fonduri-europene", "/verificare-eligibilitate-fonduri-europene", "/fonduri-europene", "/metodologie-verificare-eligibilitate"]
  },
  {
    pattern: /\/(?:despre-faber|metodologie|surse-oficiale|studii-de-caz|testimoniale|portofoliu|glosar)/i,
    links: ["/metodologie-verificare-eligibilitate", "/surse-oficiale-fonduri-europene", "/despre-faber", "/contact"]
  },
  {
    pattern: /\/fonduri-europene$/i,
    links: ["/consultanta-fonduri-europene", "/fonduri-europene-imm", "/fonduri-europene-agricultura", "/fonduri-europene-digitalizare", "/fonduri-regionale", "/programul-tranzitie-justa"]
  },
  {
    pattern: /\/(?:programul-tranzitie-justa|fonduri-europene-nord-est|fonduri-europene-bucuresti|consultanta-fonduri-europene-bucuresti|por-adr-nord-est|investitii-modernizarea-microintreprinderilor)/i,
    links: ["/programul-tranzitie-justa", "/fonduri-regionale", "/fonduri-europene-imm", "/consultanta-fonduri-europene", "/surse-oficiale-fonduri-europene"]
  }
];

function routeLabel(pathname) {
  const clean = normalizeCanonicalPath(pathname);
  if (ROUTE_LABELS.has(clean)) return ROUTE_LABELS.get(clean);
  const slug = clean.split("/").filter(Boolean).pop() || "pagina";
  return slug.replace(/-/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function parentClusterForPath(pathname) {
  const clean = normalizeCanonicalPath(pathname);
  if (clean === "/") return null;
  for (const rule of CLUSTER_RULES) {
    if (rule.pattern.test(clean) && rule.href !== clean) return { href: rule.href, label: rule.label };
  }
  if (clean !== "/fonduri-europene") return { href: "/fonduri-europene", label: "Fonduri europene" };
  return null;
}

function breadcrumbItemsForPath(pathname, currentName) {
  const clean = normalizeCanonicalPath(pathname);
  const items = [{ name: "Acasa", item: canonicalUrl("/") }];
  if (clean === "/") return items;
  const parent = parentClusterForPath(clean);
  if (parent) items.push({ name: parent.label, item: canonicalUrl(parent.href) });
  items.push({ name: cleanText(currentName) || routeLabel(clean), item: canonicalUrl(clean) });
  return items;
}

function normalizeLinkItem(item) {
  if (!item) return null;
  if (typeof item === "string") {
    const href = normalizeCanonicalPath(item);
    return { href, label: routeLabel(href) };
  }
  if (Array.isArray(item)) {
    const href = normalizeCanonicalPath(item[0]);
    return { href, label: cleanText(item[1]) || routeLabel(href) };
  }
  const href = normalizeCanonicalPath(item.href || item.url || item.item);
  return { href, label: cleanText(item.label || item.name || item.title) || routeLabel(href) };
}

function standardInternalLinksForPath(pathname, existing = []) {
  const clean = normalizeCanonicalPath(pathname);
  const grouped = INTERNAL_LINK_GROUPS
    .filter((group) => group.pattern.test(clean))
    .flatMap((group) => group.links);
  const normalized = [...grouped, ...(Array.isArray(existing) ? existing : [])]
    .map(normalizeLinkItem)
    .filter((item) => item && item.href && item.href !== clean);
  const seen = new Set();
  return normalized.filter((item) => {
    if (seen.has(item.href)) return false;
    seen.add(item.href);
    return true;
  });
}

function cleanUrl(value) {
  if (!value || value === "/") return "/";
  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      if (url.origin === SITE) return canonicalUrl(url.pathname);
      if (url.pathname === "/" && !url.search && !url.hash) return `${url.origin}/`;
    } catch {
      // Fall back to a simple trim below.
    }
    return value.replace(/\/+$/g, "");
  }
  return normalizeCanonicalPath(value);
}

function absoluteUrl(value) {
  const clean = cleanUrl(value);
  if (/^https?:\/\//i.test(clean)) return clean;
  return canonicalUrl(clean);
}

function normalizeQuestion(value) {
  return cleanText(value)
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
}

function normalizeFaqItem(item) {
  if (Array.isArray(item)) {
    return { question: cleanText(item[0]), answer: cleanText(item[1]) };
  }
  return {
    question: cleanText(item?.question || item?.q || item?.name),
    answer: cleanText(item?.answer || item?.a || item?.text || item?.acceptedAnswer?.text)
  };
}

function uniqueFaqItems(faqItems) {
  const seen = new Set();
  const unique = [];
  for (const raw of Array.isArray(faqItems) ? faqItems : []) {
    const item = normalizeFaqItem(raw);
    const key = normalizeQuestion(item.question);
    if (!key || !item.answer || seen.has(key)) continue;
    seen.add(key);
    unique.push(item);
  }
  return unique;
}

function organizationSchema(options = {}) {
  const schema = {
    "@type": "Organization",
    "@id": ORGANIZATION_ID,
    name: BRAND_NAME,
    alternateName: BRAND_ALTERNATE_NAMES,
    url: SITE,
    description: BRAND_DESCRIPTION,
    logo: {
      "@type": "ImageObject",
      url: LOGO_URL
    },
    image: IMAGE_URL,
    email: EMAIL,
    areaServed: {
      "@type": "Country",
      name: "România"
    },
    contactPoint: TELEPHONES.map((telephone) => ({
      "@type": "ContactPoint",
      telephone,
      contactType: "customer service",
      availableLanguage: "ro-RO"
    })),
    knowsAbout: KNOWS_ABOUT
  };

  if (options.minimal) {
    return {
      "@type": "Organization",
      "@id": ORGANIZATION_ID,
      name: BRAND_NAME,
      alternateName: BRAND_ALTERNATE_NAMES,
      url: SITE,
      description: BRAND_DESCRIPTION,
      logo: { "@type": "ImageObject", url: LOGO_URL }
    };
  }

  return schema;
}

function localBusinessSchema() {
  return {
    "@type": ["LocalBusiness", "ProfessionalService"],
    "@id": LOCAL_BUSINESS_ID,
    name: BRAND_NAME,
    url: SITE,
    email: EMAIL,
    telephone: TELEPHONES[0],
    openingHours: "Mo-Fr 09:00-18:00",
    image: IMAGE_URL,
    areaServed: {
      "@type": "Country",
      name: "România"
    },
    parentOrganization: { "@id": ORGANIZATION_ID }
  };
}

function websiteSchema(options = {}) {
  const schema = {
    "@type": "WebSite",
    "@id": WEBSITE_ID,
    url: SITE,
    name: BRAND_NAME,
    publisher: { "@id": ORGANIZATION_ID },
    inLanguage: "ro-RO"
  };

  if (options.searchUrl) {
    schema.potentialAction = {
      "@type": "SearchAction",
      target: options.searchUrl,
      "query-input": "required name=search_term_string"
    };
  }

  return schema;
}

function webPageSchema(options) {
  const url = absoluteUrl(options.url || options.route);
  const schema = {
    "@type": options.type || "WebPage",
    "@id": options.id || `${url}#webpage`,
    url,
    name: cleanText(options.name || options.title),
    description: cleanText(options.description),
    isPartOf: { "@id": WEBSITE_ID },
    inLanguage: "ro-RO",
    publisher: { "@id": ORGANIZATION_ID }
  };

  if (options.datePublished) schema.datePublished = options.datePublished;
  if (options.dateModified) schema.dateModified = options.dateModified;
  if (options.about) schema.about = options.about;
  if (options.author) schema.author = personOrOrganization(options.author);
  if (options.reviewer) schema.reviewedBy = personOrOrganization(options.reviewer);
  if (Array.isArray(options.citation) && options.citation.length) schema.citation = options.citation;

  return schema;
}

function breadcrumbSchema(items) {
  const cleanItems = (items || []).filter((item) => item && item.name && item.item);
  if (!cleanItems.length) return null;
  return {
    "@type": "BreadcrumbList",
    itemListElement: cleanItems.map((item, index) => ({
      "@type": "ListItem",
      position: index + 1,
      name: cleanText(item.name),
      item: absoluteUrl(item.item)
    }))
  };
}

function faqPageSchema(faqItems, options = {}) {
  const items = uniqueFaqItems(faqItems);
  const minItems = Number(options.minItems || 1);
  if (items.length < minItems) return null;
  return {
    "@type": "FAQPage",
    mainEntity: items.map((item) => ({
      "@type": "Question",
      name: item.question,
      acceptedAnswer: {
        "@type": "Answer",
        text: item.answer
      }
    }))
  };
}

function blogPostingSchema(options) {
  const url = absoluteUrl(options.url || options.route);
  const schema = {
    "@type": options.type || "BlogPosting",
    headline: cleanText(options.headline || options.title),
    description: cleanText(options.description),
    author: personOrOrganization(options.author || BRAND_NAME),
    publisher: organizationSchema({ minimal: true }),
    datePublished: options.datePublished,
    dateModified: options.dateModified || options.datePublished,
    mainEntityOfPage: {
      "@type": "WebPage",
      "@id": url
    },
    url,
    inLanguage: "ro-RO"
  };

  if (options.reviewer) schema.reviewedBy = personOrOrganization(options.reviewer);
  if (options.editor) schema.editor = personOrOrganization(options.editor);
  if (options.image) schema.image = /^https?:\/\//i.test(options.image) ? options.image : `${SITE}${options.image}`;
  if (options.keywords) schema.keywords = Array.isArray(options.keywords) ? options.keywords.join(", ") : options.keywords;

  return schema;
}

function serviceSchema(options) {
  return {
    "@type": options.type || "Service",
    "@id": `${absoluteUrl(options.url || options.route)}#service`,
    name: cleanText(options.name),
    description: cleanText(options.description),
    provider: { "@id": ORGANIZATION_ID },
    areaServed: "RO",
    serviceType: cleanText(options.serviceType || options.category)
  };
}

function webApplicationSchema(options) {
  return {
    "@type": "WebApplication",
    "@id": `${absoluteUrl(options.url || options.route)}#app`,
    name: cleanText(options.name),
    description: cleanText(options.description),
    applicationCategory: options.applicationCategory || "FinanceApplication",
    operatingSystem: "Web",
    url: absoluteUrl(options.url || options.route),
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "RON"
    },
    provider: { "@id": ORGANIZATION_ID }
  };
}

function personOrOrganization(value) {
  if (value && typeof value === "object") return value;
  return {
    "@type": "Organization",
    name: cleanText(value || BRAND_NAME)
  };
}

function jsonLdGraph(nodes) {
  return JSON.stringify({
    "@context": "https://schema.org",
    "@graph": (nodes || []).filter(Boolean)
  }, null, 2);
}

module.exports = {
  SITE,
  BRAND_NAME,
  BRAND_ALTERNATE_NAMES,
  BRAND_DESCRIPTION,
  ORGANIZATION_ID,
  LOCAL_BUSINESS_ID,
  WEBSITE_ID,
  LOGO_URL,
  IMAGE_URL,
  EMAIL,
  TELEPHONES,
  absoluteUrl,
  buildPageMetadata,
  breadcrumbItemsForPath,
  breadcrumbSchema,
  canonicalUrl,
  faqPageSchema,
  jsonLdGraph,
  localBusinessSchema,
  normalizeCanonicalPath,
  parentClusterForPath,
  normalizeQuestion,
  organizationSchema,
  routeLabel,
  serviceSchema,
  standardInternalLinksForPath,
  uniqueFaqItems,
  webApplicationSchema,
  webPageSchema,
  websiteSchema,
  blogPostingSchema
};
