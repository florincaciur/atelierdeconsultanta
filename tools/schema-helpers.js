"use strict";

const { canonicalContactIdentity } = require("./canonical-contact");
const { breadcrumbItemsForRoute } = require("./breadcrumb-registry");
const { approvedIdentity, loadLegalIdentity } = require("./legal-identity-governance");

const SITE = "https://atelierdeconsultanta.ro";
const LEGAL_CONFIG = loadLegalIdentity();
const LEGAL_IDENTITY = approvedIdentity(LEGAL_CONFIG) || {};
const BRAND_NAME = LEGAL_IDENTITY.brandName || "FABER – Atelier de Consultanță";
const BRAND_ALTERNATE_NAMES = [
  "FABER",
  "Atelier de Consultanță",
  "Atelier de Consultanță FABER",
  "atelierdeconsultanta.ro"
];
const BRAND_DESCRIPTION = "FABER - Atelier de Consultanță ajută firme, fermieri, start-up-uri și IMM-uri să verifice eligibilitatea și să pregătească proiecte pentru fonduri europene și finanțări nerambursabile.";
const ORGANIZATION_ID = `${SITE}/#organization`;
// Organization și ProfessionalService descriu aceeași entitate juridică și
// trebuie să folosească același identificator canonic.
const PROFESSIONAL_SERVICE_ID = ORGANIZATION_ID;
const LOCAL_BUSINESS_ID = PROFESSIONAL_SERVICE_ID;
const WEBSITE_ID = `${SITE}/#website`;
const LOGO_URL = `${SITE}/favicon-192.png`;
const IMAGE_URL = `${SITE}/og-image.jpg`;
const CANONICAL_CONTACT = canonicalContactIdentity();
const EMAIL = CANONICAL_CONTACT.email?.value || null;
const TELEPHONES = CANONICAL_CONTACT.phones.map((phone) => phone.value);
const LANGUAGE = "ro-RO";
const AREA_SERVED_NAME = LEGAL_IDENTITY.serviceArea || "România";
const KNOWS_ABOUT = [
  "fonduri europene",
  "finanțări nerambursabile",
  "AFIR",
  "PNRR",
  "Start-Up Nation",
  "Digitalizare IMM",
  "consultanță IMM"
];

const FABER_ENTITY_CONFIG = Object.freeze({
  site: SITE,
  name: BRAND_NAME,
  alternateNames: Object.freeze([...BRAND_ALTERNATE_NAMES]),
  description: BRAND_DESCRIPTION,
  ids: Object.freeze({
    organization: ORGANIZATION_ID,
    professionalService: PROFESSIONAL_SERVICE_ID,
    website: WEBSITE_ID
  }),
  logo: LOGO_URL,
  image: IMAGE_URL,
  email: EMAIL,
  telephones: Object.freeze([...TELEPHONES]),
  areaServed: AREA_SERVED_NAME,
  knowsAbout: Object.freeze([...KNOWS_ABOUT]),
  language: LANGUAGE
});

const PAGE_KINDS = Object.freeze({
  ARTICLE: "article",
  SERVICE: "service",
  WEB_APPLICATION: "web-application",
  WEB_PAGE: "web-page"
});

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
  ["/", "Acasă"],
  ["/fonduri-europene", "Fonduri europene"],
  ["/consultanta-fonduri-europene", "Consultanță fonduri europene"],
  ["/verificare-eligibilitate-fonduri-europene", "Verificare eligibilitate"],
  ["/fonduri-europene-imm", "Fonduri europene IMM"],
  ["/fonduri-europene-agricultura", "Fonduri europene agricultură"],
  ["/fonduri-europene-digitalizare", "Fonduri europene digitalizare"],
  ["/fonduri-regionale", "Fonduri regionale"],
  ["/programul-tranzitie-justa", "Programul Tranziție Justă"],
  ["/programul-tranzitie-justa-intrebari-documente", "Întrebări și documente PTJ"],
  ["/fonduri-nerambursabile", "Fonduri nerambursabile"],
  ["/afir", "AFIR"],
  ["/consultanta-afir", "Consultanță AFIR"],
  ["/dr12-afir", "DR 12 AFIR"],
  ["/dr14", "DR 14 AFIR"],
  ["/calculator-soc", "Calculator SO AFIR"],
  ["/start-up-nation-2026", "Start-Up Nation 2026"],
  ["/consultanta-start-up-nation-2026", "Consultanță Start-Up Nation"],
  ["/fonduri-europene-femei-antreprenor", "Fonduri pentru femei antreprenor"],
  ["/digitalizare-imm", "Digitalizare IMM"],
  ["/digitalizare-imm-pnrr", "Digitalizare IMM / PNRR"],
  ["/pnrr", "PNRR"],
  ["/consultanta-pnrr-digitalizare", "Consultanță PNRR digitalizare"],
  ["/pocidif-21", "PoCIDIF 2.1"],
  ["/fondul-de-modernizare", "Fondul de Modernizare"],
  ["/fondul-modernizare-energie-regenerabila-2026", "Energie regenerabilă 2026"],
  ["/finantari-panouri-fotovoltaice", "Finanțări panouri fotovoltaice"],
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
  { href: "/programul-tranzitie-justa", label: "Programul Tranziție Justă", pattern: /\/(?:programul-tranzitie-justa-intrebari-documente)/i },
  { href: "/fonduri-regionale", label: "Fonduri regionale", pattern: /\/(?:programul-tranzitie-justa|fonduri-europene-nord-est|fonduri-europene-bucuresti|consultanta-fonduri-europene-bucuresti|por-adr-nord-est|investitii-modernizarea-microintreprinderilor)/i },
  { href: "/consultanta-fonduri-europene", label: "Consultanță", pattern: /\/(?:consultanta|consultant-fonduri|firma-consultanta|cat-costa-consultanta|cum-alegi-consultant)/i },
  { href: "/despre-faber", label: "Încredere și metodologie", pattern: /\/(?:despre-faber|metodologie|surse-oficiale|studii-de-caz|testimoniale|portofoliu|glosar)/i },
  { href: "/ghiduri", label: "Ghiduri", pattern: /\/(?:blog|ghiduri|resurse|intrebari|acte-necesare|greseli|cum-se|ce-acte|cand-merita|idei-afaceri)/i },
  { href: "/fonduri-europene-imm", label: "Fonduri europene IMM", pattern: /\/(?:fonduri-europene-imm|fonduri-europene-femei-antreprenor|femeia-antreprenor|fonduri-europene-nerambursabile-2026)/i },
  { href: "/fonduri-europene-agricultura", label: "Agricultură", pattern: /\/(?:fonduri-europene-agricultura|fonduri-europene-caen\/0111)/i }
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
    links: ["/programul-tranzitie-justa", "/programul-tranzitie-justa-intrebari-documente", "/fonduri-regionale", "/fonduri-europene-imm", "/consultanta-fonduri-europene", "/surse-oficiale-fonduri-europene"]
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
  return breadcrumbItemsForRoute(pathname, currentName);
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

function pageKindForPath(pathname, hints = {}) {
  const route = normalizeCanonicalPath(pathname);
  const type = cleanText(hints.type).toLowerCase();
  const schemaType = cleanText(hints.schemaType).toLowerCase();
  if (route === "/calculator-soc") return PAGE_KINDS.WEB_APPLICATION;
  if (route === "/instrumente") return PAGE_KINDS.WEB_PAGE;
  if (schemaType === "webapplication") return PAGE_KINDS.WEB_APPLICATION;
  if (type === "service" || (!type && schemaType === "service")) return PAGE_KINDS.SERVICE;
  if (["article", "blog", "program"].includes(type) || ["article", "blogposting"].includes(schemaType)) {
    return PAGE_KINDS.ARTICLE;
  }
  if (/^\/(?:consultanta(?:-|$)|consultant-fonduri|firma-consultanta|verificare-eligibilitate|proiectare-fonduri|studiu-fezabilitate|management-proiecte|plan-de-afaceri-fonduri)/i.test(route)) {
    return PAGE_KINDS.SERVICE;
  }
  if (/^\/(?:intrebari\/|fonduri-europene-caen\/|fonduri-europene-(?:bacau|bucuresti|iasi|suceava)$|programul-tranzitie-justa-intrebari-documente$)/i.test(route)) {
    return PAGE_KINDS.ARTICLE;
  }
  if (route === "/dr12-vs-dr14") return PAGE_KINDS.ARTICLE;
  if (/^\/blog-[^/]+$/iu.test(route)) return PAGE_KINDS.ARTICLE;
  return PAGE_KINDS.WEB_PAGE;
}

function areaServedSchema() {
  return {
    "@type": "AdministrativeArea",
    name: AREA_SERVED_NAME
  };
}

function approvedPostalAddress() {
  const value = cleanText(LEGAL_IDENTITY.registeredOffice);
  const parts = value.split(",").map((part) => cleanText(part)).filter(Boolean);
  const locality = parts.find((part) => /^Sat\s+/iu.test(part))?.replace(/^Sat\s+/iu, "");
  const number = parts.find((part) => /^nr\.\s*/iu.test(part));
  const street = parts.find((part) => /^(?:Str\.|Strada)\s+/iu.test(part));
  const region = parts.find((part) => /^județul\s+/iu.test(part))?.replace(/^județul\s+/iu, "");

  if (!value || !locality || !number || !street || !region) {
    throw new Error("Sediul aprobat nu poate fi transformat fără pierderi într-o adresă PostalAddress");
  }

  return {
    "@type": "PostalAddress",
    streetAddress: `${street}, ${number}`,
    addressLocality: locality,
    addressRegion: region,
    addressCountry: "RO"
  };
}

function schemaTelephone(value) {
  const digits = String(value || "").replace(/\D/gu, "");
  if (digits.length === 11 && digits.startsWith("40")) {
    return `+40-${digits.slice(2, 5)}-${digits.slice(5, 8)}-${digits.slice(8)}`;
  }
  return value || undefined;
}

function contactPointsSchema() {
  return TELEPHONES.map((telephone) => ({
    "@type": "ContactPoint",
    telephone,
    contactType: "customer service",
    availableLanguage: LANGUAGE
  }));
}

function organizationSchema(options = {}) {
  const schema = {
    "@type": ["Organization", "ProfessionalService"],
    "@id": ORGANIZATION_ID,
    name: BRAND_NAME,
    legalName: LEGAL_IDENTITY.legalName,
    url: `${SITE}/`,
    email: EMAIL,
    telephone: schemaTelephone(LEGAL_IDENTITY.publicPhone),
    taxID: LEGAL_IDENTITY.taxIdentifier,
    address: approvedPostalAddress(),
    sameAs: LEGAL_IDENTITY.officialProfileUrls,
    logo: {
      "@type": "ImageObject",
      url: LOGO_URL
    }
  };
  for (const key of ["legalName", "email", "telephone", "taxID"]) {
    if (!schema[key]) delete schema[key];
  }
  if (!Array.isArray(schema.sameAs) || !schema.sameAs.length) delete schema.sameAs;
  // `minimal` rămâne acceptat pentru compatibilitate, dar entitatea este
  // intenționat identică peste tot: există o singură descriere canonică FABER.
  void options;
  return schema;
}

function professionalServiceSchema() {
  return organizationSchema();
}

function localBusinessSchema() {
  return professionalServiceSchema();
}

function websiteSchema(options = {}) {
  const schema = {
    "@type": "WebSite",
    "@id": WEBSITE_ID,
    url: SITE,
    name: BRAND_NAME,
    publisher: { "@id": ORGANIZATION_ID },
    inLanguage: LANGUAGE
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
    inLanguage: LANGUAGE,
    publisher: { "@id": ORGANIZATION_ID }
  };

  if (options.datePublished) schema.datePublished = options.datePublished;
  if (options.dateModified) schema.dateModified = options.dateModified;
  if (options.about) schema.about = options.about;
  const author = personOrOrganization(options.author);
  const reviewer = personOrOrganization(options.reviewer);
  if (author) schema.author = author;
  if (reviewer) schema.reviewedBy = reviewer;
  if (Array.isArray(options.citation) && options.citation.length) schema.citation = options.citation;

  return schema;
}

function breadcrumbSchema(items) {
  const cleanItems = (items || [])
    .filter((item) => item && item.name && item.item)
    .slice(0, 6);
  if (!cleanItems.length) return null;
  const currentUrl = absoluteUrl(cleanItems.at(-1).item);
  return {
    "@type": "BreadcrumbList",
    "@id": `${currentUrl}#breadcrumb`,
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
  const schema = {
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
  if (options.url || options.route) schema["@id"] = `${absoluteUrl(options.url || options.route)}#faq`;
  return schema;
}

function blogPostingSchema(options) {
  const url = absoluteUrl(options.url || options.route);
  const schema = {
    "@type": options.type || "BlogPosting",
    headline: cleanText(options.headline || options.title),
    description: cleanText(options.description),
    publisher: { "@id": ORGANIZATION_ID },
    "@id": options.id || `${url}#${options.type === "Article" ? "article" : "blogposting"}`,
    mainEntityOfPage: { "@id": `${url}#webpage` },
    url,
    inLanguage: LANGUAGE
  };

  if (options.datePublished) schema.datePublished = options.datePublished;
  if (options.dateModified) schema.dateModified = options.dateModified;
  const author = personOrOrganization(options.author);
  const reviewer = personOrOrganization(options.reviewer);
  const editor = personOrOrganization(options.editor);
  if (author) schema.author = author;
  if (reviewer) schema.reviewedBy = reviewer;
  if (editor) schema.editor = editor;
  if (options.image) schema.image = /^https?:\/\//i.test(options.image) ? options.image : `${SITE}${options.image}`;
  if (options.keywords) schema.keywords = Array.isArray(options.keywords) ? options.keywords.join(", ") : options.keywords;

  return schema;
}

function articleSchema(options) {
  return blogPostingSchema({ ...options, type: "Article" });
}

function serviceSchema(options) {
  return {
    "@type": options.type || "Service",
    "@id": `${absoluteUrl(options.url || options.route)}#service`,
    name: cleanText(options.name),
    description: cleanText(options.description),
    provider: { "@id": ORGANIZATION_ID },
    areaServed: areaServedSchema(),
    serviceType: cleanText(options.serviceType || options.category),
    inLanguage: LANGUAGE
  };
}

function webApplicationSchema(options) {
  const schema = {
    "@type": "WebApplication",
    "@id": `${absoluteUrl(options.url || options.route)}#app`,
    name: cleanText(options.name),
    description: cleanText(options.description),
    applicationCategory: options.applicationCategory || "FinanceApplication",
    operatingSystem: "Web",
    url: absoluteUrl(options.url || options.route),
    inLanguage: LANGUAGE,
    provider: { "@id": ORGANIZATION_ID }
  };
  if (Array.isArray(options.citation) && options.citation.length) schema.citation = options.citation;
  return schema;
}

function personOrOrganization(value) {
  if (!value) return null;
  if (value && typeof value === "object") {
    if (value["@id"] === ORGANIZATION_ID) return { "@id": ORGANIZATION_ID };
    const types = Array.isArray(value["@type"]) ? value["@type"] : [value["@type"]];
    const name = cleanText(value.name);
    const url = String(value.url || "").trim();
    if (types.includes("Person") && name && /^https:\/\//iu.test(url)) {
      return {
        "@type": "Person",
        "@id": String(value["@id"] || url),
        name,
        url
      };
    }
    return null;
  }
  const name = cleanText(value);
  const comparable = normalizeQuestion(name);
  if (comparable.includes("faber") || comparable === "atelier de consultanta") {
    return { "@id": ORGANIZATION_ID };
  }
  return null;
}

const INCENTIVE_STATUS_BY_CANONICAL_STATUS = Object.freeze({
  ANNOUNCED: "IncentiveStatusInDevelopment",
  PREPARATION: "IncentiveStatusInDevelopment",
  PUBLIC_CONSULTATION: "IncentiveStatusInDevelopment",
  CONSULTATIVE_GUIDE: "IncentiveStatusInDevelopment",
  FINAL_GUIDE: "IncentiveStatusInDevelopment",
  APPROVED_SCHEME: "IncentiveStatusInDevelopment",
  SCHEDULED: "IncentiveStatusInDevelopment",
  OPEN: "IncentiveStatusActive",
  CLOSED: "IncentiveStatusRetired",
  SUSPENDED: "IncentiveStatusOnHold",
  CANCELLED: "IncentiveStatusRetired",
  COMPLETED: "IncentiveStatusRetired"
});

function incentiveStatusForProgram(program) {
  const member = INCENTIVE_STATUS_BY_CANONICAL_STATUS[program?.canonicalStatus];
  return member ? `https://schema.org/${member}` : undefined;
}

function fundingProgramSchema(program) {
  if (!program || program.publicationState !== "public" || !program.pageUrl || !program.name) return null;
  const url = canonicalUrl(program.pageUrl);
  const authorityId = `${url}#program-authority`;
  const sourceId = `${url}#official-source`;

  const schema = {
    "@type": "FinancialIncentive",
    "@id": `${url}#funding-program`,
    name: cleanText(program.name),
    alternateName: cleanText(program.shortName),
    description: cleanText(program.statusLabel),
    identifier: cleanText(program.slug),
    url,
    mainEntityOfPage: { "@id": `${url}#webpage` },
    provider: {
      "@type": "Organization",
      "@id": authorityId,
      name: cleanText(program.sourceName)
    },
    subjectOf: {
      "@type": "CreativeWork",
      "@id": sourceId,
      name: cleanText(program.sourceVersion),
      url: program.sourceUrl,
      publisher: { "@id": authorityId }
    }
  };
  const incentiveStatus = incentiveStatusForProgram(program);
  if (incentiveStatus) schema.incentiveStatus = incentiveStatus;
  if (program.applicationStart) schema.validFrom = program.applicationStart;
  if (program.applicationEnd) schema.validThrough = program.applicationEnd;
  return schema;
}

function sortJsonValue(value) {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (!value || typeof value !== "object") return value;
  return Object.keys(value)
    .sort((left, right) => left.localeCompare(right))
    .reduce((result, key) => {
      result[key] = sortJsonValue(value[key]);
      return result;
    }, {});
}

function serializeJsonLd(value) {
  return JSON.stringify(sortJsonValue(value), null, 2);
}

function jsonLdGraph(nodes) {
  return serializeJsonLd({
    "@context": "https://schema.org",
    "@graph": (nodes || []).filter(Boolean)
  });
}

module.exports = {
  SITE,
  BRAND_NAME,
  BRAND_ALTERNATE_NAMES,
  BRAND_DESCRIPTION,
  FABER_ENTITY_CONFIG,
  PAGE_KINDS,
  ORGANIZATION_ID,
  PROFESSIONAL_SERVICE_ID,
  LOCAL_BUSINESS_ID,
  WEBSITE_ID,
  LOGO_URL,
  IMAGE_URL,
  EMAIL,
  TELEPHONES,
  LANGUAGE,
  AREA_SERVED_NAME,
  absoluteUrl,
  articleSchema,
  buildPageMetadata,
  breadcrumbItemsForPath,
  breadcrumbSchema,
  canonicalUrl,
  faqPageSchema,
  fundingProgramSchema,
  incentiveStatusForProgram,
  jsonLdGraph,
  localBusinessSchema,
  professionalServiceSchema,
  normalizeCanonicalPath,
  parentClusterForPath,
  pageKindForPath,
  normalizeQuestion,
  organizationSchema,
  routeLabel,
  serviceSchema,
  serializeJsonLd,
  standardInternalLinksForPath,
  uniqueFaqItems,
  webApplicationSchema,
  webPageSchema,
  websiteSchema,
  blogPostingSchema
};
