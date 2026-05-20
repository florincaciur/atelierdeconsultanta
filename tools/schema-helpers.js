"use strict";

const SITE = "https://atelierdeconsultanta.ro";
const BRAND_NAME = "FABER - Atelier de Consultanta";
const BRAND_ALTERNATE_NAMES = [
  "FABER",
  "Atelier de Consultanta",
  "Atelier de Consultanță",
  "Atelier de Consultanta FABER",
  "atelierdeconsultanta.ro"
];
const BRAND_DESCRIPTION = "FABER - Atelier de Consultanta ajuta firme, fermieri, start-up-uri si IMM-uri sa verifice eligibilitatea si sa pregateasca proiecte pentru fonduri europene si finantari nerambursabile.";
const ORGANIZATION_ID = `${SITE}/#organization`;
const LOCAL_BUSINESS_ID = `${SITE}/#localbusiness`;
const WEBSITE_ID = `${SITE}/#website`;
const LOGO_URL = `${SITE}/favicon-192.png`;
const IMAGE_URL = `${SITE}/og-image.jpg`;
const EMAIL = "atelier.consultanta@gmail.com";
const TELEPHONES = ["+40769828338", "+40753326229"];
const KNOWS_ABOUT = [
  "fonduri europene",
  "finantari nerambursabile",
  "AFIR",
  "PNRR",
  "Start-Up Nation",
  "Digitalizare IMM",
  "consultanta IMM"
];

function cleanText(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function cleanUrl(value) {
  if (!value || value === "/") return "/";
  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      if (url.pathname === "/" && !url.search && !url.hash) return `${url.origin}/`;
    } catch {
      // Fall back to a simple trim below.
    }
    return value.replace(/\/+$/g, "");
  }
  return `/${String(value).replace(/^\/+/, "").replace(/\.html$/i, "").replace(/\/+$/g, "")}`;
}

function absoluteUrl(value) {
  const clean = cleanUrl(value);
  if (/^https?:\/\//i.test(clean)) return clean;
  return `${SITE}${clean === "/" ? "/" : clean}`;
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
      name: "Romania"
    },
    contactPoint: TELEPHONES.map((telephone) => ({
      "@type": "ContactPoint",
      telephone,
      contactType: "customer service",
      availableLanguage: "Romanian"
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
      name: "Romania"
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
  breadcrumbSchema,
  faqPageSchema,
  jsonLdGraph,
  localBusinessSchema,
  normalizeQuestion,
  organizationSchema,
  serviceSchema,
  uniqueFaqItems,
  webApplicationSchema,
  webPageSchema,
  websiteSchema,
  blogPostingSchema
};
