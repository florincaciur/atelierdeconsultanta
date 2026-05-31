#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  DESIGN_FAMILY_BY_SLUG,
  normalizeDesignSlug
} = require("./design-family-map");
const { normalizeHtmlCopy } = require("./normalize-copy-ro");

const ROOT = path.resolve(__dirname, "..");
const DESIGN_CSS = '<link rel="stylesheet" href="/assets/design-profiles.css">';
const FAMILY_HERO_CLASS = /\bhero--(?:home|afir|gal|digital|startup|energy|cluster|service|editorial|caen|trust|tool|contact|legal|generic)\b/g;

const PROFILES = {
  home: {
    items: [["Promisiune", "eligibilitate si program potrivit"], ["Programe", "AFIR, PNRR, energie, startup"], ["Proces", "analiza inainte de dosar"], ["CTA", "un singur pas urmator clar"]],
    primary: "Verifica eligibilitatea proiectului",
    secondary: "Vezi programele active"
  },
  afir: {
    items: [["Solicitant", "profil, exploatatie, documente"], ["Investitie", "utilaje, ferme sau autoconsum"], ["Punctaj", "criterii si riscuri"], ["Ghid", "verificare in sursa oficiala"]],
    primary: "Verifica eligibilitatea",
    secondary: "Vezi sursa oficiala"
  },
  gal: {
    items: [["Teritoriu", "reguli locale si sesiune"], ["Beneficiar", "public sau privat"], ["DR36", "legatura cu LEADER"], ["Implementare", "documente si termene"]],
    primary: "Verifica eligibilitatea GAL",
    secondary: "Vezi sursa oficiala"
  },
  digital: {
    items: [["Hardware", "echipamente justificate"], ["Software", "ERP, CRM, cloud"], ["Cyber", "securitate si audit"], ["Procese", "legatura cu activitatea firmei"]],
    primary: "Verifica eligibilitatea",
    secondary: "Vezi sursa oficiala"
  },
  startup: {
    items: [["CAEN", "cod si activitate eligibila"], ["Buget", "cheltuieli si cofinantare"], ["Plan", "ipoteze verificabile"], ["Status", "confirmare in ghidul activ"]],
    primary: "Verifica ideea de proiect",
    secondary: "Vezi conditiile"
  },
  energy: {
    items: [["Consum", "dimensionare dupa nevoie"], ["Avize", "racordare si amplasament"], ["Buget", "echipamente si costuri"], ["Riscuri", "reguli tehnice si ghid"]],
    primary: "Verifica proiectul energetic",
    secondary: "Vezi sursa oficiala"
  },
  cluster: {
    items: [["Program", "alegere dupa profil"], ["Solicitant", "firma, locatie, activitate"], ["Documente", "set minim de verificare"], ["Riscuri", "eligibilitate, punctaj, timp"]],
    primary: "Verifica programul potrivit",
    secondary: "Vezi resursele"
  },
  service: {
    items: [["Verificare", "eligibilitate inainte de dosar"], ["Strategie", "program, buget, pasi"], ["Dosar", "documente si clarificari"], ["Implementare", "ritm si raspunsuri"]],
    primary: "Solicita analiza",
    secondary: "Vezi documentele"
  },
  editorial: {
    items: [["Pe scurt", "raspuns rapid si prudent"], ["Ce verifici", "criterii si documente"], ["Surse", "ghiduri si reguli oficiale"], ["Pas urmator", "analiza pe situatia ta"]],
    primary: "Verifica situatia ta",
    secondary: "Vezi resursele"
  },
  caen: {
    items: [["Cod CAEN", "activitatea exacta conteaza"], ["Apel", "eligibilitatea depinde de ghid"], ["Cheltuieli", "lista se verifica separat"], ["Programe", "compatibilitate orientativa"]],
    primary: "Verifica CAEN-ul",
    secondary: "Vezi programe compatibile"
  },
  trust: {
    items: [["Beneficiar", "context si profil"], ["Problema", "blocaj initial"], ["Interventie", "ce a verificat echipa"], ["Lectie", "ce ramane util"]],
    primary: "Discuta un caz similar",
    secondary: "Vezi portofoliul"
  },
  tool: {
    items: [["Date", "introduse de utilizator"], ["Calcul", "orientativ, nu decizie"], ["Praguri", "de verificat in ghid"], ["Urmator", "analiza pe documente"]],
    primary: "Calculeaza si verifica",
    secondary: "Vezi metodologia"
  },
  contact: {
    items: [["Context", "program si idee"], ["Documente", "ce exista acum"], ["Risc", "eligibilitate si termene"], ["Raspuns", "pasul urmator clar"]],
    primary: "Trimite contextul",
    secondary: "Vezi serviciile"
  },
  legal: {
    items: [["Document", "reguli institutionale"], ["Claritate", "text cu latime controlata"], ["Acces", "ancore si citire rapida"], ["Contact", "canal pentru intrebari"]],
    primary: "Contacteaza echipa",
    secondary: "Inapoi la site"
  },
  generic: {
    items: [["Context", "rolul paginii"], ["Actualizare", "informatie structurata"], ["Legaturi", "traseu intern clar"], ["Urmator", "actiune potrivita"]],
    primary: "Vezi urmatorul pas",
    secondary: "Contact"
  }
};

const TOC_IDS = ["pe-scurt", "ce-verifici", "documente", "pasii-urmatori"];
const TOC_LABELS = ["Pe scurt", "Ce verifici", "Documente", "Pasii urmatori"];

function existingFilesForSlug(slug) {
  const normalized = normalizeDesignSlug(slug);
  if (!normalized) return [path.join(ROOT, "index.html")].filter(fs.existsSync);
  const candidates = [
    path.join(ROOT, `${normalized}.html`),
    path.join(ROOT, normalized, "index.html")
  ];
  return candidates.filter((file, index) => fs.existsSync(file) && candidates.indexOf(file) === index);
}

function addCss(html) {
  if (html.includes("/assets/design-profiles.css")) return html;
  return html.replace(/<\/head>/i, `  ${DESIGN_CSS}\n</head>`);
}

function addBodyFamily(html, family) {
  return html.replace(/<body\b([^>]*)>/i, (match, attrs) => {
    if (/\bclass\s*=/.test(attrs)) {
      return match.replace(/\bclass\s*=\s*"([^"]*)"/i, (_, classes) => {
        const cleaned = classes
          .replace(/\bpage-family-[a-z-]+\b/g, "")
          .split(/\s+/)
          .filter(Boolean);
        cleaned.push(`page-family-${family}`);
        return `class="${cleaned.join(" ")}"`;
      });
    }
    return `<body class="page-family-${family}"${attrs}>`;
  });
}

function addHeroFamily(html, family) {
  return html.replace(/<(header|section)([^>]*class="([^"]*hero[^"]*)"[^>]*)>/i, (match, tag, attrs, classes) => {
    let nextAttrs = attrs;
    const nextClasses = classes
      .replace(FAMILY_HERO_CLASS, "")
      .split(/\s+/)
      .filter(Boolean);
    nextClasses.push(`hero--${family}`);
    nextAttrs = nextAttrs.replace(/class="([^"]*)"/i, `class="${nextClasses.join(" ")}"`);
    if (!/\bdata-design-family=/.test(nextAttrs)) {
      nextAttrs += ` data-design-family="${family}"`;
    } else {
      nextAttrs = nextAttrs.replace(/\bdata-design-family="[^"]*"/i, `data-design-family="${family}"`);
    }
    return `<${tag}${nextAttrs}>`;
  });
}

function profileFor(family) {
  return PROFILES[family] || PROFILES.generic;
}

function renderSummary(family) {
  const profile = profileFor(family);
  const items = profile.items
    .map(([title, text]) => `<div class="audit-design-summary__item"><strong>${title}</strong><span>${text}</span></div>`)
    .join("");
  return `
<aside class="audit-design-summary" aria-label="Pe scurt">
  <p class="audit-design-summary__label">Pe scurt</p>
  <div class="audit-design-summary__grid">${items}</div>
</aside>`;
}

function renderHeroActions(family) {
  const profile = profileFor(family);
  return `
    <div class="hero-actions">
      <a class="btn-primary" href="/contact">${profile.primary}</a>
      <a class="btn-secondary" href="/resurse">${profile.secondary}</a>
    </div>`;
}

function findFirstHero(html) {
  const open = /<(header|section)([^>]*class="[^"]*hero[^"]*"[^>]*)>/i.exec(html);
  if (!open) return null;
  const close = new RegExp(`</${open[1]}>`, "i");
  const closeMatch = close.exec(html.slice(open.index + open[0].length));
  if (!closeMatch) return null;
  const end = open.index + open[0].length + closeMatch.index + closeMatch[0].length;
  return { start: open.index, end, tag: open[1] };
}

function addHeroActions(html, family) {
  if (html.includes("hero-actions")) return html;
  const hero = findFirstHero(html);
  if (!hero) return html;
  const closeTag = `</${hero.tag}>`;
  return `${html.slice(0, hero.end - closeTag.length)}${renderHeroActions(family)}\n${html.slice(hero.end - closeTag.length)}`;
}

function addSummary(html, family) {
  if (html.includes("hero-summary") || html.includes("audit-design-summary")) return html;
  const hero = findFirstHero(html);
  if (!hero) return html;
  return `${html.slice(0, hero.end)}${renderSummary(family)}${html.slice(hero.end)}`;
}

function addArticleToc(html) {
  if (!html.includes('class="post-body') || html.includes("article-toc")) return html;
  let idIndex = 0;
  let withIds = html.replace(/<h2(?![^>]*\bid=)([^>]*)>/gi, (match, attrs) => {
    if (idIndex >= TOC_IDS.length) return match;
    const id = TOC_IDS[idIndex++];
    return `<h2 id="${id}"${attrs}>`;
  });
  if (idIndex < 2) return html;
  const links = TOC_IDS.slice(0, idIndex)
    .map((id, index) => `<a href="#${id}">${TOC_LABELS[index]}</a>`)
    .join("");
  const toc = `
      <nav class="article-toc" aria-label="Cuprins articol">
        <strong>Cuprins</strong>
        <div>${links}</div>
      </nav>
`;
  return withIds.replace(/(<article\b[^>]*class="[^"]*post-body[^"]*"[^>]*>)/i, `$1${toc}`);
}

function decorateFile(file, family) {
  const before = fs.readFileSync(file, "utf8");
  let html = before;
  html = addCss(html);
  html = addBodyFamily(html, family);
  html = addHeroFamily(html, family);
  html = addHeroActions(html, family);
  html = addSummary(html, family);
  html = addArticleToc(html);
  html = normalizeHtmlCopy(html);
  if (html !== before) fs.writeFileSync(file, html, "utf8");
  return html !== before;
}

let touched = 0;
let checked = 0;

for (const [slug, family] of Object.entries(DESIGN_FAMILY_BY_SLUG)) {
  for (const file of existingFilesForSlug(slug)) {
    checked += 1;
    if (decorateFile(file, family)) touched += 1;
  }
}

console.log(`Applied design profiles to ${touched} file(s); checked ${checked} file(s).`);
