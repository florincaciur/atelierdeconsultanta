const fs = require("fs");
const fsp = require("fs/promises");
const http = require("http");
const path = require("path");
const vm = require("vm");
const cheerio = require("cheerio");
const { chromium } = require("playwright");

const ROOT = process.cwd();
const SITE = "https://atelierdeconsultanta.ro";
const REPORT_DIR = path.join(ROOT, "reports");
const SCREENSHOT_DIR = path.join(REPORT_DIR, "functional-screenshots");
const APPLY = process.argv.includes("--apply");
const SKIP_FUNCTIONAL = process.argv.includes("--skip-functional");
const FUNCTIONAL_ONLY = process.argv.includes("--functional-only");

const EXCLUDED_DIRS = new Set([".git", ".github", ".wrangler", "dist", "node_modules", "reports"]);
const NON_CONTENT_FILES = new Set(["404.html", "admin/index.html"]);
const SEE_ALSO_CSS = "/assets/see-also.css";
const SEO_HUB_CSS = "/assets/seo-hub.css";

const CANONICAL_ALIASES = new Map([
  ["/start-up-nation", "/start-up-nation-2026"],
  ["/consultanta-start-up-nation", "/consultanta-start-up-nation-2026"],
  ["/start-up-nation-2026-idei-afaceri-plan", "/start-up-nation-2026-idei-afaceri"],
]);

const CANONICAL_ROOT_HTML_ROUTES = new Set([
  "por-adr-nord-est",
  "dr12-afir",
  "afir-autoconsum-agroalimentar",
  "autoconsum-public-fotovoltaice-institutii-publice",
  "dr14",
  "digitalizare-imm",
  "femeia-antreprenor-2026",
  "pro-infra",
  "start-up-nation-2026",
  "calculator-soc",
]);

const PROGRAM_ROUTES = [
  "/por-adr-nord-est",
  "/fonduri-europene-nord-est",
  "/dr12-afir",
  "/afir-autoconsum-agroalimentar",
  "/autoconsum-public-fotovoltaice-institutii-publice",
  "/dr14",
  "/digitalizare-imm",
  "/femeia-antreprenor-2026",
  "/pro-infra",
  "/start-up-nation-2026",
  "/calculator-soc",
  "/fondul-de-modernizare",
  "/consultanta-pnrr-digitalizare",
  "/fonduri-europene-digitalizare",
  "/consultanta-fonduri-europene",
  "/fonduri-europene",
  "/calendar-fonduri-europene",
];

const FUNCTIONAL_PAGES = [
  { label: "home", path: "/" },
  { label: "contact", path: "/contact" },
  { label: "fonduri-europene", path: "/fonduri-europene" },
  { label: "consultanta-fonduri-europene", path: "/consultanta-fonduri-europene" },
  { label: "calendar-fonduri-europene", path: "/calendar-fonduri-europene" },
  { label: "consultanta-pnrr-digitalizare", path: "/consultanta-pnrr-digitalizare" },
  { label: "start-up-nation-2026", path: "/start-up-nation-2026" },
  ...PROGRAM_ROUTES.map((route) => ({ label: route.slice(1), path: route })),
].filter((item, index, items) => items.findIndex((candidate) => candidate.path === item.path) === index);

const SEE_ALSO_DESCRIPTIONS = new Map([
  ["fonduri-europene", "Hub central pentru programe, eligibilitate, ghiduri și resurse utile."],
  ["consultanta-fonduri-europene", "Servicii de verificare, pregătire dosar și suport pentru proiecte."],
  ["calendar-fonduri-europene", "Urmărește programele și pregătește documentele înainte de apel."],
  ["consultanta-pnrr-digitalizare", "Sprijin pentru proiecte PNRR, digitalizare IMM și bugete IT."],
  ["start-up-nation-2026", "Condiții, cheltuieli, idei și pași pentru Start-Up Nation."],
  ["pnrr", "Resurse despre PNRR, indicatori, cheltuieli și implementare."],
  ["afir", "Programe AFIR pentru ferme, tineri fermieri și investiții agricole."],
  ["calculator-soc", "Calculează orientativ Standard Output pentru pragurile AFIR."],
  ["dr12-afir", "Informații pentru instalarea tinerilor fermieri și praguri SO."],
  ["dr14", "Detalii pentru ferme mici, punctaj și eligibilitate orientativă."],
  ["digitalizare-imm", "Programe și cheltuieli pentru transformare digitală în IMM-uri."],
  ["femeia-antreprenor-2026", "Resurse pentru programe dedicate antreprenoriatului feminin."],
  ["fondul-de-modernizare", "Finanțări pentru energie, eficiență și proiecte de autoconsum."],
  ["fonduri-europene-imm", "Resurse pentru investiții, digitalizare și dezvoltare IMM."],
  ["fonduri-europene-agricultura", "Fonduri pentru ferme, utilaje, AFIR și proiecte agricole."],
  ["ghiduri", "Articole și explicații pentru pregătirea dosarului de finanțare."],
  ["contact", "Trimite datele proiectului pentru o evaluare inițială."],
]);

const SEE_ALSO_LABELS = new Map([
  ["fonduri-europene", "Fonduri europene"],
  ["consultanta-fonduri-europene", "Consultanță fonduri europene"],
  ["calendar-fonduri-europene", "Calendar fonduri europene"],
  ["consultanta-pnrr-digitalizare", "Consultanță PNRR și digitalizare"],
  ["start-up-nation-2026", "Start-Up Nation"],
  ["pnrr", "PNRR"],
  ["afir", "AFIR"],
  ["calculator-soc", "Calculator SO"],
  ["dr12-afir", "DR 12 AFIR"],
  ["dr14", "DR 14 AFIR"],
  ["digitalizare-imm", "Digitalizare IMM"],
  ["femeia-antreprenor-2026", "Femeia Antreprenor 2026"],
  ["fondul-de-modernizare", "Fondul de Modernizare"],
  ["fonduri-europene-imm", "Fonduri europene IMM"],
  ["fonduri-europene-agricultura", "Fonduri europene agricultură"],
  ["ghiduri", "Ghiduri fonduri europene"],
  ["contact", "Contact"],
]);

const PROGRAM_CLUSTER_CONFIG = {
  "consultanta-fonduri-europene/index.html": {
    heading: "Pe scurt: consultanță fonduri europene",
    intro: "Pagina funcționează ca nod comercial pentru antreprenorii care vor să înțeleagă ce se verifică înainte de pregătirea unui dosar de finanțare.",
    audience: ["firme care caută programul potrivit", "fermieri și IMM-uri cu investiții planificate", "antreprenori care vor o evaluare înainte de costuri"],
    checks: ["eligibilitatea solicitantului și codului CAEN", "bugetul, cofinanțarea și documentele disponibile", "riscurile din ghid, punctaj și calendar"],
    steps: ["descrie investiția și localitatea", "verifică programul și cheltuielile", "pregătește lista de documente", "decide depunerea doar după analiza riscurilor"],
    links: [["/fonduri-europene", "Fonduri europene"], ["/calendar-fonduri-europene", "Calendar fonduri europene"], ["/contact", "Contact"]],
  },
  "start-up-nation-2026.html": {
    heading: "Pe scurt: Start-Up Nation 2026",
    intro: "Clusterul Start-Up Nation trebuie citit împreună cu paginile despre condiții, cheltuieli, idei de afaceri și plan de afaceri.",
    audience: ["antreprenori la început de drum", "firme noi care pregătesc codul CAEN", "beneficiari care vor să valideze bugetul"],
    checks: ["condițiile solicitantului", "cheltuielile eligibile și contribuția proprie", "documentele și calendarul apelului"],
    steps: ["alege ideea și codul CAEN", "verifică lista de cheltuieli", "construiește bugetul", "pregătește planul și documentele"],
    links: [["/start-up-nation-2026-conditii", "Condiții Start-Up Nation"], ["/start-up-nation-2026-cheltuieli-eligibile", "Cheltuieli eligibile"], ["/consultanta-start-up-nation-2026", "Consultanță Start-Up Nation"]],
  },
  "dr12-afir.html": {
    heading: "Pe scurt: DR 12 AFIR",
    intro: "DR 12 trebuie analizat prin dimensiunea economică a exploatației, statutul solicitantului și documentele care pot susține instalarea.",
    audience: ["tineri fermieri", "exploatații agricole în dezvoltare", "beneficiari care verifică pragul SO"],
    checks: ["dimensiunea economică și documentele exploatației", "calificarea și forma juridică", "investiția propusă și punctajul orientativ"],
    steps: ["calculează SO", "verifică documentele agricole", "stabilește investiția", "simulează punctajul înainte de depunere"],
    links: [["/calculator-soc", "Calculator SO"], ["/afir", "AFIR"], ["/consultanta-afir", "Consultanță AFIR"]],
  },
  "dr14.html": {
    heading: "Pe scurt: DR 14 AFIR",
    intro: "DR 14 cere o verificare atentă a fermei mici, a componentei proiectului și a punctajului minim înainte de pregătirea dosarului.",
    audience: ["ferme mici", "exploatații vegetale sau zootehnice", "beneficiari care verifică punctajul DR 14"],
    checks: ["pragul SO și componenta proiectului", "vechimea, asocierea și proprietatea", "documentele agricole și investiția propusă"],
    steps: ["calculează SO", "alege componenta corectă", "completează calculatorul de punctaj", "verifică documentele suport"],
    links: [["/calculator-soc", "Calculator SO"], ["/dr-14-afir-conditii-eligibilitate-greseli-frecvente", "Condiții DR 14"], ["/afir", "AFIR"]],
  },
  "calculator-soc.html": {
    heading: "Pe scurt: Calculator SO",
    intro: "Calculatorul SO este un instrument orientativ pentru încadrarea economică a fermei și pentru discuția inițială despre DR 12 sau DR 14.",
    audience: ["fermieri care verifică praguri AFIR", "consultanți care pregătesc o discuție inițială", "beneficiari care combină culturi și animale"],
    checks: ["suprafețele și efectivele reale", "valorile SO folosite pentru fiecare categorie", "încadrarea în pragurile programului"],
    steps: ["adaugă culturile și animalele", "verifică totalul SO", "compară cu pragurile DR 12 și DR 14", "confirmă datele înainte de depunere"],
    links: [["/dr12-afir", "DR 12 AFIR"], ["/dr14", "DR 14 AFIR"], ["/consultanta-afir", "Consultanță AFIR"]],
  },
  "digitalizare-imm.html": {
    heading: "Pe scurt: Digitalizare IMM",
    intro: "Proiectele de digitalizare sunt mai solide când pornesc de la procese reale și indicatori măsurabili, nu doar de la o listă de achiziții.",
    audience: ["IMM-uri care vor software sau automatizare", "firme care pregătesc investiții IT", "beneficiari care verifică PNRR sau granturi digitale"],
    checks: ["nevoia de business", "cheltuielile eligibile", "ofertele și specificațiile tehnice"],
    steps: ["descrie procesele actuale", "alege soluțiile compatibile", "verifică indicatorii", "pregătește bugetul și documentele"],
    links: [["/fonduri-europene-digitalizare", "Fonduri digitalizare"], ["/consultanta-pnrr-digitalizare", "Consultanță PNRR"], ["/pnrr-digitalizare-imm-cheltuieli-eligibile", "Cheltuieli eligibile"]],
  },
  "femeia-antreprenor-2026.html": {
    heading: "Pe scurt: Femeia Antreprenor 2026",
    intro: "Programul trebuie verificat prin structura acționariatului, activitatea firmei, investiția și documentele disponibile.",
    audience: ["antreprenoare și firme eligibile", "IMM-uri cu acționariat relevant", "beneficiare care compară programe"],
    checks: ["structura acționariatului", "codul CAEN și investiția", "bugetul și documentele firmei"],
    steps: ["verifică eligibilitatea firmei", "clarifică investiția", "pregătește bugetul", "compară cu alte programe IMM"],
    links: [["/fonduri-europene-femei-antreprenor", "Fonduri femei antreprenor"], ["/fonduri-europene-imm", "Fonduri IMM"], ["/consultanta-fonduri-europene", "Consultanță"]],
  },
  "por-adr-nord-est.html": {
    heading: "Pe scurt: POR ADR Nord-Est",
    intro: "Pentru programele regionale, compatibilitatea depinde de regiune, solicitant, investiție și criteriile apelului activ.",
    audience: ["IMM-uri din regiunea vizată", "firme cu investiții productive", "beneficiari care compară programe regionale"],
    checks: ["locația investiției", "codul CAEN și datele financiare", "bugetul și cofinanțarea"],
    steps: ["confirmă regiunea", "verifică ghidul apelului", "pregătește bugetul", "corelează investiția cu punctajul"],
    links: [["/fonduri-europene-imm", "Fonduri IMM"], ["/calendar-fonduri-europene", "Calendar"], ["/consultanta-fonduri-europene", "Consultanță"]],
  },
  "pro-infra.html": {
    heading: "Pe scurt: PRO INFRA",
    intro: "PRO INFRA trebuie analizat prin tipul solicitantului, investiția propusă, calendar și documentele tehnice necesare.",
    audience: ["firme cu investiții în producție sau materiale", "beneficiari care urmăresc apeluri sectoriale", "echipe care pregătesc bugete tehnice"],
    checks: ["încadrarea solicitantului", "cheltuielile și documentele tehnice", "calendarul și cofinanțarea"],
    steps: ["definește investiția", "verifică ghidul", "pregătește ofertele", "revizuiește riscurile înainte de depunere"],
    links: [["/fonduri-europene-imm", "Fonduri IMM"], ["/calendar-fonduri-europene", "Calendar"], ["/contact", "Contact"]],
  },
  "afir-autoconsum-agroalimentar.html": {
    heading: "Pe scurt: AFIR autoconsum agroalimentar",
    intro: "Proiectele de autoconsum trebuie dimensionate după consum, locație, avize și condițiile apelului de finanțare.",
    audience: ["ferme și procesatori agroalimentari", "beneficiari care urmăresc energie regenerabilă", "solicitanți care pregătesc documente tehnice"],
    checks: ["consumul energetic", "soluția tehnică și avizele", "eligibilitatea solicitantului și a cheltuielilor"],
    steps: ["analizează consumul", "dimensionează investiția", "verifică documentele tehnice", "corelează bugetul cu ghidul"],
    links: [["/fondul-de-modernizare", "Fondul de Modernizare"], ["/finantari-panouri-fotovoltaice", "Finanțări fotovoltaice"], ["/consultanta-afir", "Consultanță AFIR"]],
  },
  "autoconsum-public-fotovoltaice-institutii-publice.html": {
    heading: "Pe scurt: autoconsum pentru instituții publice",
    intro: "Finanțările pentru fotovoltaice la instituții publice trebuie pregătite cu date de consum, documente tehnice și clarificarea eligibilității solicitantului.",
    audience: ["instituții publice", "UAT-uri și entități eligibile", "echipe tehnice care pregătesc proiecte de energie"],
    checks: ["tipul solicitantului", "consumul și dimensionarea", "documentele tehnice și bugetul"],
    steps: ["colectează datele de consum", "verifică programul potrivit", "pregătește documentele tehnice", "confirmă calendarul depunerii"],
    links: [["/fondul-de-modernizare", "Fondul de Modernizare"], ["/finantari-panouri-fotovoltaice", "Finanțări fotovoltaice"], ["/contact", "Contact"]],
  },
  "fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html": {
    heading: "Pe scurt: Fondul de Modernizare",
    intro: "Proiectele de energie și autoconsum necesită verificarea solicitantului, a consumului, a avizelor și a soluției tehnice.",
    audience: ["firme și instituții cu investiții în energie", "beneficiari care urmăresc autoconsum", "echipe care pregătesc proiecte fotovoltaice"],
    checks: ["consumul energetic", "eligibilitatea solicitantului", "bugetul, avizele și calendarul"],
    steps: ["analizează consumul", "alege programul compatibil", "pregătește documentele tehnice", "verifică bugetul și termenul"],
    links: [["/fondul-de-modernizare", "Fondul de Modernizare"], ["/afir-autoconsum-agroalimentar", "AFIR autoconsum"], ["/autoconsum-public-fotovoltaice-institutii-publice", "Autoconsum instituții publice"]],
  },
};

const GENERIC_PROGRAM_CLUSTER_ROUTES = new Set([
  "fonduri-europene/index.html",
  "fonduri-nerambursabile/index.html",
  "fonduri-europene-nerambursabile-2026/index.html",
  "pnrr/index.html",
  "afir/index.html",
  "fonduri-europene-imm/index.html",
  "fonduri-europene-agricultura/index.html",
  "fonduri-europene-digitalizare/index.html",
  "fonduri-europene-femei-antreprenor/index.html",
  "calendar-fonduri-europene/index.html",
  "eligibilitate-fonduri-europene/index.html",
  "verificare-eligibilitate-fonduri-europene/index.html",
  "consultanta-pnrr-digitalizare/index.html",
  "digitalizare-imm-pnrr/index.html",
  "granturi-digitalizare-imm/index.html",
  "fondul-de-modernizare/index.html",
  "finantari-panouri-fotovoltaice/index.html",
  "consultanta-afir/index.html",
  "fonduri-pentru-ferme/index.html",
  "fonduri-pentru-utilaje-agricole/index.html",
  "consultanta-start-up-nation-2026/index.html",
  "start-up-nation-2026-conditii/index.html",
  "start-up-nation-2026-cheltuieli-eligibile/index.html",
  "start-up-nation-2026-plan-de-afaceri/index.html",
  "start-up-nation-2026-idei-afaceri/index.html",
  "cod-caen-start-up-nation-2026/index.html",
]);

const GENERIC_PROGRAM_CLUSTER_LINKS = [
  [/start-up-nation|cod-caen/, [["/start-up-nation-2026", "Start-Up Nation 2026"], ["/consultanta-start-up-nation-2026", "Consultanță Start-Up Nation"], ["/start-up-nation-2026-cheltuieli-eligibile", "Cheltuieli eligibile"]]],
  [/afir|ferme|utilaje-agricole|agricultura/, [["/consultanta-afir", "Consultanță AFIR"], ["/calculator-soc", "Calculator SO"], ["/fonduri-pentru-ferme", "Fonduri pentru ferme"]]],
  [/pnrr|digitalizare|granturi-digitalizare/, [["/consultanta-pnrr-digitalizare", "Consultanță PNRR și digitalizare"], ["/digitalizare-imm", "Digitalizare IMM"], ["/pnrr-digitalizare-imm-cheltuieli-eligibile", "Cheltuieli eligibile"]]],
  [/modernizare|fotovoltaice|panouri/, [["/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum", "Finanțări energie și autoconsum"], ["/afir-autoconsum-agroalimentar", "AFIR autoconsum"], ["/contact", "Contact"]]],
  [/femei-antreprenor/, [["/femeia-antreprenor-2026", "Femeia Antreprenor 2026"], ["/fonduri-europene-imm", "Fonduri IMM"], ["/consultanta-fonduri-europene", "Consultanță"]]],
];

function posix(value) {
  return value.split(path.sep).join("/");
}

function cleanPath(value) {
  if (!value || value === "/") return "/";
  if (/^(mailto|tel|sms|javascript|data|blob|whatsapp):/i.test(value)) return value;
  if (/^https?:\/\//i.test(value)) {
    const url = new URL(value);
    if (!/^(www\.)?atelierdeconsultanta\.ro$/i.test(url.hostname)) return value;
    return `${SITE}${cleanPath(`${url.pathname}${url.search}${url.hash}`)}`;
  }
  const hashIndex = value.indexOf("#");
  const queryIndex = value.indexOf("?");
  const suffixIndex = [hashIndex, queryIndex].filter((index) => index >= 0).sort((a, b) => a - b)[0];
  const pathname = suffixIndex >= 0 ? value.slice(0, suffixIndex) : value;
  const suffix = suffixIndex >= 0 ? value.slice(suffixIndex) : "";
  if (!pathname || pathname === "/") return `/${suffix}`.replace(/\/$/, "/");
  const withoutHtml = pathname.replace(/\.html$/i, "");
  const withoutSlash = withoutHtml.length > 1 ? withoutHtml.replace(/\/+$/g, "") : withoutHtml;
  const clean = withoutSlash || "/";
  return `${CANONICAL_ALIASES.get(clean) || clean}${suffix}`;
}

function escapeAttr(value) {
  return String(value).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}

function escapeHtml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function stripTags(value) {
  return String(value).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function truncate(value, max = 160) {
  const text = value.replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1).trim()}…` : text;
}

function slugFromHref(href) {
  const clean = cleanPath(href);
  const pathOnly = clean.replace(/^https?:\/\/[^/]+/i, "").split(/[?#]/)[0].replace(/^\/+|\/+$/g, "");
  return pathOnly || "home";
}

function descriptionFor(href, label) {
  const slug = slugFromHref(href);
  return SEE_ALSO_DESCRIPTIONS.get(slug) || `Continuă cu resursa conexă despre ${label.toLowerCase()}.`;
}

function labelFor(href, labelHtml) {
  const slug = slugFromHref(href);
  if (SEE_ALSO_LABELS.has(slug)) return SEE_ALSO_LABELS.get(slug);
  const titleMatch = labelHtml.match(/<span\s+class=["'][^"']*\bsee-also-card-title\b[^"']*["'][^>]*>([\s\S]*?)<\/span>/i);
  let label = stripTags(titleMatch ? titleMatch[1] : labelHtml);
  const description = descriptionFor(href, label);
  while (label.includes(description)) label = label.replace(description, "").replace(/\s+/g, " ").trim();
  return label || slug.replace(/-/g, " ");
}

function walkHtmlFiles(root) {
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name) && !entry.name.endsWith("_files")) walk(fullPath);
      } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html") && !entry.name.startsWith("FABER")) {
        files.push(fullPath);
      }
    }
  }
  walk(root);
  return files.sort((a, b) => posix(a).localeCompare(posix(b)));
}

function canonicalFor(relativePath) {
  const normalized = relativePath.replace(/\\/g, "/");
  if (normalized === "index.html") return `${SITE}/`;
  let route = normalized;
  if (route.endsWith("/index.html")) route = route.slice(0, -"/index.html".length);
  else if (route.endsWith(".html")) route = route.slice(0, -".html".length);
  route = `/${route.replace(/^\/+|\/+$/g, "")}`;
  return `${SITE}${cleanPath(route)}`;
}

function insertAfterHead(html, tag) {
  if (/<head\b[^>]*>/i.test(html)) {
    return html.replace(/<head\b[^>]*>/i, (match) => `${match}\n  ${tag}`);
  }
  return html;
}

function upsertMetaDescription(html, description) {
  if (/<meta\b(?=[^>]*\bname=["']description["'])[^>]*>/i.test(html)) return html;
  return insertAfterHead(html, `<meta name="description" content="${escapeAttr(description)}" />`);
}

function upsertCanonical(html, canonical) {
  if (/<link\b(?=[^>]*\brel=["']canonical["'])[^>]*>/i.test(html)) return html;
  return insertAfterHead(html, `<link rel="canonical" href="${escapeAttr(canonical)}" />`);
}

function addMissingAltAttributes(html) {
  return html.replace(/<img\b([^>]*?)>/gi, (match, attrs) => {
    if (/\salt\s*=/.test(attrs)) return match;
    const srcMatch = attrs.match(/\ssrc=["']([^"']+)["']/i);
    const src = srcMatch ? srcMatch[1] : "imagine";
    const base = path.basename(src.split(/[?#]/)[0], path.extname(src.split(/[?#]/)[0]));
    const alt = base.replace(/[-_]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()).trim() || "Imagine";
    return `<img${attrs} alt="${escapeAttr(alt)}">`;
  });
}

function ensureSeeAlsoStylesheet(html) {
  if (!/<head\b/i.test(html)) return html;
  if (!/(vezi-si-section|program-cluster|related-links)/.test(html)) return html;
  if (/related-links/.test(html) && !/(vezi-si-section|program-cluster)/.test(html) && html.includes(SEO_HUB_CSS)) return html;
  if (html.includes(SEE_ALSO_CSS)) return html;
  const tag = `  <link rel="stylesheet" href="${SEE_ALSO_CSS}" />`;
  const lastStylesheet = [...html.matchAll(/^[ \t]*<link\s+rel=["']stylesheet["'][^>]*>\s*$/gim)].pop();
  if (lastStylesheet) {
    const index = lastStylesheet.index + lastStylesheet[0].length;
    return `${html.slice(0, index)}\n${tag}${html.slice(index)}`;
  }
  return html.replace(/<\/head>/i, `${tag}\n</head>`);
}

function normalizeSeeAlso(html) {
  return html.replace(/<ul\s+class=["']([^"']*\bvezi-si\b[^"']*)["'][^>]*>([\s\S]*?)<\/ul>/gi, (block, className, inner) => {
    const items = [];
    inner.replace(/<li[^>]*>\s*<a\s+([^>]*?)href=["']([^"']+)["']([^>]*)>([\s\S]*?)<\/a>\s*<\/li>/gi, (_match, before, href, after, labelHtml) => {
      const label = labelFor(href, labelHtml);
      if (!label) return "";
      const cleanHref = cleanPath(href);
      items.push(
        `    <li class="see-also-card"><a ${before || ""}href="${escapeAttr(cleanHref)}"${after || ""}>` +
        `<span class="see-also-card-title">${escapeHtml(label)}</span>` +
        `<span class="see-also-card-text">${escapeHtml(descriptionFor(cleanHref, label))}</span>` +
        `</a></li>`
      );
      return "";
    });
    if (!items.length) return block;
    const classes = new Set(className.split(/\s+/).filter(Boolean));
    classes.add("see-also-grid");
    return `<ul class="${[...classes].join(" ")}">\n${items.join("\n")}\n  </ul>`;
  });
}

function list(items, ordered = false) {
  const tag = ordered ? "ol" : "ul";
  return `<${tag}>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</${tag}>`;
}

function clusterHtml(config) {
  const linkHtml = config.links
    .map(([href, label]) => `<a href="${escapeAttr(cleanPath(href))}">${escapeHtml(label)}</a>`)
    .join("");

  return `
  <section class="program-cluster" aria-labelledby="program-cluster-title">
    <div class="program-cluster-card">
      <span class="program-cluster-kicker">Cluster informațional</span>
      <h2 id="program-cluster-title">${escapeHtml(config.heading)}</h2>
      <p>${escapeHtml(config.intro)}</p>
      <div class="program-cluster-grid">
        <section class="program-cluster-panel">
          <h3>Cui se adresează</h3>
          ${list(config.audience)}
        </section>
        <section class="program-cluster-panel">
          <h3>Ce trebuie verificat</h3>
          ${list(config.checks)}
        </section>
        <section class="program-cluster-panel">
          <h3>Pași recomandați</h3>
          ${list(config.steps, true)}
        </section>
      </div>
      <div class="program-cluster-links">${linkHtml}</div>
    </div>
  </section>
`;
}

function clusterTitle(title, relativePath) {
  const fromTitle = stripTags(title || "").split(/\s[|–-]\s/)[0].trim();
  if (fromTitle) return fromTitle;
  return relativePath
    .replace(/\/index\.html$|\.html$/g, "")
    .split("/")
    .pop()
    .replace(/-/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function genericProgramClusterConfig(relativePath, title) {
  if (!GENERIC_PROGRAM_CLUSTER_ROUTES.has(relativePath)) return null;
  const route = relativePath.replace(/\/index\.html$|\.html$/g, "");
  const name = clusterTitle(title, relativePath);
  const matchedLinks = GENERIC_PROGRAM_CLUSTER_LINKS.find(([pattern]) => pattern.test(route));
  return {
    heading: `Pe scurt: ${name}`,
    intro: `Această pagină funcționează ca nod informațional pentru ${name.toLowerCase()}, cu trimiteri către eligibilitate, calendar, documente și resurse conexe.`,
    audience: ["antreprenori și organizații care compară finanțări", "beneficiari care verifică eligibilitatea înainte de dosar", "echipe care pregătesc bugetul, documentele și calendarul"],
    checks: ["încadrarea solicitantului și a investiției", "cheltuielile, cofinanțarea și documentele disponibile", "calendarul apelului și legăturile cu programele conexe"],
    steps: ["clarifică investiția", "verifică eligibilitatea", "pregătește bugetul și documentele", "alege ruta de consultanță sau ghidul potrivit"],
    links: matchedLinks ? matchedLinks[1] : [["/consultanta-fonduri-europene", "Consultanță fonduri europene"], ["/calendar-fonduri-europene", "Calendar fonduri europene"], ["/contact", "Contact"]],
  };
}

function ensureProgramCluster(html, relativePath, title) {
  const config = PROGRAM_CLUSTER_CONFIG[relativePath] || genericProgramClusterConfig(relativePath, title);
  if (!config) return html;
  const section = clusterHtml(config);
  const existingCluster = /\s*<section\s+class=["']program-cluster["'][\s\S]*?<\/section>\s*(?=<section\s+class=["'][^"']*\bvezi-si-section\b|<footer\b|<\/main>)/i;
  if (existingCluster.test(html)) return html.replace(existingCluster, `${section}`);
  if (/<section\s+class=["'][^"']*\bvezi-si-section\b/i.test(html)) {
    return html.replace(/(\s*)<section\s+class=["'][^"']*\bvezi-si-section\b/i, `${section}$1<section class="vezi-si-section`);
  }
  if (/<footer\b/i.test(html)) return html.replace(/(\s*)<footer\b/i, `${section}$1<footer`);
  if (/<\/main>/i.test(html)) return html.replace(/<\/main>/i, `${section}</main>`);
  return html.replace(/<\/body>/i, `${section}</body>`);
}

function ensureFallbackIndexing(html, relativePath) {
  const fallbackTargets = new Map([
    ["start-up-nation/index.html", "https://atelierdeconsultanta.ro/start-up-nation-2026"],
    ["start-up-nation-2026/index.html", "https://atelierdeconsultanta.ro/start-up-nation-2026"],
  ]);
  if (!fallbackTargets.has(relativePath)) return html;
  const canonical = fallbackTargets.get(relativePath);
  let updated = html;
  if (/<meta\s+name=["']robots["'][^>]*>/i.test(updated)) {
    updated = updated.replace(/<meta\s+name=["']robots["'][^>]*>/i, '<meta name="robots" content="noindex, follow" />');
  } else {
    updated = insertAfterHead(updated, '<meta name="robots" content="noindex, follow" />');
  }
  if (/<link\s+[^>]*rel=["']canonical["'][^>]*>/i.test(updated)) {
    updated = updated.replace(/<link\s+[^>]*rel=["']canonical["'][^>]*>/i, `<link rel="canonical" href="${canonical}" />`);
  } else {
    updated = insertAfterHead(updated, `<link rel="canonical" href="${canonical}" />`);
  }
  return updated;
}

function routePath(value) {
  const clean = cleanPath(String(value || "").trim().replace(/^['"]|['"]$/g, ""));
  return clean.replace(/^https?:\/\/[^/]+/i, "").split(/[?#]/)[0] || "/";
}

function removeSelfRedirects(html, relativePath) {
  const normalized = relativePath.replace(/\\/g, "/");
  if (normalized.includes("/") || !normalized.endsWith(".html")) return html;

  const route = normalized.slice(0, -".html".length);
  if (!CANONICAL_ROOT_HTML_ROUTES.has(route)) return html;

  const targetPath = `/${route}`;
  let updated = html.replace(/^[ \t]*<meta\b[^>]*\bhttp-equiv=["']refresh["'][^>]*>[ \t]*\r?\n?/gim, (match) => {
    const content = (match.match(/\bcontent=["']([^"']+)["']/i) || [])[1] || "";
    const target = content.split(";").map((part) => part.trim()).find((part) => /^url\s*=/i.test(part));
    const targetUrl = target ? target.replace(/^url\s*=/i, "").trim() : "";
    return routePath(targetUrl) === targetPath ? "" : match;
  });

  updated = updated.replace(/^[ \t]*<script>\s*window\.location\.replace\((["'])([^"']+)\1\);\s*<\/script>[ \t]*\r?\n?/gim, (match, _quote, targetUrl) => (
    routePath(targetUrl) === targetPath ? "" : match
  ));
  return updated;
}

function updateHtml(filePath, root) {
  const relativePath = posix(path.relative(root, filePath));
  const original = fs.readFileSync(filePath, "utf8");
  let html = original;
  const $ = cheerio.load(html, { decodeEntities: false });
  const title = $("title").first().text().trim() || $("h1").first().text().trim() || "Atelier de Consultanta";

  html = upsertMetaDescription(html, truncate(title));
  html = upsertCanonical(html, canonicalFor(relativePath));
  html = addMissingAltAttributes(html);
  html = normalizeSeeAlso(html);
  html = ensureProgramCluster(html, relativePath, $("h1").first().text().trim() || title);
  html = ensureFallbackIndexing(html, relativePath);
  html = removeSelfRedirects(html, relativePath);
  html = ensureSeeAlsoStylesheet(html);

  const changed = html !== original;
  if (changed && APPLY) fs.writeFileSync(filePath, html, "utf8");
  return { relativePath, changed };
}

function parseHtml(filePath, root) {
  const relativePath = posix(path.relative(root, filePath));
  const html = fs.readFileSync(filePath, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const technicalFile = NON_CONTENT_FILES.has(relativePath) || /^google[a-z0-9]+\.html$/i.test(relativePath);
  const robots = ($('meta[name="robots" i]').attr("content") || "").toLowerCase();
  const noindex = robots.includes("noindex");
  const h1s = $("h1").toArray().map((element) => $(element).text().replace(/\s+/g, " ").trim());
  const missingAlt = $("img").toArray()
    .filter((element) => !Object.prototype.hasOwnProperty.call(element.attribs || {}, "alt"))
    .map((element) => $(element).attr("src") || "<img without src>");
  const seeAlsoCount = $(".vezi-si-section, .program-cluster").length;
  const relatedLinksCount = $(".related-links").length;
  const relatedCount = seeAlsoCount + relatedLinksCount;
  const requireRelated = !technicalFile && !noindex && /fonduri|finant|afir|pnrr|start-up|digitalizare|consultanta|calculator|dr12|dr14/i.test(relativePath);
  const jsonLdErrors = [];
  $('script[type="application/ld+json"]').each((_index, element) => {
    const raw = $(element).text().trim();
    if (!raw) return;
    try {
      JSON.parse(raw);
    } catch (error) {
      jsonLdErrors.push(error.message);
    }
  });

  const checks = {
    metaDescription: technicalFile || noindex || $('meta[name="description" i]').length === 1,
    canonical: technicalFile || $('link[rel="canonical" i]').length === 1,
    imageAltAttributes: missingAlt.length === 0,
    singleH1: technicalFile || h1s.length === 1,
    relatedLinks: !requireRelated || relatedCount > 0,
    jsonLd: jsonLdErrors.length === 0,
    seeAlsoStylesheet:
      (seeAlsoCount === 0 || html.includes(SEE_ALSO_CSS)) &&
      (relatedLinksCount === 0 || html.includes(SEE_ALSO_CSS) || html.includes(SEO_HUB_CSS)),
  };
  const issues = Object.entries(checks).filter(([, pass]) => !pass).map(([name]) => name);
  return {
    file: relativePath,
    pass: issues.length === 0,
    noindex,
    technicalFile,
    issues,
    details: {
      h1Count: h1s.length,
      h1s,
      missingAlt,
      relatedCount,
      jsonLdErrors,
    },
  };
}

function checkInlineScripts(root) {
  const failures = [];
  let checked = 0;
  for (const filePath of walkHtmlFiles(root)) {
    const relativePath = posix(path.relative(root, filePath));
    const html = fs.readFileSync(filePath, "utf8");
    let scriptIndex = 0;
    for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      scriptIndex += 1;
      const attrs = match[1] || "";
      if (/\bsrc\s*=|application\/ld\+json/i.test(attrs)) continue;
      const code = match[2];
      if (!code.trim()) continue;
      checked += 1;
      try {
        new vm.Script(code, { filename: `${relativePath}#inline-${scriptIndex}` });
      } catch (error) {
        failures.push({ file: relativePath, script: scriptIndex, message: error.message });
      }
    }
  }
  return { checked, failures };
}

function safeRelativePath(urlPath) {
  const decoded = decodeURIComponent(urlPath.split("?")[0]).replace(/^\/+/, "");
  const normalized = path.posix.normalize(decoded);
  if (!normalized || normalized === ".") return "index.html";
  if (normalized.startsWith("../")) return "";
  return normalized;
}

function resolveLocalPath(urlPath) {
  const relativePath = safeRelativePath(urlPath);
  const candidates = [];
  if (!relativePath) return null;
  if (relativePath === "index.html") candidates.push("index.html");
  else {
    const cleanRoute = relativePath.replace(/\/+$/g, "");
    candidates.push(relativePath);
    if (!path.posix.extname(cleanRoute)) {
      candidates.push(`${cleanRoute}/index.html`);
      candidates.push(`${cleanRoute}.html`);
    }
  }
  for (const candidate of candidates) {
    const fullPath = path.join(ROOT, candidate);
    const resolved = path.resolve(fullPath);
    if ((resolved === ROOT || resolved.startsWith(ROOT + path.sep)) && fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
      return resolved;
    }
  }
  return null;
}

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".html") return "text/html; charset=utf-8";
  if (ext === ".css") return "text/css; charset=utf-8";
  if (ext === ".js") return "application/javascript; charset=utf-8";
  if (ext === ".json" || ext === ".webmanifest") return "application/json; charset=utf-8";
  if (ext === ".xml") return "application/xml; charset=utf-8";
  if (ext === ".txt") return "text/plain; charset=utf-8";
  if (ext === ".png") return "image/png";
  if (ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
  if (ext === ".webp") return "image/webp";
  return "application/octet-stream";
}

function createServer() {
  const server = http.createServer((request, response) => {
    try {
      const pathname = new URL(request.url, "http://127.0.0.1").pathname;
      const filePath = resolveLocalPath(pathname);
      if (!filePath) {
        response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        response.end("Not found");
        return;
      }
      response.writeHead(200, { "content-type": contentType(filePath) });
      fs.createReadStream(filePath).pipe(response);
    } catch (error) {
      response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      response.end(String(error.stack || error));
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

async function inspectPage(page, baseUrl, pageInfo) {
  const errors = [];
  page.on("console", (message) => {
    if (message.type() === "error" && !/^Failed to load resource: net::ERR_(FAILED|ABORTED)/.test(message.text())) {
      errors.push(message.text());
    }
  });
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    const response = await page.goto(`${baseUrl}${pageInfo.path}`, { waitUntil: "commit", timeout: 10000 });
    await page.waitForSelector("body", { timeout: 8000 });
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, `${pageInfo.label}.png`), fullPage: false, timeout: 5000 });
    const dom = await page.evaluate(() => ({
      title: document.title,
      h1Count: document.querySelectorAll("h1").length,
      seeAlsoCards: document.querySelectorAll(".vezi-si .see-also-card-title").length,
      programCluster: document.querySelectorAll(".program-cluster").length,
      overflow: document.documentElement.scrollWidth - window.innerWidth,
    }));
    return {
      page: pageInfo.path,
      status: response ? response.status() : 0,
      pass: !!response && response.status() < 400 && errors.length === 0 && dom.h1Count === 1 && dom.overflow <= 1,
      errors,
      dom,
      screenshot: posix(path.relative(ROOT, path.join(SCREENSHOT_DIR, `${pageInfo.label}.png`))),
    };
  } catch (error) {
    return {
      page: pageInfo.path,
      status: 0,
      pass: false,
      errors: [...errors, error.message],
      dom: {},
      screenshot: "",
    };
  }
}

async function testContactForm(page, baseUrl) {
  const result = { name: "contact-form", pass: false, message: "" };
  await page.goto(`${baseUrl}/`, { waitUntil: "commit", timeout: 10000 });
  await page.click("#homepage-contact .im-contact-disclosure > summary");
  await page.waitForSelector("#contact-triage-form", { timeout: 8000 });
  await page.selectOption("#contact-applicant-type", "societate");
  await page.fill("#contact-location", "Iași");
  await page.fill("#contact-investment", "Digitalizarea proceselor interne");
  await page.fill("#contact-email", "test@example.com");
  await page.check("#privacy-notice-acknowledged");
  await page.click('#contact-triage-form [data-action="review-short"]');
  await page.waitForSelector('#contact-triage-form [data-form-summary]:not([hidden])', { timeout: 8000 });
  await page.click('#contact-triage-form [data-final-submit]');
  await page.waitForSelector("[data-form-success]:not([hidden])", { timeout: 8000 });
  const visible = await page.locator("[data-form-success]").isVisible();
  result.pass = visible;
  result.message = visible ? "triage summary and success message visible" : "success message missing";
  return result;
}

async function testCalculatorSo(page, baseUrl) {
  const result = { name: "calculator-so", pass: false, message: "" };
  await page.goto(`${baseUrl}/calculator-soc`, { waitUntil: "commit", timeout: 10000 });
  await page.waitForSelector("#total-so", { timeout: 8000 });
  await page.click('button[onclick*="addCulturaRow"][onclick*="culturi"]');
  await page.waitForFunction(() => {
    const text = document.querySelector("#total-so")?.textContent || "0";
    return Number(text.replace(/\D/g, "")) > 0;
  }, null, { timeout: 8000 });
  const total = await page.textContent("#total-so");
  result.pass = Number(String(total).replace(/\D/g, "")) > 0;
  result.message = `total SO: ${total}`;
  return result;
}

async function testDr14Score(page, baseUrl) {
  const result = { name: "dr14-score", pass: false, message: "" };
  await page.goto(`${baseUrl}/dr14`, { waitUntil: "commit", timeout: 10000 });
  await page.waitForSelector("[data-score-total]", { timeout: 8000 });
  await page.waitForSelector("[data-score-criteria] select", { timeout: 8000 });
  await page.locator("[data-score-criteria] select").first().selectOption({ index: 1 });
  await page.waitForFunction(() => Number(document.querySelector("[data-score-total]")?.textContent.replace(",", ".") || "0") > 0, null, { timeout: 8000 });
  const total = await page.textContent("[data-score-total]");
  result.pass = Number(String(total).replace(",", ".")) > 0;
  result.message = `DR14 score: ${total}`;
  return result;
}

async function setupPage(browser, allowFormSubmit = false) {
  const page = await browser.newPage({ viewport: { width: 1365, height: 900 } });
  page.setDefaultTimeout(10000);
  await page.route("**/*", (route) => {
    const requestUrl = new URL(route.request().url());
    if (allowFormSubmit && requestUrl.pathname === "/api/contact-triage" && route.request().method() === "POST") {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, leadId: "functional-test-lead" }),
      });
      return;
    }
    if (requestUrl.hostname === "127.0.0.1" || requestUrl.hostname === "localhost") {
      route.continue();
      return;
    }
    if (allowFormSubmit && requestUrl.hostname === "formsubmit.co") {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true }),
      });
      return;
    }
    route.abort();
  });
  return page;
}

async function runFunctionalValidation() {
  await fsp.rm(SCREENSHOT_DIR, { recursive: true, force: true });
  await fsp.mkdir(SCREENSHOT_DIR, { recursive: true });
  const { server, port } = await createServer();
  const baseUrl = `http://127.0.0.1:${port}`;
  let browser = null;
  const results = [];
  const interactions = [];
  try {
    browser = await chromium.launch();
    const page = await setupPage(browser);
    for (const pageInfo of FUNCTIONAL_PAGES) {
      console.log(`Functional page: ${pageInfo.path}`);
      results.push(await inspectPage(page, baseUrl, pageInfo));
    }
    await page.close();

    const interactionPage = await setupPage(browser, true);
    console.log("Functional interaction: contact form");
    interactions.push(await testContactForm(interactionPage, baseUrl).catch((error) => ({ name: "contact-form", pass: false, message: error.message })));
    console.log("Functional interaction: calculator SO");
    interactions.push(await testCalculatorSo(interactionPage, baseUrl).catch((error) => ({ name: "calculator-so", pass: false, message: error.message })));
    console.log("Functional interaction: DR14 score");
    interactions.push(await testDr14Score(interactionPage, baseUrl).catch((error) => ({ name: "dr14-score", pass: false, message: error.message })));
    await interactionPage.close();
  } finally {
    if (browser) await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
  const all = [...results, ...interactions];
  return {
    generatedAt: new Date().toISOString(),
    mode: APPLY ? "apply" : "check",
    baseUrl,
    summary: {
      checked: all.length,
      passed: all.filter((item) => item.pass).length,
      failed: all.filter((item) => !item.pass).length,
    },
    pages: results,
    interactions,
  };
}

function writeSummary(seoReport, functionalReport) {
  const failedSeo = seoReport.results.filter((item) => !item.pass);
  const failedFunctional = functionalReport ? [...functionalReport.pages, ...functionalReport.interactions].filter((item) => !item.pass) : [];
  const lines = [
    "# Verification Summary",
    "",
    `Generated: ${new Date().toISOString()}`,
    `Mode: ${APPLY ? "apply" : "check"}`,
    "",
    "## SEO",
    "",
    `Files checked: ${seoReport.summary.totalFiles}`,
    `Passed: ${seoReport.summary.passedFiles}`,
    `Failed: ${seoReport.summary.failedFiles}`,
    `Inline scripts checked: ${seoReport.inlineScripts.checked}`,
    `Inline script failures: ${seoReport.inlineScripts.failures.length}`,
    "",
    "## Functional",
    "",
    functionalReport
      ? `Checks: ${functionalReport.summary.checked}; passed: ${functionalReport.summary.passed}; failed: ${functionalReport.summary.failed}`
      : "Skipped by CLI flag.",
    "",
    "## Pages needing review",
    "",
    ...failedSeo.map((item) => `- SEO ${item.file}: ${item.issues.join(", ")}`),
    ...seoReport.inlineScripts.failures.map((item) => `- JS ${item.file} script ${item.script}: ${item.message}`),
    ...failedFunctional.map((item) => `- Functional ${item.page || item.name}: ${(item.errors || []).join("; ") || item.message || "failed"}`),
  ];
  if (!failedSeo.length && !seoReport.inlineScripts.failures.length && !failedFunctional.length) {
    lines.push("- None.");
  }
  fs.writeFileSync(path.join(REPORT_DIR, "verification-summary.md"), `${lines.join("\n")}\n`, "utf8");
}

async function main() {
  await fsp.mkdir(REPORT_DIR, { recursive: true });
  if (FUNCTIONAL_ONLY) {
    const functionalReport = await runFunctionalValidation();
    fs.writeFileSync(path.join(REPORT_DIR, "functional-validation.json"), `${JSON.stringify(functionalReport, null, 2)}\n`, "utf8");
    console.log(`Mode: ${functionalReport.mode}`);
    console.log(`Functional checks: ${functionalReport.summary.checked}; failed: ${functionalReport.summary.failed}`);
    console.log("Report written to reports/functional-validation.json");
    if (functionalReport.summary.failed) process.exitCode = 1;
    return;
  }
  const htmlFiles = walkHtmlFiles(ROOT);
  const changes = htmlFiles.map((filePath) => updateHtml(filePath, ROOT)).filter((item) => item.changed);
  const results = htmlFiles.map((filePath) => parseHtml(filePath, ROOT));
  const inlineScripts = checkInlineScripts(ROOT);
  const seoReport = {
    generatedAt: new Date().toISOString(),
    mode: APPLY ? "apply" : "check",
    changedFiles: changes.map((item) => item.relativePath),
    summary: {
      totalFiles: results.length,
      passedFiles: results.filter((item) => item.pass).length,
      failedFiles: results.filter((item) => !item.pass).length,
    },
    inlineScripts,
    results,
  };
  fs.writeFileSync(path.join(REPORT_DIR, "seo-validation.json"), `${JSON.stringify(seoReport, null, 2)}\n`, "utf8");

  const functionalReport = SKIP_FUNCTIONAL ? null : await runFunctionalValidation();
  if (functionalReport) {
    fs.writeFileSync(path.join(REPORT_DIR, "functional-validation.json"), `${JSON.stringify(functionalReport, null, 2)}\n`, "utf8");
  }
  writeSummary(seoReport, functionalReport);

  console.log(`Mode: ${seoReport.mode}`);
  console.log(`HTML files checked: ${seoReport.summary.totalFiles}; SEO failed: ${seoReport.summary.failedFiles}; changed: ${changes.length}`);
  console.log(`Inline scripts checked: ${inlineScripts.checked}; failures: ${inlineScripts.failures.length}`);
  if (functionalReport) {
    console.log(`Functional checks: ${functionalReport.summary.checked}; failed: ${functionalReport.summary.failed}`);
  }
  console.log("Reports written to reports/seo-validation.json, reports/functional-validation.json and reports/verification-summary.md");

  if (seoReport.summary.failedFiles || inlineScripts.failures.length || (functionalReport && functionalReport.summary.failed)) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
