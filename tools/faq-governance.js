"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { faqPageSchema, serializeJsonLd } = require("./schema-helpers");
const {
  cleanText,
  comparableText,
  fileForRoute,
  graphNodes,
  hasType,
  visibleFaqCandidates,
  visibleFaqItems
} = require("./structured-data-utils");

const LEGAL_ROUTES = new Set(["/gdpr", "/politica-de-confidentialitate", "/termeni-si-conditii"]);

// These answers came from two historical fallback lists that padded unrelated
// pages to an arbitrary FAQ count. They are migration signatures, not a ban on
// explaining the same genuine fact in two related articles.
const GENERIC_ANSWER_PATTERNS = [
  /^porneste de la solicitant cod caen localitate investitie buget si documentele disponibile/iu,
  /^nu merita sa aplici cand nu poti dovedi eligibilitatea/iu,
  /^de regula sunt necesare documente de firma sau solicitant/iu,
  /^codul caen se verifica prin certificatul constatator activitatea reala/iu,
  /^sunt sensibile cheltuielile greu de justificat/iu,
  /^(?:cofinantarea|contributia proprie) si cheltuielile neeligibile trebuie estimate separat/iu,
  /^apar probleme cand documentele sunt expirate/iu,
  /^foloseste informatiile ca filtru initial/iu,
  /^consultanta ajuta la trierea programului/iu,
  /^pregatirea trebuie inceputa inainte de deschiderea efectiva a apelului/iu,
  /^nu verificarea reduce riscurile si clarifica documentele/iu,
  /^pregatirea trebuie inceputa inainte de depunere mai ales/iu,
  /^sunt utile codul caen localitatea forma solicitantului/iu,
  /^da compararea programelor este recomandata/iu,
  /^nu continutul este orientativ si trebuie confirmat/iu,
  /^inainte de oferte ferme achizitii depunere/iu,
  /^sunt utile certificatul constatator datele financiare documentele pentru spatiu/iu,
  /^prin verificarea eligibilitatii a bugetului a cheltuielilor neeligibile/iu,
  /^solicitantul programul documentele bugetul cheltuielile eligibile si regulile apelului activ/iu,
  /^nu raspunsul este orientativ si trebuie confirmat prin documentele proiectului/iu,
  /^trimite datele proiectului prin pagina de contact pentru o verificare initiala/iu,
  /^raspunsul trebuie actualizat cand se publica un ghid nou/iu
];

function isGenericFillerFaq(question, answer) {
  const normalizedAnswer = comparableText(answer);
  return Boolean(comparableText(question) && GENERIC_ANSWER_PATTERNS.some((pattern) => pattern.test(normalizedAnswer)));
}

function normalizeFaqPairs(faqs) {
  const seen = new Set();
  const items = [];
  for (const entry of faqs || []) {
    const question = cleanText(Array.isArray(entry) ? entry[0] : entry?.question || entry?.name);
    const answer = cleanText(Array.isArray(entry) ? entry[1] : entry?.answer || entry?.text);
    const key = comparableText(question);
    if (!key || !answer || !/[?？]$/u.test(question) || seen.has(key) || isGenericFillerFaq(question, answer)) continue;
    seen.add(key);
    items.push([question, answer]);
  }
  return items;
}

function routeFiles(root, routeEntry, deployment = false) {
  const route = routeEntry.route;
  if (deployment) {
    const slug = route.replace(/^\/+|\/+$/gu, "");
    const candidates = route === "/"
      ? [path.join(root, "index.html")]
      : [path.join(root, `${slug}.html`), path.join(root, slug, "index.html")];
    const existing = candidates.filter((file) => fs.existsSync(file));
    return existing.length ? [...new Set(existing)] : [fileForRoute(root, route)];
  }
  return [...new Set([
    fileForRoute(root, route),
    path.join(root, routeEntry.sourceFile)
  ].filter(Boolean))];
}

function applyRanges(source, ranges) {
  let result = source;
  for (const range of [...ranges].sort((left, right) => right.start - left.start)) {
    result = `${result.slice(0, range.start)}${range.text || ""}${result.slice(range.end)}`;
  }
  return result;
}

function removableFaqRanges(html) {
  const $ = cheerio.load(html, { decodeEntities: false, sourceCodeLocationInfo: true });
  const candidates = visibleFaqCandidates($);
  const seen = new Set();
  const removals = [];
  let genericRemoved = 0;
  let duplicateRemoved = 0;

  for (const item of candidates) {
    const key = comparableText(item.question);
    const generic = isGenericFillerFaq(item.question, item.answer);
    const duplicate = seen.has(key);
    if (!generic && !duplicate) seen.add(key);
    if (!generic && !duplicate) continue;
    const location = item.element?.sourceCodeLocation;
    if (!location) continue;
    removals.push({ start: location.startOffset, end: location.endOffset, text: "" });
    if (generic) genericRemoved += 1;
    else duplicateRemoved += 1;
  }

  // If migration removed every genuine child, remove the now-empty visible
  // FAQ accordion instead of leaving a dead "Întrebări frecvente" control.
  $("details").each((_, wrapper) => {
    const summary = cleanText($(wrapper).children("summary").first().text());
    if (!/^(?:faq|întrebări frecvente)$/iu.test(summary)) return;
    const childCandidates = candidates.filter((item) => $(item.element).closest(wrapper).length && item.element !== wrapper);
    if (!childCandidates.length) return;
    const childLocations = childCandidates.map((item) => item.element?.sourceCodeLocation).filter(Boolean);
    const allRemoved = childLocations.every((location) => removals.some((range) => range.start === location.startOffset && range.end === location.endOffset));
    if (!allRemoved || !wrapper.sourceCodeLocation) return;
    removals.push({ start: wrapper.sourceCodeLocation.startOffset, end: wrapper.sourceCodeLocation.endOffset, text: "" });
  });

  const outerRanges = removals.filter((range, index) => !removals.some((other, otherIndex) => (
    index !== otherIndex && other.start <= range.start && other.end >= range.end
      && (other.start < range.start || other.end > range.end)
  )));
  return { html: applyRanges(html, outerRanges), genericRemoved, duplicateRemoved };
}

function removeFaqNodes(data) {
  if (Array.isArray(data)) {
    const next = data.filter((node) => !hasType(node, "FAQPage"));
    return { data: next, removed: next.length !== data.length };
  }
  if (!data || typeof data !== "object") return { data, removed: false };
  if (Array.isArray(data["@graph"])) {
    const graph = data["@graph"].filter((node) => !hasType(node, "FAQPage"));
    return { data: { ...data, "@graph": graph }, removed: graph.length !== data["@graph"].length };
  }
  if (hasType(data, "FAQPage")) return { data: null, removed: true };
  return { data, removed: false };
}

function appendFaqNode(data, faq) {
  if (!faq) return data;
  if (Array.isArray(data)) return [...data, faq];
  if (data && Array.isArray(data["@graph"])) return { ...data, "@graph": [...data["@graph"], faq] };
  return data ? [data, faq] : faq;
}

function synchronizeFaqSchema(html) {
  const $ = cheerio.load(html, { decodeEntities: false, sourceCodeLocationInfo: true });
  const visible = visibleFaqItems($);
  const faq = faqPageSchema(visible.map((item) => [item.question, item.answer]), { minItems: 2 });
  const scripts = $("script[type='application/ld+json']").toArray();
  const parsed = [];
  let preferred = -1;

  scripts.forEach((script, index) => {
    const location = script.sourceCodeLocation;
    if (!location?.startTag || !location?.endTag) return;
    const content = html.slice(location.startTag.endOffset, location.endTag.startOffset);
    const raw = content.trim();
    if (!raw) return;
    const data = JSON.parse(raw);
    if (graphNodes(data).some((node) => hasType(node, "FAQPage"))) preferred = index;
    parsed.push({ index, script, content, data, raw });
  });

  if (faq && preferred < 0) preferred = parsed.find((entry) => Array.isArray(entry.data?.["@graph"]))?.index ?? parsed[0]?.index ?? -1;
  const ranges = [];
  for (const entry of parsed) {
    const stripped = removeFaqNodes(entry.data);
    const standaloneFaq = hasType(entry.data, "FAQPage") && !Array.isArray(entry.data) && !Array.isArray(entry.data?.["@graph"]);
    const nextData = entry.index === preferred && faq && standaloneFaq
      ? { ...(entry.data["@context"] ? { "@context": entry.data["@context"] } : {}), ...faq }
      : entry.index === preferred ? appendFaqNode(stripped.data, faq) : stripped.data;
    const serialized = nextData ? serializeJsonLd(nextData) : "";
    const documentSerialized = html.includes("\r\n") ? serialized.replace(/\n/gu, "\r\n") : serialized;
    if (documentSerialized === entry.content) continue;
    const location = entry.script.sourceCodeLocation;
    ranges.push({
      start: location.startTag.endOffset,
      end: location.endTag.startOffset,
      text: documentSerialized
    });
  }
  return applyRanges(html, ranges);
}

function synchronizeFaqHtml(html) {
  const cleaned = removableFaqRanges(html);
  const parsed = cheerio.load(cleaned.html, { decodeEntities: false });
  const visibleCount = visibleFaqItems(parsed).length;
  const withAccurateMinimum = cleaned.html.replace(
    /(<meta\b[^>]*\bname=["']seo-min-faq["'][^>]*\bcontent=["'])\d+(["'][^>]*>)/iu,
    `$1${visibleCount}$2`
  );
  const next = synchronizeFaqSchema(withAccurateMinimum);
  return { ...cleaned, html: next };
}

function faqSchemaItems(nodes) {
  return nodes
    .filter((node) => hasType(node, "FAQPage"))
    .flatMap((node) => Array.isArray(node.mainEntity) ? node.mainEntity : [])
    .map((item) => ({
      question: cleanText(item?.name || item?.question),
      answer: cleanText(item?.acceptedAnswer?.text || item?.answer)
    }));
}

function temporalFaqIssues(items, program, auditToday = "2026-08-24") {
  if (!program) return [];
  const issues = [];
  const end = String(program.applicationEnd || "");
  if (program.status === "apel_deschis" && /^\d{4}-\d{2}-\d{2}$/u.test(end) && end < auditToday) {
    issues.push(`registrul marchează apelul deschis după termenul ${end}`);
  }

  for (const item of items) {
    const question = comparableText(item.question);
    const answer = comparableText(item.answer);
    const asksOpen = /^(?:este|e|apelul|programul|depunerea|sesiunea).*(?:deschis|depuner)/iu.test(question)
      || /(?:statut|status|perioada de depunere|pana cand se depune|cand se lanseaza)/iu.test(question);
    if (asksOpen && program.status !== "apel_deschis") {
      const directOpenClaim = /^(?:da\b|apelul este deschis|depunerea este deschisa|sesiunea este deschisa)/iu.test(answer);
      if (directOpenClaim) issues.push(`„${item.question}” contrazice statutul ${program.status}`);
    }
    if (asksOpen && program.status === "apel_deschis" && !/\bdeschis/iu.test(answer)) {
      issues.push(`„${item.question}” nu confirmă statutul deschis din registru`);
    }
    if (program.canonicalStatus === "FINAL_GUIDE" && asksOpen && /(?:documentatia|forma|ghidul).{0,25}consultativ/iu.test(answer)) {
      issues.push(`„${item.question}” folosește etapa consultativă după publicarea ghidului final`);
    }
    if (/la data verificarii/iu.test(answer) && !/(?:\b\d{1,2}\s+[a-z]+\s+20\d{2}\b|\b20\d{2}-\d{2}-\d{2}\b)/iu.test(answer)) {
      issues.push(`„${item.question}” folosește o dată relativă fără data absolută a verificării`);
    }
  }
  return issues;
}

module.exports = {
  LEGAL_ROUTES,
  faqSchemaItems,
  isGenericFillerFaq,
  normalizeFaqPairs,
  routeFiles,
  synchronizeFaqHtml,
  temporalFaqIssues
};
