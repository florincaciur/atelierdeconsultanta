"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { normalizeRomanianCopy } = require("./normalize-copy-ro");
const registry = JSON.parse(fs.readFileSync(path.join(__dirname, "../config/seo-programs.json"), "utf8"));
const programRoutes = new Set(registry.programs.map(program => program.pageUrl));
const sections = require("../config/editorial-review-sections.json");

const terms = {
  aplicatii: "aplicații", automatizari: "automatizări", scalabila: "scalabilă", clara: "clară",
  serioasa: "serioasă", amanarea: "amânarea", primeste: "primește", intelege: "înțelege",
  inchiderea: "închiderea", prioritati: "priorități", prioritatile: "prioritățile",
  semnaturile: "semnăturile", fisierele: "fișierele", solida: "solidă", inteles: "înțeles",
  receptie: "recepție", cerinta: "cerința", platii: "plății", rationament: "raționament",
  nepotrivita: "nepotrivită", cateva: "câteva", localitati: "localități", autorizata: "autorizată",
  documentata: "documentată", verificati: "verificați", verificăți: "verificați", fisa: "fișă",
  situatii: "situații", greseli: "greșeli", gresit: "greșit", relatia: "relația", clientii: "clienții",
  strange: "strânge", leaga: "leagă", pregateste: "pregătește", propusa: "propusă",
  zootehnica: "zootehnică", vegetala: "vegetală", mixta: "mixtă", grau: "grâu",
  explicatii: "explicații", descarcare: "descărcare", descarcabile: "descărcabile", judetele: "județele",
  judeteana: "județeană", orasului: "orașului", orase: "orașe", creste: "crește", scadea: "scădea",
  depaseste: "depășește", funcțieaza: "funcționează", funcţionează: "funcționează"
};
const termsRe = new RegExp(`(?<![\\p{L}\\p{N}_])(${Object.keys(terms).join("|")})(?![\\p{L}\\p{N}_])`, "giu");
function readerText(value) {
  return normalizeRomanianCopy(String(value))
    .replace(/experienta relevanta/giu, "experiența relevantă")
    .replace(/coerenta bugetului/giu, "coerența bugetului")
    .replace(/transparenta privind/giu, "transparența privind")
    .replace(/Reviewer editorial:/giu, "Revizie editorială:")
    .replace(/\bPublisher:/gu, "Publicat de:")
    .replace(/\b(a|poate|pot|ar|va|vor) transformă(?!\p{L})/giu, "$1 transforma")
    .replace(/pagina evită valori fixe când nu există apel final publicat sau documente verificate\./giu, "Condițiile specifice depind de documentele aplicabile proiectului.")
    .replace(/fără prețuri inventate/giu, "pe baza documentelor proiectului")
    .replace(termsRe, word => {
      const result = terms[word.toLocaleLowerCase("ro")];
      return word[0] === word[0].toLocaleUpperCase("ro") ? result[0].toLocaleUpperCase("ro") + result.slice(1) : result;
    });
}
function plain(value) {
  return String(value).normalize("NFD").replace(/[\u0300-\u036f]/gu, "").toLowerCase().replace(/\s+/gu, " ").trim();
}
const headingNames = new Map(Object.entries({
  "cta contextual": "Discută proiectul cu un consultant",
  "autor, reviewer si actualizare": "Responsabilitate editorială",
  "context si intentie de cautare": "Verificări pentru investiție",
  "scenariu realist": "Exemplu ipotetic",
  "scenariu realist anonimizat": "Exemplu ipotetic",
  "exemplu realist anonimizat": "Exemplu ipotetic",
  "traseu intern pentru alegerea programului": "Pașii alegerii programului",
  "concluzie — actioneaza acum": "Verifică etapa proiectului înainte de achiziții"
}));
const removeProse = /^(?:tema „|informatiile de pe aceasta pagina sunt construite|pagina raspunde (?:natural|intentiei)|pentru intentia „|acest continut trebuie|continutul (?:extins este construit|trebuie citit)|selectie scurta derivata din familia|pagina (?:ajuta beneficiarii|organizeaza informatia)|resursele ajuta beneficiarii|evenimentele transforma informatia|aceasta este pagina suport|o pagina seo buna|landing page local indexabil|pentru bucuresti, recomandarea editoriala|o pagina separata pentru un judet|pagina regionala trimite catre pagini canonice)/u;
const depthPadding = /^(?:pentru .+, decizia nu se ia doar dupa denumirea programului|un dosar bine pregatit porneste de la documente verificabile|o verificare utila incepe cu intrebari simple|daca proiectul are lucrari, echipamente sau servicii tehnice|pentru firmele cu mai multe activitati|pentru proiectele de digitalizare, lista de achizitii|pentru proiectele energetice, consumul|un raspuns responsabil poate fi si amanarea depunerii)/u;
const irrelevantNonProgramSections = /^(?:exemplu numeric de cofinantare|calendar orientativ|criterii de selectie si punctaj|eligibilitatea se verifica prin solicitant, activitate, documente si investitie\.)$/u;

function reviseHtml(html, route, changes = []) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const main = $("main").first();
  if (!main.length) return html;
  let changed = false;
  const record = (kind, before, after) => { changed = true; changes.push({ kind, before: String(before).replace(/\s+/gu, " ").trim(), after: String(after).replace(/\s+/gu, " ").trim() }); };
  const section = sections[route];
  if (section && !main.find(`[id="${section.id}"]`).length) {
    const escape = value => String(value).replace(/&/gu, "&amp;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;").replace(/"/gu, "&quot;");
    const paragraphs = (section.paragraphs || []).map(text => `<p>${escape(text)}</p>`).join("");
    const rows = (section.rows || []).map(([label, text, href]) => `<li><strong>${escape(label)}</strong><p>${escape(text)} <a href="${escape(href)}">Condițiile apelului</a></p></li>`).join("");
    const links = (section.links || []).map(link => `<p><a href="${escape(link.href)}">${escape(link.label)}</a></p>`).join("");
    const block = `<section id="${section.id}" aria-labelledby="${section.id}-title"><h2 id="${section.id}-title">${escape(section.heading)}</h2>${paragraphs}${rows ? `<ul>${rows}</ul>` : ""}${links}</section>`;
    const article = main.find("article.panel, .program-family-how").first();
    const bridge = article.find("[data-search-intent-links]").first();
    if (bridge.length) bridge.after(block);
    else if (article.is(".program-family-how")) article.before(block);
    else if (article.length) article.prepend(block);
    else main.prepend(block);
    record("specific_guidance", "", section.heading);
  }
  function preserveIds(nodes) {
    const ids = nodes.find("[id]").addBack("[id]").map((_, node) => $(node).attr("id")).get();
    const anchor = nodes.first();
    if (ids.length) anchor.before(ids.map(id => `<span id="${String(id).replace(/"/gu, "&quot;")}"></span>`).join(""));
  }
  if (!["/calculator-soc", "/contact", "/politica-de-confidentialitate", "/termeni-si-conditii"].includes(route)) {
    main.find("article.panel > h2").each((_, node) => {
      const heading = $(node);
      const name = plain(heading.text());
      const genericBudgetOrCalendar = /^(?:exemplu numeric de cofinantare|calendar orientativ)$/u.test(name);
      if ((!genericBudgetOrCalendar && programRoutes.has(route)) || !irrelevantNonProgramSections.test(name)) return;
      let section = heading;
      for (let next = heading.next(); next.length && !next.is("h1,h2"); next = next.next()) section = section.add(next);
      if (section.find("input,button,form,[data-funding-calendar]").length) return;
      if (programRoutes.has(route) && name === "calendar orientativ" && /\b20\d\d\b/u.test(section.text())) return;
      record("irrelevant_template_section", section.text(), "");
      preserveIds(section);
      section.remove();
    });
  }
  main.find("tr").each((_, node) => {
    const row = $(node);
    if (plain(row.children("th,td").first().text()) === "cta") { record("internal_table_label", row.text(), ""); row.remove(); }
  });
  main.find("h1,h2,h3,h4,summary").each((_, node) => {
    const heading = $(node), current = heading.text().trim(), replacement = headingNames.get(plain(current));
    if (replacement) {
      record("reader_heading", current, replacement); heading.text(replacement);
      if (replacement === "Exemplu ipotetic" && !/ipotet|fictiv|ipotez/iu.test(heading.next("p").text())) {
        heading.after('<p data-example-assumption="">Exemplul este ipotetic. Datele și deciziile ilustrează o situație de analiză, fără a descrie un client sau un rezultat obținut.</p>');
      }
    }
  });
  main.find("p").each((_, node) => {
    const p = $(node), text = p.text().trim(), normalized = plain(text);
    if (p.closest("[data-editorial-governance],.program-factual-status,[data-guide-program-status],.official-sources").length) return;
    if (removeProse.test(normalized) || depthPadding.test(normalized) || /continutul trebuie citit ca filtru de lucru|continutul extins este construit pentru|linkurile interne trebuie sa trimita/u.test(normalized)) {
      const links = p.find("a[href]").map((_, a) => $.html(a)).get();
      record("work_copy_or_padding", text, links.length ? "Legături relevante păstrate." : "");
      if (links.length) p.html(links.join(" · "));
      else p.remove();
    } else if (/^exemplele de mai jos sunt (?:anonime|anonimizate)/u.test(normalized)) {
      const replacement = "Exemplele sunt ipotetice și ilustrează verificările necesare. Ipotezele nu descriu rezultate ale clienților.";
      record("hypothetical_example", text, replacement); p.text(replacement);
    }
  });
  main.find("li").each((_, node) => {
    const item = $(node);
    if (/^linkurile interne trebuie sa trimita|^decide daca pagina locala merita/u.test(plain(item.text()))) {
      record("authoring_instruction", item.text(), ""); item.remove();
    }
  });
  main.find("details").each((_, node) => {
    const item = $(node), question = plain(item.children("summary").first().text());
    if (/^de ce (?:nu sunt indexate|sunt consolidate)|^cand este utila o pagina locala/u.test(question)) {
      record("editorial_process_faq", item.text(), ""); preserveIds(item); item.remove();
    }
  });
  // Keep one copy of repeated prose within each authored article. FAQ answers,
  // sources, independent status cards, summaries and interactive controls remain.
  main.find("article.panel,article.post-body").each((_, article) => {
    const seen = new Set();
    $(article).find("p").each((__, node) => {
      const p = $(node), value = p.text().replace(/\s+/gu, " ").trim();
      if (value.length < 100 || p.closest("details,[data-guide-program-status],[data-editorial-governance],.official-sources,[data-search-intent-links]").length) return;
      if (seen.has(value)) { record("duplicate_prose", value, ""); p.remove(); }
      else seen.add(value);
    });
  });
  $("title,meta[name=description],meta[property='og:title'],meta[property='og:description'],meta[name='twitter:title'],meta[name='twitter:description']").each((_, node) => {
    const item = $(node), before = node.name === "title" ? item.text() : item.attr("content");
    if (!before) return;
    const after = readerText(before);
    if (after !== before) { record("metadata_language", before, after); if (node.name === "title") item.text(after); else item.attr("content", after); }
  });
  $("body").find("*").contents().each((_, node) => {
    if (node.type !== "text" || ["script", "style", "code", "pre", "textarea"].includes(node.parent?.name)) return;
    // Raw document URLs and identifiers must remain exact, including visible links.
    if (/^(?:https?:|mailto:|tel:)/iu.test(node.data.trim())) return;
    const after = readerText(node.data);
    if (after !== node.data) { record("visible_language", node.data, after); node.data = after; }
  });
  return changed ? $.html() : html;
}

module.exports = { readerText, reviseHtml, plain };
