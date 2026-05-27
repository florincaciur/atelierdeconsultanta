#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const TARGET = path.resolve(process.argv.slice(2).find((arg) => !arg.startsWith("--")) || ROOT);

const EXCLUDED_DIRS = new Set([
  ".git",
  ".github",
  ".wrangler",
  "dist",
  "node_modules",
  "reports",
]);

const ROMANIAN_COPY_REPLACEMENTS = [
  [/Țîn/g, "Țin"],
  [/țîn/g, "țin"],
  [/\bMicrointreprinderi\b/g, "Microîntreprinderi"],
  [/\bmicrointreprinderi\b/g, "microîntreprinderi"],
  [/\bAcasa\b/g, "Acasă"],
  [/\bacasa\b/g, "acasă"],
  [/\bSolicita\b/g, "Solicită"],
  [/\bsolicita\b/g, "solicită"],
  [/\bSa\b/g, "Să"],
  [/\bsa\b/g, "să"],
  [/\bDaca\b/g, "Dacă"],
  [/\bdaca\b/g, "dacă"],
  [/\bColectie\b/g, "Colecție"],
  [/\bcolectie\b/g, "colecție"],
  [/\binitiala\b/g, "inițială"],
  [/\binitial\b/g, "inițial"],
  [/\boficiala\b/g, "oficială"],
  [/\boficial\b/g, "oficial"],
  [/\bfinala\b/g, "finală"],
  [/\bpractica\b/g, "practică"],
  [/\breala\b/g, "reală"],
  [/\brealistă\b/g, "realistă"],
  [/\brealista\b/g, "realistă"],
  [/\bprudenta\b/g, "prudentă"],
  [/\borientativa\b/g, "orientativă"],
  [/\bagricola\b/g, "agricolă"],
  [/\beconomica\b/g, "economică"],
  [/\bjuridica\b/g, "juridică"],
  [/\btehnica\b/g, "tehnică"],
  [/\boperationala\b/g, "operațională"],
  [/\bdisponibila\b/g, "disponibilă"],
  [/\bestimata\b/g, "estimată"],
  [/\bposibila\b/g, "posibilă"],
  [/\bpotrivita\b/g, "potrivită"],
  [/\bneclara\b/g, "neclară"],
  [/\bneeligibila\b/g, "neeligibilă"],
  [/\bConsultanta\b/g, "Consultanță"],
  [/\bconsultanta\b/g, "consultanță"],
  [/\bFinantare\b/g, "Finanțare"],
  [/\bfinantare\b/g, "finanțare"],
  [/\bfinantari\b/g, "finanțări"],
  [/\bfinantarii\b/g, "finanțării"],
  [/\bfinantata\b/g, "finanțată"],
  [/\bfinantat\b/g, "finanțat"],
  [/\bfinantate\b/g, "finanțate"],
  [/\bfinantator\b/g, "finanțator"],
  [/\bCofinantare\b/g, "Cofinanțare"],
  [/\bcofinantare\b/g, "cofinanțare"],
  [/\bcofinantarea\b/g, "cofinanțarea"],
  [/\bcofinantarii\b/g, "cofinanțării"],
  [/\bInvestitii\b/g, "Investiții"],
  [/\binvestitii\b/g, "investiții"],
  [/\binvestitie\b/g, "investiție"],
  [/\binvestitia\b/g, "investiția"],
  [/\binvestitiei\b/g, "investiției"],
  [/\binvestitiile\b/g, "investițiile"],
  [/\bConditii\b/g, "Condiții"],
  [/\bconditii\b/g, "condiții"],
  [/\bconditiile\b/g, "condițiile"],
  [/\bconditie\b/g, "condiție"],
  [/\bPregatire\b/g, "Pregătire"],
  [/\bpregatire\b/g, "pregătire"],
  [/\bpregatirea\b/g, "pregătirea"],
  [/\bpregateste\b/g, "pregătește"],
  [/\bpregatesti\b/g, "pregătești"],
  [/\bpregatesc\b/g, "pregătesc"],
  [/\bpregatite\b/g, "pregătite"],
  [/\bpregatit\b/g, "pregătit"],
  [/\bpregatita\b/g, "pregătită"],
  [/\bpregatim\b/g, "pregătim"],
  [/\bSe verifica\b/g, "Se verifică"],
  [/\bse verifica\b/g, "se verifică"],
  [/\bVerifica\b/g, "Verifică"],
  [/\bverificari\b/g, "verificări"],
  [/\bverificarile\b/g, "verificările"],
  [/\bverificata\b/g, "verificată"],
  [/\bverificat\b/g, "verificat"],
  [/\bverificate\b/g, "verificate"],
  [/\bIntrebari\b/g, "Întrebări"],
  [/\bintrebari\b/g, "întrebări"],
  [/\bintrebarea\b/g, "întrebarea"],
  [/\bintai\b/g, "întâi"],
  [/\bInainte\b/g, "Înainte"],
  [/\binainte\b/g, "înainte"],
  [/\bDupa\b/g, "După"],
  [/\bdupa\b/g, "după"],
  [/\bCand\b/g, "Când"],
  [/\bcand\b/g, "când"],
  [/\bCat\b/g, "Cât"],
  [/\bcat\b/g, "cât"],
  [/\bCatre\b/g, "Către"],
  [/\bcatre\b/g, "către"],
  [/(?<![A-Za-zĂÂÎȘȚăâîșț])In(?![A-Za-zĂÂÎȘȚăâîșț])/g, "În"],
  [/(?<![A-Za-zĂÂÎȘȚăâîșț])in(?![A-Za-zĂÂÎȘȚăâîșț])/g, "în"],
  [/(?<![A-Za-zĂÂÎȘȚăâîșț])si(?![A-Za-zĂÂÎȘȚăâîșț])/g, "și"],
  [/\bEste\b/g, "Este"],
  [/\bexista\b/g, "există"],
  [/\bExista\b/g, "Există"],
  [/\binseamna\b/g, "înseamnă"],
  [/\bInseamna\b/g, "Înseamnă"],
  [/\bobtin\b/g, "obțin"],
  [/\bobtine\b/g, "obține"],
  [/\bobtinut\b/g, "obținut"],
  [/\bobtinere\b/g, "obținere"],
  [/\bFirma\b/g, "Firmă"],
  [/\bfirma\b/g, "firmă"],
  [/\bfermei\b/g, "fermei"],
  [/\bexploatatie\b/g, "exploatație"],
  [/\bexploatatia\b/g, "exploatația"],
  [/\bexploatatiei\b/g, "exploatației"],
  [/\bexploatatii\b/g, "exploatații"],
  [/\bexploatatiile\b/g, "exploatațiile"],
  [/\bcomparatie\b/g, "comparație"],
  [/\bTanar\b/g, "Tânăr"],
  [/\btanar\b/g, "tânăr"],
  [/\btineri\b/g, "tineri"],
  [/\bvarsta\b/g, "vârstă"],
  [/\bvarstei\b/g, "vârstei"],
  [/\bLocatie\b/g, "Locație"],
  [/\blocatie\b/g, "locație"],
  [/\blocatia\b/g, "locația"],
  [/\bspatiu\b/g, "spațiu"],
  [/\bspatiul\b/g, "spațiul"],
  [/\bspatii\b/g, "spații"],
  [/\bcladire\b/g, "clădire"],
  [/\bcladiri\b/g, "clădiri"],
  [/\bfolosinta\b/g, "folosință"],
  [/\bfolosintei\b/g, "folosinței"],
  [/\badaposturi\b/g, "adăposturi"],
  [/\bsuprafete\b/g, "suprafețe"],
  [/\bsuprafetele\b/g, "suprafețele"],
  [/\bdotari\b/g, "dotări"],
  [/\bdotarile\b/g, "dotările"],
  [/\beficienta\b/g, "eficiență"],
  [/\bproductie\b/g, "producție"],
  [/\bproductiei\b/g, "producției"],
  [/\binstalatii\b/g, "instalații"],
  [/\bincarcare\b/g, "încărcare"],
  [/\belectrica\b/g, "electrică"],
  [/\bregenerabila\b/g, "regenerabilă"],
  [/\bprivati\b/g, "privați"],
  [/\bLocala\b/g, "Locală"],
  [/\blocala\b/g, "locală"],
  [/\bAdresa\b/g, "Adresă"],
  [/\badresa\b/g, "adresă"],
  [/\bsituatii\b/g, "situații"],
  [/\bsituatiile\b/g, "situațiile"],
  [/\bselectie\b/g, "selecție"],
  [/\bselectia\b/g, "selecția"],
  [/\bachizitii\b/g, "achiziții"],
  [/\bachizitie\b/g, "achiziție"],
  [/\bplati\b/g, "plăți"],
  [/\bplata\b/g, "plată"],
  [/\braportari\b/g, "raportări"],
  [/\bobligatii\b/g, "obligații"],
  [/\bautorizari\b/g, "autorizări"],
  [/\bclarificari\b/g, "clarificări"],
  [/\bsemnaturi\b/g, "semnături"],
  [/\bfisiere\b/g, "fișiere"],
  [/\bInformatii\b/g, "Informații"],
  [/\binformatii\b/g, "informații"],
  [/\binformatiile\b/g, "informațiile"],
  [/\braspuns\b/g, "răspuns"],
  [/\braspunsuri\b/g, "răspunsuri"],
  [/\braspunda\b/g, "răspundă"],
  [/\braspunde\b/g, "răspunde"],
  [/\blipseste\b/g, "lipsește"],
  [/\blipsa\b/g, "lipsă"],
  [/\bfoloseste\b/g, "folosește"],
  [/\bfolosesti\b/g, "folosești"],
  [/\bcauta\b/g, "caută"],
  [/\bcauti\b/g, "cauți"],
  [/\bcitesti\b/g, "citești"],
  [/\bnoteaza\b/g, "notează"],
  [/\bconstruieste\b/g, "construiește"],
  [/\brevizuieste\b/g, "revizuiește"],
  [/\btrimiti\b/g, "trimiți"],
  [/\bpoti\b/g, "poți"],
  [/\bpoata\b/g, "poată"],
  [/\bfata\b/g, "față"],
  [/\bfara\b/g, "fără"],
  [/\bdiscutia\b/g, "discuția"],
  [/\bajunga\b/g, "ajungă"],
  [/\bmentioneaza\b/g, "menționează"],
  [/\burmarit\b/g, "urmărit"],
  [/\burmareste\b/g, "urmărește"],
  [/\bschimba\b/g, "schimbă"],
  [/\bactualizari\b/g, "actualizări"],
  [/\baprobari\b/g, "aprobări"],
  [/\bintalnire\b/g, "întâlnire"],
  [/\bdistanta\b/g, "distanță"],
  [/\bStiu\b/g, "Știu"],
  [/\bstiu\b/g, "știu"],
  [/\bramane\b/g, "rămâne"],
  [/\braman\b/g, "rămân"],
  [/\bpromisiune\b/g, "promisiune"],
  [/\bgaranteaza\b/g, "garantează"],
  [/\bgarantata\b/g, "garantată"],
  [/\bGreseli\b/g, "Greșeli"],
  [/\bgreseli\b/g, "greșeli"],
  [/\bgresit\b/g, "greșit"],
  [/\bgresita\b/g, "greșită"],
  [/\blegatura\b/g, "legătura"],
  [/\bslaba\b/g, "slabă"],
  [/\bsustin\b/g, "susțin"],
  [/\bsustine\b/g, "susține"],
  [/\bsustinuta\b/g, "susținută"],
  [/\bsustinute\b/g, "susținute"],
  [/\bsursa oficiala\b/g, "sursa oficială"],
  [/\boferta\b/g, "ofertă"],
  [/\bofertare\b/g, "ofertare"],
  [/\bactiuni\b/g, "acțiuni"],
  [/\bactiunile\b/g, "acțiunile"],
  [/\bactiune\b/g, "acțiune"],
  [/\bActiune\b/g, "Acțiune"],
  [/\bautoritatii\b/g, "autorității"],
  [/\bjudet\b/g, "județ"],
  [/\bjudetul\b/g, "județul"],
  [/\bjudetului\b/g, "județului"],
  [/\bjudete\b/g, "județe"],
  [/\bIasi\b/g, "Iași"],
  [/\bBacau\b/g, "Bacău"],
  [/\bBucuresti\b/g, "București"],
];

function normalizeRomanianCopy(value) {
  let text = String(value ?? "");
  for (const [pattern, replacement] of ROMANIAN_COPY_REPLACEMENTS) {
    text = text.replace(pattern, replacement);
  }
  return text;
}

function normalizeHtmlCopy(html) {
  const $ = cheerio.load(html, { decodeEntities: false });
  let changed = false;

  function normalizeValue(value) {
    const next = normalizeRomanianCopy(value);
    if (next !== value) changed = true;
    return next;
  }

  $("title").each((_, element) => {
    const current = $(element).text();
    const next = normalizeValue(current);
    if (next !== current) $(element).text(next);
  });

  $("meta[name='description'], meta[property='og:title'], meta[property='og:description'], meta[name='twitter:title'], meta[name='twitter:description']").each((_, element) => {
    const content = $(element).attr("content");
    if (!content) return;
    const next = normalizeValue(content);
    if (next !== content) $(element).attr("content", next);
  });

  $("[aria-label], [alt], [title], [placeholder]").each((_, element) => {
    for (const attr of ["aria-label", "alt", "title", "placeholder"]) {
      const value = $(element).attr(attr);
      if (!value) continue;
      const next = normalizeValue(value);
      if (next !== value) $(element).attr(attr, next);
    }
  });

  $("body")
    .find("*")
    .addBack()
    .contents()
    .each((_, node) => {
      if (node.type !== "text") return;
      const parent = node.parent && node.parent.name ? String(node.parent.name).toLowerCase() : "";
      if (["script", "style", "code", "pre", "textarea"].includes(parent)) return;
      const next = normalizeValue(node.data);
      if (next !== node.data) node.data = next;
    });

  return changed ? $.html() : html;
}

function* walkHtml(target) {
  const stat = fs.statSync(target);
  if (stat.isFile()) {
    if (target.toLowerCase().endsWith(".html")) yield target;
    return;
  }

  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) {
      yield* walkHtml(full);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html")) {
      yield full;
    }
  }
}

function main() {
  const changed = [];
  for (const file of walkHtml(TARGET)) {
    const input = fs.readFileSync(file, "utf8");
    const output = normalizeHtmlCopy(input);
    if (input === output) continue;
    changed.push(path.relative(ROOT, file));
    if (!CHECK_ONLY) fs.writeFileSync(file, output, "utf8");
  }

  if (CHECK_ONLY && changed.length) {
    console.error(`Romanian copy issues detected in ${changed.length} file(s):`);
    for (const file of changed) console.error(` - ${file}`);
    process.exitCode = 1;
    return;
  }

  console.log(
    CHECK_ONLY
      ? "Romanian copy check passed."
      : `Romanian copy normalized in ${changed.length} file(s).`
  );
}

if (require.main === module) main();

module.exports = {
  ROMANIAN_COPY_REPLACEMENTS,
  normalizeHtmlCopy,
  normalizeRomanianCopy,
};
