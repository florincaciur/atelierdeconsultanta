#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CHECK = process.argv.includes("--check");
const METHODOLOGY_FILE = "metodologie-verificare-eligibilitate/index.html";
const CASES_FILE = "studii-de-caz-fonduri-europene/index.html";
const GOVERNANCE_FILE = "config/about-faber-governance.json";

const METHODOLOGY_START = "<!-- TRUST_EDITORIAL_METHOD_START -->";
const METHODOLOGY_END = "<!-- TRUST_EDITORIAL_METHOD_END -->";
const EVIDENCE_START = "<!-- TRUST_EVIDENCE_POLICY_START -->";
const EVIDENCE_END = "<!-- TRUST_EVIDENCE_POLICY_END -->";

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, ...relativePath.split("/")), "utf8");
}

function write(relativePath, content) {
  fs.writeFileSync(path.join(ROOT, ...relativePath.split("/")), content, "utf8");
}

function replaceLiteral(content, previous, next, label) {
  if (content.includes(previous)) return content.split(previous).join(next);
  if (!content.includes(next)) throw new Error(`${label}: ancora așteptată lipsește.`);
  return content;
}

function syncEditorialDate(content, label, isoDate, visibleDate) {
  const modifiedPattern = /(<meta property="article:modified_time" content=")\d{4}-\d{2}-\d{2}("\s*\/?>)/u;
  const visiblePattern = /(<div><dt>Ultima actualizare<\/dt><dd><time datetime=")\d{4}-\d{2}-\d{2}(">)[^<]+(<\/time><\/dd><\/div>)/u;
  if (!modifiedPattern.test(content)) throw new Error(`${label}: meta article:modified_time lipsește.`);
  if (!visiblePattern.test(content)) throw new Error(`${label}: data editorială vizibilă lipsește.`);
  return content
    .replace(modifiedPattern, `$1${isoDate}$2`)
    .replace(visiblePattern, `$1${isoDate}$2${visibleDate}$3`);
}

function upsertBlock(content, start, end, anchor, block, label) {
  const managed = `${start}\n${block.trim()}\n${end}`;
  const startIndex = content.indexOf(start);
  const endIndex = content.indexOf(end);
  if (startIndex !== -1 || endIndex !== -1) {
    if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) throw new Error(`${label}: markeri incompleți.`);
    return `${content.slice(0, startIndex)}${managed}${content.slice(endIndex + end.length)}`;
  }
  if (!content.includes(anchor)) throw new Error(`${label}: ancora de inserare lipsește.`);
  return content.replace(anchor, `${managed}\n\n${anchor}`);
}

function formatRoDate(isoDate) {
  return new Intl.DateTimeFormat("ro-RO", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" })
    .format(new Date(`${isoDate}T00:00:00Z`));
}

const governance = JSON.parse(read(GOVERNANCE_FILE));
const policy = governance.trustEvidencePolicy;
if (!policy || policy.publicCaseStudies !== 0 || policy.publicTestimonials !== 0 || policy.reviewSchemaAllowed !== false) {
  throw new Error(`${GOVERNANCE_FILE}: politica Task 24 trebuie să păstreze zero dovezi publicate și schema de review dezactivată.`);
}

const methodologyBlock = `
      <section id="metodologie-editoriala" aria-labelledby="metodologie-editoriala-title" data-trust-methodology="task-24">
        <h2 id="metodologie-editoriala-title">Cum verificăm și publicăm informația editorială</h2>
        <p>FABER pornește de la sursa primară aplicabilă și separă explicit ce este confirmat de ceea ce este încă orientativ. Rezumatul nostru ajută la înțelegerea programului, dar nu înlocuiește ghidul, schema, ordinul, anexele, corrigenda, clarificările sau comunicările instituției emitente.</p>

        <h3>Prioritatea surselor</h3>
        <ol class="process-list">
          <li><strong>Documentul oficial aplicabil.</strong> Ghidul, schema, ordinul, anexa, corrigendumul ori clarificarea publicată de AFIR, MIPE, minister, ADR, autoritatea de management, Monitorul Oficial sau instituția emitentă are prioritate.</li>
          <li><strong>Comunicarea instituției emitente.</strong> Un anunț sau calendar oficial poate confirma intenția și etapa, dar nu este tratat drept perioadă de depunere dacă documentele apelului nu o susțin.</li>
          <li><strong>Sursele secundare.</strong> Pot ajuta la orientare, însă nu sunt folosite pentru a confirma statusul, termenul, bugetul, eligibilitatea sau alte condiții factuale.</li>
        </ol>

        <h3>Cum diferențiem etapele unui program</h3>
        <dl class="case-model">
          <div><dt>Anunțat</dt><dd>Există o intenție sau o comunicare oficială; condițiile și depunerea pot să nu fie publicate.</dd></div>
          <div><dt>Consultare publică / ghid consultativ</dt><dd>Documentele pot primi observații și se pot modifica; depunerea nu este considerată deschisă.</dd></div>
          <div><dt>Ghid final publicat</dt><dd>Versiunea finală a ghidului este publică, dar acest fapt nu dovedește singur că depunerea a început.</dd></div>
          <div><dt>Schemă aprobată</dt><dd>Cadrul de ajutor este aprobat; apelul rămâne distinct și poate să nu fie deschis.</dd></div>
          <div><dt>Apel deschis</dt><dd>Depunerea este marcată deschisă numai când sursa oficială publică perioada și mecanismul aplicabil.</dd></div>
          <div><dt>Status neconfirmat</dt><dd>Dacă sursa lipsește, este contradictorie sau nu stabilește etapa, publicăm incertitudinea în locul unei deducții.</dd></div>
        </dl>

        <h3>Verificare, <code>verifiedAt</code> și incertitudine</h3>
        <p>Pentru fiecare status verificăm instituția, URL-ul, tipul și versiunea documentului, caracterul final ori consultativ și datele explicite de depunere. <code>verifiedAt</code> este data la care informația a fost reverificată efectiv în sursa indicată; nu este data buildului, a deploy-ului sau o dată dedusă din Git. Când documentele nu permit o concluzie, informația rămâne condiționată ori cu status neconfirmat.</p>

        <h3>Cum corectăm o eroare</h3>
        <p>Oprim promovarea informației, corectăm registrul factual și toate suprafețele generate, consemnăm schimbarea materială în istoricul editorial și reverificăm sursa înainte de republicare. Nu rescriem retroactiv istoricul și nu folosim o etichetă mai favorabilă până la clarificare.</p>

        <h3>Responsabilitate editorială</h3>
        <p>Publisherul public este FABER – Atelier de Consultanță. Un autor sau reviewer nominal este afișat numai după confirmarea identității, rolului și acordului de publicare; până atunci, responsabilitatea este atribuită organizațional, fără profiluri personale inventate. Erorile sau neconcordanțele pot fi semnalate prin <a href="/contact">pagina de contact</a>, iar sursele folosite sunt prezentate în <a href="/surse-oficiale-fonduri-europene">registrul de surse oficiale</a>.</p>
      </section>`;

const reviewedLabel = formatRoDate(policy.reviewedAt);
const evidenceBlock = `
      <section id="politica-dovezi" aria-labelledby="politica-dovezi-title" data-trust-evidence="task-24">
        <h2 id="politica-dovezi-title">Starea dovezilor publice</h2>
        <div class="case-note" data-publication-state="methodology-only" data-approved-case-count="${policy.publicCaseStudies}" data-approved-testimonial-count="${policy.publicTestimonials}">
          <p><strong>Stare verificată la <time datetime="${policy.reviewedAt}">${reviewedLabel}</time>:</strong> această pagină nu publică încă niciun studiu de caz drept rezultat real verificat al unui client și niciun testimonial. Conținutul de mai jos este o metodologie și un model de analiză, nu dovada unui proiect FABER finalizat.</p>
        </div>

        <h3>Când poate deveni public un studiu de caz</h3>
        <p>Un caz este publicat numai după verificarea existenței proiectului, a rolului FABER și a rezultatului descris. Fișa trebuie să delimiteze precis sectorul, programul, serviciul furnizat, investiția, locația dacă este publicabilă și etapa: analiză preliminară, eligibilitate, pregătire, depunere, clarificări, contractare, implementare sau finalizare.</p>
        <ul class="compact-checklist">
          <li>acordul beneficiarului pentru publicare și nivelul de anonimizare;</li>
          <li>documente care susțin etapa și rezultatul, fără a transforma depunerea în aprobare sau contractarea în proiect finalizat;</li>
          <li>valoarea și metoda de calcul numai dacă sunt verificabile și aprobate pentru publicare;</li>
          <li>permisiune separată pentru numele beneficiarului, autor, funcție, companie, logo și localitate;</li>
          <li>formulare care explică limitele și nu promite rezultate viitoare.</li>
        </ul>

        <h3>Testimoniale și review schema</h3>
        <p>Un testimonial poate fi adăugat numai pe baza textului aprobat, cu autorul, funcția, compania și permisiunea documentate sau cu anonimizarea acceptată explicit. Nu publicăm citate reconstruite, evaluări agregate ori markup <code>Review</code>/<code>AggregateRating</code> fără dovezi și eligibilitate pentru acel tip de date structurate.</p>
        <p><strong>Principiu de publicare:</strong> mai puține dovezi reale sunt preferabile unui volum artificial. Studiile de caz și testimonialele nu garantează finanțarea și nu înlocuiesc documentația oficială aplicabilă fiecărui proiect.</p>
      </section>`;

function syncMethodology() {
  let html = read(METHODOLOGY_FILE);
  html = syncEditorialDate(html, METHODOLOGY_FILE, policy.reviewedAt, reviewedLabel);
  html = upsertBlock(
    html,
    METHODOLOGY_START,
    METHODOLOGY_END,
    "      <h2 id=\"flux-verificare\">Flux de verificare</h2>",
    methodologyBlock,
    METHODOLOGY_FILE
  );
  return html;
}

function syncCases() {
  let html = read(CASES_FILE);
  html = syncEditorialDate(html, CASES_FILE, policy.reviewedAt, reviewedLabel);
  const replacements = [
    ["Studii de caz anonimizate: proiecte pregătite pentru fonduri europene", "Studii de caz fonduri europene: metodologia și criteriile FABER"],
    ["Studii de caz anonimizate despre proiecte pregătite pentru fonduri europene: fermă AFIR, Start-Up Nation, digitalizare IMM și program regional.", "Metodologia FABER pentru studii de caz și testimoniale: dovezi, permisiuni, etape și rezultate publicabile fără exemple inventate."],
    ["Exemple anonimizate care arată metoda de analiza: eligibilitate, documente, cofinanțare, CAEN, punctaj și riscuri.", "Criterii pentru studii de caz și testimoniale reale, publicate numai cu dovezi și permisiune."],
    ["<span class=\"eyebrow\">Studii de caz anonimizate</span>", "<span class=\"eyebrow\">Metodologie și dovezi publicabile</span>"],
    ["<p>Exemple construite pentru a arată metoda de analiza: ce verificam, ce riscuri apar și cum se poate ajusta un proiect înainte de depunere.</p>", "<p>Criterii transparente pentru publicarea unor studii de caz și testimoniale reale, fără a transforma scenarii de analiză în rezultate ale clienților.</p>"],
    ["<p class=\"intro\">Aceste studii de caz sunt anonimizate și folosesc descrieri anonimizate acolo unde datele clientului trebuie confirmate. Nu publicam nume, localitati exacte, valori, statusuri sau rezultate fără acord și fără documente interne care să susțină informația.</p>", "<p class=\"intro\">Pagina explică structura folosită pentru verificarea și publicarea viitoarelor studii de caz. Nu prezentăm scenariile de analiză drept proiecte reale și nu publicăm nume, localități exacte, valori, etape sau rezultate fără acord și documente justificative.</p>"],
    ["<h2>Ce putem invata din aceste cazuri</h2>", "<h2>Ce poți învăța din structura de analiză</h2>"],
    ["<h2>Cum folosim aceste exemple în analiza unui proiect nou</h2>", "<h2>Cum folosim această structură în analiza unui proiect nou</h2>"],
    ["<h2>Programe relevante pentru cazurile de mai sus</h2>", "<h2>Programe relevante pentru scenariile de verificare</h2>"],
    ["<p>Nu toate programele sunt active în acelasi timp și nu toate permit aceleași cheltuieli. Pentru orientare inițială, cele patru modele de caz trimit către pagini interne care pot fi verificate mai departe în funcție de solicitant și investiție.</p>", "<p>Nu toate programele sunt active în același timp și nu toate permit aceleași cheltuieli. Pentru orientare inițială, scenariile de verificare trimit către pagini interne care trebuie confirmate în funcție de solicitant și investiție.</p>"],
    ["<section class=\"faq-item\"><h3>Sunt aceste studii de caz rezultate reale publicate?</h3><p>Pagină folosește exemple anonimizate și structuri de lucru. Rezultatele reale, valorile și numele clientilor se publică doar după verificare interna și acord explicit.</p></section>", "<section class=\"faq-item\"><h3>Sunt publicate aici rezultate reale ale clienților FABER?</h3><p>Nu în versiunea curentă. Pagina publică metodologia și structuri de verificare; un caz real, o valoare sau un nume va apărea numai după verificare internă și acord explicit.</p></section>"]
  ];
  for (const [previous, next] of replacements) html = replaceLiteral(html, previous, next, CASES_FILE);
  html = upsertBlock(
    html,
    EVIDENCE_START,
    EVIDENCE_END,
    "      <h2>Modelul folosit pentru fiecare studiu de caz</h2>",
    evidenceBlock,
    CASES_FILE
  );
  return html;
}

const outputs = [
  [METHODOLOGY_FILE, syncMethodology()],
  [CASES_FILE, syncCases()]
];
const changed = outputs.filter(([relativePath, content]) => read(relativePath) !== content);

if (CHECK && changed.length) {
  console.error(`Trust evidence nesincronizat: ${changed.map(([relativePath]) => relativePath).join(", ")}`);
  process.exit(1);
}
if (!CHECK) for (const [relativePath, content] of changed) write(relativePath, content);

console.log(`Trust evidence ${CHECK ? "check" : "sync"} PASS: ${outputs.length} pagini, ${changed.length} modificări.`);

module.exports = { METHODOLOGY_START, METHODOLOGY_END, EVIDENCE_START, EVIDENCE_END };
