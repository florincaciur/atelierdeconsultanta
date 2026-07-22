#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { renderContactTriageLayout } = require("./contact-triage-form");
const { loadLegalIdentity } = require("./legal-identity-governance");
const { renderContactChannels } = require("./canonical-contact");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const REVIEWED = "2026-07-20";
const CSS_HREF = "/assets/core-pages.css?v=20260720-1";
const changed = [];

const META = {
  "/consultanta-fonduri-europene": {
    title: "Consultanță fonduri europene: eligibilitate și dosar | FABER",
    description: "Verificăm solicitantul, programul, bugetul și documentele; pregătim cererea și clarificările numai după verificarea inițială a eligibilității.",
    ogTitle: "Consultanță pentru un proiect care poate fi susținut | FABER",
    ogDescription: "De la verificarea eligibilității la dosar și clarificări, fiecare etapă pornește din documentele reale ale solicitantului."
  },
  "/despre-faber": {
    title: "Despre FABER: operator, metodă și limite",
    description: "Află cine este operatorul FABER, cum este verificat un proiect, ce limite are consultanța și ce dovezi sunt necesare înainte de publicarea rezultatelor.",
    ogTitle: "FABER: consultanță prudentă înainte de dosar",
    ogDescription: "Entitatea juridică, metoda în cinci pași și limitele asumate public de FABER, prezentate din date aprobate și documente verificabile."
  },
  "/fonduri-europene": {
    title: "Fonduri europene 2026: programe pentru firme și fermieri",
    description: "Compară programe pentru firme, fermieri și instituții după solicitant, investiție, regiune, documente și contribuția proprie disponibilă.",
    ogTitle: "Găsește traseul potrivit pentru investiția ta | FABER",
    ogDescription: "Pornește de la beneficiar și investiție, apoi verifică programul, documentele și bugetul în pagina dedicată fiecărui apel."
  },
  "/contact": {
    title: "Contact FABER: trimite proiectul pentru verificare",
    description: "Trimite către FABER datele proiectului, bugetul și documentele disponibile pentru stabilirea programului și a verificărilor necesare.",
    ogTitle: "Trimite datele proiectului către FABER",
    ogDescription: "Spune-ne cine aplică, unde se face investiția și ce documente există pentru a delimita verificările necesare."
  }
};

function writeIfChanged(relativePath, before, after) {
  if (before === after) return;
  // HTML receives structured-data and analytics annotations later in the build.
  // Their semantic placement is checked by scripts/verify-core-pages.js.
  if (CHECK_ONLY && relativePath.endsWith(".html")) return;
  changed.push(relativePath);
  if (!CHECK_ONLY) fs.writeFileSync(path.join(ROOT, relativePath), after, "utf8");
}

function load(relativePath) {
  const before = fs.readFileSync(path.join(ROOT, relativePath), "utf8");
  return { before, $: cheerio.load(before, { decodeEntities: false }) };
}

function setMeta($, selector, value) {
  const element = $(selector).first();
  if (!element.length) throw new Error(`Lipsește ${selector}`);
  element.attr("content", value);
}

function ensureMeta($, name, value) {
  const selector = `meta[name='${name}']`;
  if ($(selector).length) $(selector).first().attr("content", value);
  else $("head").append(`<meta name="${name}" content="${value}">`);
}

function preparePage($, route, family, minWords, minFaq) {
  const meta = META[route];
  $("title").first().text(meta.title);
  setMeta($, "meta[name='description']", meta.description);
  setMeta($, "meta[property='og:title']", meta.ogTitle);
  setMeta($, "meta[property='og:description']", meta.ogDescription);
  if ($("meta[name='twitter:title']").length) setMeta($, "meta[name='twitter:title']", meta.ogTitle);
  if ($("meta[name='twitter:description']").length) setMeta($, "meta[name='twitter:description']", meta.ogDescription);
  ensureMeta($, "seo-min-words", String(minWords));
  ensureMeta($, "seo-min-faq", String(minFaq));

  if (!$(`link[href='${CSS_HREF}']`).length) {
    $("head").append(`<link rel="stylesheet" href="${CSS_HREF}">`);
  }
  const classes = new Set(($("body").attr("class") || "").split(/\s+/u).filter(Boolean));
  [...classes].filter((name) => name.startsWith("core-page--")).forEach((name) => classes.delete(name));
  classes.add("core-page");
  classes.add(`core-page--${family}`);
  $("body").attr("class", [...classes].join(" "));
  $(".audit-design-summary, .design-card-grid").remove();
}

function setHero($, { eyebrow, h1, description, primary, secondary, summary }) {
  const hero = $(".hero").first();
  hero.find(".eyebrow").first().text(eyebrow);
  hero.find("h1").first().text(h1);
  hero.children("p").first().text(description);
  hero.find(".hero-actions").first().html(`
      <a class="btn btn-primary" href="${primary.href}">${primary.label}</a>
      <a class="btn btn-secondary" href="${secondary.href}">${secondary.label}</a>`);
  hero.find(".hero-summary").first().html(summary.map(([label, text]) => (
    `<span class="hero-summary__item"><strong>${label}</strong><em>${text}</em></span>`
  )).join(""));
}

function contextualBlock(html) {
  return (html.match(/<!-- CONTEXTUAL_NEXT_STEP_START -->[\s\S]*?<!-- CONTEXTUAL_NEXT_STEP_END -->/u) || [""])[0];
}

function faqHtml(items) {
  return items.map(([question, answer]) => (
    `<section class="faq-item"><h3>${question}</h3><p>${answer}</p></section>`
  )).join("\n");
}

function searchSupport({ id, title, intro, faqs, sources, note }) {
  const sourceLinks = sources.map(([href, label, external = false]) => (
    `<a href="${href}"${external ? ' target="_blank" rel="noopener noreferrer"' : ""}>${label}</a>`
  )).join("\n");
  return `
      <section class="core-search-support" aria-labelledby="${id}-title">
        <div class="core-search-support__heading">
          <span class="core-kicker">Documentare</span>
          <h2 id="${id}-title">${title}</h2>
          <p>${intro}</p>
        </div>
        <details class="core-search-details" data-non-faq="">
          <summary>Consultă întrebările frecvente și sursele verificate</summary>
          <div class="core-search-details__body">
            <section class="faq" aria-label="Întrebări frecvente">
${faqHtml(faqs)}
            </section>
            <nav class="core-source-list" aria-label="Surse și pagini de verificare">
${sourceLinks}
            </nav>
            <p class="core-review-note">${note} Ultima revizuire: <time datetime="${REVIEWED}">20 iulie 2026</time>.</p>
          </div>
        </details>
      </section>`;
}

function rewriteConsulting() {
  const file = "consultanta-fonduri-europene/index.html";
  const { before, $ } = load(file);
  preparePage($, "/consultanta-fonduri-europene", "service", 550, 6);
  setHero($, {
    eyebrow: "Consultanță FABER · verificare · dosar · implementare",
    h1: "Consultanță pentru fonduri europene, de la eligibilitate la dosar",
    description: "Începem cu solicitantul, investiția și documentele. Continuăm cu cererea de finanțare numai când programul, bugetul și riscurile pot fi susținute.",
    primary: { href: "/verificare-eligibilitate-fonduri-europene", label: "Verifică proiectul" },
    secondary: { href: "/proiectare-fonduri-europene", label: "Vezi proiectarea tehnică" },
    summary: [
      ["Prima decizie", "merită sau nu pregătit dosarul"],
      ["Livrabile", "cerere, buget, anexe și clarificări"],
      ["Date necesare", "solicitant, CAEN, locație, investiție"],
      ["Limită", "aprobarea aparține autorității"]
    ]
  });

  const context = contextualBlock(before);
  $("main article.panel").first().html(`
      <section class="core-lead" aria-label="Înainte de pregătirea dosarului">
        <div class="core-lead__copy">
          <p>Un proiect bun nu începe cu formularul. Începe cu o verificare simplă: cine solicită finanțarea, ce activitate desfășoară, unde va face investiția, ce poate documenta și cum va susține contribuția proprie. Din aceste date rezultă programul care merită analizat și munca necesară pentru depunere.</p>
        </div>
        <ul class="core-checklist">
          <li>program ales după investiție, nu după valoarea grantului;</li>
          <li>punctaj susținut prin documente;</li>
          <li>buget legat de activitatea reală;</li>
          <li>responsabilități stabilite înainte de lucru.</li>
        </ul>
      </section>

      <section class="core-section" aria-labelledby="consulting-deliverables">
        <span class="core-kicker">Ce primești</span>
        <h2 id="consulting-deliverables">Livrabile clare pentru fiecare etapă</h2>
        <p class="core-section__intro">Oferta delimitează exact etapa contractată. Nu amestecăm verificarea inițială, redactarea dosarului, proiectarea și implementarea într-o promisiune generală.</p>
        <div class="core-card-grid">
          <article class="core-card"><span class="core-card__index">01</span><h3>Verdict de încadrare</h3><p>Program posibil, condiții confirmate, documente lipsă și motivele pentru care proiectul continuă, se ajustează sau se oprește.</p></article>
          <article class="core-card"><span class="core-card__index">02</span><h3>Cerere și buget coerente</h3><p>Cererea, anexele, ofertele și bugetul descriu aceeași investiție și folosesc numai criterii care pot fi demonstrate.</p></article>
          <article class="core-card"><span class="core-card__index">03</span><h3>Răspunsuri după depunere</h3><p>Clarificările, contractarea și implementarea sunt asistate dacă aceste etape sunt incluse explicit în colaborare.</p></article>
        </div>
      </section>

      <section class="core-section" aria-labelledby="consulting-process">
        <span class="core-kicker">Proces</span>
        <h2 id="consulting-process">Patru decizii înainte de depunere</h2>
        <ol class="core-steps">
          <li><strong>Încadrăm solicitantul.</strong><br>Formă juridică, dimensiune, activitate, localitate și istoric.</li>
          <li><strong>Testăm investiția.</strong><br>Cheltuieli, amplasament, capacitate tehnică și documente.</li>
          <li><strong>Construim scenariul.</strong><br>Program, punctaj prudent, contribuție proprie și calendar.</li>
          <li><strong>Pregătim forma finală.</strong><br>Cerere, buget, anexe, control și încărcare în platformă.</li>
        </ol>
      </section>

      <section class="core-section" aria-labelledby="consulting-boundaries">
        <span class="core-kicker">Decizie prudentă</span>
        <h2 id="consulting-boundaries">Când recomandăm să nu depui încă</h2>
        <p class="core-section__intro">O amânare este justificată când dreptul asupra spațiului nu acoperă perioada cerută, activitatea nu este autorizată corespunzător, cheltuielile principale nu sunt permise, punctajul depinde de dovezi inexistente sau contribuția proprie nu are o sursă realistă. În aceste situații stabilim ce trebuie corectat și ce apel poate fi urmărit.</p>
        <div class="core-fact-strip">
          <div><strong>Fără promisiuni de aprobare</strong><span>Evaluarea și selecția aparțin autorității finanțatoare.</span></div>
          <div><strong>Fără procent universal</strong><span>Grantul și contribuția se preiau din ghidul apelului ales.</span></div>
          <div><strong>Fără dosar pe presupuneri</strong><span>Afirmațiile și punctajul trebuie dovedite la termenul cerut.</span></div>
        </div>
      </section>

      <section class="core-section" data-contextual-next-step aria-labelledby="consulting-services">
        <span class="core-kicker">Trasee de lucru</span>
        <h2 id="consulting-services">Alege etapa de care are nevoie proiectul</h2>
        <div class="core-path-grid">
          <a class="core-path" href="/verificare-eligibilitate-fonduri-europene"><span class="core-path__icon" aria-hidden="true">✓</span><span><strong>Verificare inițială a eligibilității</strong><small>Pentru o idee care trebuie încadrată înainte de costuri și documentații ample.</small></span></a>
          <a class="core-path" href="/proiectare-fonduri-europene"><span class="core-path__icon" aria-hidden="true">⌂</span><span><strong>Proiectare și documentație tehnică</strong><small>Pentru investiții care cer SF, DALI, avize, proiect tehnic sau deviz.</small></span></a>
          <a class="core-path" href="/management-proiecte-fonduri-europene"><span class="core-path__icon" aria-hidden="true">→</span><span><strong>Implementare și raportare</strong><small>Pentru proiecte contractate care intră în achiziții, plăți și monitorizare.</small></span></a>
          <a class="core-path" href="/fonduri-europene"><span class="core-path__icon" aria-hidden="true">◇</span><span><strong>Compararea programelor</strong><small>Pentru beneficiari care nu au identificat încă apelul potrivit investiției.</small></span></a>
        </div>
      </section>

      <section class="core-section" aria-labelledby="consulting-price">
        <span class="core-kicker">Ofertă</span>
        <h2 id="consulting-price">Cum stabilim costul colaborării</h2>
        <p class="core-section__intro">Costul este stabilit după ce vedem programul, dimensiunea investiției, documentele existente, necesarul tehnic și etapele cerute. Oferta arată livrabilele, responsabilitățile, momentele de plată și activitățile care nu sunt incluse. Astfel poți compara servicii reale, nu procente sau prețuri fără context.</p>
      </section>

      <section class="core-callout" aria-labelledby="consulting-cta">
        <div><h2 id="consulting-cta">Ai deja investiția și bugetul?</h2><p>Trimite forma solicitantului, activitatea, localitatea, investiția, bugetul și contribuția proprie disponibilă. Aceste date sunt suficiente pentru a stabili ce trebuie verificat prima dată.</p></div>
        <div class="core-callout__actions"><a class="btn btn-primary" href="/contact">Trimite datele proiectului</a></div>
      </section>

${context}
${searchSupport({
    id: "consulting-documentation",
    title: "Întrebări și surse despre consultanța pentru fonduri europene",
    intro: "Această zonă păstrează explicațiile necesare documentării fără să întrerupă prezentarea serviciului și a livrabilelor.",
    faqs: [
      ["Ce include verificarea inițială?", "Solicitantul, activitatea sau exploatația, localitatea, investiția, bugetul, contribuția proprie și documentele disponibile sunt comparate cu regulile programului analizat."],
      ["Când începe redactarea dosarului?", "Redactarea începe după confirmarea programului, a condițiilor decisive și a documentelor care susțin eligibilitatea și punctajul estimat."],
      ["Ce livrabile poate include consultanța?", "În funcție de ofertă: analiză, cerere de finanțare, buget, anexe, verificare finală, clarificări, contractare și sprijin în implementare."],
      ["Cum se stabilește costul?", "Costul depinde de program, investiție, documentele existente, complexitatea bugetului și etapele pentru care FABER își asumă livrabile."],
      ["Poate FABER coordona și proiectarea?", "Da, când investiția cere documentație tehnică, traseul de proiectare este delimitat și corelat cu cererea de finanțare și devizul."],
      ["Cine decide aprobarea proiectului?", "Autoritatea finanțatoare evaluează, selectează și contractează proiectul. Consultantul pregătește și verifică documentația, fără a putea garanta rezultatul evaluării."]
    ],
    sources: [
      ["https://mfe.gov.ro/", "MIPE", true],
      ["https://www.afir.ro/", "AFIR", true],
      ["https://regionordest.ro/", "ADR Nord-Est", true],
      ["/cum-alegi-consultant-fonduri-europene", "Cum alegi consultantul"],
      ["/cat-costa-consultanta-fonduri-europene", "Costul consultanței"],
      ["/cat-costa-consultanta-fonduri-europene-ghid", "Ghid despre costuri"],
      ["/firma-consultanta-fonduri-europene", "Rolul firmei de consultanță"],
      ["/consultanta-fonduri-europene-bucuresti", "Consultanță pentru proiecte în București"],
      ["/surse-oficiale-fonduri-europene", "Directorul FABER de surse"]
    ],
    note: "Condițiile variabile se confirmă în documentul oficial și anexele apelului analizat."
  })}`);

  $("main > .cta-box").remove();
  writeIfChanged(file, before, $.html());
}

function rewriteAbout() {
  const file = "despre-faber/index.html";
  const { before, $ } = load(file);
  preparePage($, "/despre-faber", "trust", 700, 6);
  if (!$('link[href="/assets/about-faber.css?v=20260722-1"]').length) {
    $("head").append('<link rel="stylesheet" href="/assets/about-faber.css?v=20260722-1">');
  }
  const bodyClasses = new Set(($('body').attr('class') || '').split(/\s+/u).filter(Boolean));
  bodyClasses.add('about-page--p116');
  $('body').attr('class', [...bodyClasses].join(' '));
  $("meta[property='article:modified_time']").attr("content", "2026-07-22T00:00:00+03:00");
  setHero($, {
    eyebrow: "Despre FABER · identitate, metodă și limite",
    h1: "Consultanță prudentă înainte de dosar",
    description: "Verificare prudentă, documentată și interdisciplinară — consultanță și proiectare — înainte de dosar.",
    primary: { href: "/contact?source_page=%2Fdespre-faber", label: "Vezi dacă proiectul merită pregătit" },
    secondary: { href: "/metodologie-verificare-eligibilitate", label: "Vezi metoda de lucru" },
    summary: [
      ["Contractant", "FABER PUBLISHING S.R.L."],
      ["Decizie", "continuăm, ajustăm sau amânăm"],
      ["Verificare", "document oficial și acte ale solicitantului"],
      ["Limită", "evaluarea aparține autorității finanțatoare"]
    ]
  });

  const context = contextualBlock(before);
  $("main").html(`
    <article class="panel about-p116">
      <section class="core-lead about-intro" aria-label="Ce este FABER">
        <div class="core-lead__copy"><p>FABER este brandul sub care FABER PUBLISHING S.R.L. oferă servicii de consultanță și coordonare a proiectării pentru investiții finanțate. Înainte de pregătirea unui dosar, comparăm situația solicitantului și investiția cu documentul oficial aplicabil. Concluzia poate fi să continuăm, să ajustăm proiectul sau să amânăm pregătirea.</p></div>
        <ul class="core-checklist">
          <li>regula programului este legată de sursa oficială;</li>
          <li>punctajul orientativ pornește din documente disponibile;</li>
          <li>bugetul și proiectarea sunt corelate cu investiția;</li>
          <li>limitele și riscurile sunt explicate înainte de dosar.</li>
        </ul>
      </section>

<!-- CANONICAL_LEGAL_IDENTITY_SLOT -->

      <section class="core-section about-team" aria-labelledby="about-team-title">
        <span class="core-kicker">Oameni și responsabilitate</span>
        <h2 id="about-team-title">Cine lucrează la proiect</h2>
        <div class="about-team__layout">
          <div>
            <p class="core-section__intro">Pagina nu publică încă profiluri individuale. Numele, fotografia, rolul, specializările, experiența și profilul LinkedIn vor apărea numai după verificarea dovezilor și acordul explicit al persoanei.</p>
            <p>Pentru fiecare colaborare, responsabilitățile trebuie delimitate în oferta și contractul aplicabile. Un profil public nu înlocuiește această delimitare și nu va fi completat cu experiență presupusă.</p>
          </div>
          <aside class="about-validation-card" aria-label="Criterii pentru publicarea unui profil">
            <h3>Ce va conține un profil aprobat</h3>
            <ul>
              <li>fotografie reală și acord de publicare;</li>
              <li>nume, rol și specializări confirmate;</li>
              <li>experiență susținută de dovezi verificabile;</li>
              <li>LinkedIn numai dacă profilul este oficial;</li>
              <li>analize atribuite numai autorului real.</li>
            </ul>
          </aside>
        </div>
      </section>

      <section class="core-section about-method" id="metoda-faber" aria-labelledby="about-method-title">
        <span class="core-kicker">Metoda FABER</span>
        <h2 id="about-method-title">De la triere la implementare</h2>
        <p class="core-section__intro">Fiecare etapă are o decizie și un set de dovezi. Trecerea mai departe nu transformă o estimare în certitudine și nu transferă consultantului decizia autorității finanțatoare.</p>
        <ol class="about-method-flow">
          <li><span aria-hidden="true">01</span><strong>Triere</strong><p>Solicitantul, localitatea, investiția și canalul de contact conturează întrebările inițiale.</p></li>
          <li><span aria-hidden="true">02</span><strong>Documente</strong><p>Actele disponibile sunt comparate cu ghidul, anexele și regulile oficiale aplicabile.</p></li>
          <li><span aria-hidden="true">03</span><strong>Punctaj</strong><p>Criteriile sunt estimate prudent, iar ipotezele și dovezile lipsă sunt marcate separat.</p></li>
          <li><span aria-hidden="true">04</span><strong>Dosar</strong><p>Livrabilele, responsabilitățile, bugetul și documentația tehnică sunt delimitate înainte de redactare.</p></li>
          <li><span aria-hidden="true">05</span><strong>Clarificări și implementare</strong><p>După depunere, sprijinul continuă numai pentru etapele și obligațiile asumate contractual.</p></li>
        </ol>
      </section>

      <section class="core-section about-limits" aria-labelledby="about-limits-title">
        <span class="core-kicker">Limite asumate</span>
        <h2 id="about-limits-title">Ce nu promite FABER</h2>
        <div class="about-boundary-grid">
          <article><h3>Nu promitem aprobarea</h3><p>Selecția depinde de autoritatea finanțatoare, documentele depuse, punctaj, bugetul apelului și verificările oficiale.</p></article>
          <article><h3>Nu echivalăm o listare cu o acreditare</h3><p>O eventuală apariție într-un nomenclator nu înseamnă acreditare din partea AFIR și nu indică un clasament sau o recomandare instituțională.</p></article>
          <article><h3>Nu publicăm rezultate neverificate</h3><p>Ratele de succes, valorile proiectelor, testimonialele și afirmațiile despre portofoliu cer documente, metodă de calcul și acord.</p></article>
        </div>
      </section>

      <section class="core-section about-evidence" aria-labelledby="about-evidence-title">
        <span class="core-kicker">Probe reale</span>
        <h2 id="about-evidence-title">Ce considerăm dovadă publicabilă</h2>
        <div class="about-evidence-grid">
          <article><h3>Studiu de caz</h3><p>Context, documente care susțin afirmațiile, metodă de prezentare, acord și anonimizare acolo unde este necesar.</p></article>
          <article><h3>Rezultat</h3><p>Programul și versiunea documentului, perioada de referință, baza de calcul și limitele comparației.</p></article>
          <article><h3>Testimonial</h3><p>Acord explicit, identitate verificabilă și formulare care nu transformă experiența unui client într-o garanție.</p></article>
        </div>
        <p><a href="/studii-de-caz-fonduri-europene">Vezi politica de publicare a studiilor de caz</a></p>
      </section>

      <section class="core-section about-affiliations" aria-labelledby="about-affiliations-title">
        <span class="core-kicker">Afilieri și listări</span>
        <h2 id="about-affiliations-title">Formulări care cer confirmare oficială</h2>
        <p>Pagina nu afirmă în prezent o afiliere sau o listare instituțională. Dacă prezența FABER într-un document oficial AFIR este confirmată, formularea acceptată va fi „listată în nomenclatorul orientativ AFIR”, însoțită de document și dată. Aceasta nu va fi prezentată ca acreditare, clasament sau recomandare.</p>
      </section>

      <nav class="about-resource-links" aria-label="Documente despre FABER">
        <a href="/metodologie-verificare-eligibilitate"><strong>Metodologie</strong><span>Cum sunt verificate proiectele</span></a>
        <a href="/studii-de-caz-fonduri-europene"><strong>Studii de caz</strong><span>Reguli pentru dovezi și acord</span></a>
        <a href="/contact"><strong>Contact</strong><span>Date aprobate și formularul de triere</span></a>
      </nav>

      <section class="core-callout about-final-cta" aria-labelledby="about-cta">
        <div><h2 id="about-cta">Ai o investiție pe care vrei să o verifici?</h2><p>Trimite forma solicitantului, localitatea și investiția. Prima etapă este orientativă și stabilește ce documente trebuie analizate.</p></div>
        <div class="core-callout__actions"><a class="btn btn-primary" href="/contact?source_page=%2Fdespre-faber">Vezi dacă proiectul merită pregătit</a><a class="btn btn-secondary" href="/metodologie-verificare-eligibilitate">Vezi metoda de lucru</a></div>
      </section>

${context}
${searchSupport({
    id: "about-documentation",
    title: "Întrebări despre FABER",
    intro: "Răspunsurile de mai jos completează identitatea, metoda și limitele prezentate pe pagină. Profilurile și rezultatele lipsă nu sunt înlocuite cu estimări.",
    faqs: [
      ["Cine contractează serviciile FABER?", "Contractele și facturile sunt emise de FABER PUBLISHING S.R.L., conform datelor juridice aprobate și afișate pe această pagină."],
      ["De ce nu apar încă profiluri de echipă?", "Nu există încă un set complet aprobat de fotografii, roluri, specializări, experiență verificabilă și acorduri de publicare. Până la validare, pagina nu inventează și nu publică profiluri incomplete."],
      ["Cum este verificat un program?", "Sunt comparate documentul oficial, anexele și comunicările instituției cu situația și actele solicitantului relevante pentru investiția analizată."],
      ["De ce nu este promisă aprobarea?", "Aprobarea depinde de evaluarea autorității, bugetul apelului, punctaj, documente și respectarea tuturor condițiilor aplicabile."],
      ["Cum sunt publicate rezultatele sau testimonialele?", "Numai cu dovezi verificabile, o metodă de prezentare corectă și acordul persoanelor sau organizațiilor implicate."],
      ["Ce înseamnă o eventuală listare în nomenclatorul AFIR?", "O listare confirmată într-un nomenclator orientativ nu reprezintă acreditare, clasament sau recomandare instituțională."]
    ],
    sources: [
      ["/metodologie-verificare-eligibilitate", "Metodologia FABER"],
      ["/studii-de-caz-fonduri-europene", "Studii de caz și dovezi"],
      ["/contact", "Date de contact"]
    ],
    note: "Pagina nu publică profiluri individuale, afilieri sau afirmații numerice despre performanță fără documente și acord."
  })}
    </article>`);

  writeIfChanged(file, before, $.html());
}

function rewriteFunds() {
  const file = "fonduri-europene/index.html";
  const { before, $ } = load(file);
  preparePage($, "/fonduri-europene", "hub", 550, 6);
  setHero($, {
    eyebrow: "Hub FABER · programe pentru investiții",
    h1: "Ce program de fonduri europene se potrivește investiției tale?",
    description: "Alege mai întâi tipul solicitantului și investiția. Pagina programului îți arată apoi condițiile, documentele și statutul care trebuie confirmate înainte de depunere.",
    primary: { href: "#trasee-finantare", label: "Alege traseul" },
    secondary: { href: "/calendar-fonduri-europene", label: "Vezi calendarul" },
    summary: [
      ["Firme", "regional, digitalizare, energie, producție"],
      ["Fermieri", "AFIR, DR12, DR14, autoconsum"],
      ["Instituții", "regional, energie și infrastructură"],
      ["Start-up", "apeluri dedicate și programe regionale"]
    ]
  });

  const context = contextualBlock(before);
  $("main article.panel").first().html(`
      <section class="core-lead" aria-label="Cum folosești hubul de finanțări">
        <div class="core-lead__copy"><p>Nu există un program potrivit pentru orice proiect. Un IMM, o fermă și o instituție pot urmări investiții asemănătoare, dar folosesc reguli și documente diferite. De aceea, traseele de mai jos pornesc de la beneficiar și investiție, nu de la o sumă promovată.</p></div>
        <ul class="core-checklist"><li>selectează profilul solicitantului;</li><li>alege categoria investiției;</li><li>deschide pagina programului;</li><li>confirmă statutul și documentul oficial aplicabil.</li></ul>
      </section>

      <section class="core-section" id="trasee-finantare" aria-labelledby="funding-routes">
        <span class="core-kicker">Alege după beneficiar</span>
        <h2 id="funding-routes">Patru puncte de intrare</h2>
        <div class="core-path-grid">
          <a class="core-path" href="/fonduri-europene-imm"><span class="core-path__icon" aria-hidden="true">IMM</span><span><strong>Firme și microîntreprinderi</strong><small>Investiții productive, digitalizare, servicii, energie și apeluri regionale.</small></span></a>
          <a class="core-path" href="/fonduri-europene-agricultura"><span class="core-path__icon" aria-hidden="true">AF</span><span><strong>Fermieri și procesatori</strong><small>Intervenții AFIR, ferme mici, tineri fermieri, utilaje și autoconsum.</small></span></a>
          <a class="core-path" href="/start-up-nation-2026"><span class="core-path__icon" aria-hidden="true">ST</span><span><strong>Start-up-uri și firme noi</strong><small>Apeluri dedicate, condiții de înființare, CAEN, locuri de muncă și buget.</small></span></a>
          <a class="core-path" href="/fonduri-regionale"><span class="core-path__icon" aria-hidden="true">RO</span><span><strong>Instituții și investiții regionale</strong><small>Apeluri gestionate regional, infrastructură, servicii publice și energie.</small></span></a>
        </div>
      </section>

      <section class="core-section" aria-labelledby="funding-investments">
        <span class="core-kicker">Alege după investiție</span>
        <h2 id="funding-investments">Programe și huburi urmărite</h2>
        <p class="core-section__intro">Fiecare card duce la o pagină cu intenție distinctă. Condițiile unui apel nu sunt copiate în hub și nu sunt transferate de la un program la altul.</p>
        <div class="core-card-grid">
          <article class="core-card"><span class="core-card__index">Agricultură</span><h3>DR12 și DR14 AFIR</h3><p>Tineri fermieri, ferme mici, dimensiune economică, documentele exploatației și investiții agricole.</p><p><a href="/dr12-afir">DR12</a> · <a href="/dr14">DR14</a></p></article>
          <article class="core-card"><span class="core-card__index">Energie</span><h3>Autoconsum și surse regenerabile</h3><p>Dimensionare după consum, amplasament, stocare, racordare și documentație tehnică.</p><p><a href="/afir-autoconsum-agroalimentar">AFIR Autoconsum</a></p></article>
          <article class="core-card"><span class="core-card__index">Regional</span><h3>Modernizarea microîntreprinderilor – Apel 2</h3><p>Județ, categorie de întreprindere, CAEN, amplasament, buget și documentații SF/DALI.</p><p><a href="/investitii-modernizarea-microintreprinderilor-apel-2">Vezi condițiile apelului</a></p></article>
          <article class="core-card"><span class="core-card__index">Digitalizare</span><h3>Digitalizare IMM și PoCIDIF</h3><p>Procese, software, hardware, securitate, cercetare și indicatori care trebuie justificați.</p><p><a href="/digitalizare-imm">Digitalizare IMM</a> · <a href="/pocidif-21">PoCIDIF 2.1</a></p></article>
          <article class="core-card"><span class="core-card__index">Mobilitate</span><h3>e-MOVE RO</h3><p>Investiții în mobilitate electrică analizate după beneficiar, infrastructură și regulile apelului.</p><p><a href="/e-move">e-MOVE RO</a></p></article>
          <article class="core-card"><span class="core-card__index">Producție</span><h3>PRO INFRA</h3><p>Capacități de producție pentru materiale și echipamente legate de dezvoltarea infrastructurii.</p><p><a href="/pro-infra">PRO INFRA</a></p></article>
        </div>
      </section>

      <section class="core-section" aria-labelledby="funding-filter">
        <span class="core-kicker">Filtru înainte de dosar</span>
        <h2 id="funding-filter">Ce trebuie să se potrivească simultan</h2>
        <div class="core-fact-strip">
          <div><strong>Solicitantul</strong><span>Forma juridică, dimensiunea, vechimea, regiunea și activitatea acceptată.</span></div>
          <div><strong>Investiția</strong><span>Cheltuieli permise, amplasament, capacitate, avize și legătura cu obiectivul apelului.</span></div>
          <div><strong>Finanțarea</strong><span>Contribuție proprie, costuri neeligibile, TVA, cash-flow și termen de implementare.</span></div>
        </div>
        <p data-terminology-note="own-contribution">Pe acest site folosim «contribuție proprie» ca termen principal. În documentele oficiale pot apărea și «cofinanțare» sau «aport»; sensul și calculul se verifică în documentul aplicabil.</p>
      </section>

      <section class="core-section" aria-labelledby="funding-order">
        <span class="core-kicker">Ordine de lucru</span>
        <h2 id="funding-order">De la investiție la program</h2>
        <ol class="core-steps">
          <li><strong>Descrie investiția.</strong><br>Ce cumperi, construiești sau schimbi și de ce este necesar.</li>
          <li><strong>Verifică solicitantul.</strong><br>CAEN sau exploatație, locație, istoric și documente.</li>
          <li><strong>Compară programele.</strong><br>Eligibilitate, punctaj, calendar, contribuție și obligații.</li>
          <li><strong>Alege traseul.</strong><br>Consultanță, proiectare tehnică și documente de pregătit.</li>
        </ol>
      </section>

      <section class="core-callout" aria-labelledby="funding-cta">
        <div><h2 id="funding-cta">Nu știi ce program să alegi?</h2><p>Trimite profilul solicitantului, localitatea, investiția și bugetul. Comparăm numai programele care au legătură reală cu proiectul.</p></div>
        <div class="core-callout__actions"><a class="btn btn-primary" href="/contact">Trimite proiectul</a><a class="btn btn-secondary" href="/verificare-eligibilitate-fonduri-europene">Vezi verificarea</a></div>
      </section>

${context}
${searchSupport({
    id: "funding-documentation",
    title: "Întrebări și surse despre fondurile europene",
    intro: "Răspunsurile generale sunt grupate la final. Valorile, termenele și procentele rămân în paginile programelor și în documentele instituției finanțatoare.",
    faqs: [
      ["Cum aleg programul potrivit?", "Compară tipul solicitantului, activitatea, regiunea, investiția, bugetul, contribuția proprie și documentele cu regulile apelurilor relevante."],
      ["Eligibilitatea înseamnă că proiectul va fi selectat?", "Nu. Un proiect eligibil trebuie să atingă punctajul necesar și să intre în bugetul disponibil al sesiunii."],
      ["Există o contribuție proprie valabilă pentru toate programele?", "Nu. Intensitatea sprijinului, cheltuielile neeligibile și regulile privind TVA diferă și se confirmă în ghidul apelului."],
      ["Unde verific statutul unui apel?", "În pagina instituției finanțatoare, în ghidul solicitantului, anexele publicate și comunicările oficiale privind deschiderea sau închiderea sesiunii."],
      ["Ce documente sunt utile înainte de alegerea programului?", "Actele solicitantului, CAEN-ul sau evidențele exploatației, datele financiare, documentele amplasamentului, lista investiției și bugetul estimat."],
      ["Când este necesară proiectarea tehnică?", "Când investiția include construcții, modernizări, instalații sau lucrări pentru care apelul cere studiu, avize, deviz, DALI, SF ori proiect tehnic."]
    ],
    sources: [
      ["https://mfe.gov.ro/", "MIPE", true],
      ["https://www.afir.ro/", "AFIR", true],
      ["https://regionordest.ro/", "ADR Nord-Est", true],
      ["/calendar-fonduri-europene", "Calendar FABER"],
      ["/greseli-fonduri-europene", "Greșeli frecvente de evitat"],
      ["/webinarii", "Webinarii și evenimente"],
      ["/surse-oficiale-fonduri-europene", "Toate sursele oficiale"]
    ],
    note: "Hubul organizează trasee și nu substituie ghidul unui apel."
  })}`);

  $("main > .cta-box").remove();
  writeIfChanged(file, before, $.html());
}

function rewriteContact() {
  const file = "contact/index.html";
  const { before, $ } = load(file);
  preparePage($, "/contact", "contact", 400, 6);
  if (!$('link[href="/assets/contact-triage.css?v=20260721-1"]').length) {
    $("head").append('<link rel="stylesheet" href="/assets/contact-triage.css?v=20260721-1">');
  }
  if (!$('script[src="/assets/contact-triage.js?v=20260721-1"]').length) {
    $("head").append('<script src="/assets/contact-triage.js?v=20260721-1" defer></script>');
  }
  setHero($, {
    eyebrow: "Contact FABER · datele proiectului",
    h1: "Trimite proiectul. Îți spunem ce trebuie verificat.",
    description: "Nu trebuie să cunoști programul potrivit. Pentru trierea inițială avem nevoie doar de tipul solicitantului, localitate, investiție și un canal de răspuns.",
    primary: { href: "#contact-form-title", label: "Completează formularul" },
    secondary: { href: "#contact-direct", label: "Contact direct" },
    summary: [
      ["Poți începe fără program", "descrie investiția și solicitantul"],
      ["Timp estimat", "aprox. 60–90 secunde"],
      ["Contact", "email sau telefon, nu ambele"],
      ["Detalii", "opționale în pasul 2"]
    ]
  });

  const registry = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8"));
  const approvals = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "program-status-approvals.json"), "utf8"));
  const programAliases = Object.fromEntries((approvals.programs || []).map((approval) => [
    approval.programId,
    approval.publicationHoldUrls || []
  ]));
  const layout = renderContactTriageLayout(registry.programs || [], programAliases);
  const contactChannels = renderContactChannels(loadLegalIdentity());

  $("main").html(`
    ${layout}

    ${contactChannels}

    <section class="core-section" aria-labelledby="contact-after-send">
      <span class="core-kicker">După trimitere</span>
      <h2 id="contact-after-send">Ce se întâmplă cu solicitarea</h2>
      <ol class="core-steps">
        <li><strong>Citirea contextului.</strong><br>Identificăm informațiile suficiente și contradicțiile evidente.</li>
        <li><strong>Lista de completări.</strong><br>Cerem documentele sau datele fără de care nu poate exista o concluzie.</li>
        <li><strong>Direcția de verificare.</strong><br>Stabilim programul sau categoria de programe care merită analizată.</li>
        <li><strong>Oferta de lucru.</strong><br>Delimităm livrabilele numai dacă proiectul poate continua.</li>
      </ol>
    </section>

${searchSupport({
    id: "contact-documentation",
    title: "Întrebări despre contact și datele transmise",
    intro: "Informațiile administrative sunt păstrate la finalul paginii, după formular și canalele directe de contact.",
    faqs: [
      ["Pot trimite proiectul dacă nu știu programul?", "Da. Selectează opțiunea «Nu știu încă» și descrie solicitantul, investiția, localitatea și bugetul disponibil."],
      ["Ce informații sunt obligatorii?", "Formularul cere tipul solicitantului, județul sau localitatea, o descriere scurtă a investiției, email sau telefon și confirmarea citirii informării privind prelucrarea datelor."],
      ["Pot trimite documente pe email?", "Da. Folosește adresa publică FABER și indică în mesaj numele solicitantului și investiția la care se referă documentele."],
      ["Cum sunt folosite datele?", "Datele sunt folosite pentru analiza solicitării și răspunsul FABER, conform informării din politica de confidențialitate. Confirmarea citirii nu reprezintă acord de marketing."],
      ["În cât timp primesc o concluzie?", "Durata depinde de datele și documentele primite. Dacă lipsesc elemente decisive, primul răspuns va solicita completări, nu va presupune eligibilitatea."],
      ["Mesajul WhatsApp înlocuiește formularul?", "Nu întotdeauna. WhatsApp este util pentru contactul inițial, iar proiectele cu mai multe documente sunt continuate prin email sau formular."]
    ],
    sources: [
      ["/politica-de-confidentialitate", "Politica de confidențialitate"],
      ["/metodologie-verificare-eligibilitate", "Metodologia de verificare"],
      ["/consultanta-fonduri-europene", "Serviciile de consultanță"],
      ["/surse-oficiale-fonduri-europene", "Surse oficiale"]
    ],
    note: "Nu este publicat un termen fix de răspuns, deoarece volumul și calitatea documentelor diferă."
  })}`);

  writeIfChanged(file, before, $.html());
}

function syncSnippetConfig() {
  const file = "config/seo-snippets.json";
  const before = fs.readFileSync(path.join(ROOT, file), "utf8");
  const config = JSON.parse(before);
  const details = {
    "/consultanta-fonduri-europene": {
      primaryIntent: "contractarea consultanței pentru verificarea și pregătirea proiectului",
      primaryQuery: "consultanță fonduri europene",
      secondaryQueries: ["consultant fonduri europene", "verificare eligibilitate", "pregătire dosar fonduri europene"],
      sourceOfTruth: ["tools/rebuild-core-pages.js", "config/seo-programs.json:consultanta-fonduri-europene"],
      factualStatus: "evergreen_service_scope_verified",
      notes: "Titlul leagă interogarea principală de cele două decizii comerciale: eligibilitatea și dosarul."
    },
    "/despre-faber": {
      primaryIntent: "evaluarea identității și metodei de lucru FABER",
      primaryQuery: "despre FABER consultanță",
      secondaryQueries: ["FABER Atelier de Consultanță", "metodă consultanță FABER", "cine este FABER"],
      sourceOfTruth: ["tools/rebuild-core-pages.js", "despre-faber/index.html"],
      factualStatus: "brand_methodology_copy_verified",
      notes: "Titlul diferențiază FABER prin prudență fără a folosi rezultate sau experiență nedocumentate."
    },
    "/fonduri-europene": {
      primaryIntent: "identificarea programelor de fonduri europene pentru investiție",
      primaryQuery: "fonduri europene 2026",
      secondaryQueries: ["fonduri europene firme", "fonduri europene fermieri", "programe fonduri europene"],
      sourceOfTruth: ["tools/rebuild-core-pages.js", "fonduri-europene/index.html"],
      factualStatus: "programme_hub_routes_verified",
      notes: "Titlul folosește anul numai pentru hub; termenele și valorile rămân în paginile programelor."
    },
    "/contact": {
      primaryIntent: "contactarea FABER pentru verificarea proiectului",
      primaryQuery: "contact FABER",
      secondaryQueries: ["contact consultant fonduri europene", "trimite proiect FABER", "verificare proiect"],
      sourceOfTruth: ["tools/rebuild-core-pages.js", "contact/index.html"],
      factualStatus: "operational_contact_process_verified",
      notes: "Titlul indică acțiunea și rezultatul realist al contactului fără a promite eligibilitate sau aprobare."
    }
  };

  const pagesByRoute = new Map(config.pages.map((page) => [page.route, page]));
  for (const [route, meta] of Object.entries(META)) {
    const current = pagesByRoute.get(route) || { route };
    Object.assign(current, details[route], meta, { lastReviewed: REVIEWED });
    if (!pagesByRoute.has(route)) config.pages.push(current);
  }
  const after = `${JSON.stringify(config, null, 2)}\n`;
  writeIfChanged(file, before, after);
}

function syncConsultingSource() {
  const file = "config/seo-programs.json";
  const before = fs.readFileSync(path.join(ROOT, file), "utf8");
  const config = JSON.parse(before);
  const page = config.pages.find((item) => item.slug === "consultanta-fonduri-europene");
  if (!page) throw new Error("Lipsește consultanta-fonduri-europene din seo-programs.json");
  Object.assign(page, {
    title: META["/consultanta-fonduri-europene"].title,
    description: META["/consultanta-fonduri-europene"].description,
    h1: "Consultanță pentru fonduri europene, de la eligibilitate la dosar",
    quickAnswer: "FABER verifică solicitantul, investiția, bugetul și documentele înainte de redactarea cererii. Colaborarea poate continua cu dosarul, clarificările, proiectarea sau implementarea numai pentru etapele delimitate în ofertă.",
    minWords: 550,
    minFaq: 6
  });
  const after = `${JSON.stringify(config, null, 2)}\n`;
  writeIfChanged(file, before, after);
}

function main() {
  syncSnippetConfig();
  syncConsultingSource();
  rewriteConsulting();
  rewriteAbout();
  rewriteFunds();
  rewriteContact();

  if (CHECK_ONLY && changed.length) {
    console.error(`Core pages are not synchronized (${changed.length}):`);
    changed.forEach((file) => console.error(`- ${file}`));
    process.exitCode = 1;
    return;
  }
  console.log(`${CHECK_ONLY ? "Verified" : "Rebuilt"} 4 core pages; ${changed.length} file(s) ${CHECK_ONLY ? "out of sync" : "updated"}.`);
}

main();
