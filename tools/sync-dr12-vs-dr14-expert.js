#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "dr12-vs-dr14-expert.json");
const PROGRAMS_PATH = path.join(ROOT, "config", "seo-programs.json");
const REPORT_PATH = path.join(ROOT, "reports", "p1-19-dr12-vs-dr14-validari.md");
const STYLE_HREF = "/assets/dr12-vs-dr14-expert.css?v=20260722-1";
const AEO_START = "<!-- P1_18_AEO_QUESTIONS_START -->";
const AEO_END = "<!-- P1_18_AEO_QUESTIONS_END -->";
const TOC_START = "<!-- P1_09_LONG_FORM_TOC_START -->";
const TOC_END = "<!-- P1_09_LONG_FORM_TOC_END -->";
const GOVERNANCE_START = "<!-- EDITORIAL_GOVERNANCE_START -->";
const GOVERNANCE_END = "<!-- EDITORIAL_GOVERNANCE_END -->";

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&#39;");
}

function words(value) {
  return String(value).match(/[\p{L}\p{N}]+(?:[’'-][\p{L}\p{N}]+)*/gu) || [];
}

function displayDate(value) {
  const [year, month, day] = String(value).split("-");
  return `${day}.${month}.${year}`;
}

function managedBlock(html, start, end) {
  const pattern = new RegExp(`${start}[\\s\\S]*?${end}`, "u");
  return html.match(pattern)?.[0] || "";
}

function replaceFirst(html, pattern, replacement, label) {
  if (!pattern.test(html)) throw new Error(`Nu poate fi actualizat ${label}.`);
  return html.replace(pattern, replacement);
}

function sourceRef(program) {
  return `<span class="expert-source-ref">Sursă: <a href="#source-${escapeHtml(program.slug)}">${escapeHtml(program.shortName)}</a>, verificat la <time datetime="${escapeHtml(program.verifiedAt)}">${escapeHtml(displayDate(program.verifiedAt))}</time>.</span>`;
}

function renderTable(config) {
  const [dr12, dr14] = config.programs;
  const rows = config.comparisonRows.map((row) => `          <tr data-comparison-row="${escapeHtml(row.label)}">
            <th scope="row">${escapeHtml(row.label)}</th>
            <td>${escapeHtml(row.dr12)}${sourceRef(dr12)}</td>
            <td>${escapeHtml(row.dr14)}${sourceRef(dr14)}</td>
          </tr>`).join("\n");
  return `<div class="long-form-table-region" role="region" tabindex="0" aria-label="Comparație documentată între DR 12 și DR 14">
        <table class="expert-comparison-table" data-expert-comparison-table>
          <thead>
            <tr><th scope="col">Criteriu</th><th scope="col">DR 12</th><th scope="col">DR 14</th></tr>
          </thead>
          <tbody>
${rows}
          </tbody>
        </table>
      </div>`;
}

function renderHero(config) {
  return `<section class="post-hero hero--afir" data-design-family="afir" data-expert-analysis-hero>
    <span class="post-category">Analiză comparativă AFIR</span>
    <h1 class="post-title">${escapeHtml(config.h1)}</h1>
    <p class="post-excerpt">Comparație documentată pentru alegerea intervenției care merită analizată înainte de pregătirea dosarului.</p>
    <div class="post-meta">
      <span>Revizie factuală: <time datetime="${escapeHtml(config.reviewedAt)}">${escapeHtml(displayDate(config.reviewedAt))}</time></span>
      <span>Surse oficiale AFIR</span>
      <span>FABER – Atelier de Consultanță</span>
    </div>
    <div class="hero-actions">
      <a class="btn-primary" href="/contact#source_page=%2Fdr12-vs-dr14" data-analytics-event="cta_click" data-analytics-component="comparison_hero" data-analytics-cta-id="dr12_vs_dr14_compare_project" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_19">Compară proiectul tău cu DR 12 și DR 14</a>
      <a class="btn-secondary" href="#comparatie-documentata">Vezi comparația documentată</a>
    </div>
  </section>`;
}

function renderContent(config, preserved) {
  const [dr12, dr14] = config.programs;
  const pending = config.pendingHumanValidation.map((item) => `          <li>${escapeHtml(item)}</li>`).join("\n");
  const aeo = preserved.aeo ? `\n${preserved.aeo}\n` : "\n";
  const governance = preserved.governance ? `\n${preserved.governance}` : "";
  const toc = preserved.toc ? `${preserved.toc}\n` : "";
  return `<div class="post-container" data-long-form-layout="rail" data-long-form-content="true" data-expert-analysis="dr12-vs-dr14">
${toc}    <article class="post-body">
      <div class="expert-status-panel" role="status" aria-label="Statutul documentelor DR 12 și DR 14">
        <span class="expert-status-panel__icon" aria-hidden="true">◐</span>
        <p><strong>${escapeHtml(config.statusStatement)}</strong><br>Comparația folosește numai informațiile susținute de documentele oficiale identificate mai jos.</p>
      </div>

      <p class="expert-direct-answer" data-expert-direct-answer>${escapeHtml(config.directAnswer)}</p>
<!-- P1_19_DIRECT_ANSWER_END -->${aeo}
      <h2 id="comparatie-documentata">Ce comparăm înainte de alegerea intervenției?</h2>
      <p>DR 12 și DR 14 pot părea apropiate deoarece ambele privesc investiții agricole, dar pornesc de la logici diferite. Prima întrebare nu este care variantă afișează o valoare mai mare, ci dacă solicitantul, ferma și investiția pot fi susținute de documentele cerute. Tabelul separă condițiile finale DR 14 de elementele DR 12 care trebuie reconfirmate după publicarea formei finale.</p>
      <p class="expert-comparison-note"><strong>Cum se citește tabelul:</strong> fiecare celulă trimite la documentul AFIR folosit și la data verificării. Valorile DR 14 provin din ghidul oficial final; pentru DR 12 nu publicăm sume sau intensități finale cât timp registrul programului le păstrează neconfirmate.</p>
${renderTable(config)}

      <h2 id="orientare-dr12-dr14">Când merită analizat mai întâi fiecare program?</h2>
      <div class="expert-guidance-grid">
        <section class="expert-guidance-card" aria-labelledby="alege-dr12">
          <h3 id="alege-dr12">Alege DR 12 pentru analiza inițială dacă…</h3>
          <ul>
            <li>profilul solicitantului poate fi încadrat în categoriile intervenției;</li>
            <li>istoricul și rolul de șef al exploatației pot fi dovedite;</li>
            <li>investiția consolidează activitatea agricolă documentată;</li>
            <li>SO, amplasamentul și drepturile de folosință sunt coerente.</li>
          </ul>
          <p>Orientarea de mai jos nu este un verdict. Continuă cu <a href="${escapeHtml(dr12.canonicalUrl)}">statutul și condițiile canonice DR 12</a>.</p>
        </section>
        <section class="expert-guidance-card" aria-labelledby="analizeaza-dr14">
          <h3 id="analizeaza-dr14">Analizează DR 14 pentru început dacă…</h3>
          <ul>
            <li>proiectul pornește de la o fermă mică existentă și documentată;</li>
            <li>forma solicitantului și activitatea fermei pot fi probate;</li>
            <li>investiția este proporțională cu nevoile exploatației;</li>
            <li>demarcarea cu alte intervenții sau proiecte este clară.</li>
          </ul>
          <p>Orientarea de mai jos nu confirmă eligibilitatea. Continuă cu <a href="${escapeHtml(dr14.canonicalUrl)}">statutul și condițiile canonice DR 14</a>.</p>
        </section>
      </div>

      <h2 id="scenarii-ipotetice">Cum arată comparația în trei scenarii ipotetice?</h2>
      <p>Exemplele următoare sunt fictive și nu descriu clienți sau proiecte reale. Rolul lor este să arate ce informație schimbă ordinea analizei.</p>
      <div class="expert-scenario-grid">
        <article class="expert-scenario" data-hypothetical="true">
          <span class="expert-scenario__label">Exemplu ipotetic 1</span>
          <h3>Fermier care vrea să consolideze exploatația</h3>
          <p><strong>Ipoteză:</strong> solicitantul conduce ferma, are un istoric ce poate fi documentat și urmărește utilaje plus modernizarea spațiilor existente.</p>
          <p><strong>Orientare:</strong> DR 12 merită verificat primul, deoarece profilul și obiectivul pot corespunde intervenției. Încadrarea rămâne deschisă până la verificarea actelor, SO și formei finale a ghidului.</p>
        </article>
        <article class="expert-scenario" data-hypothetical="true">
          <span class="expert-scenario__label">Exemplu ipotetic 2</span>
          <h3>Fermă mică ce urmărește o dezvoltare proporțională</h3>
          <p><strong>Ipoteză:</strong> ferma funcționează, datele agricole sunt coerente, iar investiția urmărește modernizarea activității curente, fără o condiție de instalare invocată.</p>
          <p><strong>Orientare:</strong> DR 14 merită analizat primul. Concluzia poate fi schimbată de forma juridică, încadrarea SO, sector, demarcări și documentele tehnice.</p>
        </article>
        <article class="expert-scenario" data-hypothetical="true">
          <span class="expert-scenario__label">Exemplu ipotetic 3</span>
          <h3>Date SO apropiate de o limită și acte nealiniate</h3>
          <p><strong>Ipoteză:</strong> suprafețele și efectivele diferă între evidențe, iar drepturile asupra amplasamentului nu acoperă clar investiția.</p>
          <p><strong>Orientare:</strong> nu se alege încă DR 12 sau DR 14. Se refac datele și calculul SO, se clarifică actele și abia apoi se reia comparația.</p>
        </article>
      </div>

      <h2 id="documente-care-schimba-concluzia">Ce documente pot schimba concluzia?</h2>
      <ul class="expert-document-list">
        <li>actele solicitantului, forma juridică, reprezentarea și istoricul relevant;</li>
        <li>evidențele exploatației pentru culturi, suprafețe, animale și activitate;</li>
        <li>calculul SO și documentele din care provin datele introduse;</li>
        <li>actele de proprietate sau folosință pentru terenuri, clădiri și amplasament;</li>
        <li>descrierea investiției, ofertele, bugetul și sursele pentru contribuția proprie;</li>
        <li>avizele, acordurile și documentația tehnico-economică aplicabilă;</li>
        <li>proiectele existente sau solicitate care pot crea suprapuneri ori dublă finanțare.</li>
      </ul>
      <p>Poți folosi <a href="/calculator-soc">Calculatorul SO</a> pentru o estimare orientativă, dar rezultatul trebuie confruntat cu evidențele fermei și cu ghidul aplicabil.</p>
      <p>Dacă diferența ține de obiectivul investiției, continuă cu ghidul despre <a href="/fonduri-pentru-ferme">finanțări pentru dezvoltarea fermei</a> și cu analiza despre <a href="/fonduri-pentru-utilaje-agricole">utilaje agricole și documentele investiției</a>. Aceste pagini explică întrebări complementare; nu înlocuiesc condițiile DR 12 sau DR 14.</p>

      <h2 id="surse-versiuni-si-validare">Ce surse și versiuni susțin analiza?</h2>
      <div class="expert-source-grid">
        <article class="expert-source-card" id="source-${escapeHtml(dr12.slug)}">
          <h3>DR 12</h3>
          <p><strong>${escapeHtml(dr12.sourceLabel)}</strong></p>
          <p><a href="${escapeHtml(dr12.sourceUrl)}" target="_blank" rel="noopener noreferrer">Consultarea publică AFIR și documentele asociate</a></p>
          <p><a href="${escapeHtml(dr12.guideUrl)}" target="_blank" rel="noopener noreferrer">Deschide ghidul consultativ DR 12</a></p>
          <p>Verificat la <time datetime="${escapeHtml(dr12.verifiedAt)}">${escapeHtml(displayDate(dr12.verifiedAt))}</time>.</p>
        </article>
        <article class="expert-source-card" id="source-${escapeHtml(dr14.slug)}">
          <h3>DR 14</h3>
          <p><strong>${escapeHtml(dr14.sourceLabel)}</strong></p>
          <p><a href="${escapeHtml(dr14.sourceUrl)}" target="_blank" rel="noopener noreferrer">Pagina oficială AFIR cu ghidul și anexele DR 14</a></p>
          <p><a href="${escapeHtml(dr14.guideUrl)}" target="_blank" rel="noopener noreferrer">Deschide ghidul oficial final DR 14</a></p>
          <p>Verificat la <time datetime="${escapeHtml(dr14.verifiedAt)}">${escapeHtml(displayDate(dr14.verifiedAt))}</time>.</p>
        </article>
      </div>

      <aside class="expert-validation-note" aria-labelledby="validari-ramase">
        <h3 id="validari-ramase">Ce reconfirmăm înainte de publicarea valorilor finale?</h3>
        <ul>
${pending}
        </ul>
      </aside>

      <!-- PROGRAM_TEMPLATE_GOVERNANCE_SLOT -->${governance}

      <section class="expert-final-cta" aria-labelledby="cta-comparatie-proiect">
        <h2 id="cta-comparatie-proiect">Compară proiectul tău cu criteriile DR 12 și DR 14</h2>
        <p>Trimite forma solicitantului, localitatea, investiția și ce documente există. Formularul păstrează contextul acestei comparații, iar concluzia rămâne orientativă până la verificarea actelor și a ghidului aplicabil.</p>
        <a href="/contact#source_page=%2Fdr12-vs-dr14" data-analytics-event="cta_click" data-analytics-component="comparison_final" data-analytics-cta-id="dr12_vs_dr14_compare_project_final" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_19">Compară proiectul tău cu criteriile DR 12 și DR 14</a>
      </section>
    </article>
  </div>

  `;
}

function renderReport(config) {
  return `# P1.19 — Validări pentru „DR 12 vs DR 14”

Revizie factuală și editorială: **${displayDate(config.reviewedAt)}**.

## Surse oficiale folosite

- DR 12: ${config.programs[0].sourceLabel} — ${config.programs[0].sourceUrl}
- DR 12, document: ${config.programs[0].guideUrl}
- DR 14: ${config.programs[1].sourceLabel} — ${config.programs[1].sourceUrl}

## Elemente DR 12 și actualizări rămase de reconfirmat

${config.pendingHumanValidation.map((item) => `- DE_VALIDAT_UMAN — ${item}`).join("\n")}

## Decizia de publicare

- statut publicat: DR 12 are ghid consultativ, iar DR 14 are sesiunea lansată cu depuneri programate din 01.09.2026;
- valorile finale DR 14 și calendarul sesiunii sunt publicate conform documentelor AFIR; valorile DR 12 rămân nepublicate până la reconfirmare;
- scenariile sunt marcate explicit ca ipotetice și nu descriu clienți reali;
- CTA-ul transmite numai \`source_page=/dr12-vs-dr14\`, fără PII în URL;
- autorul și reviewerul sunt publicați organizațional; nu este publicat un nume personal fără acord.
`;
}

function validateConfig(config, programs) {
  const errors = [];
  const bySlug = new Map(programs.map((program) => [program.slug, program]));
  if (config.schemaVersion !== 1) errors.push("schemaVersion trebuie să fie 1");
  if (config.route !== "/dr12-vs-dr14") errors.push("ruta canonică este invalidă");
  if (words(config.directAnswer).length < 60 || words(config.directAnswer).length > 80) errors.push(`răspunsul direct are ${words(config.directAnswer).length} cuvinte; necesar 60–80`);
  if (!Array.isArray(config.comparisonRows) || config.comparisonRows.length !== 10) errors.push("tabelul trebuie să aibă exact 10 criterii");
  const expectedRows = ["Beneficiar", "Obiectiv", "Instalare / dezvoltare", "SO", "Tip de investiție", "Sprijin", "Contribuție proprie", "Calendar", "Documente-cheie", "Riscuri"];
  if (JSON.stringify(config.comparisonRows.map((row) => row.label)) !== JSON.stringify(expectedRows)) errors.push("criteriile tabelului diferă de contractul P1.19");
  for (const program of config.programs || []) {
    const registry = bySlug.get(program.slug);
    if (!registry) {
      errors.push(`program inexistent în registru: ${program.slug}`);
      continue;
    }
    if (!program.status || registry.status !== program.status) errors.push(`${program.slug}: statusul local nu coincide cu registrul unic`);
    if (!program.verifiedAt || registry.verifiedAt !== program.verifiedAt) errors.push(`${program.slug}: verifiedAt nu coincide cu registrul unic`);
    if (registry.sourceUrl !== program.sourceUrl) errors.push(`${program.slug}: sursa nu coincide cu registrul unic`);
    const hasApplicationDates = Boolean(registry.applicationStart || registry.applicationEnd);
    if (hasApplicationDates) {
      const completeInterval = /^\d{4}-\d{2}-\d{2}$/u.test(registry.applicationStart || "")
        && /^\d{4}-\d{2}-\d{2}$/u.test(registry.applicationEnd || "");
      const scheduledNotOpen = registry.status === "ghid_aprobat_nedeschis"
        && completeInterval
        && registry.applicationStart > config.reviewedAt
        && /anunț|sesiun/iu.test(`${registry.sourceVersion} ${registry.statusLabel}`);
      if (!scheduledNotOpen && registry.status !== "apel_deschis") {
        errors.push(`${program.slug}: intervalul de depunere nu este justificat de status și sursa oficială`);
      }
    }
    if ((registry.grantSummary || registry.cofinancingSummary) && registry.status === "consultare_publica" && registry.fundingBasis !== "consultative") errors.push(`${program.slug}: valorile numerice consultative necesită un contract de publicare separat`);
  }
  if (!Array.isArray(config.pendingHumanValidation) || config.pendingHumanValidation.length < 5) errors.push("lista de validări umane este incompletă");
  if (errors.length) throw new Error(`Config P1.19 invalid:\n- ${errors.join("\n- ")}`);
}

function synchronize(source, config) {
  const preserved = {
    aeo: managedBlock(source, AEO_START, AEO_END),
    toc: managedBlock(source, TOC_START, TOC_END),
    governance: managedBlock(source, GOVERNANCE_START, GOVERNANCE_END)
  };
  // The long-form synchronizer may place the managed TOC directly under <main>,
  // while this generator owns the editorial container. Remove every existing
  // occurrence before reinserting the single preserved block in that container.
  let output = source.replace(
    /<!-- P1_09_LONG_FORM_TOC_START -->[\s\S]*?<!-- P1_09_LONG_FORM_TOC_END -->\s*/giu,
    ""
  );
  output = replaceFirst(output, /<title>[\s\S]*?<\/title>/iu, `<title>${escapeHtml(config.title)}</title>`, "title");
  output = replaceFirst(output, /<meta\s+name=["']description["'][^>]*>/iu, `<meta name="description" content="${escapeHtml(config.metaDescription)}">`, "meta description");
  output = replaceFirst(output, /<meta\s+property=["']og:title["'][^>]*>/iu, `<meta property="og:title" content="${escapeHtml(config.title)}">`, "og:title");
  output = replaceFirst(output, /<meta\s+property=["']og:description["'][^>]*>/iu, `<meta property="og:description" content="${escapeHtml(config.metaDescription)}">`, "og:description");
  output = output.replace(/\s*<link\b[^>]*href=["']\/assets\/dr12-vs-dr14-expert\.css(?:\?[^"']*)?["'][^>]*>\s*/giu, "\n");
  output = output.replace(/<\/head>/iu, `  <link rel="stylesheet" href="${STYLE_HREF}">\n</head>`);
  output = replaceFirst(output, /<section\s+class=["'][^"']*\bpost-hero\b[^"']*["'][^>]*>[\s\S]*?<\/section>/iu, renderHero(config), "hero");
  const containerStart = output.search(/<div\s+class=["'][^"']*\bpost-container\b[^"']*["'][^>]*>/iu);
  const footerStart = output.search(/<footer\s+class=["'][^"']*\bfooter\b[^"']*["'][^>]*>/iu);
  if (containerStart < 0 || footerStart < 0 || footerStart <= containerStart) throw new Error("Containerul editorial sau footer-ul nu poate fi identificat.");
  return `${output.slice(0, containerStart)}${renderContent(config, preserved)}${output.slice(footerStart)}`;
}

function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  const programs = JSON.parse(fs.readFileSync(PROGRAMS_PATH, "utf8")).programs || [];
  validateConfig(config, programs);
  const file = path.join(ROOT, config.file);
  const source = fs.readFileSync(file, "utf8");
  const output = synchronize(source, config);
  fs.writeFileSync(file, output, "utf8");
  fs.writeFileSync(REPORT_PATH, renderReport(config), "utf8");
  console.log(`P1.19 sincronizat: ${config.route}, ${config.comparisonRows.length} criterii, ${config.pendingHumanValidation.length} validări umane rămase.`);
}

if (require.main === module) main();
module.exports = { renderContent, renderHero, renderReport, synchronize, validateConfig, words };
