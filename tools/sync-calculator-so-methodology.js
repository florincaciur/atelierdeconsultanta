#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "calculator-so-methodology.json");
const REPORT_PATH = path.join(ROOT, "reports", "p1-20-calculator-so-validari.md");
const STYLE_HREF = "/assets/calculator-so-methodology.css?v=20260809-1";
const SCRIPT_SRC = "/assets/calculator-so-methodology.js?v=20260809-1";
const METHOD_START = "<!-- P1_20_SO_METHODOLOGY_START -->";
const METHOD_END = "<!-- P1_20_SO_METHODOLOGY_END -->";
const INPUT_START = "<!-- P1_20_SO_INPUT_HELP_START -->";
const INPUT_END = "<!-- P1_20_SO_INPUT_HELP_END -->";
const DISCLAIMER = "Rezultatul calculatorului este orientativ și nu înlocuiește ghidul sau verificarea documentelor.";
const CHECK_ONLY = process.argv.includes("--check");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&#39;");
}

function displayDate(value) {
  const [year, month, day] = String(value).split("-");
  return `${day}.${month}.${year}`;
}

function replaceManaged(html, start, end, block, fallbackPattern, fallbackLabel) {
  const managed = new RegExp(`${start}[\\s\\S]*?${end}`, "u");
  if (managed.test(html)) return html.replace(managed, block);
  if (!fallbackPattern.test(html)) throw new Error(`Nu poate fi identificat ${fallbackLabel}.`);
  return html.replace(fallbackPattern, block);
}

function coefficientIndex(config) {
  return new Map(config.coefficientGroups.flatMap((group) => group.entries.map((entry) => [entry.code, entry])));
}

function calculate(items, index) {
  const exact = items.reduce((total, item) => total + index.get(item.code).coefficient * item.quantity, 0);
  return { exact, displayed: Math.round(exact) };
}

function validateConfig(config) {
  const errors = [];
  if (config.schemaVersion !== 1) errors.push("schemaVersion trebuie să fie 1");
  if (config.route !== "/calculator-soc" || config.file !== "calculator-soc.html") errors.push("ruta sau fișierul calculatorului este invalid");
  if (!/^https:\/\/www\.afir\.ro\//u.test(config.source.pageUrl) || !/^https:\/\/www\.afir\.ro\//u.test(config.source.documentUrl)) errors.push("sursa coeficienților trebuie să fie AFIR");
  if (!/SOC 2020/u.test(config.source.version)) errors.push("versiunea sursei trebuie să identifice SOC 2020");
  if (!/^[A-F0-9]{64}$/u.test(config.source.documentSha256)) errors.push("hash-ul documentului oficial este invalid");
  const entries = config.coefficientGroups.flatMap((group) => group.entries);
  const codes = entries.map((entry) => entry.code);
  if (new Set(codes).size !== codes.length) errors.push("codurile SOC trebuie să fie unice");
  for (const entry of entries) {
    if (!(Number.isFinite(entry.coefficient) && entry.coefficient > 0)) errors.push(`${entry.code}: coeficient invalid`);
    if (!entry.unit || !entry.unitLabel) errors.push(`${entry.code}: unitate lipsă`);
  }
  const index = coefficientIndex(config);
  for (const example of config.examples) {
    if (!Array.isArray(example.items) || !example.items.length) errors.push(`${example.title}: lipsesc elementele`);
    for (const item of example.items || []) if (!index.has(item.code)) errors.push(`${example.title}: cod inexistent ${item.code}`);
    if ((example.items || []).every((item) => index.has(item.code))) {
      const result = calculate(example.items, index);
      if (Math.abs(result.exact - example.exactTotal) > 0.000001) errors.push(`${example.title}: totalul exact diferă de formulă`);
      if (result.displayed !== example.displayTotal) errors.push(`${example.title}: totalul afișat diferă de Math.round`);
    }
  }
  if (config.examples.length < 2 || config.examples.length > 3) errors.push("sunt necesare 2–3 exemple");
  if (errors.length) throw new Error(errors.join("\n"));
}

function renderInputHelp(config) {
  return `${INPUT_START}
      <div class="so-source-notice" id="calculator-input-help">
        <span class="so-source-notice__icon" aria-hidden="true">✓</span>
        <div>
          <p><strong>Coeficienți: ${escapeHtml(config.source.version)}</strong>; sursă controlată la <time datetime="${escapeHtml(config.reviewedAt)}">${escapeHtml(displayDate(config.reviewedAt))}</time>.</p>
          <p>Introdu cantitatea în unitatea afișată pentru categorie. Pentru păsări, documentul AFIR exprimă coeficientul la 100 de capete. <a href="${escapeHtml(config.source.documentUrl)}" target="_blank" rel="noopener noreferrer">Consultă lista oficială completă AFIR</a>.</p>
        </div>
      </div>
      <div id="calculator-errors" class="so-calculator-errors" role="alert" aria-live="assertive"></div>
${INPUT_END}`;
}

function renderExamples(config) {
  return config.examples.map((example) => `        <article class="so-example" data-so-example>
          <span class="so-example__label">Date fictive · coeficienți oficiali</span>
          <h3>${escapeHtml(example.title)}</h3>
          <ol>
${example.steps.map((step) => `            <li>${escapeHtml(step)}</li>`).join("\n")}
          </ol>
        </article>`).join("\n");
}

function renderSources(config) {
  return [config.source, ...config.supportingSources].map((source, index) => {
    const name = index === 0 ? config.source.name : source.name;
    const url = index === 0 ? config.source.pageUrl : source.url;
    const use = index === 0 ? `${config.source.version}; document verificat prin SHA-256 ${config.source.documentSha256}.` : source.use;
    return `        <li><strong>${escapeHtml(name)}.</strong> ${escapeHtml(use)} <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Deschide sursa oficială</a>.</li>`;
  }).join("\n");
}

function renderMethodology(config) {
  return `${METHOD_START}
<section class="section" id="metodologie-calcul-so" data-so-methodology data-method-version="${escapeHtml(config.methodVersion)}">
  <div class="container">
    <div class="reveal revealed">
      <div class="sec-label">Metodologie și trasabilitate</div>
      <h2 class="sec-title">Cum calculează instrumentul dimensiunea economică SO?</h2>
      <p class="sec-sub">SO este valoarea monetară medie a producției agricole la poarta fermei, exprimată printr-un coeficient regional pentru fiecare categorie. Instrumentul înmulțește coeficientul SOC cu cantitatea documentabilă și însumează rezultatele. Totalul ajută la clasificarea orientativă a exploatației; nu confirmă programul, eligibilitatea, punctajul sau documentele unui dosar.</p>
    </div>

    <div class="so-methodology-grid">
      <article class="so-methodology-card">
        <span class="so-method-version">Metodă ${escapeHtml(config.methodVersion)}</span>
        <h3>Formula, unitățile și rotunjirea</h3>
        <div class="so-formula">${escapeHtml(config.formula)}</div>
        <p>Unitatea este hectarul, capul, familia de albine sau grupul de 100 de capete, exact cum este indicat lângă categoria selectată. ${escapeHtml(config.rounding)}</p>
        <p>Formula de înmulțire și însumare existentă nu a fost schimbată în această actualizare; a fost corectat setul de coeficienți și a fost documentată proveniența.</p>
      </article>
      <article class="so-methodology-card">
        <span class="so-method-version">Sursă verificată ${escapeHtml(displayDate(config.reviewedAt))}</span>
        <h3>Ce set de coeficienți folosește?</h3>
        <p><strong>${escapeHtml(config.source.version)}.</strong> AFIR arată că SOC 2020 este aplicabil proiectelor din Planul Strategic PAC 2023–2027 și că, pentru dosar, calculul se realizează în tabelul Cererii de finanțare aplicabile intervenției.</p>
        <p>Calculatorul include categoriile uzuale din lista AFIR. Pentru o categorie absentă sau o denumire neclară, nu alege un substitut: folosește lista completă și cere confirmarea codului.</p>
      </article>
    </div>

    <div class="so-disclosures">
    <details class="so-page-disclosure">
      <summary>Exemple de calcul cu date fictive <span aria-hidden="true"></span></summary>
      <div class="so-page-disclosure__body">
      <p>Exemplele demonstrează formula și rotunjirea interfeței. Datele despre exploatații sunt fictive; coeficienții provin din lista oficială indicată.</p>
      <div class="so-example-grid">
${renderExamples(config)}
      </div></div>
    </details>

    <details class="so-page-disclosure">
      <summary>Datele introduse, ipotezele și limitele instrumentului <span aria-hidden="true"></span></summary>
      <div class="so-page-disclosure__body">
      <h2>Ce date introduci și ce presupune instrumentul?</h2>
      <div class="so-limit-grid">
      <article class="so-limit-card">
        <h3>Date introduse de utilizator</h3>
        <ul>
          <li>categoria și codul SOC care corespund activității documentate;</li>
          <li>suprafața în hectare, efectivul în capete, familiile de albine sau unitățile de 100 de păsări;</li>
          <li>toate componentele exploatației care trebuie incluse potrivit Cererii de finanțare.</li>
        </ul>
      </article>
      <article class="so-limit-card">
        <h3>Ipoteze tehnice</h3>
        <ul>
          <li>valorile introduse sunt numere finite, pozitive sau zero;</li>
          <li>limita de 1.000.000 este doar o protecție tehnică, nu un prag de eligibilitate;</li>
          <li>calculul intern păstrează zecimalele, iar totalul vizibil este rotunjit la euro.</li>
        </ul>
      </article>
      </div>

    <h2>Ce nu poate decide Calculatorul SO?</h2>
      <div class="so-limit-grid">
      <article class="so-limit-card">
        <h3>Nu confirmă încadrarea</h3>
        <p>Totalul nu decide singur dacă solicitantul se încadrează în DR 12, DR 14 sau altă intervenție. Forma solicitantului, istoricul, amplasamentul, sectorul, condițiile eliminatorii și versiunea finală a documentelor pot schimba concluzia.</p>
      </article>
      <article class="so-limit-card">
        <h3>Nu înlocuiește evidențele</h3>
        <p>Instrumentul nu verifică IACS/APIA, ANSVSA, ANZ, registrul agricol, actele de folosință sau concordanța dintre baze. Nu poate stabili nici grantul, contribuția proprie, cash-flow-ul sau punctajul.</p>
      </article>
      </div></div>
    </details>

    <details class="so-page-disclosure">
      <summary>Documentele care dovedesc datele folosite <span aria-hidden="true"></span></summary>
      <div class="so-page-disclosure__body"><ul class="so-document-list">
      <li>înregistrările IACS/APIA din anul depunerii pentru suprafețe și culturi;</li>
      <li>înregistrările ANSVSA/DSVSA și, unde este cazul, ANZ pentru animale și familii de albine;</li>
      <li>adeverința medicului veterinar pentru păsări sau animale mici care nu figurează în bazele aplicabile;</li>
      <li>actele de proprietate ori folosință și documentele exploatației cerute de intervenție;</li>
      <li>tabelul SOC din Cererea de finanțare aplicabilă apelului ales.</li>
      </ul></div>
    </details>

    <details class="so-page-disclosure">
      <summary>Surse, autor, revizie și istoric <span aria-hidden="true"></span></summary>
      <div class="so-page-disclosure__body"><ul class="so-source-list">
${renderSources(config)}
      </ul>
    <div class="so-review-card so-review-card--approved">
      <h3>Autor și revizie</h3>
      <p><strong>Autor:</strong> FABER – Atelier de Consultanță, autor organizațional.</p>
      <p><strong>Revizie:</strong> Echipa editorială și tehnică FABER — metodă, sursă, UX și teste, la <time datetime="${escapeHtml(config.reviewedAt)}">${escapeHtml(displayDate(config.reviewedAt))}</time>.</p>
      <p><strong>Changelog ${escapeHtml(displayDate(config.reviewedAt))}:</strong> setul legacy fără proveniență a fost înlocuit cu categoriile SOC 2020 din lista AFIR noiembrie 2024; formula a rămas neschimbată; rezultatul oferă numai o sugestie prudentă de program, care necesită verificarea documentelor.</p>
    </div>
    <aside class="so-review-card" aria-labelledby="so-validari-umane">
      <h3 id="so-validari-umane">Validări care rămân obligatorii pentru un dosar</h3>
      <ul>
${config.pendingHumanValidation.map((item) => `        <li>${escapeHtml(item)}</li>`).join("\n")}
      </ul>
      </aside></div>
    </details>
    </div>
  </div>
</section>
${METHOD_END}`;
}

function renderDatabase(config) {
  const output = {};
  for (const group of config.coefficientGroups) {
    output[group.id] = Object.fromEntries(group.entries.map((entry) => [entry.name, {
      code: entry.code,
      coefficient: entry.coefficient,
      unit: entry.unit,
      unitLabel: entry.unitLabel
    }]));
  }
  return JSON.stringify(output, null, 4).replace(/^/gmu, "  ");
}

function renderCalculatorScript(config) {
  return `<script>
  // P1.20 — Formula existentă este păstrată; setul de date provine din lista AFIR SOC 2020.
  const soDatabase = ${renderDatabase(config).trimStart()};
  let hasTrackedCalculation = false;

  function addCulturaRow(type) {
    const tbody = document.getElementById(type + '-body');
    const rowId = 'row-' + type + '-' + Date.now();
    const typeLabels = {
      culturi: 'culturi de câmp',
      legume: 'legume, pepeni și căpșuni',
      fructe: 'fructe și plantații',
      animale: 'animale și familii de albine'
    };
    const typeLabel = typeLabels[type] || 'categorie';
    const categories = Object.keys(soDatabase[type]);
    const defaultSelect = categories[0];
    const defaultEntry = soDatabase[type][defaultSelect];
    const row = document.createElement('tr');
    row.id = rowId;
    row.innerHTML = \`
      <td>
        <select id="\${rowId}-category" class="cultura-select" aria-label="Categorie pentru \${typeLabel}">
          \${categories.map(function (name) {
            const entry = soDatabase[type][name];
            return \`<option value="\${name}" data-code="\${entry.code}" data-unit="\${entry.unit}" data-unit-label="\${entry.unitLabel}">\${name} (\${entry.code})</option>\`;
          }).join('')}
        </select>
      </td>
      <td><input type="number" readonly tabindex="-1" value="\${defaultEntry.coefficient}" class="so-input" aria-label="Coeficient SOC oficial pentru \${typeLabel}"></td>
      <td><input type="number" value="1" min="0" max="1000000" step="\${defaultEntry.unit === 'ha' ? '0.01' : '1'}" class="area-input" aria-label="Cantitate în \${defaultEntry.unitLabel} pentru \${typeLabel}" aria-describedby="calculator-input-help calculator-errors"></td>
      <td class="so-val" aria-label="SO calculat pentru rând">0</td>
      <td><button type="button" class="calc-remove" onclick="removeRow('\${rowId}')" aria-label="Șterge rândul din \${typeLabel}">✕ Șterge</button></td>
    \`;
    tbody.appendChild(row);
    const select = row.querySelector('.cultura-select');
    const quantity = row.querySelector('.area-input');
    select.addEventListener('change', function () {
      const entry = soDatabase[type][this.value];
      row.querySelector('.so-input').value = entry.coefficient;
      quantity.step = entry.unit === 'ha' ? '0.01' : '1';
      quantity.setAttribute('aria-label', 'Cantitate în ' + entry.unitLabel + ' pentru ' + typeLabel);
      updateCalculation();
    });
    quantity.addEventListener('input', updateCalculation);
    quantity.addEventListener('change', updateCalculation);
    updateCalculation();
  }

  function removeRow(rowId) {
    const row = document.getElementById(rowId);
    if (row) {
      row.remove();
      updateCalculation();
    }
  }

  function updateCalculation() {
    let totalSo = 0;
    document.querySelectorAll('#calculator tbody tr').forEach(row => {
      const soInput = row.querySelector('.so-input');
      const areaInput = row.querySelector('.area-input');
      const resultCell = row.querySelector('.so-val');
      if (soInput && areaInput) {
        const so = parseFloat(soInput.value) || 0;
        const area = parseFloat(areaInput.value) || 0;
        const rowTotal = so * area;
        totalSo += rowTotal;
        if (resultCell) {
          resultCell.dataset.exactValue = String(rowTotal);
          resultCell.textContent = rowTotal.toLocaleString('ro-RO', { maximumFractionDigits: 2 });
        }
      }
    });
    const roundedTotal = Math.round(totalSo);
    document.getElementById('total-so').textContent = roundedTotal.toLocaleString('ro-RO');
    document.getElementById('total-so').dataset.soValue = String(roundedTotal);
    document.getElementById('total-so').dataset.soExactValue = String(totalSo);
    updateStatusBadges(totalSo);
    if (totalSo > 0 && !hasTrackedCalculation && window.FaberAnalytics) {
      hasTrackedCalculation = true;
      window.FaberAnalytics.calculatorComplete();
    }
  }

  function updateStatusBadges(so) {
    const statusBadges = document.getElementById('status-badges');
    const suggestion = document.getElementById('so-program-suggestion');
    const statusKey = so <= 0 ? 'empty' : so < 2000 ? 'below_reference' : so < 12000 ? 'dr14_reference' : 'dr12_reference';
    if (statusBadges.dataset.statusKey === statusKey) return;
    statusBadges.dataset.statusKey = statusKey;
    statusBadges.innerHTML = so > 0
      ? '<span class="status-badge status-orange">ⓘ Rezultat orientativ — verifică documentele și intervenția</span>'
      : '<span class="status-badge status-orange">Adaugă culturi sau animale</span>';
    if (!suggestion) return;
    if (so <= 0) suggestion.innerHTML = '<strong>Sugestia de program va apărea după introducerea datelor.</strong><span>Calculatorul nu poate stabili eligibilitatea fără total și fără documentele exploatației.</span>';
    else if (so < 2000) suggestion.innerHTML = '<strong>Reper de verificat: total sub pragurile uzuale DR 14.</strong><span>Verifică unitățile, categoriile și toate componentele exploatației; rezultatul nu exclude alte intervenții.</span>';
    else if (so < 12000) suggestion.innerHTML = '<strong>Program de verificat cu prioritate: <a href="/dr14">DR 14 – Ferme mici</a>.</strong><span>Pragul minim diferă în funcție de sector, iar SO singur nu confirmă solicitantul, punctajul sau eligibilitatea.</span>';
    else suggestion.innerHTML = '<strong>Programe de verificat: <a href="/dr12-afir">DR 12</a> sau o altă intervenție AFIR.</strong><span>DR 14 vizează ferme până la 11.999 EUR SO; pentru DR 12 trebuie verificate separat profilul fermierului și toate condițiile ghidului.</span>';
  }

  function resetCalculator() {
    document.querySelectorAll('#calculator tbody').forEach(tbody => { tbody.innerHTML = ''; });
    updateCalculation();
  }

  var obs = new IntersectionObserver(function(entries){
    entries.forEach(function(e){ if(e.isIntersecting){ e.target.classList.add('revealed'); obs.unobserve(e.target); } });
  },{threshold:0.1,rootMargin:'0px 0px -30px 0px'});
  document.querySelectorAll('.reveal').forEach(function(el){ obs.observe(el); });
  updateCalculation();
</script>`;
}

function renderResult() {
  return `<!-- Result -->
      <div class="calc-result" role="status" aria-live="polite" aria-atomic="false">
        <div class="result-label">Standard Output total</div>
        <div class="result-value" id="total-so" data-so-value="0" data-so-exact-value="0">0</div>
        <div class="result-unit">EUR SO</div>
        <div class="result-status" id="status-badges"></div>
        <div id="so-program-suggestion" class="so-program-suggestion" aria-live="polite"></div>
        <div id="so-result-explanation" class="so-result-explanation"></div>
        <p><strong>${escapeHtml(DISCLAIMER)}</strong></p>
        <div class="so-result-actions" aria-label="Acțiuni pentru rezultat">
          <button type="button" data-copy-so-result>Copiază rezumatul</button>
          <button type="button" data-print-so-result>Tipărește rezultatul</button>
        </div>
        <p id="so-action-feedback" class="so-action-feedback" aria-live="polite"></p>
      </div>`;
}

function renderReport(config) {
  const count = config.coefficientGroups.reduce((total, group) => total + group.entries.length, 0);
  return `# P1.20 — Metodologia Calculatorului SO

Data reviziei: **${displayDate(config.reviewedAt)}**
Versiune metodă: **${config.methodVersion}**
Versiune coeficienți: **${config.source.version}**

## Sursa oficială

- pagină AFIR: ${config.source.pageUrl}
- document AFIR: ${config.source.documentUrl}
- SHA-256 document: \`${config.source.documentSha256}\`
- definiție și metodă generală: Eurostat, sursele publicate în pagină

## Implementare

- ${count} categorii SOC documentate prin cod, coeficient și unitate;
- formula existentă \`coeficient × cantitate\` și însumarea nu au fost schimbate;
- totalul este calculat cu zecimale și afișat prin \`Math.round\`;
- rezultatul oferă o sugestie prudentă de program, fără verdict automat de eligibilitate;
- rezultatul are explicație pe rând, copiere și tipărire fără PII;
- CTA transmite numai \`source_page\` și \`so_result\` numeric validat.

## Exemple acoperite de teste

${config.examples.map((example) => `- ${example.title}: ${example.exactTotal} EUR, afișat ${example.displayTotal} EUR.`).join("\n")}

## DE_VALIDAT_UMAN înaintea folosirii într-un dosar

${config.pendingHumanValidation.map((item) => `- ${item}`).join("\n")}

Aceste puncte nu blochează publicarea metodologiei și a coeficienților oficiali, dar blochează folosirea rezultatului drept verdict de eligibilitate ori substitut pentru tabelul Cererii de finanțare.
`;
}

function synchronize(html, config) {
  let next = html.replace(
    /<script\b[^>]*\bsrc=["']\/assets\/calculator-so-methodology\.js\?v=[^"']+["'][^>]*><\/script>\r?\n?/gu,
    ""
  );
  next = next.replace(/^[ \t]*<link\b[^>]*href=["']\/assets\/calculator-so-methodology\.css\?v=[^"']+["'][^>]*>\r?\n?/gmu, "");
  next = next.replace("</head>", `  <link rel="stylesheet" href="${STYLE_HREF}">\n</head>`);
  next = next.replace(/<body\b([^>]*)>/u, (tag, attributes) => /calculator-refresh-2026/u.test(attributes)
    ? tag
    : `<body${attributes.replace(/class=["']([^"']*)["']/u, (full, classes) => `class="${classes} calculator-refresh-2026"`)}>`);

  next = replaceManaged(
    next,
    INPUT_START,
    INPUT_END,
    renderInputHelp(config),
    /(?=<div class="calc-wrapper")/u,
    "punctul de inserare pentru ajutorul calculatorului"
  );

  next = replaceManaged(
    next,
    METHOD_START,
    METHOD_END,
    renderMethodology(config),
    /<!-- Thresholds Section -->[\s\S]*?(?=<!-- Interpretare si pregatirea dosarului -->)/u,
    "secțiunile legacy cu praguri și coeficienți"
  );

  const resultPattern = /<!-- Result -->[\s\S]*?<\/div>(?=<!-- P1_15_CONTEXTUAL_CTA_START -->)/u;
  if (!resultPattern.test(next)) throw new Error("Nu poate fi identificat rezultatul calculatorului.");
  next = next.replace(resultPattern, renderResult());

  const scriptPattern = /<script>\s*\/\/ (?:SO Values Database|P1\.20 — Formula existentă este păstrată; setul de date provine din lista AFIR SOC 2020\.)[\s\S]*?<\/script>(?=\s*<!-- P1_15_CONTEXTUAL_CTA_START -->)/u;
  if (!scriptPattern.test(next)) throw new Error("Nu poate fi identificat scriptul calculatorului.");
  next = next.replace(scriptPattern, renderCalculatorScript(config));

  next = next
    .replace(/<h3 id="calculator-culturi-title">[\s\S]*?<\/h3>/u, '<h3 id="calculator-culturi-title">Culturi de câmp</h3>')
    .replace(/<h3 id="calculator-legume-title">[\s\S]*?<\/h3>/u, '<h3 id="calculator-legume-title">Legume, pepeni și căpșuni</h3>')
    .replace(/<h3 id="calculator-fructe-title">[\s\S]*?<\/h3>/u, '<h3 id="calculator-fructe-title">Fructe și plantații</h3>')
    .replace(/<h3 id="calculator-animale-title">[\s\S]*?<\/h3>/u, '<h3 id="calculator-animale-title">Animale și familii de albine</h3>')
    .replace(/<th>SO\/ha \(EUR\)<\/th>/gu, '<th>Coeficient SOC (EUR/unitate)</th>')
    .replace(/<th>SO\/cap \(EUR\)<\/th>/gu, '<th>Coeficient SOC (EUR/unitate)</th>')
    .replace(/<th>Suprafață \(ha\)<\/th>/gu, '<th>Cantitate în unitatea oficială</th>')
    .replace(/<th>Număr capete<\/th>/gu, '<th>Cantitate în unitatea oficială</th>')
    .replace(/<button class="btn-add"/gu, '<button type="button" class="btn-add"')
    .replace(/<button class="btn-reset"/gu, '<button type="button" class="btn-reset"')
    .replace(
      /<p class="sec-sub">Selectează culturile și animalele existente și introdu suprafețele sau efectivele documentabile\.[\s\S]*?ghidul programului\.<\/p>/u,
      '<p class="sec-sub">Selectează categoriile documentabile și introdu cantitatea în unitatea oficială afișată. Calculatorul aplică coeficienții SOC 2020 și explică fiecare produs din sumă; totalul rămâne orientativ și se reconfirmă în tabelul Cererii de finanțare aplicabile.</p>'
    );

  next = next.replace("</body>", `<script src="${SCRIPT_SRC}" defer></script>\n</body>`);

  const calculatorPattern = /<!-- Calculator -->\s*<section\b[^>]*\bid=["']calculator["'][^>]*>[\s\S]*?<\/section>/u;
  const calculatorBlock = next.match(calculatorPattern)?.[0];
  if (!calculatorBlock) throw new Error("Nu poate fi mutat calculatorul imediat după banner.");
  next = next.replace(calculatorPattern, "");
  next = next.replace(/<\/header>\s*/u, `</header>\n${calculatorBlock.trim()}\n`);

  return next;
}

function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  validateConfig(config);
  const file = path.join(ROOT, config.file);
  const before = fs.readFileSync(file, "utf8");
  const after = synchronize(before, config);
  const report = renderReport(config);
  const reportBefore = fs.existsSync(REPORT_PATH) ? fs.readFileSync(REPORT_PATH, "utf8") : "";
  const changed = before !== after || reportBefore !== report;

  if (CHECK_ONLY) {
    if (changed) {
      console.error("Calculatorul SO sau raportul P1.20 nu este sincronizat.");
      process.exitCode = 1;
      return;
    }
    console.log("Calculator SO P1.20 sincronizat: metodă, coeficienți, UX și raport.");
    return;
  }

  if (before !== after) fs.writeFileSync(file, after, "utf8");
  if (reportBefore !== report) fs.writeFileSync(REPORT_PATH, report, "utf8");
  console.log(`Calculator SO P1.20 actualizat: ${config.coefficientGroups.reduce((sum, group) => sum + group.entries.length, 0)} categorii și ${config.examples.length} exemple.`);
}

if (require.main === module) main();

module.exports = { calculate, coefficientIndex, synchronize, validateConfig };
