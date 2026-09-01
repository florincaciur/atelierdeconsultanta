"use strict";

const fs = require("fs");
const path = require("path");
const { renderProgramScenes } = require("./hero-program-scenes");
const { immersiveHero, renderImmersiveControls } = require("./immersive-home-template");
const {
  hasOfficialSource,
  homepageHeroPrograms,
  isPublicProgram,
  loadProgramConfig
} = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const HOME = path.join(ROOT, "index.html");
const STYLE_FILE = path.join(ROOT, "assets", "homepage-hero.css");
const CHECK_ONLY = process.argv.includes("--check");
const START = "<!-- HOMEPAGE_DECISION_HERO_START -->";
const END = "<!-- HOMEPAGE_DECISION_HERO_END -->";
const STYLE_ID = "homepage-hero-critical-css";
const MONTHS = ["ianuarie", "februarie", "martie", "aprilie", "mai", "iunie", "iulie", "august", "septembrie", "octombrie", "noiembrie", "decembrie"];
const HERO_STATUS_PRIORITY = {
  apel_deschis: 0,
  ghid_aprobat_nedeschis: 1,
  consultare_publica: 2,
  calendar_estimativ: 3,
  apel_inchis: 4,
  arhivat: 5
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDateRo(value) {
  const [year, month, day] = String(value).split("-").map(Number);
  return `${day} ${MONTHS[month - 1]} ${year}`;
}

function latestVerifiedProgram(programs) {
  return programs
    .filter((program) => isPublicProgram(program) && hasOfficialSource(program))
    .sort((left, right) => (
      (HERO_STATUS_PRIORITY[left.status] ?? 99) - (HERO_STATUS_PRIORITY[right.status] ?? 99)
      || right.verifiedAt.localeCompare(left.verifiedAt)
      || String(right.lastMeaningfulUpdate || "").localeCompare(String(left.lastMeaningfulUpdate || ""))
      || left.slug.localeCompare(right.slug, "ro")
    ))[0];
}

function renderProgramMenu(programs) {
  const featured = homepageHeroPrograms(programs);
  if (featured.some((item) => !item || !isPublicProgram(item) || !hasOfficialSource(item))) {
    throw new Error("Meniul interactiv din hero conține un program absent sau neverificat.");
  }
  const first = featured[0];
  const items = featured.map((item, index) => `              <li><a href="${escapeHtml(item.pageUrl)}" data-hero-program-item data-program-id="${escapeHtml(item.id)}" data-program-status="${escapeHtml(item.status)}" data-status-label="${escapeHtml(item.statusLabel)}" data-verified-at="${escapeHtml(item.verifiedAt)}" data-source-url="${escapeHtml(item.sourceUrl)}" data-title="${escapeHtml(item.shortName)}" data-status="${escapeHtml(item.statusLabel)}" data-analytics-event="program_card_click" data-analytics-component="homepage_hero_program_menu" data-analytics-cta-id="hero_program_${escapeHtml(item.slug)}" data-analytics-program-slug="${escapeHtml(item.slug)}" data-analytics-program-family="${escapeHtml(item.family)}"${index === 0 ? ' aria-current="true"' : ""}>${escapeHtml(item.shortName)}</a></li>`).join("\n");
  return `<div class="hero-programs" data-hero-programs aria-labelledby="hero-programs-title">
            <div class="hero-programs__heading"><h2 id="hero-programs-title">Măsuri de finanțare</h2><span data-hero-program-count>1 / ${featured.length}</span></div>
            ${renderProgramScenes(featured)}
            <div class="hero-program-spotlight" id="hero-program-spotlight" aria-live="polite" aria-atomic="true">
              <span data-hero-program-status>${escapeHtml(first.statusLabel)}</span>
              <strong data-hero-program-title>${escapeHtml(first.shortName)}</strong>
              <a href="${escapeHtml(first.pageUrl)}" data-hero-program-link>Vezi condițiile</a>
            </div>
            <p class="hero-program-instruction">Survolează o măsură sau selectează cu o atingere.</p>
            <ul class="hero-programs-list" aria-label="Alege o măsură de finanțare">
${items}
            </ul>
          </div>`;
}

function renderHero(program, publicCount, programs) {
  if (!program) throw new Error("Registrul nu conține niciun program public cu sursă oficială completă.");
  const hero = `${START}
    <!-- Măsurile provin din registrul public; ilustrațiile conceptuale se schimbă la hover, focus și atingere. -->
    <section id="hero" class="homepage-decision-hero" data-section-id="hero" aria-labelledby="homepage-hero-title" data-homepage-hero-version="p1_15" data-homepage-revision="immersive-20260901-5">
      <div class="homepage-hero__inner">
        <div class="homepage-hero__copy">
          <div class="hero-badge"><span class="dot" aria-hidden="true"></span>FABER pentru firme, fermieri, start-up-uri, IMM-uri și instituții publice</div>
          <h1 class="hero-title" id="homepage-hero-title">Consultanță și proiectare pentru proiecte <span class="gradient-text">cu fonduri europene</span></h1>
          <p class="hero-subtitle" data-aeo-primary-answer="" data-aeo-direct-answer="">FABER – Atelier de Consultanță sprijină firme, fermieri, start-up-uri, IMM-uri și instituții publice în proiecte cu fonduri europene. Consultanța clarifică eligibilitatea, programul, cererea și documentele; proiectarea corelează soluția tehnică, bugetul și anexele. Verificăm solicitantul, investiția și sursele oficiale înainte de dosar, apoi putem sprijini pregătirea și implementarea, fără promisiunea aprobării finanțării.</p>
          <div class="hero-ctas" aria-label="Acțiuni principale">
            <a href="/contact#source_page=%2F" class="btn-primary" data-contextual-hero-cta data-analytics-event="cta_click" data-analytics-component="homepage_hero" data-analytics-cta-id="homepage_hero_project_check" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_15">Începe verificarea proiectului</a>
            <a href="/verificare-eligibilitate-fonduri-europene" class="btn-secondary" data-analytics-event="cta_click" data-analytics-component="homepage_hero" data-analytics-cta-id="homepage_hero_prepare" data-analytics-target="/verificare-eligibilitate-fonduri-europene" data-analytics-cta-view="true" data-analytics-copy-variant="p1_15">Vezi ce date pregătești</a>
          </div>
        </div>

        <aside class="homepage-hero__panel hero-flow" aria-label="Măsuri de finanțare" data-homepage-hero-latest-program data-program-id="${escapeHtml(program.id)}" data-program-status="${escapeHtml(program.status)}" data-status-label="${escapeHtml(program.statusLabel)}" data-verified-at="${escapeHtml(program.verifiedAt)}" data-source-url="${escapeHtml(program.sourceUrl)}" data-public-program-count="${publicCount}">
          ${renderProgramMenu(programs)}
        </aside>
      </div>
    </section>
${END}`;
  return immersiveHero(hero);
}

function keepManagedBlockLast(html, startMarker, endMarker, closingTag) {
  const blockPattern = new RegExp(
    `\\s*(<!--\\s*${startMarker}\\s*-->[\\s\\S]*?<!--\\s*${endMarker}\\s*-->)\\s*`,
    "iu"
  );
  const match = html.match(blockPattern);
  if (!match) return html;
  const withoutBlock = html.replace(blockPattern, "\n");
  return withoutBlock.replace(
    new RegExp(`\\s*</${closingTag}>`, "iu"),
    `\n${match[1].trim()}\n</${closingTag}>`
  );
}

function syncHomepageHero(source, programs) {
  const latest = latestVerifiedProgram(programs);
  const publicCount = programs.filter(isPublicProgram).length;
  const hero = renderHero(latest, publicCount, programs);
  const marked = new RegExp(`${START}[\\s\\S]*?${END}`);
  let output = marked.test(source)
    ? source.replace(marked, hero)
    : source.replace(/<!-- ✦ HERO ✦ -->[\s\S]*?<\/section>/, hero);
  if (output === source && !marked.test(source)) throw new Error("Nu am găsit hero-ul homepage pentru sincronizare.");
  const criticalCss = fs.readFileSync(STYLE_FILE, "utf8").trim();
  output = output
    .replace(/\s*<link rel="stylesheet" href="\/assets\/homepage-hero\.css[^>]*>/g, "")
    .replace(/\s*<script\b[^>]*data-homepage-hero-script[^>]*><\/script>/gi, "")
    .replace(new RegExp(`\\s*<style id="${STYLE_ID}">[\\s\\S]*?<\\/style>`), "");
  // Keep the managed block left-aligned. Other homepage generators normalize
  // head assets to this form, so a later --check must not oscillate on two
  // insignificant spaces before the opening tag.
  const criticalMarkup = `<style id="${STYLE_ID}">\n${criticalCss}\n  </style>\n`;
  const runtimeMarkup = '  <script src="/assets/homepage-hero.js?v=20260901-5" defer data-homepage-hero-script="p1_21"></script>\n';
  output = /<style id="homepage-faq-expand-css">/.test(output)
    ? output.replace(/(<style id="homepage-faq-expand-css">)/, `${criticalMarkup}  $1`)
    : output.replace(/<\/head>/i, `${criticalMarkup}</head>`);
  output = output.replace(/<\/head>/i, `${runtimeMarkup}</head>`);
  output = output.replace(/\s*<link\b[^>]*data-immersive-style[^>]*>/gi, "")
    .replace(/\s*<script\b[^>]*data-immersive-script[^>]*><\/script>/gi, "")
    .replace(/<!-- IMMERSIVE_CONTROLS_START -->[\s\S]*?<!-- IMMERSIVE_CONTROLS_END -->\r?\n?/g, "")
    .replace(/<\/head>/i, '  <link rel="stylesheet" href="/assets/immersive-home.css?v=20260901-5" data-immersive-style>\n  <script src="/assets/immersive-home.js?v=20260901-5" defer data-immersive-script></script>\n</head>')
    .replace(/<\/body>/i, `<!-- IMMERSIVE_CONTROLS_START -->${renderImmersiveControls()}<!-- IMMERSIVE_CONTROLS_END -->\n</body>`);
  // The global immersive layer owns the final head/body slots. Keeping its
  // managed blocks last makes both generators converge in either run order.
  output = keepManagedBlockLast(output, "SITE_IMMERSIVE_HEAD_START", "SITE_IMMERSIVE_HEAD_END", "head");
  output = keepManagedBlockLast(output, "SITE_IMMERSIVE_SCRIPT_START", "SITE_IMMERSIVE_SCRIPT_END", "body");
  return output;
}

function sameText(left, right) {
  return left.replace(/\r\n/g, "\n") === right.replace(/\r\n/g, "\n");
}

function main() {
  const { programs } = loadProgramConfig();
  const before = fs.readFileSync(HOME, "utf8");
  const after = syncHomepageHero(before, programs);
  if (CHECK_ONLY) {
    if (!sameText(after, before)) throw new Error("Hero-ul homepage nu este sincronizat. Rulează npm run sync:homepage-hero.");
    console.log("Homepage hero sync PASS.");
    return;
  }
  if (!sameText(after, before)) fs.writeFileSync(HOME, after, "utf8");
  const latest = latestVerifiedProgram(programs);
  console.log(`Homepage hero sincronizat: ${latest.slug}, verificat la ${latest.verifiedAt}.`);
}

if (require.main === module) main();

module.exports = { formatDateRo, latestVerifiedProgram, renderHero, syncHomepageHero };
