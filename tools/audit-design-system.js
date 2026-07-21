"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_FILE = path.join(ROOT, "config", "design-system.json");
const CSS_FILE = path.join(ROOT, "assets", "design-system.css");
const REPORT_JSON = path.join(ROOT, "reports", "p1-07-contrast-audit-2026-07-21.json");
const REPORT_MD = path.join(ROOT, "reports", "p1-07-contrast-audit-2026-07-21.md");
const CHECK_ONLY = process.argv.includes("--check");
const NO_REPORT = process.argv.includes("--no-report");

const PILOT = [
  { route: "/", file: "index.html" },
  { route: "/contact", file: "contact/index.html" },
  { route: "/afir-autoconsum-agroalimentar", file: "afir-autoconsum-agroalimentar/index.html" }
];

const COMPONENTS = {
  header: "#navbar",
  hero: ".hero, .homepage-decision-hero",
  programCard: ".finantare-card",
  statusBadge: ".finantare-badge, .program-factual-status",
  table: "table",
  accordion: "details",
  form: "form",
  cta: ".btn, .btn-primary, .btn-secondary, .btn-cta",
  breadcrumb: ".breadcrumb",
  carousel: ".carousel, [data-carousel], .program-carousel",
  footer: ".footer, footer",
  stickyCta: ".sticky-cta, [data-sticky-cta]"
};

function hexToRgb(hex) {
  const normalized = hex.replace("#", "");
  const value = normalized.length === 3
    ? normalized.split("").map((part) => part + part).join("")
    : normalized;
  return [0, 2, 4].map((offset) => Number.parseInt(value.slice(offset, offset + 2), 16));
}

function luminance(hex) {
  const channels = hexToRgb(hex).map((channel) => {
    const value = channel / 255;
    return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4;
  });
  return .2126 * channels[0] + .7152 * channels[1] + .0722 * channels[2];
}

function contrastRatio(foreground, background) {
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
}

function audit() {
  const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
  const css = fs.readFileSync(CSS_FILE, "utf8");
  const contrast = config.contrastChecks.map((item) => {
    const ratio = contrastRatio(config.colors[item.foreground], config.colors[item.background]);
    return { ...item, ratio: Number(ratio.toFixed(2)), pass: ratio >= item.minimum };
  });

  const pages = PILOT.map(({ route, file }) => {
    const html = fs.readFileSync(path.join(ROOT, file), "utf8");
    const $ = cheerio.load(html, { decodeEntities: false });
    const components = Object.fromEntries(Object.entries(COMPONENTS).map(([name, selector]) => [name, $(selector).length]));
    return {
      route,
      file,
      scoped: $("body").attr("data-design-system") === "p1_07",
      stylesheet: $('link[data-design-system-stylesheet="p1_07"]').attr("href") || null,
      components
    };
  });

  const contract = {
    scopedCss: /body\[data-design-system="p1_07"\]/.test(css),
    body17px: /font-size:\s*17px/.test(css),
    lineHeight: /line-height:\s*1\.65/.test(css),
    measure68ch: /--ds-container-text:\s*68ch/.test(css),
    responsiveHeadings: /font-size:\s*clamp\(/.test(css),
    focusVisible: /:focus-visible/.test(css),
    reducedMotion: /prefers-reduced-motion:\s*reduce/.test(css),
    mobileTarget44: /min-height:\s*44px/.test(css),
    loading: /aria-busy/.test(css) && /ds-spin/.test(css),
    error: /aria-invalid/.test(css) && /--ds-color-error/.test(css),
    statusSymbols: ["●", "◐", "○"].every((symbol) => css.includes(symbol)),
    stickyCtaContract: /data-sticky-cta/.test(css)
  };

  const failures = [
    ...contrast.filter((item) => !item.pass).map((item) => `Contrast ${item.foreground}/${item.background}`),
    ...pages.filter((page) => !page.scoped || !page.stylesheet).map((page) => `Pilot nesincronizat ${page.route}`),
    ...Object.entries(contract).filter(([, pass]) => !pass).map(([name]) => `Contract CSS ${name}`)
  ];

  return {
    generatedAt: "2026-07-21",
    version: config.version,
    result: failures.length ? "FAIL" : "PASS",
    contrast,
    pages,
    contract,
    componentNote: "stickyCta este definit în contract, dar nu este injectat deoarece lipsește din pilot; carousel apare numai pe homepage.",
    failures
  };
}

function renderMarkdown(report) {
  const contrastRows = report.contrast.map((item) => `| ${item.use} | ${item.foreground} / ${item.background} | ${item.ratio}:1 | ${item.minimum}:1 | ${item.pass ? "PASS" : "FAIL"} |`).join("\n");
  const pageRows = report.pages.map((page) => {
    const present = Object.entries(page.components).filter(([, count]) => count > 0).map(([name]) => name).join(", ");
    return `| ${page.route} | ${page.scoped && page.stylesheet ? "PASS" : "FAIL"} | ${present || "—"} |`;
  }).join("\n");
  return `# P1.07 — Raport de contrast și acoperire\n\nRezultat: **${report.result}**  \nVersiune: \`${report.version}\`  \nData auditului: ${report.generatedAt}\n\n## Contrast WCAG\n\n| Utilizare | Pereche | Raport | Prag | Rezultat |\n|---|---|---:|---:|---|\n${contrastRows}\n\n## Pilot și componente detectate\n\n| URL | Contract vizual | Componente prezente |\n|---|---|---|\n${pageRows}\n\n${report.componentNote}\n\n## Contract automat\n\n${Object.entries(report.contract).map(([name, pass]) => `- ${pass ? "PASS" : "FAIL"}: ${name}`).join("\n")}\n`;
}

function main() {
  const report = audit();
  if (!NO_REPORT) {
    fs.mkdirSync(path.dirname(REPORT_JSON), { recursive: true });
    fs.writeFileSync(REPORT_JSON, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    fs.writeFileSync(REPORT_MD, renderMarkdown(report), "utf8");
  }
  if (report.result !== "PASS") throw new Error(`Design system audit FAIL: ${report.failures.join("; ")}`);
  console.log(`Design system audit PASS: ${report.contrast.length} perechi de contrast, ${report.pages.length} rute pilot.`);
  if (CHECK_ONLY && !NO_REPORT) console.log("Rapoartele au fost regenerate în modul check.");
}

if (require.main === module) main();

module.exports = { audit, contrastRatio, renderMarkdown };
