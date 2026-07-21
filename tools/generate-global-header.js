#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "main-navigation.json");
const PARTIAL_PATH = path.join(ROOT, "partials", "global-header.html");
const REPORT_PATH = path.join(ROOT, "reports", "main-navigation-sitemap-2026-07-21.md");
const ASSET_VERSION = "20260721-1";

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function analyticsAttributes(item, component, groupId) {
  return `data-analytics-event="nav_click" data-analytics-component="${component}" data-analytics-cta-id="nav_${groupId}_${item.href.replace(/[^a-z0-9]+/giu, "_").replace(/^_|_$/gu, "")}" data-analytics-target="${escapeHtml(item.href)}"`;
}

function desktopGroup(group) {
  const triggerId = `nav-${group.id}-trigger`;
  const panelId = group.id === "programe" ? "dropdownPanel" : `nav-${group.id}-panel`;
  const buttonId = group.id === "programe" ? "dropdownBtn" : triggerId;
  const items = group.items.map((item) => `          <li><a href="${escapeHtml(item.href)}" class="dropdown-item" ${analyticsAttributes(item, "desktop_nav", group.id)}>${escapeHtml(item.label)}</a></li>`).join("\n");
  return `      <div class="nav-dropdown" data-nav-disclosure data-nav-group="${group.id}">
        <button class="nav-dropdown-btn" type="button" id="${buttonId}" aria-expanded="false" aria-controls="${panelId}" ${group.id === "programe" ? 'data-nav-trigger-id="nav-programe-trigger"' : ""} data-analytics-event="${group.id === "programe" ? "program_menu_click" : "nav_click"}" data-analytics-component="desktop_nav_disclosure" data-analytics-cta-id="nav_${group.id}_toggle">
          ${escapeHtml(group.label)} <span class="arrow" aria-hidden="true"></span>
        </button>
        <div class="nav-dropdown-panel" id="${panelId}" aria-labelledby="${buttonId}" hidden>
          <p class="dropdown-header">${escapeHtml(group.label)}</p>
          <ul class="nav-submenu-list">
${items}
          </ul>
        </div>
      </div>`;
}

function mobileGroup(group) {
  const triggerId = `mobile-${group.id}-trigger`;
  const panelId = `mobile-${group.id}-panel`;
  const items = group.items.map((item) => `            <li><a href="${escapeHtml(item.href)}" ${analyticsAttributes(item, "mobile_nav", group.id)}>${escapeHtml(item.label)}</a></li>`).join("\n");
  return `      <section class="mobile-disclosure" data-mobile-disclosure data-nav-group="${group.id}">
        <button class="mobile-disclosure-btn" type="button" id="${triggerId}" aria-expanded="false" aria-controls="${panelId}" data-analytics-event="${group.id === "programe" ? "program_menu_click" : "nav_click"}" data-analytics-component="mobile_nav_disclosure" data-analytics-cta-id="nav_${group.id}_toggle_mobile">
          ${escapeHtml(group.label)} <span class="arrow" aria-hidden="true"></span>
        </button>
        <div class="mobile-disclosure-panel" id="${panelId}" aria-labelledby="${triggerId}" hidden>
          <ul>
${items}
          </ul>
        </div>
      </section>`;
}

function logo() {
  return `<a class="nav-logo" href="/" aria-label="FABER – Atelier de Consultanță, acasă" data-analytics-event="nav_click" data-analytics-component="desktop_nav" data-analytics-cta-id="home_logo" data-analytics-target="/">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 44" width="240" height="44" aria-hidden="true">
        <text x="0" y="32" font-family="Georgia,'Times New Roman',serif" font-size="28" font-weight="700" fill="#b84716" letter-spacing="3">FABER</text>
        <path d="M118,22 L125,13 L132,22 L125,31 Z" fill="white" opacity="0.95"></path>
        <text x="138" y="18" font-family="'Inter','Helvetica Neue',sans-serif" font-size="10" font-weight="600" fill="white" letter-spacing="2">ATELIER de</text>
        <text x="138" y="33" font-family="'Inter','Helvetica Neue',sans-serif" font-size="10" font-weight="600" fill="white" letter-spacing="2">CONSULTANȚĂ</text>
      </svg>
    </a>`;
}

function whatsappDialog() {
  return `<div id="eligibility-whatsapp-dialog" class="eligibility-whatsapp-dialog" role="dialog" aria-modal="true" aria-labelledby="eligibility-whatsapp-title" hidden>
  <div class="eligibility-whatsapp-card" role="document">
    <button type="button" class="eligibility-whatsapp-close" data-whatsapp-dialog-close aria-label="Închide fereastra">×</button>
    <span class="eligibility-whatsapp-eyebrow">Contact rapid</span>
    <h2 id="eligibility-whatsapp-title">Trimite mesaj prin WhatsApp</h2>
    <p>Alege numărul la care dorești să trimiți mesajul.</p>
    <div class="eligibility-whatsapp-options">
      <a href="https://wa.me/40769828338" target="_blank" rel="noopener noreferrer" data-analytics-event="contact_whatsapp" data-analytics-component="whatsapp_dialog" data-analytics-cta-id="whatsapp_option_a"><span>WhatsApp</span><strong>0769 828 338</strong></a>
      <a href="https://wa.me/40753326229" target="_blank" rel="noopener noreferrer" data-analytics-event="contact_whatsapp" data-analytics-component="whatsapp_dialog" data-analytics-cta-id="whatsapp_option_b"><span>WhatsApp</span><strong>0753 326 229</strong></a>
    </div>
  </div>
</div>`;
}

function renderHeader(config = loadConfig()) {
  const groups = config.primaryDestinations.filter((item) => Array.isArray(item.items));
  const contact = config.primaryDestinations.find((item) => item.id === "contact");
  const cta = config.cta;
  return `<!-- GLOBAL_HEADER_START --><link rel="stylesheet" href="/assets/global-header.css?v=${ASSET_VERSION}">
<nav id="navbar" aria-label="Navigare principală" data-navigation-config="config/main-navigation.json">
  <div class="nav-container">
    ${logo()}
    <div class="nav-links" data-desktop-navigation>
${groups.map(desktopGroup).join("\n")}
      <a href="${escapeHtml(contact.href)}" class="nav-primary-link" data-nav-destination="contact" ${analyticsAttributes(contact, "desktop_nav", "contact")}>${escapeHtml(contact.label)}</a>
      <a href="${escapeHtml(cta.href)}" class="nav-cta" data-analytics-event="cta_click" data-analytics-component="desktop_nav" data-analytics-cta-id="${escapeHtml(cta.analyticsId)}_desktop" data-analytics-target="${escapeHtml(cta.href)}" data-analytics-cta-view="true" data-analytics-copy-variant="p1_02">${escapeHtml(cta.label)}</a>
    </div>
    <div class="nav-mobile-actions">
      <a href="${escapeHtml(cta.href)}" class="nav-compact-cta" aria-label="${escapeHtml(cta.label)}" data-analytics-event="cta_click" data-analytics-component="mobile_header" data-analytics-cta-id="${escapeHtml(cta.analyticsId)}_compact" data-analytics-target="${escapeHtml(cta.href)}" data-analytics-cta-view="true" data-analytics-copy-variant="p1_02_compact"><span>${escapeHtml(cta.compactLabel)}</span></a>
      <button class="hamburger" id="hamburgerBtn" type="button" aria-label="Deschide meniul" aria-expanded="false" aria-controls="mobileMenu" data-analytics-event="nav_click" data-analytics-component="mobile_menu_toggle" data-analytics-cta-id="mobile_menu_toggle"><span></span><span></span><span></span></button>
    </div>
  </div>
</nav>
<div id="mobileMenu" aria-label="Meniu principal mobil" hidden>
  <nav class="mobile-links" aria-label="Destinații principale">
${groups.map(mobileGroup).join("\n")}
    <a href="${escapeHtml(contact.href)}" class="mobile-contact" data-nav-destination="contact" ${analyticsAttributes(contact, "mobile_nav", "contact")}>${escapeHtml(contact.label)}</a>
    <a href="${escapeHtml(cta.href)}" class="mobile-cta" data-analytics-event="cta_click" data-analytics-component="mobile_nav" data-analytics-cta-id="${escapeHtml(cta.analyticsId)}_mobile" data-analytics-target="${escapeHtml(cta.href)}" data-analytics-cta-view="true" data-analytics-copy-variant="p1_02">${escapeHtml(cta.label)}</a>
  </nav>
</div>
${whatsappDialog()}
<div class="global-header-spacer" aria-hidden="true"></div>
<script src="/assets/global-header.js?v=${ASSET_VERSION}"></script>
<!-- GLOBAL_HEADER_END -->`;
}

function renderReport(config = loadConfig()) {
  const rows = config.primaryDestinations.map((destination) => {
    if (destination.href) return `| ${destination.label} | \`${destination.href}\` | direct |`;
    return destination.items.map((item) => `| ${destination.label} | ${item.label} → \`${item.href}\` | disclosure |`).join("\n");
  }).join("\n");
  return `# P1.02 — Sitemap de navigare

Configurație canonică: \`config/main-navigation.json\`

Breakpoint desktop: **${config.desktopBreakpoint}px**
CTA separat: **${config.cta.label}** → \`${config.cta.href}\`

| Destinație principală | Destinație secundară / URL | Interacțiune |
|---|---|---|
${rows}

` + "```mermaid\ngraph TD\n  NAV[\"Navigare principală\"] --> S[\"Servicii\"]\n  NAV --> P[\"Programe\"]\n  NAV --> I[\"Instrumente\"]\n  NAV --> G[\"Ghiduri\"]\n  NAV --> D[\"Despre FABER\"]\n  NAV --> C[\"Contact\"]\n  NAV -. CTA separat .-> V[\"Începe verificarea proiectului\"]\n```\n" + `
## Reguli

- Desktop: cinci disclosure-uri semantice, Contact direct și CTA separat.
- Mobil: butoane disclosure reale cu \`aria-expanded\`; linkurile nu deschid accidental grupurile.
- Maximum ${config.policy.maxVisibleItemsPerGroup} linkuri vizibile în fiecare grup.
- Navigarea nu conține statusuri, etichete de status, date de verificare sau valori de program.
- URL-urile canonice nu sunt schimbate de această configurație.
`;
}

function run({ check = false } = {}) {
  const config = loadConfig();
  const outputs = new Map([[PARTIAL_PATH, `${renderHeader(config)}\n`], [REPORT_PATH, renderReport(config)]]);
  const stale = [];
  for (const [file, content] of outputs) {
    if (check) {
      if (!fs.existsSync(file) || fs.readFileSync(file, "utf8") !== content) stale.push(path.relative(ROOT, file));
    } else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, content, "utf8");
    }
  }
  if (stale.length) throw new Error(`Headerul generat este expirat: ${stale.join(", ")}`);
  console.log(`${check ? "PASS" : "GENERATED"}: 6 destinații principale, ${config.primaryDestinations.filter((item) => item.items).reduce((sum, item) => sum + item.items.length, 0)} linkuri secundare, CTA separat.`);
}

if (require.main === module) {
  try {
    run({ check: process.argv.includes("--check") });
  } catch (error) {
    console.error(`FAIL: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { ASSET_VERSION, CONFIG_PATH, PARTIAL_PATH, loadConfig, renderHeader, renderReport, run };
