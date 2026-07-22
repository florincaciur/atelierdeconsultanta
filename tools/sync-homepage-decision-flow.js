"use strict";

const fs = require("fs");
const path = require("path");
const { loadProgramConfig } = require("./program-factual-governance");
const { renderPriorityCarousel } = require("./sync-homepage-programs");

const ROOT = path.resolve(__dirname, "..");
const HOME = path.join(ROOT, "index.html");
const CONFIG = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "homepage-decision-flow.json"), "utf8"));
const BANNERS = JSON.parse(fs.readFileSync(path.join(ROOT, "banners.json"), "utf8"));
const CHECK_ONLY = process.argv.includes("--check");
const HERO_END = "<!-- HOMEPAGE_DECISION_HERO_END -->";
const START = "<!-- P1_21_HOMEPAGE_FLOW_START -->";
const END = "<!-- P1_21_HOMEPAGE_FLOW_END -->";
const STYLE = '<link rel="stylesheet" href="/assets/homepage-decision-flow.css?v=20260722-1" data-homepage-decision-flow-style="p1_21">';

function esc(value) {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function heading(eyebrow, id, title, text) {
  return `<header class="homepage-flow-heading"><span class="homepage-eyebrow">${esc(eyebrow)}</span><h2 id="${esc(id)}">${esc(title)}</h2><p>${esc(text)}</p></header>`;
}

function renderMethod() {
  const steps = CONFIG.methodSteps.map((step) => `<li class="homepage-method-step"><span class="homepage-method-number">${esc(step.number)}</span><strong>${esc(step.title)}</strong><p>${esc(step.text)}</p></li>`).join("\n");
  return `<section id="homepage-method" class="homepage-flow-section" aria-labelledby="homepage-method-title"><div class="homepage-flow-inner">${heading("Metoda FABER", "homepage-method-title", "Cum decidem dacă merită continuat", "Cinci verificări, în ordinea în care pot schimba decizia și bugetul proiectului.")}<ol class="homepage-method-list">${steps}</ol></div></section>`;
}

function renderCardSection(id, eyebrow, title, text, items, gridClass) {
  const cards = items.map((item) => `<article class="homepage-card"><span class="homepage-eyebrow">${esc(item.kind || eyebrow)}</span><h3>${esc(item.title)}</h3><p>${esc(item.text)}</p><a href="${esc(item.href)}">${esc(item.label)}</a></article>`).join("\n");
  return `<section id="${id}" class="homepage-flow-section" aria-labelledby="${id}-title"><div class="homepage-flow-inner">${heading(eyebrow, `${id}-title`, title, text)}<div class="${gridClass}">${cards}</div></div></section>`;
}

function renderProofs() {
  const cards = CONFIG.proofs.map((item) => `<article class="homepage-proof-card"><h3>${esc(item.title)}</h3><p>${esc(item.text)}</p></article>`).join("\n");
  return `<section id="homepage-proof" class="homepage-flow-section" aria-labelledby="homepage-proof-title"><div class="homepage-flow-inner">${heading("De ce FABER", "homepage-proof-title", "Decizii documentate, cu limite explicite", "Trei principii verificabile în modul în care publicăm și analizăm informația.")}<div class="homepage-proof-grid">${cards}</div></div></section>`;
}

function renderAnalysis() {
  const item = CONFIG.recentAnalysis;
  return `<section id="homepage-analysis" class="homepage-flow-section" aria-labelledby="homepage-analysis-title"><div class="homepage-flow-inner"><article class="homepage-analysis-card"><div><span class="homepage-eyebrow">${esc(item.eyebrow)}</span><h2 id="homepage-analysis-title">${esc(item.title)}</h2><p>${esc(item.text)}</p></div><a class="homepage-flow-action" href="${esc(item.href)}">${esc(item.label)}</a></article></div></section>`;
}

function renderContact() {
  const item = CONFIG.contact;
  const phones = item.phones.map((phone, index) => `<a href="${esc(phone.href)}" data-analytics-event="contact_phone" data-analytics-component="homepage_final_contact" data-analytics-cta-id="homepage_phone_${index + 1}">${esc(phone.label)}</a>`).join("");
  return `<section id="homepage-contact" class="homepage-flow-section" aria-labelledby="homepage-contact-title"><div class="homepage-flow-inner"><div><span class="homepage-eyebrow">Următorul pas</span><h2 id="homepage-contact-title">${esc(item.title)}</h2><p>${esc(item.text)}</p><div class="homepage-contact-direct" aria-label="Contact direct">${phones}<a href="${esc(item.email.href)}" data-analytics-event="contact_email" data-analytics-component="homepage_final_contact" data-analytics-cta-id="homepage_email">${esc(item.email.label)}</a></div></div><div class="homepage-contact-actions"><a class="homepage-flow-action" href="${esc(item.primaryHref)}" data-analytics-event="cta_click" data-analytics-component="homepage_final_cta" data-analytics-cta-id="homepage_final_project_check" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_21">${esc(item.primaryLabel)}</a></div></div></section>`;
}

function renderFlow(programs) {
  const banners = new Map(BANNERS.map((banner) => [banner.programId, banner]));
  return `${START}\n${renderMethod()}\n${renderPriorityCarousel(programs, banners)}\n${renderCardSection("homepage-services", "Servicii", "De la verificare la implementare", "Patru roluri distincte, alese în funcție de stadiul proiectului.", CONFIG.services, "homepage-service-grid")}\n${renderCardSection("homepage-tools", "Instrumente și ghiduri", "Pregătește datele înainte de discuție", "Un instrument și două ghiduri pentru întrebările care apar înaintea dosarului.", CONFIG.tools, "homepage-tool-grid")}\n${renderProofs()}\n${renderAnalysis()}\n${renderContact()}\n${END}`;
}

function removeLegacyRuntime(source) {
  let output = source.replace(/\s*<div class="modal-overlay" id="modalOverlay"[\s\S]*?<\/div>\s*<\/div>\s*<\/div>/i, "");
  const removeBetweenLabels = (value, startLabel, endLabel) => {
    const startLabelIndex = value.indexOf(startLabel);
    const endLabelIndex = value.indexOf(endLabel, startLabelIndex + startLabel.length);
    if (startLabelIndex < 0 || endLabelIndex < 0) return value;
    const start = value.lastIndexOf("/*", startLabelIndex);
    const end = value.lastIndexOf("/*", endLabelIndex);
    return start >= 0 && end > start ? `${value.slice(0, start)}${value.slice(end)}` : value;
  };
  output = removeBetweenLabels(output, "CARD CAROUSELS", "BACK TO TOP");
  const heroLabel = output.indexOf("HERO PROGRAM SELECTOR");
  const heroStart = heroLabel >= 0 ? output.lastIndexOf("/*", heroLabel) : -1;
  const heroEnd = heroLabel >= 0 ? output.indexOf("console.log", heroLabel) : -1;
  if (heroStart >= 0 && heroEnd > heroStart) output = `${output.slice(0, heroStart)}${output.slice(heroEnd)}`;
  const newsletterStart = output.indexOf("async function handleNewsletterSubmit");
  if (newsletterStart >= 0) {
    const scriptEnd = output.indexOf("</script>", newsletterStart);
    if (scriptEnd > newsletterStart) output = `${output.slice(0, newsletterStart)}${output.slice(scriptEnd)}`;
  }
  const faqNeedle = "document.getElementById('homepage-faq-toggle')";
  const faqIndex = output.indexOf(faqNeedle);
  if (faqIndex >= 0) {
    const scriptStart = output.lastIndexOf("<script", faqIndex);
    const scriptEnd = output.indexOf("</script>", faqIndex);
    if (scriptStart >= 0 && scriptEnd > faqIndex) output = `${output.slice(0, scriptStart)}${output.slice(scriptEnd + 9)}`;
  }
  return output
    .replace("closeMobileMenu(); closeModal(); closeDropdown();", "closeMobileMenu(); closeDropdown();")
    .replace(/\r?\n[ \t]+\r?\n(?=<!-- P1_15_CONTEXTUAL_CTA_START -->)/, "\n\n");
}

function synchronize(source, programs) {
  if (!source.includes(HERO_END) || !/<\/main>/i.test(source)) throw new Error("Homepage-ul nu are limitele necesare pentru fluxul P1.21.");
  const toc = source.match(/<!-- P1_09_LONG_FORM_TOC_START -->[\s\S]*?<!-- P1_09_LONG_FORM_TOC_END -->/);
  const preservedToc = toc ? `\n${toc[0]}` : "";
  let output = source.replace(new RegExp(`${HERO_END}[\\s\\S]*?<\\/main>`, "i"), `${HERO_END}${preservedToc}\n${renderFlow(programs)}\n  </main>`);
  output = output
    .replace(/\s*<style id="homepage-faq-expand-css">[\s\S]*?<\/style>/gi, "")
    .replace(/\s*<script>\s*\/\* Homepage FAQ progressive disclosure[\s\S]*?<\/script>/gi, "");
  const managedStyles = output.match(/<link\b[^>]*data-homepage-decision-flow-style=["']p1_21["'][^>]*>/gi) || [];
  if (managedStyles.length !== 1) {
    output = output.replace(/\s*<link\b[^>]*data-homepage-decision-flow-style=["']p1_21["'][^>]*>/gi, "");
    output = output.replace(/<\/head>/i, `  ${STYLE}\n</head>`);
  }
  return removeLegacyRuntime(output);
}

function main() {
  const { programs } = loadProgramConfig();
  const before = fs.readFileSync(HOME, "utf8");
  const after = synchronize(before, programs);
  if (CHECK_ONLY) {
    if (after !== before) throw new Error("Homepage-ul P1.21 nu este sincronizat. Rulează npm run sync:homepage-decision-flow.");
    console.log("Homepage decision flow sync PASS.");
    return;
  }
  if (after !== before) fs.writeFileSync(HOME, after, "utf8");
  console.log("Homepage P1.21 sincronizat: un singur traseu, zero formulare inline, un carusel.");
}

if (require.main === module) main();

module.exports = { renderFlow, synchronize };
