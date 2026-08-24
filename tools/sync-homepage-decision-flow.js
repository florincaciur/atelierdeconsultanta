"use strict";

const fs = require("fs");
const path = require("path");
const { loadProgramConfig } = require("./program-factual-governance");
const { renderPriorityCarousel } = require("./sync-homepage-programs");

const ROOT = path.resolve(__dirname, "..");
const HOME = path.join(ROOT, "index.html");
const CONFIG = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "homepage-decision-flow.json"), "utf8"));
const CHECK_ONLY = process.argv.includes("--check");
const HERO_END = "<!-- HOMEPAGE_DECISION_HERO_END -->";
const START = "<!-- P1_21_HOMEPAGE_FLOW_START -->";
const END = "<!-- P1_21_HOMEPAGE_FLOW_END -->";
const STYLE = '<link rel="stylesheet" href="/assets/homepage-decision-flow.css?v=20260722-2" data-homepage-decision-flow-style="p1_22">';
const SCRIPT = '<script src="/assets/homepage-decision-flow.js?v=20260722-2" defer data-homepage-decision-flow-script="p1_22"></script>';

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

function renderMethodExperience() {
  const tabs = CONFIG.methodSteps.map((step, index) => `<button type="button" role="tab" id="homepage-method-tab-${index + 1}" aria-controls="homepage-method-frame-${index + 1}" aria-selected="${index === 0 ? "true" : "false"}"${index === 0 ? "" : ' tabindex="-1"'} data-homepage-method-tab data-method-index="${index}"><span>${esc(step.number)}</span><strong>${esc(step.title)}</strong></button>`).join("\n");
  const frames = CONFIG.methodSteps.map((step, index) => `<div class="homepage-method-frame${index === 0 ? " is-active" : ""}" id="homepage-method-frame-${index + 1}" role="tabpanel" aria-labelledby="homepage-method-tab-${index + 1}" data-homepage-method-frame data-method-index="${index}">
  <span class="homepage-method-frame__number">${esc(step.number)}</span>
  <div><h3>${esc(step.title)}</h3><p>${esc(step.text)}</p></div>
</div>`).join("\n");
  const nodes = CONFIG.methodSteps.map((step, index) => `<g class="homepage-method-node${index === 0 ? " is-active" : ""}" data-homepage-method-node data-method-index="${index}" transform="translate(${50 + index * 135} 70)"><circle r="18"></circle><text text-anchor="middle" dy="5">${index + 1}</text><title>${esc(step.title)}</title></g>`).join("\n");
  return `<section id="homepage-method" class="homepage-flow-section homepage-method" aria-labelledby="homepage-method-title" data-homepage-method>
  <div class="homepage-flow-inner homepage-method-layout">
    ${heading("Metoda FABER", "homepage-method-title", "Cum decidem dacă merită continuat", "Cinci verificări, într-o singură secvență. Alege etapa sau glisează pentru a vedea următorul filtru de decizie.")}
    <div class="homepage-method-experience">
      <svg class="homepage-method-svg" viewBox="0 0 640 140" aria-hidden="true" focusable="false">
        <path class="homepage-method-route" d="M50 70 C105 24 130 24 185 70 S265 116 320 70 S400 24 455 70 S535 116 590 70"></path>
        ${nodes}
        <g class="homepage-method-marker" data-homepage-method-marker><circle r="10"></circle><circle class="homepage-method-marker__pulse" r="18"></circle></g>
      </svg>
      <div class="homepage-method-frames" tabindex="0" aria-label="Etapele metodei FABER" data-homepage-method-viewport>${frames}</div>
      <div class="homepage-method-controls">
        <button type="button" class="homepage-sequence-arrow" aria-label="Etapa anterioară" data-homepage-method-previous><span aria-hidden="true">←</span></button>
        <div class="homepage-method-tabs" role="tablist" aria-label="Alege etapa metodei">${tabs}</div>
        <button type="button" class="homepage-sequence-arrow" aria-label="Etapa următoare" data-homepage-method-next><span aria-hidden="true">→</span></button>
      </div>
      <p class="homepage-sequence-status" role="status" aria-live="polite" aria-atomic="true" data-homepage-method-status>Etapa 1 din ${CONFIG.methodSteps.length}: ${esc(CONFIG.methodSteps[0].title)}</p>
    </div>
  </div>
</section>`;
}

function renderExplorerCard(item, eyebrow, index) {
  const link = item.href ? `<a href="${esc(item.href)}">${esc(item.label)}</a>` : "";
  return `<article class="homepage-card"><span class="homepage-eyebrow">${esc(item.kind || eyebrow)}</span><span class="homepage-card-index" aria-hidden="true">0${index + 1}</span><h4>${esc(item.title)}</h4><p>${esc(item.text)}</p>${link}</article>`;
}

function renderExplorer() {
  const frames = [
    {
      id: "homepage-services",
      label: "Servicii",
      eyebrow: "Servicii",
      title: "Patru servicii, roluri distincte",
      text: "Alege analiza, consultanța, proiectarea sau implementarea potrivită stadiului proiectului.",
      content: `<div class="homepage-service-grid">${CONFIG.services.map((item, index) => renderExplorerCard(item, "Serviciu", index)).join("\n")}</div>`
    },
    {
      id: "homepage-tools",
      label: "Instrumente",
      eyebrow: "Instrumente și ghiduri",
      title: "Pregătește datele înainte de discuție",
      text: "Folosește un instrument și două ghiduri pentru întrebările care apar înaintea dosarului.",
      content: `<div class="homepage-tool-grid">${CONFIG.tools.map((item, index) => renderExplorerCard(item, item.kind || "Resursă", index)).join("\n")}</div>`
    },
    {
      id: "homepage-proof",
      label: "De ce FABER",
      eyebrow: "De ce FABER",
      title: "Metodologie și surse, nu promisiuni",
      text: "Află cine este FABER, cum verificăm statutul programelor și care sunt limitele analizei.",
      content: `<div class="homepage-proof-grid">${CONFIG.proofs.map((item, index) => renderExplorerCard(item, "Principiu", index)).join("\n")}</div>`
    },
    {
      id: "homepage-analysis",
      label: "Comparație",
      eyebrow: CONFIG.recentAnalysis.eyebrow,
      title: CONFIG.recentAnalysis.title,
      text: CONFIG.recentAnalysis.text,
      content: `<a class="homepage-flow-action" href="${esc(CONFIG.recentAnalysis.href)}">${esc(CONFIG.recentAnalysis.label)}</a>`
    }
  ];
  const tabs = frames.map((frame, index) => `<button type="button" role="tab" id="homepage-explorer-tab-${index + 1}" aria-controls="${frame.id}" aria-selected="${index === 0 ? "true" : "false"}"${index === 0 ? "" : ' tabindex="-1"'} data-homepage-explorer-tab data-explorer-index="${index}"><span>0${index + 1}</span>${esc(frame.label)}</button>`).join("\n");
  const panels = frames.map((frame, index) => `<div class="homepage-explorer-frame${index === 0 ? " is-active" : ""}" id="${frame.id}" role="tabpanel" aria-labelledby="homepage-explorer-tab-${index + 1}" data-homepage-explorer-frame data-explorer-index="${index}">
  <header><span class="homepage-eyebrow">${esc(frame.eyebrow)}</span><h3>${esc(frame.title)}</h3><p>${esc(frame.text)}</p></header>
  ${frame.content}
</div>`).join("\n");
  const nodes = frames.map((frame, index) => `<g class="homepage-explorer-node${index === 0 ? " is-active" : ""}" data-homepage-explorer-node data-explorer-index="${index}" transform="translate(${70 + index * 160} 58)"><circle r="17"></circle><text text-anchor="middle" dy="5">${index + 1}</text><title>${esc(frame.label)}</title></g>`).join("\n");
  return `<section id="homepage-explorer" class="homepage-flow-section homepage-explorer" aria-labelledby="homepage-explorer-title" data-homepage-explorer>
  <div class="homepage-flow-inner">
    ${heading("Servicii, instrumente și verificare", "homepage-explorer-title", "Ce oferă FABER și cum verifică informația", "Vezi serviciile, instrumentele de pregătire, metodologia și o comparație de programe într-un singur cadru interactiv.")}
    <div class="homepage-explorer-shell">
      <div class="homepage-explorer-tabs" role="tablist" aria-label="Alege secțiunea">${tabs}</div>
      <svg class="homepage-explorer-svg" viewBox="0 0 620 110" aria-hidden="true" focusable="false">
        <path d="M70 58 C130 10 170 106 230 58 S330 10 390 58 S490 106 550 58"></path>
        ${nodes}
        <g class="homepage-explorer-marker" data-homepage-explorer-marker><circle r="9"></circle><circle class="homepage-explorer-marker__pulse" r="17"></circle></g>
      </svg>
      <div class="homepage-explorer-viewport" tabindex="0" aria-label="Conținut selectat" data-homepage-explorer-viewport>${panels}</div>
      <div class="homepage-explorer-controls">
        <button type="button" class="homepage-sequence-arrow" aria-label="Secțiunea anterioară" data-homepage-explorer-previous><span aria-hidden="true">←</span></button>
        <p class="homepage-sequence-status" role="status" aria-live="polite" aria-atomic="true" data-homepage-explorer-status>Secțiunea 1 din ${frames.length}: ${esc(frames[0].label)}</p>
        <button type="button" class="homepage-sequence-arrow" aria-label="Secțiunea următoare" data-homepage-explorer-next><span aria-hidden="true">→</span></button>
      </div>
    </div>
  </div>
</section>`;
}

function renderContactExperience() {
  const item = CONFIG.contact;
  const phones = item.phones.map((phone, index) => `<a href="${esc(phone.href)}" data-analytics-event="contact_phone" data-analytics-component="homepage_final_contact" data-analytics-cta-id="homepage_phone_${index + 1}"><span>Telefon</span><strong>${esc(phone.label)}</strong></a>`).join("");
  return `<section id="homepage-contact" class="homepage-flow-section" aria-labelledby="homepage-contact-title"><div class="homepage-flow-inner homepage-contact-card">
    <div class="homepage-contact-copy"><span class="homepage-eyebrow">Următorul pas</span><h2 id="homepage-contact-title">${esc(item.title)}</h2><p>${esc(item.text)}</p><div class="homepage-contact-direct" aria-label="Contact direct">${phones}<a href="${esc(item.email.href)}" data-analytics-event="contact_email" data-analytics-component="homepage_final_contact" data-analytics-cta-id="homepage_email"><span>Email</span><strong>${esc(item.email.label)}</strong></a></div></div>
    <div class="homepage-contact-actions"><span class="homepage-contact-actions__label">Începe cu datele esențiale</span><a class="homepage-flow-action" href="${esc(item.primaryHref)}" data-analytics-event="cta_click" data-analytics-component="homepage_final_cta" data-analytics-cta-id="homepage_final_project_check" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_22">${esc(item.primaryLabel)} <span aria-hidden="true">→</span></a><a class="homepage-contact-secondary" href="/verificare-eligibilitate-fonduri-europene">Vezi ce date pregătești</a></div>
  </div></section>`;
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
  return `${START}\n${renderMethodExperience()}\n${renderPriorityCarousel(programs)}\n${renderExplorer()}\n${renderContactExperience()}\n${END}`;
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
  // The homepage is touched by both legacy CRLF generators and newer LF generators.
  // Keep this owned asset block on LF so repeated pipeline runs cannot oscillate only
  // because an adjacent generator emitted a different newline sequence.
  const newline = "\n";
  const toc = source.match(/<!-- P1_09_LONG_FORM_TOC_START -->[\s\S]*?<!-- P1_09_LONG_FORM_TOC_END -->/);
  const preservedToc = toc ? `\n${toc[0]}` : "";
  let output = source.replace(new RegExp(`${HERO_END}[\\s\\S]*?<\\/main>`, "i"), `${HERO_END}${preservedToc}\n${renderFlow(programs)}\n  </main>`);
  output = output
    .replace(/\s*<style id="homepage-faq-expand-css">[\s\S]*?<\/style>/gi, "")
    .replace(/\s*<script>\s*\/\* Homepage FAQ progressive disclosure[\s\S]*?<\/script>/gi, "");
  output = output
    .replace(/^[ \t]*<link\b[^>]*data-homepage-decision-flow-style=["'][^"']+["'][^>]*>\r?\n?/gim, "")
    .replace(/^[ \t]*<script\b[^>]*data-homepage-decision-flow-script=["'][^"']+["'][^>]*><\/script>\r?\n?/gim, "");
  const homepageHeroStyle = /\s*(?=<style\b[^>]*id=["']homepage-hero-critical-css["'][^>]*>)/i;
  const longFormAsset = /\s*(?=<link\b[^>]*data-long-form-layout-style=["'][^"']+["'][^>]*>)/i;
  if (homepageHeroStyle.test(output)) output = output.replace(homepageHeroStyle, `${newline}  ${STYLE}${newline}  ${SCRIPT}${newline}  `);
  else if (longFormAsset.test(output)) output = output.replace(longFormAsset, `${newline}  ${STYLE}${newline}  ${SCRIPT}${newline}  `);
  else output = output.replace(/<\/head>/i, `  ${STYLE}${newline}  ${SCRIPT}${newline}</head>`);
  return removeLegacyRuntime(output);
}

function sameText(left, right) {
  return left.replace(/\r\n/g, "\n") === right.replace(/\r\n/g, "\n");
}

function main() {
  const { programs } = loadProgramConfig();
  const before = fs.readFileSync(HOME, "utf8");
  const after = synchronize(before, programs);
  if (CHECK_ONLY) {
    if (!sameText(after, before)) {
      let mismatch = 0;
      while (mismatch < before.length && mismatch < after.length && before[mismatch] === after[mismatch]) mismatch += 1;
      const contextStart = Math.max(0, mismatch - 90);
      const describe = (value) => value.slice(contextStart, mismatch + 180).replace(/\r/g, "\\r").replace(/\n/g, "\\n");
      throw new Error(`Homepage-ul P1.21 nu este sincronizat la caracterul ${mismatch}. IN=${describe(before)} OUT=${describe(after)}`);
    }
    console.log("Homepage decision flow sync PASS.");
    return;
  }
  if (!sameText(after, before)) fs.writeFileSync(HOME, after, "utf8");
  console.log("Homepage P1.21 sincronizat: un singur traseu, zero formulare inline, un carusel.");
}

if (require.main === module) main();

module.exports = { renderFlow, synchronize };
