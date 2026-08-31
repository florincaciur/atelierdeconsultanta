"use strict";

const { positioning } = require("../config/editorial-terminology.json");

// This presentation layer is called by the existing homepage generator. The
// program registry, attribution, links and structured data stay authoritative.
function renderSculpture(className = "") {
  return `<div class="im-sculpture ${className}" aria-hidden="true">
    <div class="im-orbit im-orbit--one"></div><div class="im-orbit im-orbit--two"></div>
    <div class="im-sculpture-shadow"></div>
    <div class="im-sculpture-core">
      <div class="im-slab im-slab--1 is-active"><span>01</span></div>
      <div class="im-slab im-slab--2"><span>02</span></div>
      <div class="im-slab im-slab--3"><span>03</span></div>
      <div class="im-slab im-slab--4"><span>04</span></div>
      <div class="im-slab im-slab--5"><span>05</span></div>
      <div class="im-spark"></div>
    </div>
    <span class="im-coordinate im-coordinate--top">IDEE / POTENȚIAL</span>
    <span class="im-coordinate im-coordinate--bottom">STRUCTURĂ / DIRECȚIE</span>
  </div>`;
}

function immersiveHero(hero) {
  let result = hero.replace('class="homepage-decision-hero"', 'class="homepage-decision-hero im-hero"');
  result = result.replace('<div class="hero-badge"><span class="dot" aria-hidden="true"></span>FABER pentru firme, fermieri, start-up-uri, IMM-uri și instituții publice</div>', '<div class="hero-badge"><span class="dot" aria-hidden="true"></span>Atelierul în care ideile prind contur</div>');
  result = result.replace(/(<p class="hero-subtitle"[\s\S]*?<\/p>)/, (detail) => {
    const expanded = detail.replace('class="hero-subtitle"', 'class="im-detail-copy"').replace(/ data-aeo-(?:primary|direct)-answer=""/g, "");
    return '<p class="hero-subtitle im-lead" data-aeo-primary-answer="" data-aeo-direct-answer="">FABER – Atelier de Consultanță sprijină proiecte cu fonduri europene, de la verificarea inițială a eligibilității la documentație și implementare. Fără promisiunea aprobării finanțării. ' + positioning + '</p><details class="im-about"><summary>Ce facem pentru proiectul tău <span aria-hidden="true">+</span></summary>' + expanded + '</details>';
  });
  result = result.replace('    </section>', `      <div class="im-hero-bottom"><a href="#homepage-method" class="im-scroll-link"><span class="im-scroll-icon" aria-hidden="true">↓</span> Derulează. Descoperă. Construiește.</a><span>De la întrebare la un plan documentat.</span><span class="im-edition">FABER — 01 / 05</span></div>\n    </section>`);
  return result;
}

function renderImmersiveControls() {
  return `<div class="im-progress" aria-hidden="true"><span data-im-progress></span></div>
  <nav class="im-chapters" aria-label="Secțiunile paginii">
    <a href="#hero" aria-label="01 — Introducere" aria-current="location"><span>01</span><i></i></a>
    <a href="#homepage-method" aria-label="02 — Metoda FABER"><span>02</span><i></i></a>
    <a href="#priority-programs" aria-label="03 — Finanțări"><span>03</span><i></i></a>
    <a href="#homepage-explorer" aria-label="04 — Servicii"><span>04</span><i></i></a>
    <a href="#homepage-contact" aria-label="05 — Contact"><span>05</span><i></i></a>
  </nav>
  <button class="im-motion-toggle" type="button" data-im-motion aria-pressed="false" hidden><span aria-hidden="true">◈</span><span data-im-motion-label>Oprește animațiile</span></button>`;
}

module.exports = { immersiveHero, renderSculpture, renderImmersiveControls };
