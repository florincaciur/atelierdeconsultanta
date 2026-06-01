"use strict";

const BRAND_LOGO_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 44" width="240" height="44" aria-hidden="true">
          <text x="0" y="32" font-family="Georgia,'Times New Roman',serif" font-size="28" font-weight="700" fill="#b84716" letter-spacing="3">FABER</text>
          <path d="M118,22 L125,13 L132,22 L125,31 Z" fill="white" opacity="0.95"></path>
          <text x="138" y="18" font-family="'Inter','Helvetica Neue',sans-serif" font-size="10" font-weight="600" fill="white" letter-spacing="2">ATELIER de</text>
          <text x="138" y="33" font-family="'Inter','Helvetica Neue',sans-serif" font-size="10" font-weight="600" fill="white" letter-spacing="2">CONSULTANȚĂ</text>
        </svg>`;

function brandLogoLink(className = "brand") {
  return `<a class="${className}" href="/" aria-label="FABER - Atelier de Consultanță, acasă">${BRAND_LOGO_SVG}</a>`;
}

module.exports = {
  BRAND_LOGO_SVG,
  brandLogoLink
};
