#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const sharp = require("sharp");

const ROOT = path.resolve(__dirname, "..");
const OUT_DIR = path.join(ROOT, "assets", "hero");

const scenes = [
  {
    file: "hero-agriculture.webp",
    bg: ["#1d3f2b", "#8db255"],
    accent: "#f5a623",
    svg: `
      <rect x="0" y="0" width="1600" height="900" fill="url(#bg)"/>
      <circle cx="1280" cy="170" r="82" fill="#f5a623" opacity=".95"/>
      <path d="M0 585 C260 500 520 550 800 485 C1060 425 1290 455 1600 390 L1600 900 L0 900 Z" fill="#24492f"/>
      <path d="M0 705 C280 610 565 650 830 575 C1080 505 1320 515 1600 475 L1600 900 L0 900 Z" fill="#315f35"/>
      <g opacity=".62" stroke="#f6d48a" stroke-width="7">
        <path d="M45 890 C320 720 575 640 850 575"/>
        <path d="M225 900 C455 735 670 655 910 590"/>
        <path d="M420 900 C585 760 765 680 990 610"/>
        <path d="M640 900 C765 785 910 710 1095 635"/>
        <path d="M890 900 C970 795 1100 725 1260 655"/>
      </g>
      <g transform="translate(210 390)">
        <polygon points="0,95 130,0 260,95" fill="#b84716"/>
        <rect x="28" y="95" width="206" height="150" rx="6" fill="#f8f0df"/>
        <rect x="112" y="150" width="52" height="95" fill="#7b3f1f"/>
      </g>`
  },
  {
    file: "hero-solar.webp",
    bg: ["#09263a", "#2b7a78"],
    accent: "#e0f2fe",
    svg: `
      <rect width="1600" height="900" fill="url(#bg)"/>
      <circle cx="1270" cy="190" r="118" fill="#f5a623" opacity=".9"/>
      <path d="M0 620 C240 580 420 610 650 555 C950 485 1180 525 1600 455 L1600 900 L0 900 Z" fill="#123a4b" opacity=".9"/>
      <g transform="translate(130 470)" opacity=".95">
        ${Array.from({ length: 4 }, (_, row) => Array.from({ length: 6 }, (_, col) => {
    const x = col * 220 + row * 28;
    const y = row * 74;
    return `<polygon points="${x},${y + 40} ${x + 175},${y} ${x + 220},${y + 82} ${x + 35},${y + 132}" fill="#0f4c81" stroke="#dbeafe" stroke-width="4"/>
      <path d="M${x + 35},${y + 51} L${x + 205},${y + 92} M${x + 70},${y + 29} L${x + 115},${y + 111} M${x + 118},${y + 18} L${x + 162},${y + 101}" stroke="#93c5fd" stroke-width="3" opacity=".7"/>`;
  }).join("")).join("")}
      </g>
      <path d="M0 760 L1600 640 L1600 900 L0 900 Z" fill="#0d1f3c" opacity=".42"/>`
  },
  {
    file: "hero-digital.webp",
    bg: ["#0d1f3c", "#3b2f73"],
    accent: "#22d3ee",
    svg: `
      <rect width="1600" height="900" fill="url(#bg)"/>
      <circle cx="1220" cy="190" r="150" fill="#22d3ee" opacity=".12"/>
      <circle cx="360" cy="690" r="250" fill="#f5a623" opacity=".08"/>
      <g stroke="#67e8f9" stroke-width="4" opacity=".58">
        <path d="M260 280 L530 405 L770 260 L1030 405 L1320 280"/>
        <path d="M530 405 L545 650 L810 735 L1030 405"/>
        <path d="M770 260 L810 735"/>
        <path d="M260 280 L545 650"/>
      </g>
      <g fill="#e0f2fe">
        ${[[260,280],[530,405],[770,260],[1030,405],[1320,280],[545,650],[810,735]].map(([x,y]) => `<circle cx="${x}" cy="${y}" r="18"/>`).join("")}
      </g>
      <g transform="translate(505 455)">
        <rect x="0" y="0" width="590" height="315" rx="28" fill="#111827" stroke="#cbd5e1" stroke-width="8"/>
        <rect x="38" y="38" width="514" height="220" rx="12" fill="#102a43"/>
        <path d="M-70 330 H660 L615 390 H-25 Z" fill="#cbd5e1"/>
        <rect x="110" y="85" width="175" height="22" rx="11" fill="#22d3ee"/>
        <rect x="110" y="128" width="320" height="18" rx="9" fill="#f5a623" opacity=".85"/>
        <rect x="110" y="170" width="255" height="18" rx="9" fill="#93c5fd"/>
      </g>`
  },
  {
    file: "hero-business.webp",
    bg: ["#102033", "#39556e"],
    accent: "#f97316",
    svg: `
      <rect width="1600" height="900" fill="url(#bg)"/>
      <path d="M0 650 C260 545 520 600 760 520 C1030 430 1250 500 1600 410 L1600 900 L0 900 Z" fill="#0d1f3c" opacity=".72"/>
      <g transform="translate(300 285)">
        <rect x="0" y="0" width="330" height="420" rx="18" fill="#f8fafc" opacity=".95"/>
        <rect x="48" y="65" width="190" height="18" rx="9" fill="#b84716"/>
        <rect x="48" y="118" width="245" height="12" rx="6" fill="#94a3b8"/>
        <rect x="48" y="154" width="210" height="12" rx="6" fill="#94a3b8"/>
        <rect x="48" y="225" width="56" height="120" rx="8" fill="#f5a623"/>
        <rect x="132" y="185" width="56" height="160" rx="8" fill="#1a3a6a"/>
        <rect x="216" y="135" width="56" height="210" rx="8" fill="#b84716"/>
      </g>
      <g transform="translate(780 235)">
        <rect x="0" y="0" width="470" height="330" rx="22" fill="#ffffff" opacity=".12" stroke="#e2e8f0" stroke-width="4"/>
        <path d="M52 250 C130 180 190 210 260 125 C315 60 370 90 420 45" fill="none" stroke="#f5a623" stroke-width="14" stroke-linecap="round"/>
        <circle cx="420" cy="45" r="18" fill="#f5a623"/>
        <circle cx="260" cy="125" r="15" fill="#f8fafc"/>
        <circle cx="130" cy="180" r="15" fill="#f8fafc"/>
      </g>`
  },
  {
    file: "hero-local.webp",
    bg: ["#16324f", "#417c68"],
    accent: "#f5a623",
    svg: `
      <rect width="1600" height="900" fill="url(#bg)"/>
      <path d="M0 640 C250 545 470 610 700 535 C980 445 1260 520 1600 430 L1600 900 L0 900 Z" fill="#153c35" opacity=".82"/>
      <path d="M0 735 C260 675 500 725 775 645 C1075 560 1300 615 1600 560 L1600 900 L0 900 Z" fill="#1f5f48"/>
      <g transform="translate(660 185)">
        <path d="M140 0 C62 0 0 62 0 140 C0 255 140 410 140 410 C140 410 280 255 280 140 C280 62 218 0 140 0 Z" fill="#b84716"/>
        <circle cx="140" cy="140" r="58" fill="#fff7ed"/>
      </g>
      <g stroke="#f8fafc" stroke-width="8" opacity=".75" fill="none">
        <path d="M110 775 C340 665 520 690 720 610 C910 535 1080 560 1490 435"/>
        <path d="M190 845 C420 735 620 735 830 665 C1045 595 1210 605 1540 515"/>
      </g>
      <g fill="#f5a623" opacity=".9">
        <circle cx="260" cy="735" r="13"/><circle cx="510" cy="682" r="11"/><circle cx="980" cy="594" r="12"/><circle cx="1300" cy="518" r="12"/>
      </g>`
  }
];

function sceneSvg(scene) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900">
    <defs>
      <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="${scene.bg[0]}"/>
        <stop offset="1" stop-color="${scene.bg[1]}"/>
      </linearGradient>
      <filter id="grain">
        <feTurbulence type="fractalNoise" baseFrequency=".85" numOctaves="2" stitchTiles="stitch"/>
        <feColorMatrix type="saturate" values="0"/>
        <feComponentTransfer><feFuncA type="table" tableValues="0 .08"/></feComponentTransfer>
      </filter>
    </defs>
    ${scene.svg}
    <rect width="1600" height="900" filter="url(#grain)" opacity=".45"/>
    <rect width="1600" height="900" fill="#06111f" opacity=".12"/>
  </svg>`;
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  await Promise.all(scenes.map(async (scene) => {
    const out = path.join(OUT_DIR, scene.file);
    await sharp(Buffer.from(sceneSvg(scene)))
      .resize(1600, 900, { fit: "cover" })
      .webp({ quality: 78, effort: 5 })
      .toFile(out);
  }));
  console.log(`Generated ${scenes.length} hero assets in ${path.relative(ROOT, OUT_DIR)}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
