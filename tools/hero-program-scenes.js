"use strict";

// Decorative, symbolic illustrations. Program facts stay in the public registry.
const sun = '<g class="pv-sun"><circle cx="334" cy="54" r="18"/><path d="M334 24v-8m0 76v-8m30-30h8m-76 0h8m9-21-6-6m48 48-6-6m0-42 6-6m-48 48 6-6"/></g>';
const plant = '<path class="pv-grow" d="M103 203v-52m0 27c-28 0-37-17-30-29 25 1 30 15 30 29Zm0-9c1-26 15-37 32-28-1 22-17 28-32 28Z"/>';
const house = '<g class="pv-building"><path d="m139 135 69-57 71 57v77H139Z"/><path class="pv-accent" d="m128 136 80-67 82 67-10 12-72-59-69 59Z"/><path class="pv-glass" d="M156 146h28v30h-28Zm71 0h30v30h-30Z"/><path d="M194 175h28v37h-28"/></g>';
const battery = (x, y) => `<g transform="translate(${x} ${y})"><path class="pv-building" d="m0 12 21-9 41 14v99l-21 9L0 111Z"/><path d="m0 12 41 15 21-10M41 27v98"/><path class="pv-charge" d="m12 38 17 6v13l-17-6Zm0 23 17 6v13l-17-6Zm0 23 17 6v13l-17-6Z"/><path d="m43 2 11 4v12l-11-4Z"/></g>`;
const panels = '<g class="pv-panels"><path d="m100 127 127-33 75 64-127 33Z"/><path d="m142 116 75 63m-32-75 75 64m-139-20 128-33m-107 51 129-33M148 184v31m110-50v38"/><path class="pv-glint" d="m162 113 13-3 75 64-13 3Z"/></g>';
const wheels = (x1, x2, y=202) => `<g class="pv-wheels"><circle cx="${x1}" cy="${y}" r="18"/><circle cx="${x2}" cy="${y}" r="18"/><circle cx="${x1}" cy="${y}" r="7"/><circle cx="${x2}" cy="${y}" r="7"/></g>`;
const scenes = {
  "modernizare-microintreprinderi-ne-2": '<g class="pv-rise"><path class="pv-building" d="m131 108 111-30 71 37v95l-113 31-69-35Z"/><path d="m131 108 69 34 113-27M200 142v99"/><path class="pv-glass" d="m146 133 36 17v23l-36-17Zm71 15 30-8v25l-30 8Zm45-12 32-9v25l-32 9Z"/><path class="pv-accent" d="m130 108 111-30 71 37-111 28Z"/></g><g class="pv-crane"><path d="M104 196V49h156M94 49h174l-35-20H104Zm13-20 50 20m-8-20 47 20m-5-20 41 20M253 49v42"/><path class="pv-accent" d="m241 94 12-6 14 7v15l-13 6-13-7Z"/></g>',
  "dr12-afir": house + plant + '<g class="pv-sprout"><path d="M315 207v-70m0 28c-31 2-43-18-34-33 25 1 34 17 34 33Zm0-10c0-27 21-41 39-28-7 23-22 28-39 28Z"/></g><path class="pv-field" d="m85 224 230-9m-202 19 182-9"/>',
  "dr14-afir": '<g class="pv-drive"><path class="pv-accent" d="M128 182v-49h99v-40h49l23 57h27v40H128Z"/><path class="pv-glass" d="M239 105h28l17 43h-45Z"/><path d="M139 145h24m-24 10h24m5-23v-26h12v26M217 182h70"/>' + wheels(183, 296) + '</g>' + plant + '<path class="pv-flow" d="M75 231h282"/>',
  "dr18-afir": '<g class="pv-greenhouse"><path d="M106 205v-89l103-52 105 52v89Zm0-89h208M209 64v141m-54-116v116m108-116v116M107 157h206"/><path class="pv-glass" d="m113 116 42-23v108h-42Zm100-44 45 22v107h-45Z"/></g><g class="pv-grow"><path d="M178 210v-49m63 49v-33"/><g class="pv-accent"><path d="M178 162c-30-4-20-34-1-16 10-25 36-5 11 11 27 9 3 33-10 5Zm63 17c-23-4-18-28-2-16 14-21 30 0 12 7 19 15-3 30-10 9Z"/></g></g>',
  "afir-energie-autoconsum": sun + '<path class="pv-building" d="m261 116 51-37 42 26v70h-76v-46Z"/>' + panels + '<path class="pv-flow" d="M199 195v30h129v-43"/>',
  "e-move-ro": '<g class="pv-drive"><path class="pv-building" d="M80 116h173v83H80Z"/><path class="pv-accent" d="M253 141h49l32 31v27h-81Z"/><path class="pv-glass" d="M269 151h27l20 22h-47Z"/><path class="pv-bolt" d="m178 130-25 33h21l-13 22 39-38h-24Z"/>' + wheels(129, 295) + '</g><path class="pv-flow" d="M59 230h296"/>',
  "diaspora-investeste-acasa": house + '<g class="pv-orbit"><path class="pv-flow" d="M78 156C19 11 336 5 351 125"/><path class="pv-accent" d="m335 95 29 9-17 25-2-18-10-16Z"/></g><circle class="pv-pulse" cx="105" cy="74" r="9"/>' + plant,
  "e-drive": '<g class="pv-drive"><path class="pv-accent" d="M79 198V108q0-16 16-16h218q22 0 22 22v84Z"/><path class="pv-glass" d="M96 110h35v42H96Zm48 0h35v42h-35Zm48 0h35v42h-35Zm49 0h35v42h-35Zm48 0h27v77h-27Z"/><path d="M81 171h191"/>' + wheels(136, 277) + '</g><path class="pv-flow" d="M58 230h301"/>',
  "e-mobility-ro": '<g class="pv-station"><rect class="pv-building" x="90" y="76" width="56" height="137" rx="10"/><path class="pv-glass" d="M103 89h30v35h-30Z"/><path class="pv-flow" d="M145 130h18q12 0 12 15v33q0 12 13 12h16"/><path class="pv-bolt" d="m119 143-13 24h13l-6 17 19-29h-13Z"/></g><g class="pv-drive"><path class="pv-accent" d="m191 168 24-36h61l30 36 29 10v25H183v-25Z"/><path class="pv-glass" d="m208 164 14-22h48l20 22Z"/>' + wheels(220, 303, 205) + '</g>',
  "fondul-modernizare-pc1-stocare": battery(105, 99) + battery(181, 78) + battery(257, 99) + '<path class="pv-flow" d="M143 229h152m-76-7v-20"/><g class="pv-float"><path class="pv-bolt" d="m221 16-33 40h24l-10 26 35-41h-24Z"/></g>'
};

const familyScenes = {
  agriculture: house + plant + '<path class="pv-field" d="m74 226 272-12m-239 28 205-12"/>',
  digital: '<g class="pv-rise"><path class="pv-building" d="M105 92h210v119H105Z"/><path class="pv-glass" d="M126 115h63v43h-63Zm84 0h84v22h-84Zm0 38h84v37h-84Z"/><path class="pv-accent" d="M91 211h238v19H91Z"/></g><g class="pv-orbit"><circle cx="102" cy="74" r="10"/><circle cx="329" cy="72" r="8"/><path class="pv-flow" d="M112 74h207M102 84v34m227-38v38"/></g>',
  energy: sun + panels + '<path class="pv-flow" d="M149 211v24h129v-47"/>',
  mobility: scenes["e-mobility-ro"],
  regional: scenes["modernizare-microintreprinderi-ne-2"],
  entrepreneur: house + '<g class="pv-rise"><path class="pv-accent" d="M107 125h83l-8-35h-67Z"/><path class="pv-building" d="M113 125h72v76h-72Z"/><path class="pv-glass" d="M130 144h38v26h-38Z"/></g>' + plant,
  generic: '<g class="pv-rise"><path class="pv-building" d="M119 74h174l35 35v114H119Z"/><path class="pv-glass" d="M145 112h117v15H145Zm0 34h117v15H145Zm0 34h80v15h-80Z"/><path class="pv-accent" d="M293 74v36h35Z"/></g>'
};

function sceneArtwork(program = {}) {
  if (scenes[program.id]) return scenes[program.id];
  const family = String(program.family || "");
  if (/afir|agricultur|leader/iu.test(family)) return familyScenes.agriculture;
  if (/mobilitate/iu.test(family)) return familyScenes.mobility;
  if (/energie/iu.test(family)) return familyScenes.energy;
  if (/digital|pnrr/iu.test(family)) return familyScenes.digital;
  if (/regional|tranzitie/iu.test(family)) return familyScenes.regional;
  if (/antrepren/iu.test(family)) return familyScenes.entrepreneur;
  return familyScenes.generic;
}

function renderProgramScenes(programs) {
  return `<div class="hero-program-visuals" id="hero-program-visuals" aria-hidden="true">
    <div class="hero-program-gridfloor"></div>
    ${programs.map((program, index) => `<div class="hero-program-scene${index === 0 ? ' is-active' : ''}" data-program-scene="${program.id}"${index ? ' hidden' : ''}>
      <svg viewBox="0 0 420 270" focusable="false"><ellipse class="pv-shadow" cx="213" cy="231" rx="142" ry="18"/><path class="pv-platform" d="m55 216 149-51 158 51-150 48Z"/>${sceneArtwork(program)}</svg>
    </div>`).join("\n")}
  </div>`;
}

module.exports = { renderProgramScenes, sceneArtwork };
