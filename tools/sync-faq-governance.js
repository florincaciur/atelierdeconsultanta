#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { buildInventory } = require("./generate-route-inventory");
const {
  normalizeFaqPairs,
  routeFiles,
  synchronizeFaqHtml
} = require("./faq-governance");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "seo-programs.json");
const CHECK_ONLY = process.argv.includes("--check");

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function normalizedConfig(source) {
  const config = JSON.parse(source);
  for (const page of config.pages || []) {
    if (!Array.isArray(page.faq)) continue;
    page.faq = normalizeFaqPairs(page.faq);
  }
  return `${JSON.stringify(config, null, 2)}\n`;
}

function main() {
  const changed = [];
  const configSource = fs.readFileSync(CONFIG_PATH, "utf8");
  const nextConfig = normalizedConfig(configSource);
  if (nextConfig !== configSource) {
    changed.push("config/seo-programs.json");
    if (!CHECK_ONLY) fs.writeFileSync(CONFIG_PATH, nextConfig, "utf8");
  }

  const inventory = buildInventory();
  let sourceCount = 0;
  let genericRemoved = 0;
  let duplicateRemoved = 0;
  for (const routeEntry of inventory.routes) {
    const files = routeFiles(ROOT, routeEntry).filter((file) => fs.existsSync(file));
    for (const file of files) {
      sourceCount += 1;
      const source = fs.readFileSync(file, "utf8");
      const synchronized = synchronizeFaqHtml(source);
      genericRemoved += synchronized.genericRemoved;
      duplicateRemoved += synchronized.duplicateRemoved;
      if (synchronized.html === source) continue;
      changed.push(toPosix(path.relative(ROOT, file)));
      if (!CHECK_ONLY) fs.writeFileSync(file, synchronized.html, "utf8");
    }
  }

  if (CHECK_ONLY && changed.length) {
    console.error(`FAQ nesincronizat în ${changed.length} fișiere:\n${changed.map((file) => `- ${file}`).join("\n")}`);
    process.exitCode = 1;
    return;
  }
  console.log(`${CHECK_ONLY ? "Verificate" : "Sincronizate"} ${inventory.routes.length} rute și ${sourceCount} surse HTML; ${changed.length} fișiere ${CHECK_ONLY ? "neconforme" : "actualizate"}, ${genericRemoved} răspunsuri fallback și ${duplicateRemoved} duplicate eliminate.`);
}

if (require.main === module) main();

module.exports = { normalizedConfig };
