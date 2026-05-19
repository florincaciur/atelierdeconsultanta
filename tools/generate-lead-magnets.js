#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "..");
const OUT = path.join(ROOT, "resurse", "descarcari");

function ensureExcelJs() {
  try {
    return require("exceljs");
  } catch {
    throw new Error("Lipseste pachetul exceljs. Ruleaza: npm install --save-dev exceljs");
  }
}

function htmlDoc(title, sections) {
  return `<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <title>${title}</title>
  <style>
    body{font-family:Arial,sans-serif;color:#1a2540;line-height:1.55;margin:42px}
    h1{color:#0d1f3c;font-size:28px;margin-bottom:8px}
    h2{color:#112a50;font-size:18px;margin-top:24px}
    .note{background:#fff7ed;border:1px solid #f5a623;padding:12px;border-radius:8px}
    li{margin-bottom:6px}
    footer{margin-top:28px;color:#6b7a99;font-size:12px}
  </style>
</head>
<body>
  <h1>${title}</h1>
  <p class="note">Resursa orientativa. Conditiile finale se verifica in apelul activ si in documentele solicitantului.</p>
  ${sections.map((section) => `<h2>${section.title}</h2><ul>${section.items.map((item) => `<li>${item}</li>`).join("")}</ul>`).join("")}
  <footer>FABER - Atelier de Consultanta | atelierdeconsultanta.ro</footer>
</body>
</html>`;
}

async function writePdf(file, title, sections) {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.setContent(htmlDoc(title, sections), { waitUntil: "load" });
    await page.pdf({ path: file, format: "A4", printBackground: true, margin: { top: "18mm", right: "16mm", bottom: "18mm", left: "16mm" } });
  } finally {
    await browser.close();
  }
}

async function writeWorkbook(file, sheets) {
  const ExcelJS = ensureExcelJs();
  const workbook = new ExcelJS.Workbook();
  workbook.creator = "FABER - Atelier de Consultanta";
  workbook.created = new Date();
  for (const sheet of sheets) {
    const ws = workbook.addWorksheet(sheet.name);
    ws.columns = sheet.columns;
    ws.addRows(sheet.rows);
    ws.getRow(1).font = { bold: true };
    ws.columns.forEach((column) => { column.width = Math.max(column.width || 18, 18); });
  }
  await workbook.xlsx.writeFile(file);
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  await writePdf(path.join(OUT, "checklist-documente-fonduri-europene.pdf"), "Checklist documente fonduri europene", [
    { title: "Date solicitant", items: ["certificat constatator actualizat", "documente identificare reprezentant", "situatii financiare disponibile", "declaratii privind ajutoarele primite"] },
    { title: "Investitie", items: ["descrierea investitiei", "oferte orientative", "documente pentru spatiu sau teren", "calendar de implementare"] },
    { title: "Verificari inainte de depunere", items: ["cod CAEN si autorizare", "cofinantare", "cheltuieli eligibile", "riscuri de punctaj"] }
  ]);
  await writePdf(path.join(OUT, "checklist-afir-dr12-dr14.pdf"), "Checklist AFIR DR12 si DR14", [
    { title: "Exploatatie", items: ["calcul Standard Output", "documente APIA sau echivalente", "documente animale sau culturi", "drept de folosinta"] },
    { title: "Investitie", items: ["utilaje proportionale", "oferte si specificatii", "justificare economica", "evitarea dublei finantari"] },
    { title: "Depunere", items: ["cerere completata", "anexe", "declaratii", "verificare finala"] }
  ]);
  await writeWorkbook(path.join(OUT, "buget-digitalizare-imm.xlsx"), [
    {
      name: "Buget",
      columns: [
        { header: "Categorie", key: "category", width: 28 },
        { header: "Descriere", key: "description", width: 46 },
        { header: "Valoare estimata EUR", key: "value", width: 22 },
        { header: "Observatii", key: "notes", width: 42 }
      ],
      rows: [
        { category: "Software", description: "ERP/CRM/gestiune", value: "", notes: "verifica eligibilitatea in apel" },
        { category: "Hardware", description: "echipamente IT necesare", value: "", notes: "justifica prin procese" },
        { category: "Securitate", description: "backup, antivirus, audit", value: "", notes: "coreleaza cu riscurile firmei" },
        { category: "Implementare", description: "configurare si instruire", value: "", notes: "include livrabile clare" }
      ]
    }
  ]);
  await writeWorkbook(path.join(OUT, "calendar-pregatire-depunere.xlsx"), [
    {
      name: "Calendar",
      columns: [
        { header: "Etapa", key: "stage", width: 32 },
        { header: "Responsabil", key: "owner", width: 24 },
        { header: "Termen intern", key: "deadline", width: 18 },
        { header: "Status", key: "status", width: 18 },
        { header: "Observatii", key: "notes", width: 42 }
      ],
      rows: [
        { stage: "Verificare eligibilitate", owner: "", deadline: "", status: "", notes: "solicitant, program, investitie" },
        { stage: "Documente firma", owner: "", deadline: "", status: "", notes: "certificat constatator, situatii financiare" },
        { stage: "Oferte si buget", owner: "", deadline: "", status: "", notes: "specificatii si justificare" },
        { stage: "Cerere si anexe", owner: "", deadline: "", status: "", notes: "revizie inainte de depunere" }
      ]
    }
  ]);
  console.log(`Generated lead magnets in ${path.relative(ROOT, OUT)}.`);
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
