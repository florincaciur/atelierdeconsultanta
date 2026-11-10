import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import * as cheerio from "cheerio";
import ExcelJS from "exceljs";
import { chromium } from "playwright";
import structuredData from "../tools/structured-data-utils.js";

const root = path.resolve(import.meta.dirname, "..");
const { fileForRoute } = structuredData;
const cofin = "/cum-se-calculeaza-cofinantarea-fonduri-europene";
const live = process.argv.includes("--live");
const mime = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"]
]);
const server = http.createServer(async (req, res) => {
  const route = new URL(req.url, "http://localhost").pathname;
  const file = path.extname(route) ? path.resolve(root, `.${route}`) : fileForRoute(root, route);
  if (!file.startsWith(root + path.sep)) return res.writeHead(404).end();
  try {
    const data = await fs.readFile(file);
    res.setHeader("Content-Type", mime.get(path.extname(file)) || "application/octet-stream");
    res.end(data);
  } catch { res.writeHead(404).end(); }
});

if (!live) await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const origin = live ? "https://atelierdeconsultanta.ro" : `http://127.0.0.1:${server.address().port}`;

async function get(route) {
  const response = await fetch(origin + route, { redirect: "manual", signal: AbortSignal.timeout(20000) });
  assert.equal(response.status, 200, route);
  return response;
}

async function checkWorkbooks() {
  const $ = cheerio.load(await (await get("/resurse")).text());
  const preview = await fs.readFile(path.join(root, "templates/resource-workbook-previews.fragment"), "utf8");
  assert.deepEqual(
    $("#previzualizare-excel").parent().text().replace(/\s+/gu, " ").trim(),
    cheerio.load(preview)("section").text().replace(/\s+/gu, " ").trim(),
    "previzualizarea trebuie să corespundă sursei"
  );
  const sheets = [
    ["buget-digitalizare-imm", "Buget", "Valoare estimata EUR", "#buget-digitalizare-tabel"],
    ["calendar-pregatire-depunere", "Calendar", "Termen intern", "#calendar-pregatire-tabel"]
  ];
  for (const [filename, sheetName, column, caption] of sheets) {
    const url = `/resurse/descarcari/${filename}.xlsx`;
    assert.equal($(`main a[href="${url}"][download]`).length, 1);
    const bytes = Buffer.from(await (await get(url)).arrayBuffer());
    assert.deepEqual(bytes, await fs.readFile(path.join(root, `.${url}`)));
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(bytes);
    const sheet = workbook.getWorksheet(sheetName);
    assert.equal(sheet.getCell("C1").value, column);
    assert.equal(sheet.rowCount, 5);
    assert(sheet.getRows(2, 4).every(row => row.getCell(3).value === ""));
    assert.equal($(caption).parent().find("tbody tr").length, 4);
  }
  assert.equal($("#buget-digitalizare-tabel").parent().find("tbody tr").toArray()
    .reduce((sum, row) => sum + Number($(row).children().last().text().replaceAll(".", "")), 0), 30000);
  const dates = $("#calendar-pregatire-tabel").parent().find("time").map((_, node) => Date.parse($(node).attr("datetime"))).get();
  assert.equal((dates.at(-1) - dates[0]) / 86400000, 14);
  assert.deepEqual($("section:has(> #previzualizare-excel) code").map((_, node) => $(node).text()).get(), ["=SUM(C2:C5)", "=C5-C2"]);
}

async function visit(page, route) {
  const response = await page.goto(origin + route, { waitUntil: "load" });
  assert.equal(response.status(), 200, route);
  assert.equal(new URL(page.url()).pathname, route);
}

async function checkProgramLinks() {
  for (const [route, targets] of [
    ["/dr12-afir", ["/calculator-soc#exemple-calcul-so", cofin + "#calculator-cofinantare"]],
    ["/dr14", ["/calculator-soc#exemple-calcul-so", cofin + "#pasii-urmatori"]],
    ["/digitalizare-imm-regiunea-centru-apel-2", ["/resurse#buget-digitalizare-excel", cofin + "#calculator-cofinantare"]]
  ]) {
    const $ = cheerio.load(await (await get(route)).text());
    for (const target of targets) assert.equal($(`main a[href="${target}"]`).length, 1, `${route} → ${target}`);
  }
}

async function checkNoScript(browser) {
  for (const width of [390, 1440]) {
    const context = await browser.newContext({ viewport: { width, height: 900 }, javaScriptEnabled: false });
    await context.route("**/*", route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
    const page = await context.newPage();
    await visit(page, "/resurse");
    assert(await page.locator("#buget-digitalizare-tabel").isVisible());
    assert(await page.locator("#calendar-pregatire-tabel").isVisible());
    await visit(page, cofin);
    assert(await page.locator("#cofinantare-formule").isVisible());
    assert(await page.locator("#pasii-urmatori").isVisible());
    assert(!(await page.locator("#cofinantare-form").isVisible()));
    await visit(page, "/calculator-soc");
    assert.equal(await page.locator("[data-so-example]:visible").count(), 4);
    const disclosure = page.locator("#coeficienti-soc-2020 > summary");
    await disclosure.focus();
    await page.keyboard.press("Enter");
    assert.equal(await page.locator("[data-soc-code]:visible").count(), 46);
    const regions = page.locator(".so-coefficient-table");
    assert(await regions.evaluateAll(elements => elements.every(element => element.getBoundingClientRect().right <= innerWidth + 1)));
    await context.close();
  }
}

async function checkCalculators(browser) {
  const context = await browser.newContext({ viewport: { width: 390, height: 900 } });
  await context.route("**/*", route => route.request().method() === "GET" && new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  const page = await context.newPage();
  await visit(page, cofin);
  const form = page.locator("#cofinantare-form");
  assert(await form.isVisible());
  assert(await form.locator("input").evaluateAll(inputs => inputs.every(input => input.required && input.labels.length === 1)));
  assert(await form.evaluate(element => element.getBoundingClientRect().right <= innerWidth + 1));
  const button = form.getByRole("button", { name: "Calculează contribuția" });
  const format = new Intl.NumberFormat("ro-RO", { style: "currency", currency: "EUR" });
  async function calculate(fields, expected) {
    for (const [field, value] of Object.entries(fields)) {
      await form.locator(`input[name="${field}"]`).fill(String(value));
    }
    await button.focus();
    await page.keyboard.press("Enter");
    for (const [key, value] of Object.entries(expected)) {
      assert.equal(await form.locator(`[data-cofinantare="${key}"]`).textContent(), format.format(value), key);
    }
    assert(await form.getByRole("status").isVisible());
  }
  await calculate({}, { base: 70000, grant: 50000, ownEligible: 20000, gross: 90750, afterGrant: 40750, netOwn: 25000 });
  await calculate({ eligible: 40000, ineligible: 2000, intensity: 80, eligibleVat: 4000, recoverableVat: 1100, excludedVat: 300 },
    { base: 44000, grant: 35200, ownEligible: 8800, gross: 47400, afterGrant: 12200, netOwn: 11100 });
  await calculate({ eligible: 0.03, ineligible: 0, eligibleVat: 0, recoverableVat: 0, excludedVat: 0, intensity: 50 }, { grant: 0.01, ownEligible: 0.02 });
  await calculate({ intensity: 0 }, { grant: 0, ownEligible: 0.03 });
  await calculate({ intensity: 100, cap: 0 }, { grant: 0 });
  await calculate({ eligible: 1000000000, eligibleVat: 1000000000, cap: 1000000000 }, { base: 2000000000, grant: 1000000000 });
  for (const [field, invalid, original] of [["intensity", "100.01", "100"], ["eligible", "-1", "100"], ["cap", "", "50000"], ["eligibleVat", "0.001", "0"]]) {
    const input = form.locator(`input[name="${field}"]`);
    await input.fill(invalid);
    await button.click();
    assert(!(await form.locator("#cofinantare-rezultate").isVisible()));
    assert(await input.evaluate(node => !node.validity.valid));
    await input.fill(original);
  }
  await visit(page, "/calculator-soc");
  await page.getByRole("button", { name: /adaugă animal/iu }).click();
  const select = page.locator("#animale-body select").last();
  const animalQuantity = page.locator("#animale-body .area-input").last();
  await select.selectOption(await select.locator("option[data-code='A5140']").getAttribute("value"));
  const total = page.locator("#total-so");
  await animalQuantity.fill("1.50");
  assert(Math.abs(Number(await total.getAttribute("data-so-exact-value")) - 749.685) < 1e-9);
  for (const invalid of ["-1", "1000001", "1.001"]) {
    await animalQuantity.fill(invalid);
    assert.equal(await animalQuantity.getAttribute("aria-invalid"), "true");
    assert.equal(await total.textContent(), "—");
    assert(await page.locator("#calculator-errors").isVisible());
    assert(await page.locator("[data-copy-so-result]").isDisabled());
  }
  await animalQuantity.fill("0");
  assert.equal(await total.getAttribute("data-so-exact-value"), "0");
  await animalQuantity.fill("1000000");
  assert.equal(await total.getAttribute("data-so-exact-value"), "499790000");
  await select.selectOption(await select.locator("option[data-code='A2300F']").getAttribute("value"));
  await animalQuantity.fill("1.5");
  assert.equal(await animalQuantity.getAttribute("aria-invalid"), "true");
  await animalQuantity.fill("8");
  assert.equal(await total.getAttribute("data-so-value"), "11300");
  await context.close();
}

let browser;
try {
  await checkWorkbooks();
  await checkProgramLinks();
  browser = await chromium.launch();
  await checkNoScript(browser);
  await checkCalculators(browser);
  console.log(`Instrumente PASS (${live ? "producție" : "local"}): 2 XLSX, 6 verificări fără JavaScript, formule, acces de la tastatură și valori-limită.`);
} finally {
  if (browser) await browser.close();
  if (!live) await new Promise(resolve => server.close(resolve));
}
