import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright";

const ROOT = path.resolve(import.meta.dirname, "..");
const VALID_CUI = "14837428";
const MIME = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webp": "image/webp"
};

let apiMode = "success";
let apiRequests = 0;
const company = {
  data: {
    name: "BORG DESIGN SRL",
    cui: VALID_CUI,
    establishedAt: "2002-08-26",
    primaryCaen: {
      code: "6210",
      description: "Activități de realizare a soft-ului la comandă",
      revision: "3",
      rev3Code: "6210",
      requiresRev3Confirmation: false
    },
    registeredOffice: { county: "SUCEAVA", city: "SUCEAVA" },
    status: "functiune",
    legalForm: "SRL",
    financials: {
      2023: { turnover: 1100000 },
      2024: { turnover: 1350000 },
      2025: {
        turnover: 1500000,
        netProfit: 120000,
        employees: 4,
        fixedAssets: 400000,
        currentAssets: 600000,
        totalAssets: 1000000,
        totalDebts: 250000
      }
    }
  },
  source: "ListaFirme",
  fetchedAt: "2026-09-07T00:00:00.000Z",
  cui: VALID_CUI,
  fieldsAvailable: ["name", "financials.2025.turnover"]
};

function json(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  response.end(JSON.stringify(payload));
}

const server = http.createServer(async (request, response) => {
  const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  if (pathname.startsWith("/api/company/")) {
    apiRequests += 1;
    if (apiMode === "loading") await new Promise((resolve) => setTimeout(resolve, 180));
    if (apiMode === "not-found") return json(response, 404, { error: "company_not_found" });
    if (apiMode === "unavailable") return json(response, 503, { error: "provider_unavailable" });
    if (apiMode === "partial") {
      const partial = structuredClone(company);
      partial.data.financials[2024].turnover = null;
      partial.data.financials[2025].currentAssets = null;
      partial.data.financials[2025].totalAssets = null;
      return json(response, 200, partial);
    }
    return json(response, 200, company);
  }

  let resolvedPath = pathname;
  if (resolvedPath === "/investitii-modernizarea-microintreprinderilor-apel-2") {
    resolvedPath = "/investitii-modernizarea-microintreprinderilor-apel-2/index.html";
  }
  let file = path.resolve(ROOT, resolvedPath.replace(/^\/+/, ""));
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
  if (!file.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(file)) {
    response.writeHead(404);
    response.end("Not found");
    return;
  }
  response.writeHead(200, {
    "cache-control": "no-store",
    "content-type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream"
  });
  fs.createReadStream(file).pipe(response);
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true });

try {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await page.goto(`${baseUrl}/investitii-modernizarea-microintreprinderilor-apel-2`, { waitUntil: "domcontentloaded" });
  const form = page.locator("[data-micro-apel-2-form]");
  await form.waitFor({ state: "visible" });

  await page.evaluate(() => {
    const currentForm = document.querySelector("[data-micro-apel-2-form]");
    const manual = {
      grant: "225000",
      ownContribution: "22",
      implementationCounty: "bt",
      newJobs: "3",
      disadvantagedHire: "yes",
      microenterprise: "",
      activityHistory: "",
      fixedAssets: "",
      deMinimis: "",
      siteRights: "",
      annexes: "",
      cashFlow: ""
    };
    for (const [name, value] of Object.entries(manual)) currentForm.elements.namedItem(name).value = value;
    currentForm.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const requestsBeforeInvalid = apiRequests;
  await page.locator("[data-company-cui-input]").fill("12345678");
  await page.locator("[data-company-lookup-button]").click();
  await assert.doesNotReject(() => page.waitForFunction(() => document.querySelector("[data-company-lookup-status]")?.textContent.includes("CUI românesc valid")));
  assert.equal(apiRequests, requestsBeforeInvalid, "invalid CUI must not reach the internal API");

  apiMode = "loading";
  await page.locator("[data-company-cui-input]").fill(`RO ${VALID_CUI}`);
  await page.locator("[data-company-lookup-button]").click();
  assert.equal(await page.locator("[data-company-lookup-button]").isDisabled(), true, "button must be disabled while loading");
  assert.equal(await page.locator("[data-company-lookup]").getAttribute("aria-busy"), "true");
  assert.equal((await page.locator("[data-company-lookup-status]").textContent()).trim(), "Se verifică datele societății...");
  await page.waitForFunction(() => document.querySelector("[data-company-lookup-status]")?.dataset.state === "success");

  assert.equal(await page.locator("[data-company-cui-input]").inputValue(), VALID_CUI, "RO prefix must be normalized in UI");
  assert.equal((await page.locator("[data-company-name]").textContent()).trim(), "BORG DESIGN SRL");
  assert.equal((await page.locator("[data-company-source]").textContent()).trim(), "ListaFirme");
  assert.match((await page.locator("[data-company-success-message]").textContent()).trim(), /completate automat/iu);
  assert.equal(await form.locator("[name=caen]").inputValue(), "6210");
  assert.equal(await form.locator("[name=establishedAt]").inputValue(), "2002-08-26");
  assert.equal(await form.locator("[name=headquartersCounty]").inputValue(), "sv");
  assert.equal(await form.locator("[name=employees2025]").inputValue(), "4");
  assert.equal(await form.locator("[name=netProfit2025]").inputValue(), "120000");
  assert.equal(await form.locator("[name=turnover2023]").inputValue(), "1100000");
  assert.equal(await form.locator("[name=turnover2024]").inputValue(), "1350000");
  assert.equal(await form.locator("[name=turnover2025]").inputValue(), "1500000");
  assert.equal(await form.locator("[name=assets2025]").inputValue(), "1000000");
  assert.equal(await form.locator("[name=debts2025]").inputValue(), "250000");
  assert.equal((await form.locator("[name=assets2025]").locator("xpath=.. ").locator(".micro2-auto-formatted").textContent()).trim(), "1.000.000 lei");
  assert.equal(await form.locator("[name=assets2025]").locator("xpath=.. ").locator(".micro2-auto-badge").getAttribute("title"), "Valoare calculată: Active imobilizate + Active circulante.");
  assert.equal(await form.locator(".micro2-auto-badge").count(), 10, "every populated public field gets an automatic indicator");

  for (const [name, expected] of Object.entries({ grant: "225000", ownContribution: "22", implementationCounty: "bt", newJobs: "3", disadvantagedHire: "yes" })) {
    assert.equal(await form.locator(`[name=${name}]`).inputValue(), expected, `${name} must not be overwritten`);
  }
  for (const name of ["microenterprise", "activityHistory", "fixedAssets", "deMinimis", "siteRights", "annexes", "cashFlow"]) {
    assert.equal(await form.locator(`[name=${name}]`).inputValue(), "", `${name} must remain De verificat`);
  }
  assert.match((await page.locator("[data-score-completion]").textContent()).trim(), /^11 \/ 11/u, "autofill must trigger existing score recalculation");
  assert.notEqual((await page.locator("[data-score-total]").textContent()).trim(), "25", "score panel must update after autofill");
  assert.equal((await page.locator("[data-score-verdict]").textContent()).includes("Firma este eligibilă"), false);

  await form.locator("[name=turnover2025]").fill("1600000");
  assert.equal(await form.locator("[name=turnover2025]").inputValue(), "1600000", "autofilled values remain editable");
  assert.equal(await form.locator("[name=turnover2025]").getAttribute("data-company-autofilled"), null, "manual edit removes provenance badge");
  apiMode = "success";
  await page.locator("[data-company-lookup-button]").click();
  await page.waitForFunction(() => document.querySelector("[data-company-lookup-status]")?.dataset.state === "success");
  assert.equal(await form.locator("[name=turnover2025]").inputValue(), "1500000", "only an explicit new lookup may replace a manual edit");

  apiMode = "partial";
  await page.locator("[data-company-lookup-button]").click();
  await page.waitForFunction(() => document.querySelector("[data-company-warning]")?.textContent.includes("doar o parte"));
  assert.equal(await form.locator("[name=assets2025]").inputValue(), "", "total assets must stay blank when one component is missing");
  assert.match((await page.locator("[data-company-warning]").textContent()).trim(), /Date financiare insuficiente/iu);

  apiMode = "not-found";
  await page.locator("[data-company-lookup-button]").click();
  await page.waitForFunction(() => document.querySelector("[data-company-lookup-status]")?.textContent.includes("Nu am identificat"));
  assert.equal(await page.locator("[data-company-summary]").isHidden(), true, "failed lookup must hide the previous company summary");
  assert.equal(await form.locator("[name=caen]").inputValue(), "", "failed explicit lookup must clear stale automatic company data");
  apiMode = "unavailable";
  await page.locator("[data-company-lookup-button]").click();
  await page.waitForFunction(() => document.querySelector("[data-company-lookup-status]")?.textContent.includes("Formularul poate fi completat manual"));

  const controls = await page.evaluate(() => ({
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    cuiHeight: document.querySelector("[data-company-cui-input]").getBoundingClientRect().height,
    buttonHeight: document.querySelector("[data-company-lookup-button]").getBoundingClientRect().height,
    allMappedEditable: Array.from(document.querySelectorAll("[data-company-autofilled]"), (field) => !field.disabled && !field.readOnly).every(Boolean)
  }));
  assert.ok(controls.overflow <= 1, `lookup must not cause horizontal overflow: ${controls.overflow}px`);
  assert.ok(controls.cuiHeight >= 44 && controls.buttonHeight >= 44, "lookup controls must have touch targets of at least 44px");
  assert.equal(controls.allMappedEditable, true, "automatic fields remain editable");
  await page.close();
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

console.log("PASS micro-apel-2 company lookup UI, states, autofill, recalculation and manual-field preservation");
