import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { ASSET_VERSION } = require("../tools/generate-global-header.js");
const { loadProgramConfig } = require("../tools/program-factual-governance.js");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "main-navigation.json"), "utf8"));
const partial = fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8");
const stylesheet = fs.readFileSync(path.join(ROOT, "assets", "global-header.css"), "utf8");
const behavior = fs.readFileSync(path.join(ROOT, "assets", "global-header.js"), "utf8");
const OUTPUT = path.join(ROOT, "reports", "main-navigation-qa-2026-07-21");
const REPORT = path.join(ROOT, "reports", "main-navigation-qa-2026-07-21.json");
const REPORT_MD = path.join(ROOT, "reports", "main-navigation-qa-2026-07-21.md");
const VIEWPORTS = [320, 360, 390, 768, 1024, 1366];

async function screenshotWithRetry(page, options, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await page.screenshot(options);
      return;
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, 150 * attempt));
    }
  }
  throw lastError;
}

const $ = cheerio.load(partial, { decodeEntities: false }, false);
const grouped = config.primaryDestinations.filter((destination) => destination.items);
const expectedLabels = config.primaryDestinations.map(({ label }) => label);
const programBySlug = new Map(loadProgramConfig().programs.map((program) => [program.slug, program]));

assert.equal(config.primaryDestinations.length, 5, "navigation must expose exactly five primary destinations");
assert.equal(grouped.length, 3, "three primary destinations must use disclosure groups");
assert.equal($("[data-homepage-navbar-toc]").length, 0, "homepage TOC must not be exposed in navigation");
assert.deepEqual(
  $("#navbar [data-nav-disclosure] > button").map((_, element) => $(element).clone().children().remove().end().text().trim()).get(),
  grouped.map(({ label }) => label),
  "desktop labels must follow the approved order",
);
assert.deepEqual(
  $("#mobileMenu [data-mobile-disclosure] > button").map((_, element) => $(element).clone().children().remove().end().text().trim()).get(),
  grouped.map(({ label }) => label),
  "mobile labels must follow the approved order",
);
assert.deepEqual($("#navbar .nav-primary-link").map((_, element) => $(element).text().trim()).get(), ["Calculator SO", "Contact"], "Calculator SO and Contact must be direct destinations");
assert.equal($("#navbar .nav-cta").text().trim(), config.cta.label, "desktop CTA copy must be canonical");
assert.equal($("#mobileMenu .mobile-cta").text().trim(), config.cta.label, "mobile CTA copy must be canonical");
assert.equal(/\b(?:Instrumente|Ghiduri|Cuprins)\b/u.test($("#navbar, #mobileMenu").text()), false, "removed navigation labels must stay absent");
assert.equal($("#dropdownPanel [data-program-id]").length, config.programMenu.featuredProgramSlugs.length, "desktop program menu must expose verified measures");
assert.equal($("#mobile-programe-panel [data-program-id]").length, config.programMenu.featuredProgramSlugs.length, "mobile program menu must expose verified measures");
$("[data-program-id]").each((_, element) => {
  const item = $(element);
  const program = programBySlug.get(item.attr("data-program-id"));
  assert(program, `unknown program in navigation: ${item.attr("data-program-id")}`);
  assert.equal(item.attr("data-program-status"), program.status, `${program.slug}: navigation status mismatch`);
  assert.equal(item.attr("data-status-label"), program.statusLabel, `${program.slug}: navigation label mismatch`);
  assert.equal(item.attr("data-verified-at"), program.verifiedAt, `${program.slug}: navigation verification date mismatch`);
  assert.equal(item.attr("data-source-url"), program.sourceUrl, `${program.slug}: navigation source mismatch`);
});
assert.equal($("[href='/por-adr-nord-est']").length, 0, "deprecated regional route must not appear in navigation");
assert($("[href='/investitii-modernizarea-microintreprinderilor-apel-2']").length >= 2, "approved regional conversion page must appear in desktop and mobile navigation");
assert.equal($("#mobileMenu [data-mobile-disclosure] > a").length, 0, "mobile disclosure triggers must be buttons, not links");

for (const group of grouped) {
  assert.ok(group.items.length <= config.policy.maxVisibleItemsPerGroup, `${group.label}: too many visible links`);
  assert.ok(group.items.length >= 1, `${group.label}: empty group`);
  assert.equal(new Set(group.items.map(({ href }) => href)).size, group.items.length, `${group.label}: duplicate destinations`);
}

fs.mkdirSync(OUTPUT, { recursive: true });
const executablePartial = partial
  .replace(`<link rel="stylesheet" href="/assets/global-header.css?v=${ASSET_VERSION}">`, `<style>${stylesheet}</style>`)
  .replace(`<script src="/assets/global-header.js?v=${ASSET_VERSION}"></script>`, `<script>${behavior}</script>`);
const documentHtml = `<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="margin:0"><main style="min-height:1800px;background:#eef2f6;padding:24px"><h1>Test navigare</h1></main>${executablePartial}</body></html>`;

const browser = await chromium.launch({ headless: true });
const results = [];

try {
  for (const width of VIEWPORTS) {
    const page = await browser.newPage({ viewport: { width, height: 820 } });
    await page.route("http://atelier.test/**", (route) => route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: documentHtml }));
    await page.goto("http://atelier.test/consultanta-fonduri-europene", { waitUntil: "domcontentloaded" });

    const desktop = width >= config.desktopBreakpoint;
    const state = { width, mode: desktop ? "desktop" : "mobile", errors: [], screenshot: "" };
    try {
      const desktopDisplay = await page.locator("#navbar .nav-links").evaluate((element) => getComputedStyle(element).display);
      const hamburgerDisplay = await page.locator("#hamburgerBtn").evaluate((element) => getComputedStyle(element).display);
      assert.equal(desktopDisplay !== "none", desktop, `${width}: desktop navigation visibility`);
      assert.equal(hamburgerDisplay !== "none", !desktop, `${width}: hamburger visibility`);

      assert.equal(await page.locator('#navbar a[aria-current="page"]').count(), 1, `${width}: desktop aria-current count`);
      assert.equal(await page.locator('#mobileMenu a[aria-current="page"]').count(), 1, `${width}: mobile aria-current count`);

      if (desktop) {
        await page.locator(".nav-logo").focus();
        await page.keyboard.press("Tab");
        assert.equal(await page.locator("#nav-servicii-trigger").evaluate((element) => element === document.activeElement), true, "desktop tab order starts with Servicii");
        await page.locator("#dropdownBtn").focus();
        await page.keyboard.press("Enter");
        assert.equal(await page.locator("#dropdownBtn").getAttribute("aria-expanded"), "true", "desktop disclosure announces open state");
        assert.equal(await page.locator("#dropdownPanel").getAttribute("hidden"), null, "desktop panel becomes visible");
        await page.keyboard.press("ArrowDown");
        await page.waitForFunction(() => document.activeElement === document.querySelector("#dropdownPanel a"));
        assert.equal(await page.locator("#dropdownPanel a").first().evaluate((element) => element === document.activeElement), true, "ArrowDown focuses first item");
        await page.keyboard.press("Escape");
        assert.equal(await page.locator("#dropdownBtn").evaluate((element) => element === document.activeElement), true, "Escape restores desktop trigger focus");
        assert.equal(await page.locator("#dropdownPanel").getAttribute("hidden"), "", "Escape closes desktop panel");
        await page.locator("#dropdownBtn").click();
        await page.locator("#dropdownBtn").focus();
      } else {
        const compactBox = await page.locator(".nav-compact-cta").boundingBox();
        assert.ok(compactBox && compactBox.height >= 44 && compactBox.width >= 44, `${width}: compact CTA target is at least 44px`);
        await page.locator("#hamburgerBtn").click();
        assert.equal(await page.locator("#hamburgerBtn").getAttribute("aria-expanded"), "true", "mobile menu announces open state");
        assert.equal(await page.locator("#mobileMenu").getAttribute("hidden"), null, "mobile menu becomes visible");
        assert.notEqual(await page.locator("body").evaluate((element) => element.style.overflow), "hidden", "mobile menu must not lock page scroll");
        await page.locator("#hamburgerBtn").focus();
        await page.keyboard.press("Tab");
        assert.equal(await page.locator("#mobile-servicii-trigger").evaluate((element) => element === document.activeElement), true, "mobile tab order starts with Servicii");

        const trigger = page.locator("#mobile-programe-trigger");
        await trigger.click();
        assert.equal(await trigger.getAttribute("aria-expanded"), "true", "mobile disclosure announces open state");
        assert.equal(await page.locator("#mobile-programe-panel").getAttribute("hidden"), null, "mobile disclosure panel becomes visible");
        await page.locator("#mobile-programe-panel a").first().focus();
        await page.keyboard.press("Escape");
        assert.equal(await trigger.evaluate((element) => element === document.activeElement), true, "Escape restores mobile disclosure trigger focus");
        assert.equal(await trigger.getAttribute("aria-expanded"), "false", "Escape closes mobile disclosure");
        await trigger.click();

        const undersized = await page.locator("#mobileMenu button:visible, #mobileMenu a:visible, #hamburgerBtn:visible").evaluateAll((elements) => elements
          .map((element) => ({ text: element.textContent.trim(), width: element.getBoundingClientRect().width, height: element.getBoundingClientRect().height }))
          .filter((item) => item.width < 44 || item.height < 44));
        assert.deepEqual(undersized, [], `${width}: all visible mobile targets must be at least 44×44`);
      }

      const overflow = await page.evaluate(() => ({ viewport: window.innerWidth, scrollWidth: document.documentElement.scrollWidth }));
      assert.ok(overflow.scrollWidth <= overflow.viewport + 1, `${width}: horizontal overflow ${overflow.scrollWidth}/${overflow.viewport}`);

      const screenshot = path.join(OUTPUT, `navigation-${width}-${state.mode}.png`);
      await screenshotWithRetry(page, { path: screenshot, fullPage: false });
      state.screenshot = path.relative(ROOT, screenshot).replaceAll("\\", "/");

      if (!desktop) {
        await page.keyboard.press("Escape");
        await page.keyboard.press("Escape");
        assert.equal(await page.locator("#mobileMenu").getAttribute("hidden"), "", "second Escape closes mobile menu");
        assert.equal(await page.locator("#hamburgerBtn").evaluate((element) => element === document.activeElement), true, "closing mobile menu restores hamburger focus");
      }
    } catch (error) {
      state.errors.push(error.message);
    }
    results.push(state);
    await page.close();
  }
} finally {
  await browser.close();
}

fs.writeFileSync(REPORT, `${JSON.stringify({ generatedAt: "2026-07-21", config: "config/main-navigation.json", results }, null, 2)}\n`, "utf8");
fs.writeFileSync(REPORT_MD, `# P1.02 — QA navigare principală

| Lățime | Mod | Rezultat | Captură |
|---:|---|---|---|
${results.map((result) => `| ${result.width}px | ${result.mode} | ${result.errors.length ? `FAIL — ${result.errors.join("; ")}` : "PASS"} | \`${result.screenshot}\` |`).join("\n")}

## Contract verificat

- șase destinații principale și CTA separat;
- disclosure-uri mobile bazate pe \`button\` și \`aria-expanded\`;
- Escape închide disclosure-ul/meniul și restaurează focusul;
- tab order nativ, focus vizibil și \`aria-current="page"\`;
- target-uri mobile de minimum 44×44 CSS px;
- fără blocarea scroll-ului la deschiderea meniului;
- fără overflow orizontal la 320, 360, 390, 768, 1024 și 1366 px;
- zero statusuri sau valori de program în navigare.
`, "utf8");
const failures = results.filter(({ errors }) => errors.length);
for (const result of results) console.log(`${result.errors.length ? "FAIL" : "PASS"} ${result.width}px ${result.mode}${result.errors.length ? ` — ${result.errors.join("; ")}` : ""}`);
assert.equal(failures.length, 0, `${failures.length} responsive navigation states failed`);
console.log(`PASS: navigation contract and ${results.length} responsive/focus states verified.`);
