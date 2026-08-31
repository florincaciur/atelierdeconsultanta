import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { chromium } from "playwright";

const ROOT = path.resolve(import.meta.dirname, "..");
const require = createRequire(import.meta.url);
const { carouselPrograms, loadProgramConfig } = require("../tools/program-factual-governance");
const homepagePrograms = carouselPrograms(loadProgramConfig().programs);
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".json": "application/json", ".svg": "image/svg+xml", ".webp": "image/webp", ".png": "image/png" };
const server = http.createServer((request, response) => {
  let pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  if (pathname === "/") pathname = "/index.html";
  let file = path.join(ROOT, pathname.replace(/^\//, ""));
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
  if (!file.startsWith(ROOT) || !fs.existsSync(file)) { response.writeHead(404); response.end("Not found"); return; }
  response.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream", "Cache-Control": "no-store" });
  fs.createReadStream(file).pipe(response);
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true });

try {
  for (const viewport of [{ width: 320, height: 720 }, { width: 390, height: 844 }, { width: 768, height: 900 }, { width: 1366, height: 768 }]) {
    const page = await browser.newPage({ viewport });
    const consoleErrors = [];
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      const location = message.location().url || "inline";
      consoleErrors.push(`${message.text()} (${location})`);
    });
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    await page.locator("[data-priority-carousel]").waitFor({ state: "visible" });
    const metrics = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      forms: document.querySelectorAll("main form").length,
      scrollY: window.scrollY,
      carousels: document.querySelectorAll("main [data-priority-carousel]").length,
      sections: document.querySelectorAll("main > section").length,
      ctaBottom: document.querySelector("#hero .btn-primary")?.getBoundingClientRect().bottom,
      tocOpen: document.querySelector("#nav-homepage-toc-trigger")?.getAttribute("aria-expanded") === "true",
      familyDescription: document.querySelectorAll(".homepage-program-hubs").length,
      methodVisible: Array.from(document.querySelectorAll("[data-homepage-method-frame]")).filter((node) => getComputedStyle(node).display !== "none").length,
      explorerVisible: Array.from(document.querySelectorAll("[data-homepage-explorer-frame]")).filter((node) => getComputedStyle(node).display !== "none").length
    }));
    assert(metrics.overflow <= 0, `${viewport.width}px: scroll orizontal`);
    assert.equal(metrics.forms, 1);
    assert.equal(metrics.scrollY, 0, "formularul integrat nu trebuie să mute pagina la încărcare");
    assert.equal(metrics.carousels, 1);
    assert.equal(metrics.sections, 5);
    assert.equal(metrics.tocOpen, false);
    assert.equal(metrics.familyDescription, 0);
    assert.equal(metrics.methodVisible, 1);
    assert.equal(metrics.explorerVisible, 1);
    const sceneFits = await page.locator('.hero-program-scene.is-active svg').evaluate(node => node.getBoundingClientRect().height <= node.parentElement.getBoundingClientRect().height + 1);
    assert(sceneFits, `${viewport.width}px: ilustrația trebuie să încapă integral în cadru`);
    if (viewport.width === 390 || viewport.width === 1366) assert(metrics.ctaBottom <= viewport.height, `${viewport.width}px: CTA-ul principal este sub fold`);
    const choices = page.locator("[data-hero-program-item]");
    for (let index = 0; index < await choices.count(); index++) {
      const choice = choices.nth(index);
      await choice.hover();
      const id = await choice.getAttribute("data-program-id");
      assert.equal(await page.locator("[data-program-scene]:not([hidden])").count(), 1);
      assert.equal(await page.locator("[data-program-scene]:not([hidden])").getAttribute("data-program-scene"), id);
      assert.equal(await page.locator("[data-hero-program-link]").getAttribute("href"), await choice.getAttribute("href"));
    }
    await choices.nth(0).click();
    assert.equal(new URL(page.url()).pathname, "/", "selectarea unei măsuri trebuie să arate previzualizarea fără navigare");
    await choices.nth(0).press("ArrowRight");
    assert.equal(await choices.nth(1).getAttribute("aria-pressed"), "true");
    await page.locator("[data-priority-next]").click();
    assert.equal((await page.locator("[data-priority-counter]").textContent()).trim(), `2 din ${homepagePrograms.length}`);
    // Scrolling back from the catalogue now enters the last method stage.
    // Select a known starting stage before testing the manual next control.
    await page.locator("#homepage-method-tab-1").click();
    await page.waitForFunction(() => {
      const method = document.querySelector("#homepage-method");
      if (!method.classList.contains("im-scroll-enabled")) return true;
      const travel = method.offsetHeight - (innerHeight - 80);
      return Math.abs(method.getBoundingClientRect().top - (80 - travel * .06)) < 5;
    });
    await page.locator("[data-homepage-method-next]").click();
    assert.match((await page.locator("[data-homepage-method-status]").textContent()).trim(), /^Etapa 2 din 5:/);
    assert.equal(await page.locator("[data-homepage-method]").getAttribute("data-active-index"), "1");
    assert.equal(await page.locator("[data-homepage-method-indicator]").getAttribute("data-active-index"), "1");
    assert.equal(await page.locator("[data-homepage-method-tab][aria-selected='true']").getAttribute("data-method-index"), "1");
    assert.equal(await page.locator(".im-method-sculpture .im-slab.is-active").count(), 1);
    assert.equal(await page.locator(".im-method-sculpture .im-slab.is-active span").textContent(), "02");
    await page.locator("[data-homepage-explorer-next]").click();
    assert.match((await page.locator("[data-homepage-explorer-status]").textContent()).trim(), /^Secțiunea 2 din 4:/);
    assert.equal(await page.locator("[data-homepage-explorer-frame]").evaluateAll((frames) => frames.filter((node) => getComputedStyle(node).display !== "none").length), 1);
    if (viewport.width === 1366) {
      // A reload clears any in-flight manual scroll; native scrolling must
      // move the sequence in both directions while the content stays pinned.
      await page.reload({ waitUntil: "domcontentloaded" });
      for (const [progress, expected] of [[.7, 3], [.25, 1]]) {
        await page.evaluate((fraction) => {
          const method = document.querySelector("#homepage-method");
          const start = scrollY + method.getBoundingClientRect().top - 80;
          const travel = method.offsetHeight - (innerHeight - 80);
          scrollTo({ top: start + travel * fraction, behavior: "instant" });
        }, progress);
        await page.waitForFunction((index) => document.querySelector(`[data-homepage-method-tab][data-method-index="${index}"]`).getAttribute("aria-selected") === "true", expected);
        assert.equal(await page.locator(".im-method-sculpture .im-slab.is-active span").textContent(), String(expected + 1).padStart(2, "0"));
        const pinnedTop = await page.locator(".homepage-method-layout").evaluate(node => node.getBoundingClientRect().top);
        assert(Math.abs(pinnedTop - 80) < 2, "metoda trebuie să rămână vizibilă la scroll");
      }
      await page.locator("[data-im-motion]").click();
      assert.equal(await page.locator("[data-im-motion]").getAttribute("aria-pressed"), "true");
      assert.equal(await page.locator("#homepage-method").evaluate(node => node.classList.contains("im-scroll-enabled")), false);
      await page.reload({ waitUntil: "domcontentloaded" });
      assert.equal(await page.locator("[data-im-motion]").getAttribute("aria-pressed"), "true", "preferința trebuie păstrată");
      await page.locator("[data-im-motion]").click();
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.waitForFunction(() => document.documentElement.classList.contains("im-motion-off"));
      assert.equal(await page.locator("#homepage-method").evaluate(node => node.classList.contains("im-scroll-enabled")), false);
    }
    assert.deepEqual(consoleErrors, [], `${viewport.width}px: erori console`);
    await page.close();
  }
  const formPage = await browser.newPage({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
  const submissions = [];
  await formPage.route(/^https?:\/\/(?!127\.0\.0\.1)/u, route => route.abort());
  await formPage.route("**/api/contact-triage", async route => {
    submissions.push(route.request().postData());
    await route.fulfill({ status: submissions.length === 1 ? 503 : 200, contentType: "application/json", body: JSON.stringify(submissions.length === 1 ? { success: false, message: "Eroare simulată pentru verificarea reîncercării." } : { success: true, leadId: "homepage-test-only" }) });
  });
  await formPage.goto(baseUrl, { waitUntil: "domcontentloaded" });
  assert.equal(await formPage.locator('.contact-no-js-submit').isVisible(), false, "submit-ul de rezervă nu trebuie să dubleze fluxul cu JavaScript");
  await formPage.locator('[data-hero-program-item][data-program-id="e-drive"]').tap();
  assert.equal(await formPage.locator('[data-program-scene]:not([hidden])').getAttribute('data-program-scene'), 'e-drive', "atingerea selectează scena fără a deschide pagina programului");
  assert.equal(new URL(formPage.url()).pathname, "/");
  await formPage.locator('[data-action="review-short"]').click();
  assert.equal(await formPage.locator('[data-error-summary]').isVisible(), true);
  assert.equal(submissions.length, 0, "formularul incomplet nu se trimite");
  await formPage.locator('#contact-applicant-type').selectOption('societate');
  await formPage.locator('#contact-location').fill('Test local');
  await formPage.locator('#contact-investment').fill('Verificare locală a formularului, date fictive.');
  await formPage.locator('#contact-email').fill('qa@example.invalid');
  await formPage.locator('#privacy-notice-acknowledged').check();
  await formPage.locator('[data-action="add-details"]').click();
  await formPage.locator('#contact-description').fill('Detaliu păstrat între etape.');
  await formPage.locator('[data-action="back-to-step-1"]').click();
  assert.equal(await formPage.locator('#contact-email').inputValue(), 'qa@example.invalid');
  await formPage.locator('[data-action="review-short"]').click();
  await formPage.locator('[data-final-submit]').click();
  await formPage.locator('[data-retry-submit]').waitFor({ state: 'visible' });
  assert.equal(await formPage.locator('#contact-email').inputValue(), 'qa@example.invalid');
  await formPage.locator('[data-retry-submit]').click();
  await formPage.locator('[data-form-success]').waitFor({ state: 'visible' });
  assert.equal(submissions.length, 2);
  assert.match(submissions[0], /name="page_url"\r\n\r\n\/\r\n/);
  assert.match(submissions[0], /name="source_page"\r\n\r\n\/\r\n/);
  assert.equal(await formPage.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), true);
  await formPage.close();

  const hoverPage = await browser.newPage({ viewport: { width: 1366, height: 900 }, reducedMotion: "reduce" });
  await hoverPage.route(/^https?:\/\/(?!127\.0\.0\.1)/u, route => route.abort());
  await hoverPage.goto(baseUrl, { waitUntil: "domcontentloaded" });
  for (let index = 0; index < 5; index += 1) {
    await hoverPage.locator("[data-homepage-method-tab]").nth(index).hover();
    await hoverPage.waitForFunction(expected => document.querySelector("[data-homepage-method]").dataset.activeIndex === String(expected), index);
    assert.equal(await hoverPage.locator(".im-method-sculpture .im-slab.is-active").count(), 1);
    assert.equal(await hoverPage.locator(".im-method-sculpture .im-slab.is-active span").textContent(), String(index + 1).padStart(2, "0"));
    assert.match(await hoverPage.locator(".im-slab.is-active").evaluate(node => getComputedStyle(node).backgroundImage), /linear-gradient/);
  }
  await hoverPage.close();

  const noScriptPage = await browser.newPage({ javaScriptEnabled: false, viewport: { width: 390, height: 844 } });
  await noScriptPage.goto(baseUrl, { waitUntil: "load" });
  assert.equal(await noScriptPage.locator("#hero .btn-primary").isVisible(), true);
  assert.equal(await noScriptPage.locator("[data-im-motion]").isVisible(), false);
  assert.equal(await noScriptPage.locator("[data-hero-program-item]").first().getAttribute("role"), null, "fără JavaScript măsurile rămân linkuri obișnuite");
  assert.equal(await noScriptPage.locator("#contact-triage-form [data-form-step='2']").isVisible(), true);
  assert.equal(await noScriptPage.locator("[data-homepage-method-frame]").evaluateAll(nodes => nodes.filter(node => getComputedStyle(node).display !== "none").length), 5);
  assert.equal(await noScriptPage.locator("[data-homepage-explorer-frame]").evaluateAll(nodes => nodes.filter(node => getComputedStyle(node).display !== "none").length), 4);
  await noScriptPage.close();
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

console.log("Homepage responsive PASS: 320, 390, 768 și 1366 px; carusel, scroll în ambele sensuri, mișcare redusă, preferință persistentă și fallback fără JavaScript.");
