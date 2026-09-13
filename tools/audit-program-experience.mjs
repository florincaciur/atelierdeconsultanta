import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import sharp from 'sharp';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { routes } = require('./sync-program-visuals');
const { fileForRoute } = require('./structured-data-utils');
const args = Object.fromEntries(process.argv.slice(2).map(arg => arg.replace(/^--/, '').split('=')));
const label = args.label || 'current';
if (!/^[a-z0-9-]+$/i.test(label)) throw new Error('Invalid report label');
const out = path.join(ROOT, 'reports', `program-experience-${label}`);
fs.mkdirSync(out, { recursive: true });
const mime = { '.css': 'text/css', '.js': 'text/javascript', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.webp': 'image/webp', '.json': 'application/json', '.woff2': 'font/woff2' };
const server = http.createServer((req, res) => {
  try {
    const route = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    const file = path.extname(route) ? path.resolve(ROOT, route.replace(/^\/+/, '')) : fileForRoute(ROOT, route);
    if (!file.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404).end(); return; }
    res.setHeader('Content-Type', `${mime[path.extname(file)] || 'application/octet-stream'}; charset=utf-8`);
    fs.createReadStream(file).pipe(res);
  } catch { res.writeHead(500).end(); }
});
if (!args.base) await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = args.base || `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const results = [];
try {
  await Promise.all([390, 1440].map(async width => {
    const context = await browser.newContext({ viewport: { width, height: 960 }, reducedMotion: 'reduce' });
    // Exclude third-party widgets/analytics from the reproducible local audit.
    if (!args.base) await context.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort());
    const page = await context.newPage();
    for (const [index, route] of routes().entries()) {
      const errors = [], assets = [];
      const onError = error => errors.push(error.message);
      const onResponse = response => { if (response.status() >= 400 && response.url().startsWith(base)) assets.push({ url: response.url().replace(base, ''), status: response.status() }); };
      page.on('pageerror', onError); page.on('response', onResponse);
      const response = await page.goto(`${base}${route}`, { waitUntil: 'load' });
      await page.evaluate(() => document.fonts.ready);
      await page.mouse.move(0, 0);
      const metrics = await page.evaluate(() => {
        const visible = el => el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden';
        const h1 = [...document.querySelectorAll('h1')].map(el => el.textContent.trim());
        const missingAnchors = [...document.querySelectorAll('a[href^="#"]')].filter(el => el.hash.length > 1 && !document.getElementById(decodeURIComponent(el.hash.slice(1)))).map(el => ({ href: el.hash, text: el.textContent.trim() }));
        const duplicateIds = [...document.querySelectorAll('[id]')].map(el => el.id).filter((id, i, ids) => ids.indexOf(id) !== i);
        const smallText = [...document.querySelectorAll('main p, main li, main label')].filter(visible).filter(el => parseFloat(getComputedStyle(el).fontSize) < 14).map(el => ({ text: el.textContent.trim().slice(0, 80), size: getComputedStyle(el).fontSize }));
        const brokenImages = [...document.images].filter(el => el.complete && !el.naturalWidth).map(el => el.getAttribute('src'));
        const heroActionGroups = document.querySelectorAll('[data-program-visual] .hero-actions,[data-program-visual] .program-hero__actions').length;
        const heroStatusCount = document.querySelectorAll('.post-hero .program-hero__status').length;
        return { title: document.title, h1, canonical: document.querySelector('link[rel="canonical"]')?.href, robots: document.querySelector('meta[name="robots"]')?.content, missingAnchors, duplicateIds, brokenImages, smallText, heroActionGroups, heroStatusCount, pageHeight: document.documentElement.scrollHeight, overflow: document.documentElement.scrollWidth - innerWidth };
      });
      const accessibility = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa', 'best-practice']).analyze();
      const violations = accessibility.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help, helpUrl: v.helpUrl, nodes: v.nodes.map(n => ({ target: n.target, html: n.html, summary: n.failureSummary })) }));
      if (!('no-screenshots' in args)) {
        // Reveal below-fold sections through scrolling before the full-page capture.
        await page.evaluate(async () => {
          document.documentElement.style.scrollBehavior = 'auto';
          for (const el of document.querySelectorAll('[data-site-reveal]')) { el.scrollIntoView({ behavior: 'instant' }); await new Promise(resolve => setTimeout(resolve, 20)); }
          window.scrollTo({ top: 0, behavior: 'instant' });
          await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        });
        await page.screenshot({ path: path.join(out, `${index + 1}-${width}-top.png`) });
        await page.screenshot({ path: path.join(out, `${index + 1}-${width}-full.png`), fullPage: true });
      }
      const steps = page.locator('[data-program-step]');
      let stepsWork = null;
      if (await steps.count()) {
        await steps.nth(2).click();
        stepsWork = await steps.nth(2).getAttribute('aria-pressed') === 'true';
      }
      const pause = page.locator('[data-program-animation-pause]');
      let pauseWorks = null;
      if (await pause.count()) {
        const before = await pause.getAttribute('aria-pressed');
        await pause.click();
        pauseWorks = await pause.getAttribute('aria-pressed') !== before;
        await pause.click();
        pauseWorks &&= await pause.getAttribute('aria-pressed') === before;
        pauseWorks &&= await page.locator('[data-program-visual]').getAttribute('data-animation-paused') === before;
      }
      // Exercise disclosures using the same keyboard activation available to visitors.
      const disclosures = page.locator('main details > summary');
      let disclosuresWork = true;
      for (const summary of await disclosures.all()) {
        if (!await summary.isVisible()) continue;
        const before = await summary.evaluate(el => el.parentElement.open);
        await summary.focus(); await page.keyboard.press('Enter');
        disclosuresWork &&= await summary.evaluate(el => el.parentElement.open) !== before;
        await page.keyboard.press('Enter');
      }
      // Audit content hidden in disclosures separately from the initial view.
      await page.locator('main details').evaluateAll(nodes => nodes.forEach(node => { node.open = true; }));
      const expanded = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa', 'best-practice']).analyze();
      const expandedViolations = expanded.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.map(n => ({ target: n.target, summary: n.failureSummary })) }));
      let stickyWorks = null, stickyHeight = null;
      if (await page.locator('[data-sticky-cta]').count() && await page.locator('[data-contextual-hero-cta]').count()) {
        await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
        await page.waitForFunction(() => document.querySelector('[data-sticky-cta]').hidden);
        stickyWorks = true;
        await page.locator('[data-contextual-hero-cta]').evaluate(el => window.scrollTo({ top: scrollY + el.getBoundingClientRect().bottom + 150, behavior: 'instant' }));
        if (width < 760) {
          await page.waitForFunction(() => !document.querySelector('[data-sticky-cta]').hidden);
          stickyHeight = await page.locator('[data-sticky-cta]').evaluate(el => el.getBoundingClientRect().height);
          stickyWorks = stickyHeight <= 110;
          stickyWorks &&= await page.evaluate(() => parseFloat(getComputedStyle(document.body).paddingBottom) >= document.querySelector('[data-sticky-cta]').getBoundingClientRect().height - 1);
          if (!('no-screenshots' in args)) await page.screenshot({ path: path.join(out, `${index + 1}-${width}-sticky.png`) });
        } else stickyWorks = await page.locator('[data-sticky-cta]').isHidden();
      }
      let menuWorks = null;
      const menuToggle = page.locator('#hamburgerBtn');
      if (width === 390 && await menuToggle.isVisible()) {
        await menuToggle.click();
        menuWorks = await page.locator('#mobileMenu').isVisible();
        menuWorks &&= await menuToggle.getAttribute('aria-expanded') === 'true';
        await page.keyboard.press('Escape');
        // The first Escape closes the current program's expanded submenu;
        // a second Escape then closes its parent navigation panel.
        if (await page.locator('#mobileMenu').isVisible()) await page.keyboard.press('Escape');
        menuWorks &&= await page.locator('#mobileMenu').isHidden();
      }
      results.push({ route, width, status: response.status(), ...metrics, errors, assets, violations, expandedViolations, axeIncomplete: accessibility.incomplete.map(v => v.id), stepsWork, pauseWorks, disclosuresWork, menuWorks, stickyWorks, stickyHeight });
      page.off('pageerror', onError); page.off('response', onResponse);
      console.log(`${width} ${route}: ${violations.length} accessibility rules, ${metrics.missingAnchors.length} broken anchors`);
    }
    await context.close();
  }));
} finally {
  await browser.close();
  if (server.listening) await new Promise(resolve => server.close(resolve));
}
results.sort((a, b) => a.width - b.width || a.route.localeCompare(b.route));
fs.writeFileSync(path.join(out, 'audit.json'), JSON.stringify({ date: new Date().toISOString(), base, viewports: [390, 1440], results }, null, 2));
if (!('no-screenshots' in args)) {
  for (const width of [390, 1440]) {
    for (let start = 0; start < routes().length; start += 9) {
      const images = [];
      const cellWidth = 400, cellHeight = width === 390 ? 1020 : 327;
      for (let i = start; i < Math.min(start + 9, routes().length); i++) {
        const png = await sharp(path.join(out, `${i + 1}-${width}-top.png`)).resize(400).png().toBuffer();
        const x = ((i - start) % 3) * cellWidth, y = Math.floor((i - start) / 3) * cellHeight;
        const title = routes()[i].slice(0, 48);
        images.push({ input: Buffer.from(`<svg width="400" height="32"><rect width="400" height="32" fill="white"/><text x="8" y="22" font-size="12">${i + 1}. ${title}</text></svg>`), left: x, top: y });
        images.push({ input: png, left: x, top: y + 32 });
      }
      await sharp({ create: { width: 1200, height: cellHeight * 3, channels: 3, background: '#e5e7eb' } }).composite(images).png().toFile(path.join(out, `overview-${width}-${start / 9 + 1}.png`));
    }
  }
}
const failures = results.filter(r => r.status !== 200 || r.errors.length || r.assets.length || r.missingAnchors.length || r.duplicateIds.length || r.brokenImages.length || r.overflow > 1 || r.heroActionGroups > 1 || r.heroStatusCount > 1 || r.stepsWork === false || r.pauseWorks === false || r.menuWorks === false || r.stickyWorks === false || !r.disclosuresWork || r.violations.length || r.expandedViolations.length);
console.log(`${results.length} page/viewport combinations; ${failures.length} need review. Report: ${out}`);
if (failures.length) process.exitCode = 1;
