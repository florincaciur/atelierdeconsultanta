import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';

const root = path.resolve(import.meta.dirname, '..');
const remote = process.argv.find(arg => arg.startsWith('--base='))?.slice(7);
const out = path.join(root, '.codex', remote ? 'homepage-states-live' : 'homepage-states-local');
fs.mkdirSync(out, { recursive: true });
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.webp': 'image/webp' };
const server = http.createServer((req, res) => {
  let file = path.resolve(root, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
  if (!file.startsWith(root + path.sep) && file !== root) return res.writeHead(403).end();
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  if (!fs.existsSync(file)) return res.writeHead(404).end();
  res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
  fs.createReadStream(file).pipe(res);
});
if (!remote) await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = remote || `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const results = [];
try {
  await Promise.all([320, 390, 768, 1440].map(async width => {
    const context = await browser.newContext({ viewport: { width, height: 960 }, reducedMotion: 'reduce' });
    if (!remote) await context.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort());
    // Always intercept form submissions, including on production: no test leads.
    let submissions = 0;
    await context.route('**/api/contact-triage', route => {
      submissions += 1;
      return route.fulfill({ status: submissions === 1 ? 503 : 200, contentType: 'application/json', body: JSON.stringify(submissions === 1 ? { success: false, message: 'Eroare simulată pentru audit.' } : { success: true, leadId: 'local-audit-only' }) });
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base, { waitUntil: 'load' });
    await page.evaluate(() => document.fonts.ready);
    const darkPanelLabel = await page.locator('.homepage-contact-actions__label').evaluate(node => getComputedStyle(node).color);
    if (darkPanelLabel !== 'rgb(255, 255, 255)') results.push({ width, state: 'dark-contact-label', violations: [{ id: 'dark-panel-text-color', actual: darkPanelLabel }], clipped: [] });
    async function audit(state, selector = 'main', screenshot = true) {
      const target = page.locator(selector);
      await target.scrollIntoViewIfNeeded();
      await page.mouse.move(0, 0);
      const axe = await new AxeBuilder({ page }).include(selector).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa', 'best-practice']).analyze();
      const layout = await target.evaluate(el => ({
        overflow: document.documentElement.scrollWidth - innerWidth,
        clipped: [...el.querySelectorAll('input:not([type=hidden]), select, textarea, button, label, h1, h2, h3')].filter(node => {
          const style = getComputedStyle(node), box = node.getBoundingClientRect();
          if (!node.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
          // Tabs deliberately scroll inside their own rail on narrow screens.
          for (let parent = node.parentElement; parent && parent !== el; parent = parent.parentElement) {
            if (/auto|scroll/.test(getComputedStyle(parent).overflowX) && parent.scrollWidth > parent.clientWidth) return false;
          }
          return style.visibility !== 'hidden' && style.opacity !== '0' && (box.left < -1 || box.right > innerWidth + 1);
        }).map(node => ({ tag: node.tagName, id: node.id, text: node.textContent.trim().slice(0, 90) }))
      }));
      const panelContrast = await page.locator('.contact-form-panel').evaluate(panel => {
        const rgb = value => (value.match(/[\d.]+/g) || []).map(Number);
        const luminance = channels => channels.slice(0, 3).map(n => n / 255).map(n => n <= .04045 ? n / 12.92 : ((n + .055) / 1.055) ** 2.4).reduce((sum, n, i) => sum + n * [.2126, .7152, .0722][i], 0);
        const checks = [];
        for (const node of panel.querySelectorAll('*')) {
          if (!node.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) continue;
          const style = getComputedStyle(node);
          const hasText = [...node.childNodes].some(child => child.nodeType === 3 && child.textContent.trim());
          const placeholder = node.matches('input[placeholder],textarea[placeholder]') && !node.value;
          if (!hasText && !placeholder) continue;
          let background;
          for (let parent = node; parent; parent = parent.parentElement) {
            const color = rgb(getComputedStyle(parent).backgroundColor);
            if (color.length === 3 || color[3] === 1) { background = color; break; }
          }
          if (!background) continue;
          const foreground = rgb(placeholder ? getComputedStyle(node, '::placeholder').color : style.color);
          const a = luminance(foreground), b = luminance(background);
          const ratio = (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
          const large = parseFloat(style.fontSize) >= 24 || (parseFloat(style.fontSize) >= 18.66 && parseInt(style.fontWeight) >= 700);
          const minimum = large ? 3 : 4.5;
          if (ratio + .01 < minimum) checks.push({ selector: node.id || node.className || node.tagName, text: (node.textContent || node.placeholder).trim().slice(0, 90), ratio, minimum });
        }
        return checks;
      });
      const row = { width, state, ...layout, panelContrast, violations: axe.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.map(n => ({ target: n.target, summary: n.failureSummary })) })), incomplete: axe.incomplete.map(v => ({ id: v.id, targets: v.nodes.map(n => n.target) })) };
      results.push(row);
      if (screenshot && [390, 1440].includes(width)) await target.screenshot({ path: path.join(out, `${width}-${state}.png`) });
      console.log(`${width} ${state}: ${row.violations.length} violations, ${row.clipped.length} clipped controls, overflow ${row.overflow}px`);
    }
    await audit('initial');
    for (const id of ['hero', 'homepage-method', 'priority-programs', 'homepage-explorer', 'homepage-contact']) {
      if (await page.locator('#' + id).count()) await audit(id, '#' + id);
    }
    for (let i = 1; i < 5; i++) {
      await page.locator('[data-homepage-method-tab]').nth(i).click();
      await audit(`method-${i + 1}`, '#homepage-method');
    }
    for (let i = 1; i < 4; i++) {
      await page.locator('[data-homepage-explorer-tab]').nth(i).click();
      await audit(`explorer-${i + 1}`, '#homepage-explorer');
    }
    await page.locator('.im-contact-disclosure > summary').click();
    await audit('form-step-1', '#homepage-contact');
    await page.locator('[data-action="review-short"]').click();
    await audit('form-validation-errors', '#homepage-contact');
    await page.locator('#contact-applicant-type').selectOption('societate');
    await page.locator('#contact-location').fill('Iași');
    await page.locator('#contact-investment').fill('Date fictive pentru verificarea vizuală locală.');
    await page.locator('#contact-email').fill('qa@example.invalid');
    await page.locator('#privacy-notice-acknowledged').check();
    await page.locator('[data-action="add-details"]').click();
    for (const detail of await page.locator('#homepage-contact .contact-optional').all()) await detail.evaluate(node => { node.open = true; });
    await audit('form-step-2-expanded', '#homepage-contact');
    await page.locator('#contact-description').fill('Exemplu fictiv de investiție, fără trimitere către server.');
    await page.locator('[data-action="review-full"]').click();
    await audit('form-review', '#homepage-contact');
    await page.locator('[data-final-submit]').click();
    await page.locator('[data-retry-submit]').waitFor({ state: 'visible' });
    await audit('form-server-error', '#homepage-contact');
    await page.locator('[data-retry-submit]').click();
    await page.locator('[data-form-success]').waitFor({ state: 'visible' });
    await audit('form-success', '#homepage-contact');
    if (errors.length || submissions !== 2) results.push({ width, state: 'runtime', errors, submissions, violations: [{ id: 'runtime-or-form-flow' }], clipped: [] });
    await context.close();
  }));
} finally {
  await browser.close();
  if (server.listening) await new Promise(resolve => server.close(resolve));
  fs.writeFileSync(path.join(out, 'audit.json'), JSON.stringify({ date: new Date().toISOString(), base, results }, null, 2));
}
const failures = results.filter(row => row.violations.length || row.clipped.length || row.panelContrast?.length || row.overflow > 1);
console.log(`${results.length} homepage state/viewport checks; ${failures.length} need review. Report: ${out}`);
if (failures.length) process.exitCode = 1;
