'use strict';
const fs = require('fs');
const path = require('path');
const http = require('http');
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { default: AxeBuilder } = require('@axe-core/playwright');
const root = path.resolve(__dirname, '..');
const out = path.join(root, '.codex/dr12-final-ui');
fs.mkdirSync(out, { recursive: true });
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.webp': 'image/webp' };
const server = http.createServer((req, res) => {
  let file = path.join(root, decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) return res.writeHead(404).end();
  res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
  fs.createReadStream(file).pipe(res);
});

(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch();
  const results = [];
  try {
    for (const width of [320, 390, 768, 1440]) {
      const context = await browser.newContext({ viewport: { width, height: 960 }, reducedMotion: 'reduce' });
      const page = await context.newPage();
      await page.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort());
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(base + '/dr12-afir#dr12-punctaj');
      await page.locator('[data-dr12-calculator]').waitFor({ state: 'visible' });
      await page.locator('select[name=education]').selectOption('20');
      await page.locator('select[name=association]').selectOption('10');
      await page.locator('input[name=land]').fill('100');
      await page.locator('input[name=building]').check();
      await page.locator('input[name=precision]').fill('10');
      await page.locator('input[name=circular]').check();
      await page.locator('select[name=risk]').selectOption('forest');
      await page.locator('select[name=history]').selectOption('installation');
      assert.equal(await page.locator('[data-dr12-total]').innerText(), '100');
      await page.locator('[data-dr12-calculator]').screenshot({ path: path.join(out, `calculator-${width}.png`) });
      await page.locator('button[type=reset]').click();
      await page.waitForFunction(() => document.querySelector('[data-dr12-total]').textContent === '0');
      await page.locator('input[name=insurance]').fill('50');
      await page.locator('select[name=risk]').selectOption('forest');
      await page.locator('select[name=risk]').selectOption('insurance');
      assert.equal(await page.locator('[data-dr12-total]').innerText(), '5', 'insurance restored on first change');
      await page.locator('input[name=insurance]').fill('0');
      await page.locator('input[name=land]').fill('101');
      assert.equal(await page.locator('[data-dr12-total]').innerText(), '—');
      await page.locator('input[name=land]').fill('0');
      const axe = await new AxeBuilder({ page }).include('main').analyze();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      await page.goto(base + '/dr12-afir');
      await page.screenshot({ path: path.join(out, `dr12-${width}.png`) });
      const result = { width, errors, overflow, violations: axe.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) })) };
      results.push(result);
      console.log(JSON.stringify(result));
      await context.close();
    }
    fs.writeFileSync(path.join(out, 'visual.json'), JSON.stringify(results, null, 2));
    assert(!results.some(r => r.errors.length || r.overflow > 0 || r.violations.length), 'UI/accessibility regression');
  } finally {
    await browser.close();
    server.close();
  }
})().catch(error => { console.error(error); server.close(); process.exitCode = 1; });
