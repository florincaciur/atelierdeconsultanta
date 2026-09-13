import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, '..');
const { visual, programForRoute } = require('../tools/sync-program-visuals');
const css = fs.readFileSync(path.join(ROOT, 'assets/program-visuals.css'), 'utf8');
const js = fs.readFileSync(path.join(ROOT, 'assets/site-immersive.js'), 'utf8');
const hero = visual('/dr14', programForRoute('/dr14'));
const browser = await chromium.launch();
try {
  for (const reducedMotion of ['no-preference', 'reduce']) {
    const page = await browser.newPage({ reducedMotion, viewport: { width: 1440, height: 960 } });
    await page.setContent(`<html><head><style>${css}</style></head><body data-site-immersive><main>${hero}</main></body></html>`);
    await page.addScriptTag({ content: js });
    const banner = page.locator('[data-program-visual]');
    const pause = page.locator('[data-program-animation-pause]');
    assert.equal(await pause.getAttribute('aria-pressed'), String(reducedMotion === 'reduce'));
    if (reducedMotion === 'no-preference') {
      await page.waitForFunction(() => document.querySelector('[data-program-visual]').dataset.activeStep === '2', null, { timeout: 6000 });
      assert.equal(await page.locator('.program-visual__live').getAttribute('aria-live'), 'off');
      assert.match(await page.locator('.program-visual__live').innerText(), /Investiție/);
      await pause.click();
      await page.mouse.move(0, 0);
      await pause.evaluate(el => el.blur());
      const step = await banner.getAttribute('data-active-step');
      await page.waitForTimeout(4000);
      assert.equal(await banner.getAttribute('data-active-step'), step, 'Pause stops automatic rotation even after focus leaves');
      assert.equal(await page.locator('.program-visual__track').first().evaluate(el => getComputedStyle(el).animationPlayState), 'paused');
    }
    await page.locator('[data-program-step="4"]').click();
    assert.equal(await banner.getAttribute('data-active-step'), '4', 'Manual selection works while paused');
    assert.equal(await page.locator('.program-visual__live').getAttribute('aria-live'), 'polite');
    if (reducedMotion === 'no-preference') {
      await pause.click();
      await page.mouse.move(0, 0);
      await pause.evaluate(el => el.blur());
      await page.waitForFunction(() => document.querySelector('[data-program-visual]').dataset.activeStep !== '4', null, { timeout: 6000 });
      assert.equal(await pause.getAttribute('aria-pressed'), 'false');
    }
    await page.close();
  }
  console.log('PASS program animation: automatic updates stay silent, pause/resume, manual selection and reduced motion.');
} finally { await browser.close(); }
