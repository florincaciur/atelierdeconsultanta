import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import * as cheerio from 'cheerio';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, '..');
const { fileForRoute } = require('../tools/structured-data-utils');
const { findPublicHtmlFiles } = require('../tools/sync-global-header');
const { validateConfig } = require('../tools/validate-seo-snippets');
const DIST = process.argv.includes('--dist');
const BASE = DIST ? path.join(ROOT, 'dist') : ROOT;
const logo = '/assets/faber-navbar-20260906.jpg';
assert.equal(createHash('sha256').update(fs.readFileSync(path.join(BASE, logo))).digest('hex'),
  'a9bd8ebbc9c0b787dc7e57abcfb121219b30ce0a4e6a58877199492b4da12a56', 'Logo must preserve the supplied image');

let checked = 0;
for (const source of findPublicHtmlFiles()) {
  const file = path.join(BASE, source);
  if (!fs.existsSync(file)) continue;
  const $ = cheerio.load(fs.readFileSync(file, 'utf8'));
  if (!$('#navbar').length) continue;
  const images = $('#navbar .nav-logo img');
  assert.equal(images.length, 1, `${file}: one logo in navbar`);
  assert.equal(images.attr('src'), logo, `${file}: same supplied logo on every page`);
  assert.equal(images.attr('alt'), 'FABER – Atelier de Consultanță');
  assert.equal($('#navbar .nav-logo svg').length, 0, `${file}: no previous navbar logo`);
  checked++;
}
assert.ok(checked >= 100, 'Check public navbar coverage');

const cases = [
  ['/dr14', [/Sesiune deschisă|depuneri deschise/i, /50\.000/, /montaj/i], [/Nu încă\./i]],
  ['/dr12-afir', [/200\.000/, /consultativ/i, /12\.000/], [/Pentru query-ul/i]],
  ['/investitii-modernizarea-microintreprinderilor-apel-2', [/100\.000/, /300\.000/, /28 septembrie 2026/i], []],
  ['/e-drive', [/30\.000/, /300\.000/, /4 milioane/, /60 de zile/], []],
  ['/pro-infra', [/15(?:\.000\.000| milioane)/, /EMS/, /excep/i], []],
  ['/e-mobility', [/30 milioane/, /75%/, /pe șosea/, /nou-înființate/], []],
  ['/diaspora-investeste-acasa', [/200\.000/, /5%/, /10%/, /15%/, /operaționalizare/], []],
];
for (const [route, expected, forbidden] of cases) {
  const $ = cheerio.load(fs.readFileSync(fileForRoute(BASE, route), 'utf8'));
  const main = $('main').clone(); main.find('script,style,nav').remove();
  const text = main.text().replace(/\s+/g, ' ');
  for (const pattern of expected) assert.match(text, pattern, `${route}: required factual answer`);
  for (const pattern of forbidden) assert.doesNotMatch(text, pattern, `${route}: outdated answer`);
  assert.equal($('h1').length, 1, `${route}: one H1`);
  assert.equal($('head > title').length, 1);
  assert.equal($('link[rel=canonical]').attr('href'), `https://atelierdeconsultanta.ro${route}`);
  assert.doesNotMatch($('meta[name=robots]').attr('content') || '', /noindex|nosnippet/);
  assert.equal($('[data-aeo-program-summary]').first().attr('data-verified-at'), '2026-09-06');
  $('script[type="application/ld+json"]').each((_, el) => assert.doesNotThrow(() => JSON.parse($(el).html())));
}

const snippets = JSON.parse(fs.readFileSync(path.join(ROOT, 'config/seo-snippets.json')));
const page = snippets.pages.find(p => p.route.includes('microintreprinderilor-apel-2'));
page.title = 'Microîntreprinderi Nord-Est, Apel 2: 100.000–300.000 €';
assert.ok(!validateConfig(snippets).errors.some(e => e.includes('majuscule excesive')), 'Funding numbers are not uppercase words');
page.title += ' EXTRA SUPER';
assert.ok(validateConfig(snippets).errors.some(e => e.includes('majuscule excesive')), 'Uppercase spam remains rejected');
console.log(`Program SEO/logo regression PASS: 7 pages; ${checked} public navbars; original logo bytes; funding labels and snippet rules (${DIST ? 'dist' : 'source'}).`);
