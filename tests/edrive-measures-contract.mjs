import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import * as cheerio from 'cheerio';
const require=createRequire(import.meta.url);
const registry=require('../config/seo-programs.json').programs;
const program=registry.find(p=>p.id==='e-drive');
const $=cheerio.load(fs.readFileSync(new URL('../e-drive/index.html',import.meta.url),'utf8'));
assert.equal(program.canonicalStatus,'PUBLIC_CONSULTATION');
assert.equal(program.consultationEnd,'2026-11-18');
assert.equal(program.applicationStart,null,'Consultation must not become an application window');
assert.equal(program.applicationEnd,null);
assert.equal($('h1').length,1);
for(const id of ['masura-1','masura-2']) {
  assert.equal($(`main section#${id}`).length,1);
  assert($(`nav.edrive-navigation a[href="#${id}"]`).length,'Both measures must be reachable without JavaScript');
  assert.equal($(`#${id} h3`).length,5,'Each measure needs beneficiaries, fleet, finance, scoring and documents');
}
const m1=$('#masura-1').text(),m2=$('#masura-2').text();
assert.match(m1,/130\.000 EUR/);
assert.match(m1,/300\.000 EUR/);
assert.match(m1,/80 puncte.*70.*65/s);
assert.match(m2,/4931.*4932.*4933/s);
assert.match(m2,/4 milioane EUR/);
assert.match(m2,/70 puncte.*10 puncte.*20 puncte/s);
assert.match(m2,/diferența.*cost/si);
assert.match($('.edrive-notice').text(),/nu este termen de depunere/i);
assert($('a[href="https://fonduri.mt.ro/documente/GS_M1_%C8%99i_M2.zip"]').length);
assert.equal($('nav.edrive-navigation a[href="#calendar-depunere"]').length, 1);
assert.match($('#calendar-depunere').text(), /maximum 30 de zile.*publicarea ghidului în Monitorul Oficial/s);
assert.equal($('#calendar-depunere a[href$="/Monitorul_Oficial_Partea_I_nr._739.pdf"]').length, 1);
assert.match($('#masura-1 .edrive-measure__version a').attr('href'), /omti03112026dgpet-2$/);
assert.match($('#masura-2 .edrive-measure__version a').attr('href'), /omti03112026dgpet$/);
for (const route of ['e-move', 'e-mobility', 'finantari-panouri-fotovoltaice']) {
 const related = cheerio.load(fs.readFileSync(new URL(`../${route}/index.html`, import.meta.url), 'utf8'));
 for (const measure of ['masura-1', 'masura-2']) {
   assert(related(`main a[href="/e-drive#${measure}"]`).length, `${route} should link to ${measure}`);
 }
}
const nodes=$('script[type="application/ld+json"]').toArray().flatMap(el=>{
 const data=JSON.parse($(el).text());return data['@graph']||[data];
});
const page=nodes.find(n=>n['@type']==='WebPage');
assert.equal(page.hasPart.length,2,'Structured data must describe both visible measure sections');
for(const section of page.hasPart) {
 const measure = $(new URL(section.url).hash);
 assert.equal(measure.find('h2').text(),section.name);
 const officialGuide = measure.find('.edrive-measure__version a').attr('href');
 assert(section.citation.some(citation=>citation.url===officialGuide), 'Each measure should cite its official guide');
}
assert.equal($('meta[name="description"]').attr('content'),program.metaDescription);
assert.equal($('meta[property="og:title"]').attr('content'),program.metaTitle);
const {syncHtml}=require('../tools/sync-on-page-seo');
const sample=robots=>`<html><head><title>Test</title><meta name="description" content="Test"><meta name="robots" content="${robots}"><link rel="canonical" href="https://atelierdeconsultanta.ro/test"></head><body><h1>Test</h1></body></html>`;
assert.match(syncHtml(sample('index, follow')),/max-image-preview:large/);
assert.doesNotMatch(syncHtml(sample('noindex, follow')),/max-image-preview:large/);
assert.match(syncHtml(sample('index, max-snippet:20')),/max-snippet:20/);
assert.doesNotMatch(syncHtml(sample('index, max-snippet:20')),/max-snippet:-1/);
const headers=fs.readFileSync(new URL('../_headers',import.meta.url),'utf8');
const assetsRule=headers.match(/^\/assets\/\*\r?\n((?:[ \t]+[^\n]*\r?\n)*)/m)?.[1]||'';
assert.doesNotMatch(assetsRule,/noindex/i,'Shared image assets must remain eligible for image indexing');
for(const p of registry.filter(p=>p.canonicalStatus==='OPEN')) {
 assert(p.applicationStart<='2026-11-03' && p.applicationEnd>='2026-11-03',`${p.id}: OPEN requires a current verified window`);
}
// Authored explanations and FAQ must not contradict a newly synchronized status banner.
for (const [file, obsolete] of [
 ['dr12-afir/index.html', /nu anunțase încă intervalul|Calendarul depunerii nu este încă anunțat/i],
 ['dr14/index.html', /Termenul anunțat este 31 octombrie|și 31 octombrie 2026, ora 16:00/i],
 ['dr18/index.html', /depunerea nu era încă deschisă|o sesiune programată nu este încă deschisă/i],
 ['investitii-modernizarea-microintreprinderilor-apel-2/index.html', /Nu încă\. Apelul este lansat/i]
]) {
 const doc=cheerio.load(fs.readFileSync(new URL('../'+file,import.meta.url),'utf8'));
 const main=doc('main').clone();main.find('script,style,[data-editorial-governance]').remove();
 assert.doesNotMatch(main.text(),obsolete,`${file}: stale authored copy alongside current official status`);
}
console.log('e-DRIVE measures PASS: consultation, two server-rendered measures, distinct budgets/scoring/documents, source citations, schema parity and crawler previews.');
