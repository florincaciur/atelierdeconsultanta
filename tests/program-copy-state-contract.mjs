import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import * as cheerio from 'cheerio';
const require = createRequire(import.meta.url);
const { programs } = require('../config/seo-programs.json');
const { fileForRoute } = require('../tools/structured-data-utils');
const root = new URL('../', import.meta.url);
const { fileURLToPath } = await import('node:url');
const preOpeningClaim = /depunerea\s+nu\s+(?:a\s+început|este\s+(?:încă\s+)?deschisă)/iu;
for (const program of programs.filter(p => p.canonicalStatus === 'OPEN')) {
  for (const [field, text] of Object.entries({ quickAnswer: program.quickAnswer, editorialDisclaimer: program.editorialDisclaimer, calendarNote: program.presentation?.calendar?.note })) {
    assert.doesNotMatch(text || '', preOpeningClaim, `${program.id}/${field}: o sesiune deschisă nu poate fi descrisă ca neîncepută`);
  }
  const $ = cheerio.load(fs.readFileSync(fileForRoute(fileURLToPath(root), program.pageUrl), 'utf8'));
  const copy = $('[data-program-calendar], [data-answer-field="status"]').text();
  assert.doesNotMatch(copy, preOpeningClaim, `${program.pageUrl}: calendarul și răspunsul direct contrazic statutul aprobat`);
}
for (const program of programs.filter(program => program.presentation?.guideRoutes?.length)) {
  for (const route of program.presentation.guideRoutes) {
    const $ = cheerio.load(fs.readFileSync(fileForRoute(fileURLToPath(root), route), 'utf8'));
    const notice = $(`[data-guide-program-status="${program.id}"]`);
    assert.equal(notice.length, 1, `${route}: lipsește contextul sesiunii din registru`);
    assert(notice.text().includes(program.statusLabel), `${route}: statutul ghidului este nesincronizat`);
    assert.equal(notice.find(`a[href="${program.pageUrl}"]`).length, 1);
  }
}
const dr12 = programs.find(program => program.id === 'dr12-afir');
const dr12Page = cheerio.load(fs.readFileSync(fileForRoute(fileURLToPath(root), dr12.pageUrl), 'utf8'));
for (const component of dr12.presentation.calendar.components) {
  assert(dr12Page(`[data-answer-field="applicationWindow"] time[datetime="${component.endAt}"]`).length
    || dr12Page(`.program-factual-status__facts time[datetime="${component.endAt}"]`).length,
    `${component.name}: termenul componentei trebuie afișat în rezumatul factual`);
}
console.log('Program copy state PASS: open-call summaries, component deadlines and guide session context.');
