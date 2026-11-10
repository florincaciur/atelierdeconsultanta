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
const calendar = dr12.presentation.calendar;
const componentTable = dr12Page('[data-answer-field="deadline"] table');
assert.equal(componentTable.length, 1, 'DR-12: fișa pe componente trebuie să fie disponibilă în HTML');
assert.equal(componentTable.find('tbody tr').length, calendar.components.length);
assert.equal(dr12Page(`[data-answer-field="deadline"] time[datetime="${calendar.checkedAt}"]`).length, 1);
const fundingCalendar = cheerio.load(fs.readFileSync(fileForRoute(fileURLToPath(root), '/calendar-fonduri-europene'), 'utf8'));
const fundingRow = fundingCalendar('[data-calendar-program="dr12-afir"]');
const home = cheerio.load(fs.readFileSync(fileForRoute(fileURLToPath(root), '/'), 'utf8'));
assert.equal(home('[data-hero-program-item][data-program-id="dr12-afir"]').attr('data-status-label'), dr12.statusLabel);
assert(fundingRow.text().includes(dr12.statusLabel));
for (const [i, component] of calendar.components.entries()) {
  const row = componentTable.find('tbody tr').eq(i);
  assert.equal(row.find('th[scope="row"]').text(), component.name);
  assert.deepEqual(row.find('time').map((_, time) => dr12Page(time).attr('datetime')).get(), [component.startAt, component.endAt]);
  const calendarItem = fundingRow.find(`li:has(time[datetime="${component.endAt}"])`);
  assert(calendarItem.text().includes(row.find('td').last().text()));
}
if (calendar.components.some(component => component.endAt.includes('T00:00:00'))) {
  for (const text of [dr12Page('[data-answer-field="deadline"]').text(), fundingRow.text()]) {
    assert.match(text, /ora 00:00\b/u);
    assert.match(text, /începutul zilei/u);
  }
}
console.log('Program copy state PASS: open-call summaries, component deadlines and guide session context.');
