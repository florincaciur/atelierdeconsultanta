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
console.log('Program copy state PASS: open calls have no contradictory pre-opening claims in summaries or calendars.');
