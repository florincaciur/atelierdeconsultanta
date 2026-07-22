import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "aeo-question-blocks.json"), "utf8"));
const failures = [];

function wordCount(value) {
  return (String(value).match(/[\p{L}\p{N}]+(?:[’'-][\p{L}\p{N}]+)*/gu) || []).length;
}

function internalTargetExists(href) {
  const url = new URL(href, "https://atelierdeconsultanta.ro");
  const route = url.pathname.replace(/\/$/u, "") || "/";
  const candidates = route === "/"
    ? [path.join(ROOT, "index.html")]
    : [path.join(ROOT, `${route.replace(/^\//u, "")}.html`), path.join(ROOT, route.replace(/^\//u, ""), "index.html")];
  const file = candidates.find((candidate) => fs.existsSync(candidate));
  if (!file) return false;
  if (!url.hash) return true;
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html);
  return $(`[id="${decodeURIComponent(url.hash.slice(1))}"]`).length === 1;
}

for (const page of config.pages) {
  const file = path.join(ROOT, page.file);
  if (!fs.existsSync(file)) {
    failures.push(`${page.route}: fișierul sursă lipsește`);
    continue;
  }
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html);
  const block = $("[data-aeo-question-set]");
  const questions = block.find("[data-aeo-question]");

  if (block.length !== 1) failures.push(`${page.route}: trebuie să existe exact un bloc AEO`);
  if (questions.length !== page.questions.length) failures.push(`${page.route}: numărul de întrebări din HTML diferă de registru`);
  if (questions.length < 3 || questions.length > 6) failures.push(`${page.route}: sunt permise 3–6 întrebări`);
  if ($(`link[href^="/assets/aeo-question-blocks.css"]`).length !== 1) failures.push(`${page.route}: stylesheet-ul P1.18 lipsește sau este duplicat`);
  if ($(`details[open]`).length > 6) failures.push(`${page.route}: mai mult de șase disclosures sunt deschise inițial`);
  if (block.is("[hidden]") || block.parents("[hidden]").length || /display\s*:\s*none/iu.test(block.attr("style") || "")) failures.push(`${page.route}: răspunsurile AEO sunt ascunse`);
  if (block.find("script, [data-ai], [data-ai-answer]").length) failures.push(`${page.route}: blocul AEO conține markup sau logică specială AI`);

  for (const question of page.questions) {
    const article = block.find(`[data-aeo-question="${question.id}"]`);
    if (article.length !== 1) {
      failures.push(`${page.route} / ${question.id}: articol absent sau duplicat`);
      continue;
    }
    const h2 = article.children("h2").first();
    const direct = article.children("[data-aeo-direct-answer]").first();
    if (h2.text().trim() !== question.question) failures.push(`${page.route} / ${question.id}: H2 nesincronizat`);
    if (!question.question.endsWith("?")) failures.push(`${page.route} / ${question.id}: titlul nu este întrebare naturală`);
    if (direct.text().trim() !== question.answer) failures.push(`${page.route} / ${question.id}: răspuns nesincronizat`);
    const count = wordCount(direct.text());
    if (count < 40 || count > 80) failures.push(`${page.route} / ${question.id}: răspunsul are ${count} cuvinte`);
    if (article.closest("details").length) failures.push(`${page.route} / ${question.id}: răspunsul direct nu trebuie ascuns într-un disclosure`);
    if (article.find("[data-aeo-official-source]").length !== question.sources.length) failures.push(`${page.route} / ${question.id}: sursele nu sunt sincronizate`);
    if (article.find("time[datetime]").length !== question.sources.length) failures.push(`${page.route} / ${question.id}: data verificării lipsește lângă sursă`);
    if (article.find("[data-aeo-detail-link]").length !== question.detailLinks.length) failures.push(`${page.route} / ${question.id}: linkurile de detaliu nu sunt sincronizate`);
    article.find("[data-aeo-detail-link]").each((_, link) => {
      const href = $(link).attr("href") || "";
      if (!internalTargetExists(href)) failures.push(`${page.route} / ${question.id}: destinație internă inexistentă ${href}`);
      if (/[?&](?:name|email|phone|telefon|message|descriere)=/iu.test(href)) failures.push(`${page.route} / ${question.id}: linkul expune un parametru PII`);
    });
  }
}

const reportFile = path.join(ROOT, "reports", "p1-18-aeo-question-mapping.md");
const csvFile = path.join(ROOT, "reports", "p1-18-aeo-question-mapping.csv");
if (!fs.existsSync(reportFile)) failures.push("Raportul Markdown P1.18 lipsește");
if (!fs.existsSync(csvFile)) failures.push("Mapping-ul CSV P1.18 lipsește");
if (fs.existsSync(reportFile)) {
  const report = fs.readFileSync(reportFile, "utf8");
  for (const page of config.pages) for (const question of page.questions) {
    if (!report.includes(question.question)) failures.push(`Raport: întrebarea lipsește — ${question.question}`);
  }
}

if (failures.length) {
  console.error(`Contractul P1.18 a eșuat (${failures.length}):`);
  failures.forEach((failure) => console.error(`- ${failure}`));
  process.exit(1);
}

console.log(`Contract P1.18 PASS: ${config.pages.length} pagini și ${config.pages.reduce((sum, page) => sum + page.questions.length, 0)} răspunsuri directe, toate în HTML.`);
