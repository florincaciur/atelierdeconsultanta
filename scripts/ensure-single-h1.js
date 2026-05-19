const fs = require('fs');
const path = require('path');
const cheerio = require('cheerio');

const DEFAULT_RELATIVE_TARGET = path.join('atelierdeconsultanta', 'atelierdeconsultanta');
const SKIPPED_DIRS = new Set(['.git', '.wrangler', 'dist', 'node_modules']);

function resolveTargetDir() {
  if (process.argv[2]) return path.resolve(process.argv[2]);

  const requestedDefault = path.resolve(DEFAULT_RELATIVE_TARGET);
  if (fs.existsSync(requestedDefault)) return requestedDefault;

  return process.cwd();
}

function escapeHtmlText(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function normalizeText(value) {
  return value
    .replace(/\s+/g, ' ')
    .trim();
}

function cleanTitle(title, filePath) {
  const fallback = path.basename(filePath, '.html');
  const cleaned = normalizeText(title || fallback)
    .replace(/^(?:redirectionare|redirect)\s*[|:-]\s*/i, '')
    .replace(/\s*[|]\s*(?:FABER|Atelier de Consultan(?:t|ț|ţ)a|Fonduri Europene).*$/i, '')
    .trim();

  return cleaned || fallback;
}

function getPageTitle($, filePath) {
  const metaTitle = $('meta[name="title"]').first().attr('content');
  const title = metaTitle || $('title').first().text();
  return cleanTitle(title, filePath);
}

function isBrowserSavedArtifact(html) {
  return html.slice(0, 2048).toLowerCase().includes('<!-- saved from url=');
}

function hasUsableDocumentShell($) {
  return $('html').length > 0 && $('body').length > 0;
}

function convertLogoH1s(html, $) {
  if ($('.logo h1').length === 0) return { html, changed: false };

  return {
    html: html.replace(/(<[^>]*\bclass=["'][^"']*\blogo\b[^"']*["'][^>]*>[\s\S]*?)<h1\b([^>]*)>([\s\S]*?)<\/h1>/gi, (
      match,
      before,
      attrs,
      inner,
    ) => `${before}<span class="logo-text"${attrs}>${inner}</span>`),
    changed: true,
  };
}

function convertAdditionalH1s(html) {
  let seen = 0;
  let changed = false;

  const updated = html.replace(/<h1\b([^>]*)>([\s\S]*?)<\/h1>/gi, (match, attrs, inner) => {
    seen += 1;
    if (seen === 1) return match;

    changed = true;
    return `<h2${attrs}>${inner}</h2>`;
  });

  return { html: updated, changed };
}

function insertH1(html, title) {
  const heading = `<h1>${escapeHtmlText(title)}</h1>`;
  const targets = [
    {
      pattern: /(<\/header>)(\r?\n)?/i,
      insert: (match, closeTag, newline = '\n') => `${closeTag}${newline}  ${heading}${newline}`,
    },
    {
      pattern: /(<main\b[^>]*>)(\r?\n)?/i,
      insert: (match, openTag, newline = '\n') => `${openTag}${newline}  ${heading}${newline}`,
    },
    {
      pattern: /(<body\b[^>]*>)(\r?\n)?/i,
      insert: (match, openTag, newline = '\n') => `${openTag}${newline}  ${heading}${newline}`,
    },
  ];

  for (const target of targets) {
    if (target.pattern.test(html)) {
      return {
        html: html.replace(target.pattern, target.insert),
        changed: true,
      };
    }
  }

  return { html, changed: false };
}

function processFile(filePath, targetDir) {
  const originalHtml = fs.readFileSync(filePath, 'utf8');
  if (isBrowserSavedArtifact(originalHtml)) return null;

  let $ = cheerio.load(originalHtml, { decodeEntities: false });
  if (!hasUsableDocumentShell($)) return null;

  let html = originalHtml;
  let updated = false;
  const actions = [];

  const logoResult = convertLogoH1s(html, $);
  if (logoResult.changed) {
    html = logoResult.html;
    updated = true;
    actions.push('logo h1 -> span');
    $ = cheerio.load(html, { decodeEntities: false });
  }

  const h1s = $('h1');
  if (h1s.length === 0) {
    const title = getPageTitle($, filePath);
    const insertResult = insertH1(html, title);
    if (insertResult.changed) {
      html = insertResult.html;
      updated = true;
      actions.push(`added h1 "${title}"`);
    }
  } else if (h1s.length > 1) {
    const convertResult = convertAdditionalH1s(html);
    if (convertResult.changed) {
      html = convertResult.html;
      updated = true;
      actions.push(`converted ${h1s.length - 1} extra h1 to h2`);
    }
  }

  if (!updated) return null;

  fs.writeFileSync(filePath, html, 'utf8');
  return `${path.relative(targetDir, filePath)}: ${actions.join(', ')}`;
}

function walk(dir, files = []) {
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    if (item.isDirectory()) {
      if (!SKIPPED_DIRS.has(item.name) && !item.name.endsWith('_files')) {
        walk(path.join(dir, item.name), files);
      }
    } else if (item.isFile() && item.name.toLowerCase().endsWith('.html')) {
      files.push(path.join(dir, item.name));
    }
  }

  return files;
}

function main() {
  const targetDir = resolveTargetDir();
  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    console.error(`Folderul nu există sau nu este director: ${targetDir}`);
    process.exitCode = 1;
    return;
  }

  const changedFiles = [];
  for (const filePath of walk(targetDir)) {
    const result = processFile(filePath, targetDir);
    if (result) changedFiles.push(result);
  }

  if (changedFiles.length === 0) {
    console.log('Nu au fost necesare modificări H1.');
    return;
  }

  for (const line of changedFiles) console.log(line);
  console.log(`Total fișiere modificate: ${changedFiles.length}`);
}

main();
