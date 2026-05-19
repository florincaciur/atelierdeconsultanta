const fs = require('fs');
const path = require('path');

const DEFAULT_RELATIVE_TARGET = path.join('atelierdeconsultanta', 'atelierdeconsultanta');
const SKIPPED_DIRS = new Set(['.git', '.wrangler', 'dist', 'node_modules']);
const MAX_DESCRIPTION_LENGTH = 160;

function normalizeText(value) {
  return value
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&ndash;|&mdash;/gi, '-')
    .replace(/\s+/g, ' ')
    .trim();
}

function getAttribute(tag, name) {
  const attrPattern = new RegExp(
    String.raw`(?:^|\s)${name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>]+))`,
    'i'
  );
  const match = tag.match(attrPattern);
  return match ? match[1] || match[2] || match[3] || '' : '';
}

function getMetaTags(html) {
  return html.match(/<meta\b[^>]*>/gi) || [];
}

function hasMetaDescription(html) {
  return getMetaTags(html).some((tag) => getAttribute(tag, 'name').toLowerCase() === 'description');
}

function hasNoindex(html) {
  return getMetaTags(html).some((tag) => {
    const name = getAttribute(tag, 'name').toLowerCase();
    const httpEquiv = getAttribute(tag, 'http-equiv').toLowerCase();
    const content = getAttribute(tag, 'content').toLowerCase();
    const isRobotsTag = name === 'robots' || name === 'googlebot' || httpEquiv === 'x-robots-tag';
    return isRobotsTag && /\bnoindex\b/.test(content);
  });
}

function extractTitle(html) {
  const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const h1Match = html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i);
  const title = titleMatch ? normalizeText(titleMatch[1]) : '';
  const h1 = h1Match ? normalizeText(h1Match[1]) : '';
  return cleanTitle(title || h1);
}

function cleanTitle(title) {
  return title
    .replace(/\s*[|]\s*(FABER|Atelier de Consultan(?:t|ț|ţ)a|Fonduri Europene).*$/i, '')
    .replace(/\s+-\s+(FABER|Atelier de Consultan(?:t|ț|ţ)a).*$/i, '')
    .replace(/\bredirectionare\b\s*[|:-]?\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function toSentenceCase(title) {
  if (!title) return title;
  const lower = title.toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

function trimToMax(value, maxLength) {
  if (value.length <= maxLength) return value;

  const truncated = value.slice(0, maxLength - 1);
  const lastSpace = truncated.lastIndexOf(' ');
  if (lastSpace < Math.floor(maxLength * 0.7)) {
    return `${truncated.trimEnd()}…`;
  }
  return `${truncated.slice(0, lastSpace).trimEnd()}…`;
}

function generateDescription(title) {
  const topic = toSentenceCase(title.replace(/\s*[|]\s*/g, ', '));
  const description = `Află detalii despre ${topic}, pașii de eligibilitate și documentele utile pentru finanțare. Cere consultanță FABER pentru proiectul tău.`;
  return trimToMax(description, MAX_DESCRIPTION_LENGTH);
}

function escapeHtmlAttribute(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function insertDescription(html, description) {
  const closingHeadPattern = /(\r?\n)([ \t]*)<\/head>/i;
  if (closingHeadPattern.test(html)) {
    return html.replace(
      closingHeadPattern,
      `$1$2<meta name="description" content="${escapeHtmlAttribute(description)}" />$1$2</head>`
    );
  }

  if (/<\/head>/i.test(html)) {
    return html.replace(
      /<\/head>/i,
      `<meta name="description" content="${escapeHtmlAttribute(description)}" />\n</head>`
    );
  }

  return null;
}

function processFile(filePath) {
  const html = fs.readFileSync(filePath, 'utf8');

  if (hasMetaDescription(html)) return { status: 'existing' };
  if (hasNoindex(html)) return { status: 'noindex' };

  const title = extractTitle(html);
  if (!title) return { status: 'missing-title' };

  const description = generateDescription(title);
  const updated = insertDescription(html, description);
  if (!updated) return { status: 'missing-head' };

  fs.writeFileSync(filePath, updated, 'utf8');
  return { status: 'updated', description };
}

function walk(dir, files = []) {
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    if (item.isDirectory()) {
      if (!SKIPPED_DIRS.has(item.name)) {
        walk(path.join(dir, item.name), files);
      }
    } else if (item.isFile() && item.name.toLowerCase().endsWith('.html')) {
      files.push(path.join(dir, item.name));
    }
  }
  return files;
}

function resolveTargetDir() {
  if (process.argv[2]) return path.resolve(process.argv[2]);

  const requestedDefault = path.resolve(DEFAULT_RELATIVE_TARGET);
  if (fs.existsSync(requestedDefault)) return requestedDefault;

  return process.cwd();
}

function main() {
  const targetDir = resolveTargetDir();
  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    console.error(`Folderul nu există sau nu este director: ${targetDir}`);
    process.exitCode = 1;
    return;
  }

  const counts = {
    updated: 0,
    existing: 0,
    noindex: 0,
    'missing-title': 0,
    'missing-head': 0,
  };

  const updatedFiles = [];
  for (const filePath of walk(targetDir)) {
    const result = processFile(filePath);
    counts[result.status] += 1;

    if (result.status === 'updated') {
      updatedFiles.push({ filePath, description: result.description });
      console.log(`Updated: ${path.relative(targetDir, filePath)}`);
      console.log(`  ${result.description}`);
    }
  }

  if (updatedFiles.length === 0) {
    console.log('Nu au fost actualizate fișiere HTML eligibile.');
  }

  console.log(
    `Rezumat: ${counts.updated} actualizate, ${counts.existing} aveau deja descriere, ` +
      `${counts.noindex} noindex, ${counts['missing-title']} fără titlu/H1, ` +
      `${counts['missing-head']} fără </head>.`
  );
}

main();
