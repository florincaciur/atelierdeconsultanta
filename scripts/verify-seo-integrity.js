const fs = require('fs');
const path = require('path');
const cheerio = require('cheerio');

const DEFAULT_RELATIVE_TARGET = path.join('atelierdeconsultanta', 'atelierdeconsultanta');
const EXCLUDED_DIRS = new Set([
  '.git',
  '.github',
  '.wrangler',
  'dist',
  'node_modules',
  'reports',
]);

const RELATED_SELECTOR = [
  '.vezi-si',
  '.vezi-si-section',
  '.related-links',
  '[aria-labelledby*="vezi-si"]',
  '[id*="vezi-si"]',
].join(', ');

const HUB_SLUGS = new Set([
  'afir',
  'calendar-fonduri-europene',
  'cat-costa-consultanta-fonduri-europene',
  'consultant-fonduri-europene-imm',
  'consultanta-afir',
  'consultanta-fonduri-europene',
  'consultanta-pnrr-digitalizare',
  'consultanta-start-up-nation',
  'consultanta-start-up-nation-2026',
  'cum-alegi-consultant-fonduri-europene',
  'digitalizare-imm-pnrr',
  'eligibilitate-fonduri-europene',
  'finantari-panouri-fotovoltaice',
  'firma-consultanta-fonduri-europene',
  'fondul-de-modernizare',
  'fonduri-europene',
  'fonduri-europene-agricultura',
  'fonduri-europene-digitalizare',
  'fonduri-europene-femei-antreprenor',
  'fonduri-europene-imm',
  'fonduri-europene-nerambursabile-2026',
  'fonduri-nerambursabile',
  'fonduri-pentru-ferme',
  'fonduri-pentru-utilaje-agricole',
  'ghiduri',
  'granturi-digitalizare-imm',
  'greseli-fonduri-europene',
  'intrebari-frecvente',
  'pnrr',
  'start-up-nation',
  'start-up-nation-2026',
  'start-up-nation-2026-cheltuieli-eligibile',
  'start-up-nation-2026-conditii',
  'start-up-nation-2026-idei-afaceri',
  'start-up-nation-2026-plan-de-afaceri',
  'studii-de-caz',
  'verificare-eligibilitate-fonduri-europene',
]);

const NON_CONTENT_FILES = new Set([
  '404.html',
  'admin/index.html',
]);

function resolveTargetRoot() {
  const requested = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve(DEFAULT_RELATIVE_TARGET);

  if (fs.existsSync(requested)) {
    return requested;
  }

  if (!process.argv[2]) {
    console.warn(`Target ${requested} not found. Using current directory instead.`);
    return process.cwd();
  }

  throw new Error(`Target directory not found: ${requested}`);
}

function toPosix(value) {
  return value.split(path.sep).join('/');
}

function walkHtmlFiles(root) {
  const files = [];

  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name) && !entry.name.endsWith('_files')) {
          walk(fullPath);
        }
        continue;
      }
      if (entry.isFile() && entry.name.toLowerCase().endsWith('.html')) {
        if (!entry.name.startsWith('FABER')) {
          files.push(fullPath);
        }
      }
    }
  }

  walk(root);
  return files.sort((a, b) => toPosix(a).localeCompare(toPosix(b)));
}

function status(pass, details = {}) {
  return { status: pass ? 'pass' : 'fail', ...details };
}

function isNoindex($) {
  return $('meta[name="robots" i]').toArray().some((element) => {
    const content = ($(element).attr('content') || '').toLowerCase();
    return content.includes('noindex');
  });
}

function hasMetaDescription($, noindex) {
  const count = $('meta[name="description" i]').length;
  if (noindex && count === 0) {
    return status(true, { count, note: 'noindex page: meta description is optional' });
  }
  return status(count > 0, { count });
}

function hasCanonical($) {
  const count = $('link[rel="canonical" i]').length;
  return status(count > 0, { count });
}

function hasImgAlt($) {
  const images = $('img').toArray();
  const missing = images
    .filter((element) => !Object.prototype.hasOwnProperty.call(element.attribs || {}, 'alt'))
    .map((element) => $(element).attr('src') || '<img without src>');

  return status(missing.length === 0, {
    totalImages: images.length,
    missingAltCount: missing.length,
    missingAlt: missing,
  });
}

function hasSingleH1($) {
  const h1s = $('h1').toArray().map((element) => $(element).text().replace(/\s+/g, ' ').trim());
  return status(h1s.length === 1, { count: h1s.length, text: h1s });
}

function shouldRequireRelatedLinks($, relativePath, noindex) {
  if (noindex || NON_CONTENT_FILES.has(relativePath)) {
    return false;
  }

  const normalized = relativePath.replace(/\/index\.html$/i, '').replace(/\.html$/i, '');
  const slug = normalized.split('/').pop();
  const fileName = path.posix.basename(relativePath).replace(/\.html$/i, '');

  return HUB_SLUGS.has(slug)
    || HUB_SLUGS.has(fileName)
    || /blog|ghid|fonduri|finant|afir|pnrr|start-up|digitalizare|consultanta/i.test(normalized)
    || $('article.post-body, .post-hero, .blog-card, [data-section-id="blog"]').length > 0;
}

function hasRelatedLinks($, relativePath, noindex) {
  const required = shouldRequireRelatedLinks($, relativePath, noindex);
  const count = $(RELATED_SELECTOR).length;

  if (!required) {
    return status(true, { required, count, note: 'not a hub/blog page' });
  }

  return status(count > 0, { required, count });
}

function checkFile(filePath, root) {
  const relativePath = toPosix(path.relative(root, filePath));
  const html = fs.readFileSync(filePath, 'utf8');
  const $ = cheerio.load(html, { decodeEntities: false });
  const noindex = isNoindex($);
  const technicalFile = NON_CONTENT_FILES.has(relativePath) || /^google[a-z0-9]+\.html$/i.test(relativePath);

  if (technicalFile) {
    const checks = {
      metaDescription: status(true, { note: 'technical verification page' }),
      canonical: status(true, { note: 'technical verification page' }),
      imageAltAttributes: hasImgAlt($),
      singleH1: status(true, { note: 'technical verification page' }),
      relatedLinks: status(true, { required: false, note: 'technical verification page' }),
    };

    return {
      file: relativePath,
      noindex,
      technicalFile,
      pass: true,
      checks,
    };
  }

  const checks = {
    metaDescription: hasMetaDescription($, noindex),
    canonical: hasCanonical($),
    imageAltAttributes: hasImgAlt($),
    singleH1: hasSingleH1($),
    relatedLinks: hasRelatedLinks($, relativePath, noindex),
  };

  const pass = Object.values(checks).every((check) => check.status === 'pass');

  return {
    file: relativePath,
    noindex,
    pass,
    checks,
  };
}

function summarize(results) {
  const summary = {
    totalFiles: results.length,
    passedFiles: results.filter((result) => result.pass).length,
    failedFiles: results.filter((result) => !result.pass).length,
    checks: {},
  };

  for (const result of results) {
    for (const [name, check] of Object.entries(result.checks)) {
      if (!summary.checks[name]) {
        summary.checks[name] = { pass: 0, fail: 0 };
      }
      summary.checks[name][check.status] += 1;
    }
  }

  return summary;
}

function main() {
  const root = resolveTargetRoot();
  const files = walkHtmlFiles(root);
  const results = files.map((filePath) => checkFile(filePath, root));
  const summary = summarize(results);
  const report = {
    generatedAt: new Date().toISOString(),
    root,
    summary,
    results,
  };

  const reportDir = path.join(process.cwd(), 'reports');
  fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, 'seo-integrity-report.json');
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);

  console.log(`SEO integrity report written to ${toPosix(path.relative(process.cwd(), reportPath))}`);
  console.log(`Files: ${summary.totalFiles}; passed: ${summary.passedFiles}; failed: ${summary.failedFiles}`);
  for (const [name, counts] of Object.entries(summary.checks)) {
    console.log(`${name}: ${counts.pass} pass, ${counts.fail} fail`);
  }

  if (summary.failedFiles > 0) {
    console.log('\nFailed files:');
    for (const result of results.filter((item) => !item.pass)) {
      const failedChecks = Object.entries(result.checks)
        .filter(([, check]) => check.status === 'fail')
        .map(([name]) => name)
        .join(', ');
      console.log(`- ${result.file}: ${failedChecks}`);
    }
    process.exitCode = 1;
  }
}

main();
