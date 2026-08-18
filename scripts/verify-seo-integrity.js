const fs = require('fs');
const path = require('path');
const cheerio = require('cheerio');
const {
  DOCUMENT_CATEGORIES,
  classificationCounts,
  classifyHtmlFile,
  discoverHtmlDocuments
} = require('../tools/site-document-classifier');
const {
  comparableText,
  fileForRoute,
  graphNodes,
  hasType,
  sitemapRoutes,
  visibleFaqItems
} = require('../tools/structured-data-utils');

const DEFAULT_RELATIVE_TARGET = path.join('atelierdeconsultanta', 'atelierdeconsultanta');
const SITE = 'https://atelierdeconsultanta.ro';
const EXCLUDED_DIRS = new Set([
  '.git',
  '.github',
  '.wrangler',
  'dist',
  'node_modules',
  'partials',
  'reports',
]);

const RELATED_SELECTOR = [
  '.vezi-si',
  '.vezi-si-section',
  '.related-links',
  '.program-contextual-links',
  '.editorial-cluster__related',
  '.program-family-related',
  '.expert-final-cta',
  '.next-step-block',
  '[data-contextual-next-step]',
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
  'programul-tranzitie-justa',
  'start-up-nation',
  'start-up-nation-2026',
  'start-up-nation-2026-cheltuieli-eligibile',
  'start-up-nation-2026-conditii',
  'start-up-nation-2026-idei-afaceri',
  'start-up-nation-2026-plan-de-afaceri',
  'studii-de-caz',
  'studii-de-caz-fonduri-europene',
  'verificare-eligibilitate-fonduri-europene',
]);

const NON_CONTENT_FILES = new Set([
  '404.html',
  'admin/index.html',
]);

const ROBOTS_ALLOWED_DIRECTIVES = new Set([
  'allow',
  'crawl-delay',
  'disallow',
  'sitemap',
  'user-agent',
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
  return [...new Set(sitemapRoutes(root).map((route) => fileForRoute(root, route)))];
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

function hasUtf8Charset($) {
  const hasCharset = $('meta[charset]').toArray().some((element) => {
    return String($(element).attr('charset') || '').toLowerCase() === 'utf-8';
  });
  const hasHttpEquiv = $('meta[http-equiv="Content-Type" i]').toArray().some((element) => {
    return String($(element).attr('content') || '').toLowerCase().includes('charset=utf-8');
  });
  return status(hasCharset || hasHttpEquiv, { hasCharset, hasHttpEquiv });
}

function hasCanonical($) {
  const count = $('link[rel="canonical" i]').length;
  return status(count > 0, { count });
}

function hasCleanCanonical($, noindex) {
  const href = $('link[rel="canonical" i]').first().attr('href') || '';
  if (!href) return status(noindex, { href, note: noindex ? 'noindex page without canonical is ignored' : 'missing canonical' });
  try {
    const url = new URL(href);
    const clean = url.pathname === '/' || (!url.pathname.endsWith('.html') && !url.pathname.endsWith('/'));
    return status(clean, { href });
  } catch {
    return status(false, { href, note: 'invalid canonical URL' });
  }
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

function jsonLdBlocks($) {
  const blocks = [];
  $('script[type="application/ld+json"]').each((_, element) => {
    try {
      blocks.push(JSON.parse($(element).text()));
    } catch {
      blocks.push({ '@type': 'INVALID_JSONLD' });
    }
  });
  return blocks;
}

function includesJsonLdType(node, type) {
  if (!node || typeof node !== 'object') return false;
  const nodeType = node['@type'];
  if (Array.isArray(nodeType) && nodeType.includes(type)) return true;
  if (nodeType === type) return true;
  if (Array.isArray(node['@graph'])) return node['@graph'].some((child) => includesJsonLdType(child, type));
  return false;
}

function hasVisibleFaqForSchema($) {
  const hasFaqSchema = jsonLdBlocks($).some((block) => includesJsonLdType(block, 'FAQPage'));
  if (!hasFaqSchema) return status(true, { required: false, count: 0 });
  const isDepthPage = String($('meta[name="seo-depth" i]').first().attr('content') || '').toLowerCase() === 'true';
  const minFaq = Number($('meta[name="seo-min-faq" i]').first().attr('content') || 0);
  const count = $('.faq-item, .faq-q, details, [itemprop="mainEntity"], [class*="faq" i]').length;
  const threshold = minFaq || (isDepthPage ? 4 : 0);
  return status(!threshold || count >= threshold, { required: Boolean(threshold), count, threshold });
}

function hasSpeakableSchemaCoverage($) {
  const blocks = jsonLdBlocks($);
  const hasSpeakable = blocks.some((block) => JSON.stringify(block).includes('SpeakableSpecification'));
  if (!hasSpeakable) return status(true, { required: false, count: 0 });
  const count = $('.speakable, [data-speakable="true"]').length;
  return status(count > 0, { required: true, count });
}

function visibleWordCount($) {
  const clone = $.root().clone();
  clone.find('script,style,noscript,svg,template').remove();
  const text = clone.text().replace(/\s+/g, ' ').trim();
  const words = text.match(/[\p{L}\p{N}]+(?:[-'’][\p{L}\p{N}]+)*/gu);
  return words ? words.length : 0;
}

function hasRequiredContentDepth($, noindex) {
  if (noindex) return status(true, { required: false, words: 0 });
  const minWords = Number($('meta[name="seo-min-words" i]').first().attr('content') || 0);
  const required = minWords > 0 || String($('meta[name="seo-depth" i]').first().attr('content') || '').toLowerCase() === 'true';
  const threshold = minWords || 2000;
  const words = visibleWordCount($);
  return status(!required || words >= threshold, { required, words, threshold });
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
    utf8Charset: hasUtf8Charset($),
    metaDescription: hasMetaDescription($, noindex),
    canonical: hasCanonical($),
    cleanCanonical: hasCleanCanonical($, noindex),
    imageAltAttributes: hasImgAlt($),
    singleH1: noindex ? status(true, { note: 'noindex page: h1 not required' }) : hasSingleH1($),
    visibleFaqForSchema: hasVisibleFaqForSchema($),
    speakableSchemaCoverage: hasSpeakableSchemaCoverage($),
    contentDepth: hasRequiredContentDepth($, noindex),
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

function validateRobotsTxt(root) {
  const filePath = path.join(root, 'robots.txt');
  if (!fs.existsSync(filePath)) {
    return status(false, { errors: ['robots.txt is missing'] });
  }

  const errors = [];
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;

    const colonIndex = trimmed.indexOf(':');
    if (colonIndex === -1) {
      errors.push({ line: lineNumber, directive: trimmed, reason: 'missing colon' });
      return;
    }

    const directive = trimmed.slice(0, colonIndex).trim().toLowerCase();
    if (!ROBOTS_ALLOWED_DIRECTIVES.has(directive)) {
      errors.push({ line: lineNumber, directive: trimmed.slice(0, colonIndex).trim(), reason: 'unknown directive' });
    }
  });

  return status(errors.length === 0, { errors });
}

function main() {
  const root = resolveTargetRoot();
  const files = walkHtmlFiles(root);
  const results = files.map((filePath) => checkFile(filePath, root));
  const summary = summarize(results);
  const robotsTxt = validateRobotsTxt(root);
  const report = {
    generatedAt: new Date().toISOString(),
    root,
    summary,
    robotsTxt,
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
  console.log(`robots.txt: ${robotsTxt.status}${robotsTxt.errors.length ? ` (${robotsTxt.errors.length} errors)` : ''}`);

  if (summary.failedFiles > 0 || robotsTxt.status === 'fail') {
    console.log('\nFailed files:');
    for (const result of results.filter((item) => !item.pass)) {
      const failedChecks = Object.entries(result.checks)
        .filter(([, check]) => check.status === 'fail')
        .map(([name]) => name)
        .join(', ');
      console.log(`- ${result.file}: ${failedChecks}`);
    }
    if (robotsTxt.status === 'fail') {
      console.log('\nrobots.txt errors:');
      for (const error of robotsTxt.errors) {
        console.log(`- line ${error.line}: ${error.directive} (${error.reason})`);
      }
    }
    process.exitCode = 1;
  }
}

main();
