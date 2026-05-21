const fs = require('fs');
const fsp = require('fs/promises');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const ROOT = process.cwd();
const REPORT_DIR = path.join(ROOT, 'reports');
const SCREENSHOT_DIR = path.join(REPORT_DIR, 'visual-screenshots');

const PAGES = [
  { label: 'home', path: '/' },
  { label: 'contact', path: '/contact/' },
  { label: 'consultanta-fonduri-europene', path: '/consultanta-fonduri-europene/' },
  { label: 'fonduri-europene', path: '/fonduri-europene/' },
  { label: 'fonduri-europene-imm', path: '/fonduri-europene-imm/' },
  { label: 'afir', path: '/afir/' },
  { label: 'pnrr', path: '/pnrr/' },
  { label: 'idei-afaceri-fonduri-europene', path: '/idei-afaceri-fonduri-europene.html' },
  { label: 'start-up-nation-2026', path: '/start-up-nation-2026' },
];

const CANONICAL_ROOT_HTML_ROUTES = new Set([
  'por-adr-nord-est',
  'dr12-afir',
  'afir-autoconsum-agroalimentar',
  'autoconsum-public-fotovoltaice-institutii-publice',
  'dr14',
  'digitalizare-imm',
  'femeia-antreprenor-2026',
  'pro-infra',
  'start-up-nation-2026',
  'calculator-soc',
]);

const VIEWPORTS = [
  { name: 'desktop', width: 1365, height: 900 },
  { name: 'mobile', width: 390, height: 844 },
];

const MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.webp': 'image/webp',
  '.xml': 'application/xml; charset=utf-8',
};

function toPosix(value) {
  return value.split(path.sep).join('/');
}

function safeJoin(root, requestPath) {
  const decoded = decodeURIComponent(requestPath.split('?')[0]);
  const cleanPath = decoded.replace(/^\/+/, '');
  let filePath = path.join(root, cleanPath);
  if (decoded.endsWith('/')) {
    filePath = path.join(filePath, 'index.html');
  }
  if (!path.extname(filePath)) {
    const cleanRoute = cleanPath.replace(/\/+$/g, '');
    const canonicalRootPath = CANONICAL_ROOT_HTML_ROUTES.has(cleanRoute)
      ? `${filePath}.html`
      : '';
    const indexPath = path.join(filePath, 'index.html');
    const htmlPath = `${filePath}.html`;
    if (canonicalRootPath && fs.existsSync(canonicalRootPath)) return canonicalRootPath;
    if (fs.existsSync(indexPath)) return indexPath;
    if (fs.existsSync(htmlPath)) return htmlPath;
  }
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(root + path.sep) && resolved !== root) {
    return null;
  }
  return resolved;
}

function createServer() {
  const server = http.createServer(async (request, response) => {
    try {
      const requestedPath = new URL(request.url, 'http://127.0.0.1').pathname;
      const filePath = safeJoin(ROOT, requestedPath);
      if (!filePath || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('Not found');
        return;
      }

      const ext = path.extname(filePath).toLowerCase();
      response.writeHead(200, { 'content-type': MIME_TYPES[ext] || 'application/octet-stream' });
      fs.createReadStream(filePath).pipe(response);
    } catch (error) {
      response.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      response.end(String(error.stack || error));
    }
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, port: address.port });
    });
  });
}

async function inspectPage(page, pageInfo, viewport) {
  const url = page.url();

  return page.evaluate(({ pagePath, viewportName, currentUrl }) => {
    const visible = (element) => {
      const style = window.getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none'
        && style.visibility !== 'hidden'
        && Number(style.opacity) !== 0
        && rect.width > 0
        && rect.height > 0;
    };

    const normalizeText = (value) => (value || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase();
    const badge = document.querySelector('#contact .badge-centered, #contact .cta-badge, #contact .consultanta-badge, #contact .cta-eyebrow');
    const heading = Array.from(document.querySelectorAll('#contact h1, #contact h2, h1, h2'))
      .find((element) => /verificare initiala|solicita verificare|trimite detaliile proiectului/i.test(normalizeText(element.textContent)));

    let badgeCheck = { required: pagePath === '/', pass: pagePath !== '/', reason: 'not homepage contact section' };
    if (pagePath === '/') {
      if (!badge || !heading) {
        badgeCheck = { required: true, pass: false, reason: 'badge or contact verification heading not found' };
      } else {
        const badgeRect = badge.getBoundingClientRect();
        const headingRect = heading.getBoundingClientRect();
        const badgeStyle = window.getComputedStyle(badge);
        const containerStyle = window.getComputedStyle(badge.parentElement);
        const badgeCenter = badgeRect.left + badgeRect.width / 2;
        const headingCenter = headingRect.left + headingRect.width / 2;
        const delta = Math.abs(badgeCenter - headingCenter);
        const cssCentered = badge.classList.contains('badge-centered')
          || (badgeStyle.marginLeft === 'auto' && badgeStyle.marginRight === 'auto')
          || containerStyle.textAlign === 'center';

        badgeCheck = {
          required: true,
          pass: delta <= 4 && cssCentered,
          delta,
          badgeClass: badge.className,
          badgeDisplay: badgeStyle.display,
          badgeMarginLeft: badgeStyle.marginLeft,
          badgeMarginRight: badgeStyle.marginRight,
          containerTextAlign: containerStyle.textAlign,
        };
      }
    }

    const horizontalOverflow = document.documentElement.scrollWidth - window.innerWidth;
    const clippedText = [];
    const candidates = Array.from(document.querySelectorAll('h1, h2, h3, p, a, button, label, input, textarea, select, .btn-primary, .btn-secondary, .btn-cta, .cta-eyebrow, .card, .service-card, .finantare-card, .blog-card'));
    for (const element of candidates) {
      if (!visible(element)) continue;
      if (element.matches('.skip-link')) continue;
      const style = window.getComputedStyle(element);
      const hasText = (element.innerText || element.value || '').trim().length > 0;
      if (!hasText) continue;
      const widthClipped = element.scrollWidth > element.clientWidth + 2 && ['hidden', 'clip'].includes(style.overflowX);
      const heightClipped = element.scrollHeight > element.clientHeight + 2 && ['hidden', 'clip'].includes(style.overflowY);
      if (widthClipped || heightClipped) {
        clippedText.push({
          tag: element.tagName.toLowerCase(),
          className: element.className || '',
          text: (element.innerText || element.value || '').replace(/\s+/g, ' ').trim().slice(0, 120),
          scrollWidth: element.scrollWidth,
          clientWidth: element.clientWidth,
          scrollHeight: element.scrollHeight,
          clientHeight: element.clientHeight,
        });
      }
    }

    const overlapIssues = [];
    const keyElements = Array.from(document.querySelectorAll('h1, h2, .cta-eyebrow, .btn-primary, .btn-secondary, .btn-cta, form, .service-card, .finantare-card, .blog-card'))
      .filter(visible)
      .map((element, index) => ({
        index,
        tag: element.tagName.toLowerCase(),
        className: element.className || '',
        text: (element.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 80),
        rect: element.getBoundingClientRect(),
      }))
      .filter((item) => item.rect.bottom > 0 && item.rect.top < window.innerHeight)
      .slice(0, 80);

    for (let i = 0; i < keyElements.length; i += 1) {
      for (let j = i + 1; j < keyElements.length; j += 1) {
        const a = keyElements[i];
        const b = keyElements[j];
        const xOverlap = Math.max(0, Math.min(a.rect.right, b.rect.right) - Math.max(a.rect.left, b.rect.left));
        const yOverlap = Math.max(0, Math.min(a.rect.bottom, b.rect.bottom) - Math.max(a.rect.top, b.rect.top));
        const overlapArea = xOverlap * yOverlap;
        const minArea = Math.min(a.rect.width * a.rect.height, b.rect.width * b.rect.height);
        const nested = (a.rect.left <= b.rect.left && a.rect.right >= b.rect.right && a.rect.top <= b.rect.top && a.rect.bottom >= b.rect.bottom)
          || (b.rect.left <= a.rect.left && b.rect.right >= a.rect.right && b.rect.top <= a.rect.top && b.rect.bottom >= a.rect.bottom);
        if (!nested && minArea > 0 && overlapArea / minArea > 0.35) {
          overlapIssues.push({ a: a.text || a.className || a.tag, b: b.text || b.className || b.tag, ratio: overlapArea / minArea });
        }
      }
    }

    return {
      url: currentUrl,
      pagePath,
      viewportName,
      title: document.title,
      badgeCheck,
      horizontalOverflow,
      clippedText,
      overlapIssues,
      pass: badgeCheck.pass && horizontalOverflow <= 1 && clippedText.length === 0 && overlapIssues.length === 0,
    };
  }, { pagePath: pageInfo.path, viewportName: viewport.name, currentUrl: url });
}

async function main() {
  await fsp.rm(SCREENSHOT_DIR, { recursive: true, force: true });
  await fsp.mkdir(SCREENSHOT_DIR, { recursive: true });
  const { server, port } = await createServer();
  const baseUrl = `http://127.0.0.1:${port}`;
  const browser = await chromium.launch();
  const results = [];

  try {
    for (const viewport of VIEWPORTS) {
      const page = await browser.newPage({ viewport: { width: viewport.width, height: viewport.height } });
      for (const pageInfo of PAGES) {
        const url = `${baseUrl}${pageInfo.path}`;
        await page.goto(url, { waitUntil: 'load', timeout: 20000 });
        await page.screenshot({
          path: path.join(SCREENSHOT_DIR, `${pageInfo.label}-${viewport.name}.png`),
          fullPage: true,
        });
        const result = await inspectPage(page, pageInfo, viewport);
        results.push({
          ...result,
          screenshot: toPosix(path.relative(ROOT, path.join(SCREENSHOT_DIR, `${pageInfo.label}-${viewport.name}.png`))),
        });
      }
      await page.close();
    }
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }

  const summary = {
    totalChecks: results.length,
    passedChecks: results.filter((result) => result.pass).length,
    failedChecks: results.filter((result) => !result.pass).length,
  };

  const report = {
    generatedAt: new Date().toISOString(),
    baseUrl,
    summary,
    results,
  };

  const reportPath = path.join(REPORT_DIR, 'visual-integrity-report.json');
  await fsp.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);

  console.log(`Visual integrity report written to ${toPosix(path.relative(ROOT, reportPath))}`);
  console.log(`Checks: ${summary.totalChecks}; passed: ${summary.passedChecks}; failed: ${summary.failedChecks}`);
  for (const result of results.filter((item) => !item.pass)) {
    console.log(`- ${result.pagePath} @ ${result.viewportName}: badge=${result.badgeCheck.pass}, overflow=${result.horizontalOverflow}, clipped=${result.clippedText.length}, overlaps=${result.overlapIssues.length}`);
  }

  if (summary.failedChecks > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
