const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const sharp = require('sharp');
const CleanCSS = require('clean-css');
const terser = require('terser');

const IMAGE_THRESHOLD_BYTES = 200 * 1024;
const WEBP_QUALITY = 80;
const DEFAULT_RELATIVE_TARGET = path.join('atelierdeconsultanta', 'atelierdeconsultanta');
const EXCLUDED_DIRS = new Set(['.git', '.github', '.wrangler', 'node_modules', 'dist', 'reports']);
const MINIFY_EXCLUDED_DIRS = new Set(['scripts', 'tools', 'config']);

function resolveTargetRoot() {
  const requested = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve(DEFAULT_RELATIVE_TARGET);

  if (fs.existsSync(requested)) {
    return requested;
  }

  if (!process.argv[2] && fs.existsSync(process.cwd())) {
    console.warn(`Target ${requested} not found. Using current directory instead.`);
    return process.cwd();
  }

  throw new Error(`Target directory not found: ${requested}`);
}

function toPosix(filePath) {
  return filePath.split(path.sep).join('/');
}

function keyFor(filePath) {
  return path.resolve(filePath).toLowerCase();
}

function bytesLabel(bytes) {
  const abs = Math.abs(bytes);
  if (abs >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  return `${(bytes / 1024).toFixed(1)} kB`;
}

function isExternalUrl(value) {
  return /^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(value)
    || /^(?:data|mailto|tel):/i.test(value)
    || value.startsWith('#');
}

function splitUrl(value) {
  const match = value.match(/^([^?#]*)([?#].*)?$/);
  return {
    pathname: match ? match[1] : value,
    suffix: match && match[2] ? match[2] : '',
  };
}

function resolveLocalUrl(value, fromFile, targetRoot) {
  if (!value || isExternalUrl(value)) {
    return null;
  }

  const { pathname } = splitUrl(value);
  if (!pathname || pathname.startsWith('#')) {
    return null;
  }

  const withoutLeadingSlash = pathname.startsWith('/')
    ? pathname.slice(1)
    : pathname;

  return pathname.startsWith('/')
    ? path.resolve(targetRoot, withoutLeadingSlash)
    : path.resolve(path.dirname(fromFile), withoutLeadingSlash);
}

function formatLocalUrl(newFile, originalValue, fromFile, targetRoot) {
  const { pathname, suffix } = splitUrl(originalValue);
  let nextPath;

  if (pathname.startsWith('/')) {
    nextPath = `/${toPosix(path.relative(targetRoot, newFile))}`;
  } else {
    nextPath = toPosix(path.relative(path.dirname(fromFile), newFile));
    if (!nextPath.startsWith('.') && originalValue.startsWith('./')) {
      nextPath = `./${nextPath}`;
    }
  }

  return `${nextPath}${suffix}`;
}

async function walkFiles(root, shouldSkipDir) {
  const files = [];

  async function walk(dir) {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!shouldSkipDir(fullPath, entry.name)) {
          await walk(fullPath);
        }
        continue;
      }
      if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }

  await walk(root);
  return files;
}

function isInDirectory(filePath, parentDir) {
  const rel = path.relative(parentDir, filePath);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function shouldSkipDirForAssets(targetRoot, fullPath, name) {
  if (EXCLUDED_DIRS.has(name)) {
    return true;
  }

  const legacyRoot = path.join(targetRoot, 'assets', 'legacy-images');
  return path.resolve(fullPath) === path.resolve(legacyRoot)
    || isInDirectory(fullPath, legacyRoot);
}

function shouldSkipDirForMinify(targetRoot, fullPath, name) {
  if (shouldSkipDirForAssets(targetRoot, fullPath, name)) {
    return true;
  }

  const rel = path.relative(targetRoot, fullPath);
  const firstSegment = rel.split(path.sep)[0];
  return MINIFY_EXCLUDED_DIRS.has(firstSegment);
}

async function moveOriginalToLegacy(originalPath, targetRoot) {
  const legacyRoot = path.join(targetRoot, 'assets', 'legacy-images');
  const relativeOriginal = path.relative(targetRoot, originalPath);
  let destination = path.join(legacyRoot, relativeOriginal);

  await fsp.mkdir(path.dirname(destination), { recursive: true });

  if (fs.existsSync(destination)) {
    const ext = path.extname(destination);
    const base = destination.slice(0, -ext.length);
    let index = 1;
    while (fs.existsSync(`${base}-${index}${ext}`)) {
      index += 1;
    }
    destination = `${base}-${index}${ext}`;
  }

  await fsp.rename(originalPath, destination);
  return destination;
}

async function convertImages(targetRoot) {
  const files = await walkFiles(targetRoot, (fullPath, name) => shouldSkipDirForAssets(targetRoot, fullPath, name));
  const conversions = [];
  const skipped = [];
  const imageMap = new Map();

  for (const filePath of files) {
    if (!/\.(?:jpe?g|png)$/i.test(filePath)) {
      continue;
    }

    const stat = await fsp.stat(filePath);
    if (stat.size <= IMAGE_THRESHOLD_BYTES) {
      continue;
    }

    const ext = path.extname(filePath);
    const webpPath = path.join(path.dirname(filePath), `${path.basename(filePath, ext)}.webp`);
    let webpBuffer;
    try {
      webpBuffer = await sharp(filePath).webp({ quality: WEBP_QUALITY }).toBuffer();
    } catch (error) {
      skipped.push({
        source: filePath,
        reason: error && error.message ? error.message : String(error),
      });
      continue;
    }

    await fsp.writeFile(webpPath, webpBuffer);
    const legacyPath = await moveOriginalToLegacy(filePath, targetRoot);
    const savedBytes = stat.size - webpBuffer.length;

    imageMap.set(keyFor(filePath), webpPath);
    conversions.push({
      original: filePath,
      webp: webpPath,
      legacy: legacyPath,
      before: stat.size,
      after: webpBuffer.length,
      savedBytes,
    });
  }

  return { conversions, skipped, imageMap };
}

function replaceMappedUrl(value, fromFile, targetRoot, assetMap) {
  const localPath = resolveLocalUrl(value, fromFile, targetRoot);
  if (!localPath) {
    return value;
  }

  const replacement = assetMap.get(keyFor(localPath));
  if (!replacement) {
    return value;
  }

  return formatLocalUrl(replacement, value, fromFile, targetRoot);
}

function replaceHtmlAssetRefs(html, htmlFile, targetRoot, assetMap) {
  let changed = false;

  const nextHtml = html
    .replace(/\b(src|href|content|poster)\s*=\s*(["'])([^"']+)\2/gi, (match, attr, quote, value) => {
      const nextValue = replaceMappedUrl(value, htmlFile, targetRoot, assetMap);
      if (nextValue === value) {
        return match;
      }
      changed = true;
      return `${attr}=${quote}${nextValue}${quote}`;
    })
    .replace(/\bsrcset\s*=\s*(["'])([^"']+)\1/gi, (match, quote, value) => {
      const nextValue = value.split(',').map((part) => {
        const trimmed = part.trim();
        const firstSpace = trimmed.search(/\s/);
        const url = firstSpace === -1 ? trimmed : trimmed.slice(0, firstSpace);
        const descriptor = firstSpace === -1 ? '' : trimmed.slice(firstSpace);
        return `${replaceMappedUrl(url, htmlFile, targetRoot, assetMap)}${descriptor}`;
      }).join(', ');

      if (nextValue === value) {
        return match;
      }
      changed = true;
      return `srcset=${quote}${nextValue}${quote}`;
    });

  return { html: nextHtml, changed };
}

function replaceCssUrlRefs(css, cssFile, targetRoot, assetMap) {
  let changed = false;

  const nextCss = css.replace(/url\((["']?)([^"')]+)\1\)/gi, (match, quote, value) => {
    const nextValue = replaceMappedUrl(value.trim(), cssFile, targetRoot, assetMap);
    if (nextValue === value.trim()) {
      return match;
    }
    changed = true;
    return `url(${quote}${nextValue}${quote})`;
  });

  return { css: nextCss, changed };
}

async function updateCssImageReferences(targetRoot, imageMap) {
  if (!imageMap.size) {
    return [];
  }

  const files = await walkFiles(targetRoot, (fullPath, name) => shouldSkipDirForMinify(targetRoot, fullPath, name));
  const changedFiles = [];

  for (const filePath of files) {
    if (!/\.css$/i.test(filePath) || /\.min\.css$/i.test(filePath)) {
      continue;
    }

    const css = await fsp.readFile(filePath, 'utf8');
    const result = replaceCssUrlRefs(css, filePath, targetRoot, imageMap);
    if (result.changed) {
      await fsp.writeFile(filePath, result.css);
      changedFiles.push(filePath);
    }
  }

  return changedFiles;
}

async function minifyResources(targetRoot) {
  const files = await walkFiles(targetRoot, (fullPath, name) => shouldSkipDirForMinify(targetRoot, fullPath, name));
  const minified = [];
  const minMap = new Map();

  for (const filePath of files) {
    if (!/\.(?:css|js)$/i.test(filePath) || /\.min\.(?:css|js)$/i.test(filePath)) {
      continue;
    }

    const ext = path.extname(filePath).toLowerCase();
    const minPath = filePath.replace(new RegExp(`${ext}$`, 'i'), `.min${ext}`);
    const source = await fsp.readFile(filePath, 'utf8');
    let output;

    if (ext === '.css') {
      const result = new CleanCSS({ level: 2 }).minify(source);
      if (result.errors.length) {
        throw new Error(`CleanCSS failed for ${filePath}: ${result.errors.join('; ')}`);
      }
      output = result.styles;
    } else {
      const result = await terser.minify(source, {
        compress: true,
        mangle: true,
        format: { comments: false },
      });
      if (result.error) {
        throw result.error;
      }
      output = result.code || '';
    }

    await fsp.writeFile(minPath, output);
    const before = Buffer.byteLength(source);
    const after = Buffer.byteLength(output);

    minMap.set(keyFor(filePath), minPath);
    minified.push({
      source: filePath,
      minified: minPath,
      before,
      after,
      savedBytes: before - after,
    });
  }

  return { minified, minMap };
}

async function updateHtmlReferences(targetRoot, assetMap) {
  if (!assetMap.size) {
    return [];
  }

  const files = await walkFiles(targetRoot, (fullPath, name) => shouldSkipDirForAssets(targetRoot, fullPath, name));
  const changedFiles = [];

  for (const filePath of files) {
    if (!/\.html$/i.test(filePath)) {
      continue;
    }

    const html = await fsp.readFile(filePath, 'utf8');
    const result = replaceHtmlAssetRefs(html, filePath, targetRoot, assetMap);
    if (result.changed) {
      await fsp.writeFile(filePath, result.html);
      changedFiles.push(filePath);
    }
  }

  return changedFiles;
}

function printReport(targetRoot, imageConversions, skippedImages, minifiedFiles, cssRefsChanged, htmlRefsChanged) {
  const imageSavings = imageConversions.reduce((sum, item) => sum + item.savedBytes, 0);
  const minifySavings = minifiedFiles.reduce((sum, item) => sum + item.savedBytes, 0);

  console.log(`\nAsset optimization report for ${targetRoot}`);
  console.log(`Images converted: ${imageConversions.length}`);
  for (const item of imageConversions) {
    console.log(`  ${toPosix(path.relative(targetRoot, item.original))} -> ${toPosix(path.relative(targetRoot, item.webp))} (${bytesLabel(item.savedBytes)} saved)`);
  }
  console.log(`Images skipped: ${skippedImages.length}`);
  for (const item of skippedImages) {
    console.log(`  ${toPosix(path.relative(targetRoot, item.source))}: ${item.reason}`);
  }

  console.log(`CSS image references updated: ${cssRefsChanged.length}`);
  for (const filePath of cssRefsChanged) {
    console.log(`  ${toPosix(path.relative(targetRoot, filePath))}`);
  }

  console.log(`Files minified: ${minifiedFiles.length}`);
  for (const item of minifiedFiles) {
    console.log(`  ${toPosix(path.relative(targetRoot, item.source))} -> ${toPosix(path.relative(targetRoot, item.minified))} (${bytesLabel(item.savedBytes)} saved)`);
  }

  console.log(`HTML files updated: ${htmlRefsChanged.length}`);
  for (const filePath of htmlRefsChanged) {
    console.log(`  ${toPosix(path.relative(targetRoot, filePath))}`);
  }

  console.log(`Total estimated savings: ${bytesLabel(imageSavings + minifySavings)}`);
}

async function main() {
  const targetRoot = resolveTargetRoot();
  const { conversions, skipped, imageMap } = await convertImages(targetRoot);
  const cssRefsChanged = await updateCssImageReferences(targetRoot, imageMap);
  const { minified, minMap } = await minifyResources(targetRoot);
  const allHtmlRefs = new Map([...imageMap, ...minMap]);
  const htmlRefsChanged = await updateHtmlReferences(targetRoot, allHtmlRefs);

  printReport(targetRoot, conversions, skipped, minified, cssRefsChanged, htmlRefsChanged);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
