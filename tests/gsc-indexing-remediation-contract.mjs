import assert from "node:assert/strict";
import cp from "node:child_process";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "https://atelierdeconsultanta.ro";
const consolidations = new Map([
  ["/granturi-digitalizare-imm", "/digitalizare-imm"],
  ["/studii-de-caz", "/studii-de-caz-fonduri-europene"],
  ["/testimoniale", "/studii-de-caz-fonduri-europene"],
  ["/portofoliu", "/studii-de-caz-fonduri-europene"]
]);
const restoredProgramRoutes = ["/pnrr", "/fondul-de-modernizare"];

function parseRedirects(text) {
  return new Map(text.split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [source, destination, status] = line.split(/\s+/u);
      return [source, { destination: new URL(destination, SITE).pathname, status }];
    }));
}

function publicHtmlFiles() {
  return cp.execFileSync("git", ["ls-files", "-z", "*.html"], { cwd: ROOT, encoding: "utf8" })
    .split("\0")
    .filter(Boolean)
    .filter((file) => !file.startsWith("dist/") && fsSync.existsSync(path.join(ROOT, file)));
}

function canonicalFile(route) {
  const clean = route.replace(/^\//u, "");
  return [path.join(ROOT, clean, "index.html"), path.join(ROOT, `${clean}.html`)];
}

const redirects = parseRedirects(await fs.readFile(path.join(ROOT, "_redirects"), "utf8"));
const sitemapText = (await Promise.all([
  "sitemap-core.xml",
  "sitemap-guides.xml",
  "sitemap-programs.xml"
].map((file) => fs.readFile(path.join(ROOT, file), "utf8")))).join("\n");

for (const [source, target] of consolidations) {
  for (const variant of [source, `${source}/`, `${source}.html`, `${source}/index.html`]) {
    assert.deepEqual(redirects.get(variant), { destination: target, status: "301" }, `${variant}: lipsește 301 direct`);
  }
  assert.doesNotMatch(sitemapText, new RegExp(`<loc>${SITE}${source.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}</loc>`, "u"), `${source}: alias în sitemap`);
  assert.match(sitemapText, new RegExp(`<loc>${SITE}${target.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}</loc>`, "u"), `${target}: destinația lipsește din sitemap`);

  const candidates = canonicalFile(target);
  let html = "";
  for (const candidate of candidates) {
    try {
      html = await fs.readFile(candidate, "utf8");
      break;
    } catch {}
  }
  assert.ok(html, `${target}: fișier canonic inexistent`);
  const $ = cheerio.load(html);
  assert.doesNotMatch($("meta[name='robots']").first().attr("content") || "index, follow", /\bnoindex\b/iu, `${target}: destinație noindex`);
  assert.equal(new URL($("link[rel='canonical']").first().attr("href") || "", SITE).pathname, target, `${target}: canonical incorect`);
}

for (const route of restoredProgramRoutes) {
  assert.equal(redirects.get(route), undefined, `${route}: pagina-cadru restaurată nu trebuie redirecționată`);
  assert.match(sitemapText, new RegExp(`<loc>${SITE}${route.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}</loc>`, "u"), `${route}: pagina-cadru lipsește din sitemap`);
  const candidates = canonicalFile(route);
  let html = "";
  for (const candidate of candidates) {
    try {
      html = await fs.readFile(candidate, "utf8");
      break;
    } catch {}
  }
  assert.ok(html, `${route}: fișier canonic inexistent`);
  const $ = cheerio.load(html);
  assert.doesNotMatch($("meta[name='robots']").first().attr("content") || "index, follow", /\bnoindex\b/iu, `${route}: pagina-cadru este noindex`);
  assert.equal(new URL($("link[rel='canonical']").first().attr("href") || "", SITE).pathname, route, `${route}: canonical incorect`);
}

const retired = new Set(consolidations.keys());
const internalLinkErrors = [];
for (const file of publicHtmlFiles()) {
  const html = await fs.readFile(path.join(ROOT, file), "utf8");
  const $ = cheerio.load(html);
  $("a[href]").each((_, element) => {
    const raw = String($(element).attr("href") || "").trim();
    if (!raw || raw.startsWith("#") || /^(?:mailto:|tel:|javascript:)/iu.test(raw)) return;
    let url;
    try { url = new URL(raw, SITE); } catch { return; }
    if (url.origin === SITE && retired.has(url.pathname.replace(/\/+$/u, "") || "/")) internalLinkErrors.push(`${file}: ${raw}`);
    if (url.origin === SITE && url.pathname === "/contact" && url.search) internalLinkErrors.push(`${file}: contact query ${raw}`);
  });
}
assert.deepEqual(internalLinkErrors, [], `linkuri interne către aliasuri:\n${internalLinkErrors.join("\n")}`);

const robots = await fs.readFile(path.join(ROOT, "robots.txt"), "utf8");
assert.doesNotMatch(robots, /^Disallow:\s*\/admin\/?\s*$/imu, "/admin trebuie crawl-uit pentru a se vedea noindex");
const headers = await fs.readFile(path.join(ROOT, "_headers"), "utf8");
assert.match(headers, /^\/admin\s*\r?\n\s+X-Robots-Tag:\s*noindex,\s*nofollow\s*$/imu, "/admin trebuie să trimită X-Robots-Tag");

console.log(`GSC indexing remediation PASS: ${consolidations.size} consolidări, zero linkuri interne către aliasuri, admin crawlable+noindex.`);
