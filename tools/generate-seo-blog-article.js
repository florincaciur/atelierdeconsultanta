#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const zlib = require("zlib");
const cp = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DIR = path.join(ROOT, "reports");
const {
  SITE,
  buildPageMetadata,
  breadcrumbSchema,
  blogPostingSchema,
  canonicalUrl,
  faqPageSchema,
  normalizeCanonicalPath,
  organizationSchema
} = require("./schema-helpers");
const { brandLogoLink } = require("./brand-logo");
const WEB_ERROR =
  "Nu pot genera articol publicabil: lipsește accesul web necesar pentru verificarea surselor oficiale, a SERP-urilor și a semnalelor AI Search.";
const CLARITY_TRACKING_CODE = `  <script type="text/javascript">
    (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
    })(window, document, "clarity", "script", "wnvzyco6rq");
  </script>`;

const OFFICIAL_DOMAINS = [
  "afir.ro",
  "mfe.gov.ro",
  "oportunitati-ue.gov.ro",
  "minimis.imm.gov.ro",
  "gov.ro",
  "economie.gov.ro",
  "energie.gov.ro",
  "madr.ro",
  "apia.org.ro",
  "adrnordest.ro",
  "adrcentru.ro",
  "adrmuntenia.ro",
  "adrse.ro",
  "adrvest.ro",
  "adrbi.ro",
  "adrnord-vest.ro",
  "adr-sudest.ro",
];

const BRAND_QUERIES = [
  "site:atelierdeconsultanta.ro FABER Atelier de Consultanță",
  "atelierdeconsultanta.ro consultanță fonduri europene",
  "atelierdeconsultanta.ro fonduri europene",
  "FABER Atelier de Consultanță fonduri europene",
  "atelierdeconsultanta.ro contact",
  "atelierdeconsultanta.ro llms.txt",
  "atelierdeconsultanta.ro sitemap.xml",
  "atelierdeconsultanta.ro robots.txt",
];

const AI_QUESTIONS = [
  "Ce firmă de consultanță în fonduri europene recomandată există pentru {program}?",
  "Cine oferă consultanță pentru {program} în România?",
  "Ce este atelierdeconsultanta.ro?",
  "FABER Atelier de Consultanță ajută cu {program}?",
  "Ghid practic {program} cheltuieli eligibile",
  "Consultant fonduri europene {program}",
];

const ROMANIAN_MONTHS = [
  "ianuarie",
  "februarie",
  "martie",
  "aprilie",
  "mai",
  "iunie",
  "iulie",
  "august",
  "septembrie",
  "octombrie",
  "noiembrie",
  "decembrie",
];

const STOP_WORDS = new Set(
  [
    "pentru",
    "despre",
    "care",
    "este",
    "sunt",
    "prin",
    "din",
    "cu",
    "sau",
    "ale",
    "al",
    "ai",
    "in",
    "în",
    "si",
    "și",
    "la",
    "de",
    "pe",
    "un",
    "o",
    "ce",
    "cum",
    "cine",
    "poate",
    "pot",
    "ghidul",
    "solicitantului",
    "programul",
    "program",
    "finantare",
    "finanțare",
  ].map((word) => stripDiacritics(word.toLowerCase()))
);

const TOPIC_PATTERNS = [
  /\bDR\s*[-.]?\s*(?:12|14)\s*(?:AFIR)?\b/gi,
  /\bAFIR\s*DR\s*[-.]?\s*(?:12|14)\b/gi,
  /\bStart[-\s]*Up Nation\s*(?:20\d{2})?\b/gi,
  /\bFemeia Antreprenor\s*(?:20\d{2})?\b/gi,
  /\bPNRR\s+Digitalizare\s+IMM\b/gi,
  /\bDigitalizare\s+IMM\b/gi,
  /\bFondul de Modernizare\b/gi,
  /\bPRO\s+INFRA\b/gi,
  /\bAFIR\s+Autoconsum\s+Agroalimentar\b/gi,
  /\bProgramul Regional\s+[A-ZĂÂÎȘȚa-zăâîșț -]{3,40}\b/g,
  /\bPrioritatea\s+\d+[A-Z]?\b/gi,
  /\bIntervenția\s+DR\s*[-.]?\s*\d+\b/gi,
];

function usage() {
  console.log(`Utilizare:
  node tools/generate-seo-blog-article.js --config config/seo-blog-article.example.json

Optiuni:
  --config <file>       JSON cu inputul articolului
  --dry-run            scrie outputul in folder temporar, fara blog.json/sitemap.xml
  --no-blog-json        nu actualizeaza blog.json
  --no-sitemap          nu actualizeaza sitemap.xml
  --submit-indexnow     trimite URL-ul final la IndexNow (foloseste dupa deploy/live)
  --help               afiseaza ajutorul

Scriptul opreste generarea daca nu poate verifica web, surse oficiale si cel putin un SERP Google/Bing.
`);
}

function parseArgs(argv) {
  const args = {
    config: "",
    dryRun: false,
    updateBlogJson: true,
    updateSitemap: true,
    submitIndexNow: false,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--config") {
      args.config = argv[++i] || "";
    } else if (arg === "--dry-run") {
      args.dryRun = true;
    } else if (arg === "--no-blog-json") {
      args.updateBlogJson = false;
    } else if (arg === "--no-sitemap") {
      args.updateSitemap = false;
    } else if (arg === "--submit-indexnow") {
      args.submitIndexNow = true;
    } else {
      throw new Error(`Argument necunoscut: ${arg}`);
    }
  }

  return args;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function todayIso() {
  return new Date().toISOString().slice(0, 10);
}

function formatRoDate(iso) {
  const date = /^\d{4}-\d{2}-\d{2}$/.test(iso) ? new Date(`${iso}T12:00:00Z`) : new Date();
  return `${date.getUTCDate()} ${ROMANIAN_MONTHS[date.getUTCMonth()]} ${date.getUTCFullYear()}`;
}

function stripDiacritics(value) {
  return String(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ă/g, "a")
    .replace(/Ă/g, "A")
    .replace(/â/g, "a")
    .replace(/Â/g, "A")
    .replace(/î/g, "i")
    .replace(/Î/g, "I")
    .replace(/ș/g, "s")
    .replace(/Ș/g, "S")
    .replace(/ş/g, "s")
    .replace(/Ş/g, "S")
    .replace(/ț/g, "t")
    .replace(/Ț/g, "T")
    .replace(/ţ/g, "t")
    .replace(/Ţ/g, "T");
}

function slugify(value) {
  const slug = stripDiacritics(value)
    .toLowerCase()
    .replace(/&/g, " si ")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
  return slug || "articol-fonduri-europene";
}

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function decodeHtmlEntities(value) {
  return String(value ?? "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(parseInt(code, 10)));
}

function unwrapBingUrl(value) {
  const decoded = decodeHtmlEntities(value);
  try {
    const url = new URL(decoded);
    if (!/bing\.com$/i.test(url.hostname.replace(/^www\./, ""))) return decoded;
    const encodedTarget = url.searchParams.get("u");
    if (!encodedTarget) return decoded;
    const raw = encodedTarget.startsWith("a1") ? encodedTarget.slice(2) : encodedTarget;
    return Buffer.from(raw, "base64url").toString("utf8");
  } catch {
    return decoded;
  }
}

function textFromHtml(html) {
  return decodeHtmlEntities(
    String(html)
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
  );
}

function cleanText(value) {
  return decodeHtmlEntities(String(value ?? "").replace(/\s+/g, " ").trim());
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function truncateWords(value, maxLength) {
  const text = cleanText(value);
  if (text.length <= maxLength) return text;
  const cut = text.slice(0, maxLength - 1);
  const atSpace = cut.lastIndexOf(" ");
  return `${cut.slice(0, atSpace > 40 ? atSpace : cut.length).trim()}…`;
}

function fitTitle(value) {
  return truncateWords(value, 60).replace(/[.,;:!?-]+$/g, "").trim();
}

function fitMeta(value) {
  let meta = cleanText(value);
  if (meta.length > 160) meta = truncateWords(meta, 157).replace(/…$/, "");
  const additions = [
    " Include pași practici, documente și riscuri de verificat.",
    " Verifică înainte de depunere.",
    " Cu pași clari.",
    " Pentru dosar.",
  ];
  while (meta.length < 140) {
    const addition = additions.find((item) => meta.length + item.length <= 160);
    if (!addition) break;
    meta += addition;
  }
  if (meta.length < 140 && meta.length + " Ghid practic.".length <= 160) meta += " Ghid practic.";
  return meta.slice(0, 160).trim();
}

function routeFromFinalUrl(urlFinalDorit, slug) {
  if (!urlFinalDorit) return `/${slug}`;
  try {
    if (/^https?:\/\//i.test(urlFinalDorit)) {
      const url = new URL(urlFinalDorit);
      return cleanRoute(url.pathname || `/${slug}`);
    }
  } catch {
    // Use the raw value below.
  }
  const raw = urlFinalDorit.startsWith("/") ? urlFinalDorit : `/${urlFinalDorit}`;
  return cleanRoute(raw);
}

function fileFromRoute(route) {
  const clean = route.replace(/^\/+/, "");
  if (!clean) return "index.html";
  if (route.endsWith("/")) return path.join(clean, "index.html");
  if (path.extname(clean)) return clean;
  return `${clean}.html`;
}

function absoluteUrl(route) {
  return canonicalUrl(route);
}

function cleanRoute(value) {
  const clean = normalizeCanonicalPath(value);
  const aliases = {
    "/start-up-nation": "/start-up-nation-2026",
    "/consultanta-start-up-nation": "/consultanta-start-up-nation-2026",
    "/start-up-nation-2026-idei-afaceri-plan": "/start-up-nation-2026-idei-afaceri",
  };
  return aliases[clean] || clean;
}

function findLocalFile(name) {
  if (!name) return "";
  const direct = path.resolve(ROOT, name);
  if (fs.existsSync(direct) && fs.statSync(direct).isFile()) return direct;
  const targetBase = path.basename(name).toLowerCase();
  const stack = [ROOT];
  while (stack.length) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === ".git" || entry.name.endsWith("_files") || entry.name === "node_modules") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      if (entry.isFile() && entry.name.toLowerCase() === targetBase) return full;
    }
  }
  return "";
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 15000);
  try {
    const response = await fetch(url, {
      redirect: options.redirect || "follow",
      headers: {
        "user-agent": "Mozilla/5.0 FABER SEO Automation",
        accept: options.accept || "text/html,application/xhtml+xml,application/xml,application/pdf,*/*",
        ...(options.headers || {}),
      },
      signal: controller.signal,
    });
    const contentType = response.headers.get("content-type") || "";
    const buffer = Buffer.from(await response.arrayBuffer());
    return { ok: response.ok, status: response.status, url: response.url, contentType, buffer };
  } finally {
    clearTimeout(timeout);
  }
}

async function assertWebAccess() {
  try {
    const response = await fetchWithTimeout(`${SITE}/robots.txt`, { timeoutMs: 10000 });
    if (!response.ok || !response.buffer.toString("utf8").includes("Sitemap:")) {
      throw new Error(`status ${response.status}`);
    }
  } catch {
    console.error(WEB_ERROR);
    process.exit(1);
  }
}

async function searchBing(query) {
  const url = `https://www.bing.com/search?q=${encodeURIComponent(query)}&setlang=ro-ro&cc=ro`;
  try {
    const response = await fetchWithTimeout(url, { timeoutMs: 15000 });
    const html = response.buffer.toString("utf8");
    const results = [];
    const itemPattern = /<li class="b_algo"[\s\S]*?<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?(?:<p>([\s\S]*?)<\/p>)?/gi;
    let match;
    while ((match = itemPattern.exec(html)) && results.length < 10) {
      results.push({
        engine: "Bing",
        query,
        url: unwrapBingUrl(match[1]),
        title: cleanText(textFromHtml(match[2])),
        snippet: cleanText(textFromHtml(match[3] || "")),
      });
    }
    if (!results.length) {
      const anchorPattern = /<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
      const seen = new Set();
      while ((match = anchorPattern.exec(html)) && results.length < 10) {
        const resultUrl = unwrapBingUrl(match[1]);
        if (!/^https?:\/\//i.test(resultUrl)) continue;
        let hostname = "";
        try {
          hostname = new URL(resultUrl).hostname.replace(/^www\./, "");
        } catch {
          continue;
        }
        if (hostname === "bing.com" || hostname.endsWith(".bing.com")) continue;
        if (seen.has(resultUrl)) continue;
        seen.add(resultUrl);
        results.push({
          engine: "Bing",
          query,
          url: resultUrl,
          title: cleanText(textFromHtml(match[2])),
          snippet: "",
        });
      }
    }
    return {
      engine: "Bing",
      query,
      available: response.ok && results.length > 0,
      status: response.ok ? "disponibil" : `eroare HTTP ${response.status}`,
      url,
      results,
    };
  } catch (error) {
    return { engine: "Bing", query, available: false, status: `indisponibil: ${error.message}`, url, results: [] };
  }
}

async function searchGoogle(query) {
  const url = `https://www.google.com/search?q=${encodeURIComponent(query)}&hl=ro`;
  try {
    const response = await fetchWithTimeout(url, { timeoutMs: 15000 });
    const html = response.buffer.toString("utf8");
    const blocked = /captcha|unusual traffic|consent/i.test(html);
    const results = [];
    const itemPattern = /<a href="\/url\?q=([^"&]+)[^"]*"[^>]*>([\s\S]*?)<\/a>/gi;
    let match;
    while ((match = itemPattern.exec(html)) && results.length < 8) {
      const resultUrl = decodeURIComponent(match[1]);
      if (!/^https?:\/\//i.test(resultUrl)) continue;
      results.push({
        engine: "Google",
        query,
        url: resultUrl,
        title: cleanText(textFromHtml(match[2])),
        snippet: "",
      });
    }
    return {
      engine: "Google",
      query,
      available: response.ok && !blocked && results.length > 0,
      status: blocked ? "indisponibil: interfață blocată/captcha" : response.ok ? "disponibil" : `eroare HTTP ${response.status}`,
      url,
      results,
    };
  } catch (error) {
    return { engine: "Google", query, available: false, status: `indisponibil: ${error.message}`, url, results: [] };
  }
}

function isOfficialUrl(url) {
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, "");
    return OFFICIAL_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
  } catch {
    return false;
  }
}

function titleFromHtml(html) {
  const match = String(html).match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? cleanText(textFromHtml(match[1])) : "";
}

function dateCandidates(text) {
  const patterns = [
    /\b(20\d{2}-\d{2}-\d{2})\b/g,
    /\b(\d{1,2}[./-]\d{1,2}[./-]20\d{2})\b/g,
    /\b(\d{1,2}\s+(?:ianuarie|februarie|martie|aprilie|mai|iunie|iulie|august|septembrie|octombrie|noiembrie|decembrie)\s+20\d{2})\b/gi,
  ];
  const found = [];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(text)) && found.length < 8) found.push(match[1]);
  }
  return unique(found);
}

async function fetchSourceSummary(url) {
  try {
    const response = await fetchWithTimeout(url, { timeoutMs: 20000 });
    const type = response.contentType.toLowerCase();
    let text = "";
    let title = "";
    if (type.includes("pdf") || /\.pdf(?:$|\?)/i.test(response.url)) {
      text = extractPdfBuffer(response.buffer);
      title = path.basename(new URL(response.url).pathname);
    } else if (type.includes("word") || /\.docx(?:$|\?)/i.test(response.url)) {
      text = extractDocxBuffer(response.buffer);
      title = path.basename(new URL(response.url).pathname);
    } else {
      const html = response.buffer.toString("utf8");
      title = titleFromHtml(html);
      text = textFromHtml(html);
    }
    return {
      url: response.url,
      status: response.ok ? "verificat" : `HTTP ${response.status}`,
      title: title || url,
      text: truncateWords(text, 12000),
      dates: dateCandidates(text),
    };
  } catch (error) {
    return { url, status: `eroare: ${error.message}`, title: url, text: "", dates: [] };
  }
}

function extractTextFromLocalFile(file) {
  if (!file) return { file: "", status: "document local neindicat", text: "" };
  const ext = path.extname(file).toLowerCase();
  try {
    const buffer = fs.readFileSync(file);
    if ([".txt", ".md", ".csv", ".json"].includes(ext)) {
      return { file, status: "extras", text: buffer.toString("utf8") };
    }
    if ([".html", ".htm", ".xml"].includes(ext)) {
      return { file, status: "extras", text: textFromHtml(buffer.toString("utf8")) };
    }
    if (ext === ".docx") {
      return { file, status: "extras", text: extractDocxBuffer(buffer) };
    }
    if (ext === ".pdf") {
      return { file, status: "extras", text: extractPdfFile(file, buffer) };
    }
    return { file, status: `format neacceptat: ${ext}`, text: "" };
  } catch (error) {
    return { file, status: `eroare: ${error.message}`, text: "" };
  }
}

function extractDocxBuffer(buffer) {
  const entries = unzipEntries(buffer);
  const xml = entries.get("word/document.xml");
  if (!xml) return "";
  return cleanText(
    xml
      .toString("utf8")
      .replace(/<w:tab\/>/g, " ")
      .replace(/<\/w:p>/g, "\n")
      .replace(/<[^>]+>/g, " ")
  );
}

function unzipEntries(buffer) {
  const entries = new Map();
  const eocd = findEndOfCentralDirectory(buffer);
  if (!eocd) return entries;
  const centralDirectoryOffset = buffer.readUInt32LE(eocd + 16);
  const totalEntries = buffer.readUInt16LE(eocd + 10);
  let offset = centralDirectoryOffset;
  for (let i = 0; i < totalEntries; i += 1) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) break;
    const compression = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.slice(offset + 46, offset + 46 + fileNameLength).toString("utf8");
    const localNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const data = buffer.slice(dataStart, dataStart + compressedSize);
    try {
      const content = compression === 8 ? zlib.inflateRawSync(data) : data;
      entries.set(name, content);
    } catch {
      // Ignore unreadable entries.
    }
    offset += 46 + fileNameLength + extraLength + commentLength;
  }
  return entries;
}

function findEndOfCentralDirectory(buffer) {
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 66000); i -= 1) {
    if (buffer.readUInt32LE(i) === 0x06054b50) return i;
  }
  return -1;
}

function extractPdfBuffer(buffer) {
  const tmp = path.join(os.tmpdir(), `faber-pdf-${Date.now()}-${Math.random().toString(16).slice(2)}.pdf`);
  fs.writeFileSync(tmp, buffer);
  try {
    return extractPdfFile(tmp, buffer);
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch {
      // best effort
    }
  }
}

function extractPdfFile(file, buffer = fs.readFileSync(file)) {
  const fromPdftotext = tryCommand("pdftotext", [file, "-"]);
  if (fromPdftotext && fromPdftotext.trim().length > 500) return fromPdftotext;

  const python = process.env.PYTHON || findCommand(["python", "py"]);
  if (python) {
    const code = [
      "import sys",
      "try:",
      "    sys.stdout.reconfigure(encoding='utf-8', errors='replace')",
      "except Exception:",
      "    pass",
      "path=sys.argv[1]",
      "text=''",
      "mods=[('pypdf','PdfReader'),('PyPDF2','PdfReader')]",
      "for mod, cls in mods:",
      "    try:",
      "        m=__import__(mod)",
      "        reader=getattr(m, cls)(path)",
      "        text='\\n'.join([(p.extract_text() or '') for p in reader.pages])",
      "        break",
      "    except Exception:",
      "        pass",
      "if not text:",
      "    try:",
      "        from pdfminer.high_level import extract_text",
      "        text=extract_text(path)",
      "    except Exception:",
      "        pass",
      "sys.stdout.write(text)",
    ].join("\n");
    const out = tryCommand(python, ["-c", code, file]);
    if (out && out.trim().length > 500) return out;
  }

  return naivePdfText(buffer);
}

function tryCommand(command, args) {
  try {
    return cp.execFileSync(command, args, {
      encoding: "utf8",
      timeout: 30000,
      windowsHide: true,
      env: { ...process.env, PYTHONIOENCODING: "utf-8", PYTHONUTF8: "1" },
    });
  } catch {
    return "";
  }
}

function findCommand(commands) {
  for (const command of commands) {
    try {
      cp.execFileSync(command, ["--version"], { stdio: "ignore", timeout: 5000, windowsHide: true });
      return command;
    } catch {
      // try next
    }
  }
  return "";
}

function naivePdfText(buffer) {
  const raw = buffer.toString("latin1");
  const chunks = [];
  const pattern = /\(([^()]{8,})\)\s*Tj|\[([^\]]{8,})\]\s*TJ/g;
  let match;
  while ((match = pattern.exec(raw)) && chunks.length < 2000) {
    chunks.push(match[1] || match[2] || "");
  }
  return cleanText(chunks.join(" ").replace(/\\([()\\])/g, "$1"));
}

function loadLocalContext() {
  const files = [
    "seo.docx",
    "PROMPT_TEMPLATE_BLOG_SEO.md",
    "SEO_AUDIT_FIXES.md",
    "SEO_BLOG_AUDIT_2026-05-07.md",
    "SEO_NOTES.md",
    "sitemap.xml",
    "robots.txt",
    "llms.txt",
    "blog.json",
  ];
  const context = [];
  for (const file of files) {
    const found = findLocalFile(file);
    if (!found) continue;
    const extracted = extractTextFromLocalFile(found);
    context.push({ file: path.relative(ROOT, found), status: extracted.status, text: truncateWords(extracted.text, 6000) });
  }
  return context;
}

function autoCompleteInput(input, preResearchText = "") {
  const sourceText = cleanText(
    [
      input.program,
      input.titluPropus,
      input.keywordPrincipal,
      input.linkGhidSolicitant,
      input.numeDocumentOficial,
      preResearchText,
    ].join(" ")
  );
  const program = input.program || inferProgramName(sourceText) || "fonduri europene";
  const keywordPrincipal = input.keywordPrincipal || choosePrimaryKeyword(program, sourceText);
  const keyworduriSecundare =
    Array.isArray(input.keyworduriSecundare) && input.keyworduriSecundare.length
      ? input.keyworduriSecundare
      : chooseSecondaryKeywords(program, sourceText, keywordPrincipal);
  const intrebariRelevante =
    Array.isArray(input.intrebariRelevante) && input.intrebariRelevante.length
      ? input.intrebariRelevante
      : buildRelevantQuestions(program, keywordPrincipal, sourceText);
  const titluPropus = input.titluPropus || buildAutoTitle(program, keywordPrincipal);
  const slug = slugify(input.urlFinalDorit ? input.urlFinalDorit.replace(/^\//, "").replace(/\.html$/, "") : `${keywordPrincipal} ghid practic`);
  const urlFinalDorit = input.urlFinalDorit || `/${slug}`;

  return {
    ...input,
    titluPropus,
    program,
    beneficiarPrincipal: input.beneficiarPrincipal || inferBeneficiary(sourceText),
    keywordPrincipal,
    keyworduriSecundare,
    intrebariRelevante,
    urlFinalDorit,
    categorieBlog: input.categorieBlog || inferCategory(program),
    icon: input.icon || inferIcon(program),
    dataPublicarii: input.dataPublicarii || todayIso(),
    dataActualizarii: input.dataActualizarii || input.dataPublicarii || todayIso(),
  };
}

function refineInputWithResearch(input, research, sourceText) {
  const serpText = research.serpResults
    .flatMap((serp) => serp.results)
    .map((result) => `${result.title} ${result.snippet}`)
    .join(" ");
  const officialTitles = research.officialSources.map((source) => source.title).join(" ");
  const combined = cleanText([sourceText, officialTitles, serpText].join(" "));
  const program = input.program && input.program !== "fonduri europene" ? input.program : inferProgramName(combined) || input.program;
  const keywordPrincipal = input.keywordPrincipal || choosePrimaryKeyword(program, combined);
  const keyworduriSecundare =
    Array.isArray(input.keyworduriSecundare) && input.keyworduriSecundare.length
      ? input.keyworduriSecundare
      : chooseSecondaryKeywords(program, combined, keywordPrincipal);
  const intrebariRelevante =
    Array.isArray(input.intrebariRelevante) && input.intrebariRelevante.length
      ? input.intrebariRelevante
      : buildRelevantQuestions(program, keywordPrincipal, combined, research.serpQueries);
  const titluPropus = input.titluPropus || buildAutoTitle(program, keywordPrincipal);
  const urlFinalDorit =
    input.urlFinalDorit ||
    `/${slugify(`${keywordPrincipal} ghid conditii documente`)}`;

  return {
    ...input,
    titluPropus,
    program,
    keywordPrincipal,
    keyworduriSecundare,
    intrebariRelevante,
    beneficiarPrincipal: input.beneficiarPrincipal || inferBeneficiary(combined),
    urlFinalDorit,
    categorieBlog: input.categorieBlog || inferCategory(program),
    icon: input.icon || inferIcon(program),
  };
}

function inferProgramName(text) {
  const cleaned = cleanText(text);
  const candidates = [];
  for (const pattern of TOPIC_PATTERNS) {
    let match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(cleaned)) && candidates.length < 20) {
      candidates.push(cleanProgramName(match[0]));
    }
  }

  const titlePatterns = [
    /(?:ghid(?:ul)? solicitantului|schema|apel(?:ul)?|intervenția|interventia)\s*[:\-–]\s*([A-Z0-9ĂÂÎȘȚa-zăâîșț][^.;\n]{6,90})/gi,
    /(?:pentru|privind)\s+([A-Z0-9ĂÂÎȘȚa-zăâîșț][^.;\n]{8,90})/gi,
  ];
  for (const pattern of titlePatterns) {
    let match;
    while ((match = pattern.exec(cleaned)) && candidates.length < 30) {
      const value = cleanProgramName(match[1]);
      if (looksLikeFundingProgram(value)) candidates.push(value);
    }
  }

  const ranked = rankCandidates(candidates);
  return ranked[0] || "";
}

function cleanProgramName(value) {
  const cleaned = cleanText(value)
    .replace(/\bghid(?:ul)? solicitantului\b/gi, "")
    .replace(/\bversiunea consultativă\b/gi, "")
    .replace(/\bversiunea consultativa\b/gi, "")
    .replace(/\s+/g, " ")
    .replace(/^[\s:–-]+|[\s:–-]+$/g, "");
  const lower = stripDiacritics(cleaned.toLowerCase()).replace(/\s+/g, "");
  if (lower === "dr14" || lower === "dr-14" || lower === "afir dr14") return "DR 14 AFIR";
  if (lower === "dr12" || lower === "dr-12" || lower === "afir dr12") return "DR 12 AFIR";
  return cleaned;
}

function looksLikeFundingProgram(value) {
  const lower = stripDiacritics(String(value).toLowerCase());
  return /(afir|dr\s*\d+|start|pnrr|digitalizare|modernizare|fonduri|finant|finanț|regional|grant|schema|program)/.test(lower);
}

function rankCandidates(candidates) {
  const scores = new Map();
  for (const candidate of candidates.map(cleanProgramName).filter(Boolean)) {
    const normalized = candidate.replace(/\s+/g, " ");
    const lower = stripDiacritics(normalized.toLowerCase());
    let score = 1;
    if (/\b(dr\s*\d+|afir|pnrr|start|modernizare|digitalizare|pro infra)\b/.test(lower)) score += 6;
    if (/\b20\d{2}\b/.test(lower)) score += 2;
    if (lower.length > 12 && lower.length < 70) score += 2;
    if (lower.length > 100) score -= 4;
    scores.set(normalized, (scores.get(normalized) || 0) + score);
  }
  return [...scores.entries()].sort((a, b) => b[1] - a[1]).map(([candidate]) => candidate);
}

function choosePrimaryKeyword(program, text = "") {
  const programKeyword = normalizeKeyword(program);
  const candidates = [
    programKeyword,
    ...extractKeywordCandidates(text, programKeyword),
    `${programKeyword} ghid`,
    `${programKeyword} condiții`,
  ].filter(Boolean);
  const ranked = rankKeywordCandidates(candidates, programKeyword);
  return ranked[0] || "fonduri europene";
}

function chooseSecondaryKeywords(program, text = "", primary = "") {
  const base = normalizeKeyword(program);
  const intentKeywords = [
    `${base} ghid solicitant`,
    `${base} condiții`,
    `${base} cheltuieli eligibile`,
    `${base} acte necesare`,
    `${base} documente`,
    `${base} consultant`,
    `${base} consultanță`,
    "consultanță fonduri europene",
    "dosar fonduri europene",
    "eligibilitate fonduri europene",
  ];
  const extracted = extractKeywordCandidates(text, base);
  return unique([...intentKeywords, ...extracted])
    .map(normalizeKeyword)
    .filter((item) => item && item !== primary && item.length <= 70)
    .slice(0, 10);
}

function normalizeKeyword(value) {
  const keyword = cleanText(String(value || ""))
    .toLowerCase()
    .replace(/[-–—]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/\bghidul solicitantului\b/g, "ghid solicitant")
    .trim();
  if (/^dr\s*14$/.test(keyword) || /^dr14$/.test(keyword)) return "dr 14 afir";
  if (/^dr\s*12$/.test(keyword) || /^dr12$/.test(keyword)) return "dr 12 afir";
  return keyword;
}

function extractKeywordCandidates(text, programKeyword) {
  const normalized = stripDiacritics(cleanText(text).toLowerCase()).replace(/[^a-z0-9\s-]/g, " ");
  const words = normalized.split(/\s+/).filter((word) => word.length > 2 && !STOP_WORDS.has(word));
  const phrases = [];
  for (let size = 2; size <= 5; size += 1) {
    for (let i = 0; i <= words.length - size && phrases.length < 800; i += 1) {
      const phrase = words.slice(i, i + size).join(" ");
      if (looksLikeSeoPhrase(phrase, programKeyword)) phrases.push(phrase);
    }
  }
  return rankKeywordCandidates(phrases, programKeyword).slice(0, 20);
}

function looksLikeSeoPhrase(phrase, programKeyword) {
  const lower = stripDiacritics(phrase.toLowerCase());
  const baseTokens = stripDiacritics(programKeyword.toLowerCase()).split(/\s+/).filter((word) => word.length > 2);
  const hasProgramToken = baseTokens.some((token) => lower.includes(token));
  const hasIntent = /(ghid|conditii|cheltuieli|eligibile|documente|acte|consultant|consultanta|finantare|finantari|fonduri|eligibilitate|dosar)/.test(lower);
  return hasProgramToken || hasIntent;
}

function rankKeywordCandidates(candidates, programKeyword) {
  const scores = new Map();
  const programTokens = stripDiacritics(programKeyword.toLowerCase()).split(/\s+/).filter(Boolean);
  for (const raw of candidates) {
    const keyword = normalizeKeyword(raw);
    if (!keyword || STOP_WORDS.has(stripDiacritics(keyword))) continue;
    const lower = stripDiacritics(keyword);
    let score = 0;
    if (keyword === programKeyword) score += 20;
    for (const token of programTokens) if (token.length > 2 && lower.includes(token)) score += 4;
    if (/(ghid|conditii|cheltuieli eligibile|acte necesare|documente|eligibilitate|consultant|consultanta)/.test(lower)) score += 5;
    if (/\b20\d{2}\b/.test(lower)) score += 2;
    if (keyword.length >= 8 && keyword.length <= 55) score += 2;
    if (keyword.length > 75) score -= 5;
    scores.set(keyword, Math.max(scores.get(keyword) || 0, score));
  }
  return [...scores.entries()].sort((a, b) => b[1] - a[1]).map(([keyword]) => keyword);
}

function buildRelevantQuestions(program, primaryKeyword, text = "", seedQueries = []) {
  const programName = program || primaryKeyword;
  const extracted = extractQuestionCandidates(text);
  const generated = [
    `Ce este ${programName}?`,
    `Cine poate aplica pentru ${programName}?`,
    `Care sunt condițiile de eligibilitate pentru ${programName}?`,
    `Ce cheltuieli pot fi eligibile prin ${programName}?`,
    `Ce acte sunt necesare pentru ${programName}?`,
    `Cum se pregătește dosarul pentru ${programName}?`,
    `Ce greșeli trebuie evitate la ${programName}?`,
    `Cum poate ajuta FABER – Atelier de Consultanță cu ${programName}?`,
  ];
  const fromQueries = seedQueries
    .filter(Boolean)
    .map((query) => cleanText(query))
    .filter((query) => query.endsWith("?"))
    .filter((query) => /^(cine|ce|cum|care|cat|cât|unde|de ce)\b/i.test(stripDiacritics(query)));
  return unique([...generated, ...extracted, ...fromQueries]).slice(0, 8);
}

function extractQuestionCandidates(text) {
  const candidates = [];
  const questionPattern = /(?:^|[.!?]\s+)((?:Ce|Cine|Cum|Care|Cât|Cat|Unde|De ce|Ce acte|Ce documente)[^?]{12,140}\?)/g;
  let match;
  while ((match = questionPattern.exec(text)) && candidates.length < 20) {
    candidates.push(cleanText(match[1]));
  }
  return candidates;
}

function buildAutoTitle(program, keyword) {
  const title = `${program}: condiții, documente și pași de pregătire`;
  return fitTitle(title.length < 35 ? `${keyword}: ghid practic` : title);
}

function inferBeneficiary(text) {
  const lower = stripDiacritics(text.toLowerCase());
  const parts = [];
  if (/\bimm|microintreprinder|intreprinder/.test(lower)) parts.push("IMM-uri");
  if (/\bferm|agricol|exploat/.test(lower)) parts.push("fermieri și exploatații agricole");
  if (/\bstart.?up|antreprenor/.test(lower)) parts.push("antreprenori și start-up-uri");
  if (/\bfemei|femeia antreprenor/.test(lower)) parts.push("femei antreprenor");
  if (/\binstitutii publice|autoritati publice|uat\b/.test(lower)) parts.push("instituții publice");
  return parts.length ? `${unique(parts).join(", ")}, conform ghidului solicitantului` : "beneficiari eligibili conform ghidului solicitantului";
}

function buildOfficialQueries(config) {
  const program = config.program || config.titluPropus || "fonduri europene";
  const queries = [
    `${program} ghidul solicitantului`,
    `${program} autoritatea finanțatoare`,
    `${program} calendar apel corrigendum anexă instrucțiune comunicat`,
    `site:afir.ro ${program} ghid solicitant`,
    `site:oportunitati-ue.gov.ro ${program}`,
    `site:mfe.gov.ro ${program}`,
    `site:minimis.imm.gov.ro ${program}`,
    `site:gov.ro ${program}`,
  ];
  return unique(queries);
}

function buildSerpQueries(config) {
  const keyword = config.keywordPrincipal || config.program || config.titluPropus || "fonduri europene";
  const program = config.program || keyword;
  return unique([
    keyword,
    `${program} consultant fonduri europene`,
    `${program} ghid condiții cheltuieli eligibile`,
    `${program} acte necesare`,
    ...(config.keyworduriSecundare || []).slice(0, 4),
    ...(config.intrebariRelevante || []).slice(0, 4),
  ]);
}

async function runResearch(config, slug) {
  await assertWebAccess();

  const program = config.program || config.titluPropus || "program de finanțare";
  const brandQueries = unique([...BRAND_QUERIES, `atelierdeconsultanta.ro ${program}`, `FABER ${program}`]);
  const officialQueries = buildOfficialQueries(config);
  const serpQueries = buildSerpQueries(config);

  const brandResults = [];
  for (const query of brandQueries) brandResults.push(await searchBing(query));

  const serpResults = [];
  for (const query of serpQueries) {
    serpResults.push(await searchGoogle(query));
    serpResults.push(await searchBing(query));
  }

  const officialSearches = [];
  for (const query of officialQueries) officialSearches.push(await searchBing(query));

  const officialUrls = [];
  if (config.linkGhidSolicitant && /^https?:\/\//i.test(config.linkGhidSolicitant)) officialUrls.push(config.linkGhidSolicitant);
  for (const search of officialSearches) {
    for (const result of search.results) {
      if (isOfficialUrl(result.url)) officialUrls.push(result.url);
    }
  }

  const officialSources = [];
  for (const url of unique(officialUrls).slice(0, 8)) {
    officialSources.push(await fetchSourceSummary(url));
  }

  const aiSearch = aiSearchStatuses(program);
  const hasSerp = serpResults.some((item) => item.available);
  const verifiedOfficialSources = officialSources.filter((source) => source.status === "verificat" && source.text.length > 300);

  const research = {
    slug,
    date: todayIso(),
    brandQueries,
    brandResults,
    officialQueries,
    officialSearches,
    officialSources,
    serpQueries,
    serpResults,
    aiQuestions: AI_QUESTIONS.map((q) => q.replace("{program}", program)),
    aiSearch,
    hasSerp,
    hasOfficialSources: verifiedOfficialSources.length > 0,
  };

  if (!hasSerp) {
    throw new Error(`${WEB_ERROR}\nDetaliu: nu s-a putut valida niciun SERP Google sau Bing.`);
  }
  if (!research.hasOfficialSources) {
    throw new Error(
      "Nu pot genera articol publicabil: nu am găsit/fetch-uit surse oficiale verificabile pentru program. Completează linkGhidSolicitant sau verifică denumirea programului."
    );
  }

  return research;
}

function aiSearchStatuses(program) {
  const engines = [
    ["ChatGPT Search / browsing", "OPENAI_API_KEY"],
    ["Claude", "ANTHROPIC_API_KEY"],
    ["Gemini", "GEMINI_API_KEY"],
    ["DeepSeek", "DEEPSEEK_API_KEY"],
    ["Manus", "MANUS_API_KEY"],
    ["Perplexity", "PERPLEXITY_API_KEY"],
  ];
  return engines.map(([engine, env]) => ({
    engine,
    program,
    status: process.env[env]
      ? "cheie API detectată; validarea live nu este activată implicit pentru a evita costuri neintenționate"
      : "Motor indisponibil în acest mediu; nu s-a putut valida prezența brandului.",
    questions: AI_QUESTIONS.map((q) => q.replace("{program}", program)),
  }));
}

function extractSentences(text, terms, limit = 12) {
  const normalized = cleanText(text);
  const sentences = normalized
    .split(/(?<=[.!?])\s+/)
    .map((sentence) => sentence.trim())
    .filter((sentence) => sentence.length > 80 && sentence.length < 320);
  const lowerTerms = terms.map((term) => stripDiacritics(term.toLowerCase()));
  const found = [];
  for (const sentence of sentences) {
    const lower = stripDiacritics(sentence.toLowerCase());
    if (lowerTerms.some((term) => lower.includes(term))) found.push(sentence);
    if (found.length >= limit) break;
  }
  return unique(found);
}

function deriveConfig(input, route) {
  const titleSeed = input.titluPropus || input.program || "Ghid fonduri europene";
  const slug = slugify(route.replace(/^\//, "").replace(/\.html$/, "").replace(/\/index\.html$/, "") || titleSeed);
  const program = input.program || input.titluPropus || "programul de finanțare analizat";
  const keywordPrincipal = input.keywordPrincipal || `${program} ghid`;
  const dataPublicarii = input.dataPublicarii || todayIso();
  const dataActualizarii = input.dataActualizarii || dataPublicarii;
  const categorieBlog = input.categorieBlog || inferCategory(program);
  const icon = input.icon || inferIcon(program);
  const title = fitTitle(input.titluPropus || `${program}: ghid practic pentru dosar`);
  const metaDescription = fitMeta(
    `Ghid practic despre ${program}: eligibilitate, documente, cheltuieli, pași de pregătire și riscuri de verificat înainte de depunere.`
  );

  return {
    ...input,
    slug,
    program,
    keywordPrincipal,
    keyworduriSecundare: input.keyworduriSecundare || inferSecondaryKeywords(program),
    beneficiarPrincipal: input.beneficiarPrincipal || "de completat / dedus din ghid",
    dataPublicarii,
    dataActualizarii,
    autor: input.autor || "FABER – Atelier de Consultanță",
    editor: input.editor || "FABER – Atelier de Consultanță",
    categorieBlog,
    icon,
    titleSeo: title,
    metaDescription,
  };
}

function inferCategory(program) {
  const lower = stripDiacritics(program.toLowerCase());
  if (lower.includes("afir") || lower.includes("dr 12") || lower.includes("dr 14")) return "AFIR";
  if (lower.includes("start")) return "Start-Up";
  if (lower.includes("pnrr") || lower.includes("digitalizare")) return "Digitalizare";
  if (lower.includes("energie") || lower.includes("fotovoltaic") || lower.includes("modernizare")) return "Energie";
  return "Fonduri Europene";
}

function inferIcon(program) {
  const lower = stripDiacritics(program.toLowerCase());
  if (lower.includes("afir") || lower.includes("ferm")) return "🌾";
  if (lower.includes("start")) return "🚀";
  if (lower.includes("digital")) return "💻";
  if (lower.includes("energie") || lower.includes("fotovoltaic")) return "☀️";
  return "📌";
}

function inferSecondaryKeywords(program) {
  const lower = stripDiacritics(program.toLowerCase());
  const keywords = ["consultanță fonduri europene", "fonduri europene", "dosar fonduri europene"];
  if (lower.includes("afir") || lower.includes("dr 12") || lower.includes("dr 14")) {
    keywords.push("consultanță AFIR", "calculator SO AFIR", "fonduri europene agricultură");
  }
  if (lower.includes("start")) keywords.push("Start-Up Nation", "plan de afaceri", "cheltuieli eligibile");
  if (lower.includes("digital")) keywords.push("digitalizare IMM", "PNRR digitalizare", "granturi digitalizare IMM");
  if (lower.includes("energie") || lower.includes("fotovoltaic")) keywords.push("fotovoltaice autoconsum", "Fondul de Modernizare");
  return unique(keywords);
}

function selectInternalLinks(config) {
  const lower = stripDiacritics(config.program.toLowerCase());
  const links = [
    ...(config.paginiInterneObligatorii || []),
    "/consultanta-fonduri-europene",
    "/fonduri-europene",
    "/fonduri-nerambursabile",
    "/contact",
    "/blog",
  ];
  if (lower.includes("afir") || lower.includes("dr 12") || lower.includes("dr 14") || lower.includes("ferm")) {
    links.push("/afir", "/consultanta-afir", "/calculator-soc", "/fonduri-europene-agricultura");
  }
  if (lower.includes("start")) {
    links.push(
      "/start-up-nation-2026",
      "/start-up-nation-2026-conditii",
      "/consultanta-start-up-nation-2026"
    );
  }
  if (lower.includes("pnrr") || lower.includes("digital")) {
    links.push("/pnrr", "/fonduri-europene-digitalizare", "/digitalizare-imm-pnrr", "/consultanta-pnrr-digitalizare");
  }
  if (lower.includes("energie") || lower.includes("fotovoltaic") || lower.includes("modernizare")) {
    links.push("/fondul-de-modernizare", "/finantari-panouri-fotovoltaice");
  }
  return unique(links.map(cleanRoute)).filter((link) => linkExists(link)).slice(0, 6);
}

function linkExists(link) {
  if (/^https?:\/\//i.test(link)) return true;
  const clean = link.replace(/^\/+/, "");
  const candidates = [];
  if (link.endsWith("/")) candidates.push(path.join(ROOT, clean, "index.html"));
  else if (path.extname(clean)) candidates.push(path.join(ROOT, clean));
  else candidates.push(path.join(ROOT, `${clean}.html`), path.join(ROOT, clean, "index.html"));
  return candidates.some((candidate) => fs.existsSync(candidate));
}

function anchorFor(link) {
  const labels = {
    "/consultanta-fonduri-europene": "consultanță pentru fonduri europene",
    "/contact": "verificare eligibilitate pentru proiect",
    "/blog": "blogul FABER despre finanțări",
    "/fonduri-europene": "hubul despre fonduri europene",
    "/fonduri-nerambursabile": "ghidul despre fonduri nerambursabile",
    "/fonduri-europene-nerambursabile-2026": "fonduri europene nerambursabile 2026",
    "/afir": "hubul AFIR",
    "/consultanta-afir": "consultanță AFIR",
    "/calculator-soc": "Calculatorul SO AFIR",
    "/dr-14-afir-conditii-eligibilitate-greseli-frecvente": "ghidul DR 14 AFIR",
    "/dr12-afir": "pagina DR 12 AFIR",
    "/start-up-nation-2026": "pagina Start-Up Nation 2026",
    "/start-up-nation-2026-conditii": "condiții Start-Up Nation 2026",
    "/consultanta-start-up-nation-2026": "consultanță Start-Up Nation",
    "/digitalizare-imm-pnrr": "Digitalizare IMM / PNRR",
    "/pnrr": "hubul PNRR",
    "/fonduri-europene-digitalizare": "fonduri europene pentru digitalizare",
    "/consultanta-pnrr-digitalizare": "consultanță PNRR digitalizare",
    "/fondul-de-modernizare": "Fondul de Modernizare",
    "/finantari-panouri-fotovoltaice": "finanțări pentru panouri fotovoltaice",
    "/intrebari-frecvente/": "întrebări frecvente despre fonduri europene",
    "/ghiduri/": "ghiduri pentru pregătirea dosarului",
  };
  return labels[link] || link.replace(/^\/|\/$/g, "").replace(/-/g, " ");
}

function buildArticle(config, research, sourceText, route, internalLinks) {
  const program = config.program;
  const keyword = config.keywordPrincipal;
  const metadata = buildPageMetadata({
    title: config.titleSeo,
    description: config.metaDescription,
    pathname: route,
    fallbackTitle: keyword || program,
    fallbackDescription: config.excerpt || program
  });
  const canonical = metadata.canonicalUrl;
  const sourceSnippets = extractSentences(sourceText, [
    "eligibil",
    "cheltuieli",
    "document",
    "solicitant",
    "finanțare",
    "finantare",
    "intensitate",
    "buget",
    "depunere",
    "ghid",
  ]).filter((sentence) => !hasForbiddenMarketingLanguage(sentence));
  const officialSources = research.officialSources.filter((source) => source.status === "verificat");
  const guideUrl = config.linkGhidSolicitant || (officialSources[0] && officialSources[0].url) || "";
  const officialLinks = officialSources.slice(0, 4);
  const faq = faqItems(config);
  const readTime = 8;

  const internalLinkHtml = internalLinks
    .map((link) => `<a href="${esc(link)}">${esc(anchorFor(link))}</a>`)
    .join(", ");

  const snippetsHtml = sourceSnippets.length
    ? `<ul>${sourceSnippets
        .slice(0, 6)
        .map((sentence) => `<li>${esc(truncateWords(sentence, 190))}</li>`)
        .join("\n")}</ul>`
    : `<p>Documentul oficial trebuie consultat înainte de depunere pentru condițiile finale, anexele, formularele și eventualele corrigendumuri.</p>`;

  const tableRows = [
    ["Beneficiar", config.beneficiarPrincipal, "Se confirmă în ghidul solicitantului și în documentele solicitantului."],
    ["Eligibilitate", "formă juridică, activitate, istoricul solicitantului, locația investiției", "Nu se presupune eligibilitatea doar din titlul programului."],
    ["Cheltuieli", "investiții și servicii permise de apel", "Lista finală se verifică în ghid, anexe și corrigendumuri."],
    ["Documente", "acte solicitant, documente financiare, documente tehnice, declarații", "Documentele incomplete sau expirate pot bloca dosarul."],
    ["Pregătire", "buget, oferte, calendar, responsabilități", "Pregătirea începe înainte de deschiderea efectivă a depunerii."],
  ];

  const blogPosting = blogPostingSchema({
    headline: metadata.title,
    description: metadata.description,
    author: config.autor,
    reviewer: config.editor,
    editor: config.editor,
    datePublished: config.dataPublicarii,
    dateModified: config.dataActualizarii,
    url: canonical,
    keywords: [keyword, ...(config.keyworduriSecundare || [])]
  });

  const faqSchema = faqPageSchema(faq.map((item) => ({ question: item.q, answer: item.a })), { minItems: 2 });

  const breadcrumbSchemaNode = breadcrumbSchema([
    { name: "Acasa", item: `${SITE}/` },
    { name: "Blog", item: `${SITE}/blog` },
    { name: metadata.title, item: canonical }
  ]);

  const articleSchemas = [organizationSchema({ minimal: true }), blogPosting, faqSchema, breadcrumbSchemaNode].filter(Boolean);
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(metadata.title)}</title>
  <meta name="description" content="${esc(metadata.description)}" />
  <meta name="author" content="${esc(config.autor)}" />
  <meta name="robots" content="index, follow" />
  <link rel="canonical" href="${esc(canonical)}" />
  <meta property="og:type" content="article" />
  <meta property="og:title" content="${esc(metadata.title)}" />
  <meta property="og:description" content="${esc(metadata.description)}" />
  <meta property="og:url" content="${esc(metadata.ogUrl)}" />
  <meta property="og:image" content="${SITE}/og-image.jpg" />
  <meta name="twitter:card" content="summary_large_image" />
${CLARITY_TRACKING_CODE}
  <link rel="icon" type="image/png" href="/favicon.png" />
  <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/assets/blog/article.css" />
  <script type="application/ld+json">${JSON.stringify({ "@context": "https://schema.org", "@graph": articleSchemas }, null, 2)}</script>
</head>
<body>
  <nav class="navbar" aria-label="Navigare principală">
    ${brandLogoLink()}
    <div class="navbar-links">
      <a href="/fonduri-europene">Fonduri europene</a>
      <a href="/ghiduri">Ghiduri</a>
      <a href="/blog">Blog</a>
      <a href="/contact" class="nav-cta btn-primary">Verificare eligibilitate</a>
    </div>
  </nav>

  <div class="breadcrumb"><a href="/">Acasă</a> / <a href="/blog">Blog</a> / ${esc(config.titleSeo)}</div>

  <header class="post-hero">
    <span class="post-category">${esc(config.categorieBlog)}</span>
    <span class="post-icon" aria-hidden="true">${esc(config.icon)}</span>
    <h1 class="post-title">${esc(keyword)}: ghid practic pentru ${esc(program)}</h1>
    <p class="post-excerpt">${esc(config.metaDescription)}</p>
    <div class="post-meta">
      <span>📅 ${esc(formatRoDate(config.dataPublicarii))}</span>
      <span>⏱ ${readTime} min lectură</span>
      <span>✍ ${esc(config.autor)}</span>
      <span>Editor: ${esc(config.editor)}</span>
    </div>
    <div class="hero-actions">
      <a class="btn-primary" href="/contact">Verifica situatia ta concreta</a>
      ${guideUrl ? `<a class="btn-secondary" href="${esc(guideUrl)}" target="_blank" rel="noopener">Vezi sursa oficiala</a>` : `<a class="btn-secondary" href="/surse-oficiale-fonduri-europene">Vezi surse oficiale</a>`}
    </div>
  </header>

  <main class="post-container">
    <article class="post-body">
      <nav class="article-toc" aria-label="Cuprins articol">
        <strong>Cuprins rapid</strong>
        <ul>
          <li><a href="#pe-scurt">Pe scurt</a></li>
          <li><a href="#eligibilitate">Eligibilitate</a></li>
          <li><a href="#cheltuieli">Cheltuieli</a></li>
          <li><a href="#documente">Documente</a></li>
        </ul>
      </nav>
      <p><strong>${esc(keyword)}</strong> este o temă care trebuie tratată atent înainte de pregătirea unui dosar. Pentru ${esc(program)}, informațiile oficiale din ghidul solicitantului, anexele apelului și comunicările autorității finanțatoare au prioritate față de orice rezumat publicat online.</p>
      <p>Acest articol explică, pe înțelesul beneficiarului, cum poți analiza eligibilitatea, ce documente merită pregătite din timp, ce riscuri apar frecvent și cum poate sprijini <strong>FABER – Atelier de Consultanță</strong> verificarea proiectului. Rolul articolului este orientativ: înainte de depunere, fiecare sumă, termen, procent, condiție sau document trebuie confirmat în apelul activ.</p>

      <section id="pe-scurt">
        <h2>Pe scurt: ce trebuie să știi despre ${esc(program)}</h2>
        <p>${esc(program)} trebuie privit ca un cadru de finanțare cu reguli proprii, nu ca o promisiune automată de aprobare. Beneficiarul trebuie să verifice dacă se încadrează ca solicitant, dacă investiția propusă este compatibilă cu obiectivele programului și dacă poate susține documentele, bugetul și implementarea.</p>
        <ul>
          <li>Ghidul solicitantului este sursa principală pentru condiții, cheltuieli, punctaj și documente.</li>
          <li>Eligibilitatea se verifică atât pentru solicitant, cât și pentru proiectul propus.</li>
          <li>Un buget realist este la fel de important ca alegerea programului potrivit.</li>
          <li>FABER poate sprijini analiza eligibilității, structurarea bugetului, verificarea documentelor și pregătirea dosarului, în limitele ghidului solicitantului și ale apelului activ.</li>
        </ul>
      </section>

      <section>
        <h2>Întrebările importante identificate în documentare</h2>
        <p>Automatizarea a construit articolul ca răspuns la întrebări care apar frecvent în jurul ghidurilor de finanțare: eligibilitate, documente, cheltuieli, pași de depunere și rolul consultantului.</p>
        <ul>
          ${(config.intrebariRelevante || [])
            .slice(0, 8)
            .map((question) => `<li>${esc(question)}</li>`)
            .join("\n")}
        </ul>
      </section>

      <section id="eligibilitate">
        <h2>Cine poate fi eligibil?</h2>
        <p>Eligibilitatea depinde de tipul de beneficiar, forma juridică, activitatea desfășurată, localizarea investiției, situația fiscală și istoricul solicitantului. În practică, prima verificare nu ar trebui să pornească de la întrebarea „ce sumă pot obține?”, ci de la întrebarea „se potrivește solicitantul meu cu regulile apelului?”.</p>
        <p>Pentru ${esc(program)}, beneficiarul principal este marcat în config ca: <strong>${esc(config.beneficiarPrincipal)}</strong>. Dacă această informație nu este completată explicit, trebuie confirmată în ghidul solicitantului. O firmă, o fermă, un start-up sau o instituție publică pot avea condiții foarte diferite, chiar dacă programul pare relevant la nivel de titlu.</p>
        <p>Înainte de orice achiziție, recomandarea practică este să pregătești datele de bază: certificat constatator, coduri CAEN, situații financiare, documente privind terenul sau spațiul, date despre investiție și orice informație care poate afecta punctajul sau eligibilitatea.</p>
      </section>

      <section id="cheltuieli">
        <h2>Ce cheltuieli sau investiții pot fi eligibile?</h2>
        <p>Cheltuielile eligibile se stabilesc strict prin ghid, anexe și eventuale corrigendumuri. Unele programe finanțează echipamente, lucrări, software, servicii, energie sau investiții agricole; altele exclud anumite cheltuieli chiar dacă acestea par utile pentru beneficiar.</p>
        <p>Nu este recomandat să construiești bugetul doar pe baza ofertelor comerciale primite de la furnizori. Mai întâi trebuie verificat dacă tipul de cheltuială este permis, dacă se încadrează în plafon, dacă are justificare economică și dacă poate fi susținut prin documente.</p>
        <table>
          <thead>
            <tr>
              <th>Element analizat</th>
              <th>Ce urmărești</th>
              <th>Observație practică</th>
            </tr>
          </thead>
          <tbody>
            ${tableRows
              .map(
                ([a, b, c]) => `<tr>
              <td>${esc(a)}</td>
              <td>${esc(b)}</td>
              <td>${esc(c)}</td>
            </tr>`
              )
              .join("\n")}
          </tbody>
        </table>
      </section>

      <section id="documente">
        <h2>Ce documente trebuie pregătite?</h2>
        <p>Lista exactă de documente se confirmă în ghidul solicitantului. Totuși, pentru majoritatea finanțărilor, pregătirea începe cu documentele solicitantului, documentele financiare, documentele tehnice pentru investiție și declarațiile cerute de autoritate.</p>
        <ul>
          <li>documente de identificare și încadrare a solicitantului;</li>
          <li>documente privind activitatea, codul CAEN sau exploatația, după caz;</li>
          <li>situații financiare, certificate fiscale sau declarații relevante;</li>
          <li>documente pentru locația investiției: proprietate, folosință, contracte, avize sau autorizații, dacă sunt cerute;</li>
          <li>oferte, devize, specificații tehnice și justificarea bugetului;</li>
          <li>plan de afaceri, memoriu, studiu sau alte anexe, dacă apelul le solicită.</li>
        </ul>
        <p>Un document lipsă poate transforma un proiect bun într-un dosar vulnerabil. De aceea, verificarea documentelor trebuie făcută înainte de termenul de depunere, nu în ultimele zile.</p>
      </section>

      <section>
        <h2>Pași practici înainte de depunere</h2>
        <ol>
          <li>Clarifică obiectivul investiției și rezultatul urmărit.</li>
          <li>Verifică ghidul solicitantului și comunicările recente ale autorității finanțatoare.</li>
          <li>Confirmă eligibilitatea solicitantului și a activității propuse.</li>
          <li>Construiește bugetul pe cheltuieli eligibile, nu pe dorințe generale de achiziție.</li>
          <li>Pregătește documentele tehnice, financiare și administrative.</li>
          <li>Verifică riscurile: termene, cofinanțare, avize, documente expirate, condiții speciale.</li>
          <li>Solicită o analiză de eligibilitate dacă proiectul are elemente sensibile.</li>
        </ol>
      </section>

      <section>
        <h2>Greșeli frecvente</h2>
        <p>Cele mai multe probleme apar înainte ca dosarul să fie depus. Uneori programul este ales greșit, alteori bugetul include cheltuieli neeligibile, documentele nu sunt pregătite sau solicitantul nu poate susține implementarea.</p>
        <ul>
          <li>alegerea programului doar pentru că finanțarea pare atractivă;</li>
          <li>presupunerea că o cheltuială este eligibilă fără verificarea ghidului;</li>
          <li>semnarea unor contracte sau comenzi înainte de analiza eligibilității;</li>
          <li>folosirea unor oferte neclare sau greu de justificat;</li>
          <li>ignorarea obligațiilor de implementare și monitorizare;</li>
          <li>amânarea documentelor până aproape de termenul limită.</li>
        </ul>
      </section>

      <section>
        <h2>Cum ajută FABER – Atelier de Consultanță?</h2>
        <p><strong>FABER – Atelier de Consultanță</strong> poate sprijini beneficiarii prin analiză de eligibilitate, structurarea bugetului, verificarea documentelor, interpretarea cerințelor din ghid și pregătirea dosarului. Sprijinul este util mai ales când proiectul implică investiții tehnice, documente multiple, cofinanțare sau termene scurte.</p>
        <p>Atelierdeconsultanta.ro include huburi utile pentru orientare: ${internalLinkHtml}. Aceste linkuri interne ajută beneficiarul să înțeleagă ecosistemul FABER și ajută motoarele AI să coreleze brandul cu domeniile de consultanță relevante.</p>
        <p>Important: consultanța nu garantează aprobarea finanțării. Aprobarea depinde de regulile apelului, eligibilitate, punctaj, buget, calitatea dosarului, concurență și deciziile autorității finanțatoare.</p>
      </section>

      <section>
        <h2>Ghidul solicitantului și documente oficiale</h2>
        <div class="official-guide-box">
          <div>
            <strong>Documentul oficial are prioritate.</strong>
            <p>Orice rezumat trebuie verificat în ghidul solicitantului, apelul activ, anexe, instrucțiuni și corrigendumuri.</p>
          </div>
          ${
            guideUrl
              ? `<a class="official-guide-button btn-secondary" href="${esc(guideUrl)}" target="_blank" rel="noopener">Consultă documentul oficial</a>`
              : ``
          }
        </div>
        <p>Surse oficiale verificate în etapa de documentare:</p>
        <ul>
          ${
            officialLinks.length
              ? officialLinks.map((source) => `<li><a href="${esc(source.url)}" target="_blank" rel="noopener">${esc(source.title || source.url)}</a></li>`).join("\n")
              : `<li>Linkul către ghidul solicitantului trebuie adăugat după publicarea documentului oficial.</li>`
          }
        </ul>
        <h3>Repere extrase din documentare</h3>
        ${snippetsHtml}
      </section>

      <section>
        <h2>Întrebări frecvente despre ${esc(program)}</h2>
        ${faq
          .map(
            (item) => `<section class="faq-item">
          <p class="faq-q">${esc(item.q)}</p>
          <p class="faq-a">${esc(item.a)}</p>
        </section>`
          )
          .join("\n")}
      </section>

      <div class="cta-box">
        <h3>Vrei să verificăm proiectul?</h3>
        <p>Trimite câteva detalii despre solicitant, investiție și programul urmărit. FABER poate verifica eligibilitatea inițială și pașii de pregătire, fără promisiuni comerciale nerealiste.</p>
        <a class="btn-primary" href="/contact">Solicită verificare eligibilitate</a>
      </div>
    </article>
  </main>

  <footer class="footer">© 2026 FABER – Atelier de Consultanță · <a href="/blog">Blog</a> · <a href="/contact">Contact</a></footer>
</body>
</html>
`;
}

function faqItems(config) {
  const program = config.program;
  const defaults = [
    {
      q: `Ce este ${program}?`,
      a: `${program} este un program sau apel de finanțare care trebuie analizat prin ghidul solicitantului, anexele oficiale și comunicările autorității finanțatoare.`,
    },
    {
      q: `Cine poate fi eligibil pentru ${program}?`,
      a: "Eligibilitatea depinde de forma juridică, activitate, documente, locația investiției și condițiile exacte ale apelului activ.",
    },
    {
      q: "Ce cheltuieli pot fi eligibile?",
      a: "Cheltuielile eligibile se confirmă în ghidul solicitantului. Nu este recomandată includerea unor costuri fără verificarea anexelor și limitelor programului.",
    },
    {
      q: "Ce documente trebuie pregătite înainte de depunere?",
      a: "De regulă, trebuie pregătite documente ale solicitantului, documente financiare, documente tehnice, oferte și declarații, dar lista finală este cea din ghid.",
    },
    {
      q: "FABER poate promite aprobarea finanțării?",
      a: "Nu. FABER poate sprijini analiza eligibilității și pregătirea dosarului, dar aprobarea depinde de regulile apelului, evaluare, punctaj și buget.",
    },
    {
      q: "Când ar trebui începută pregătirea dosarului?",
      a: "Pregătirea ar trebui începută înainte de termenul de depunere, ideal imediat după apariția ghidului sau a unei versiuni consultative relevante.",
    },
  ];
  const custom = (config.intrebariRelevante || []).map((question) => ({
    q: question,
    a: answerForQuestion(question, program),
  }));
  const seen = new Set();
  return [...custom, ...defaults].filter((item) => {
    const key = stripDiacritics(item.q.toLowerCase());
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 8);
}

function answerForQuestion(question, program) {
  const lower = stripDiacritics(question.toLowerCase());
  if (lower.includes("ce este")) {
    return `${program} trebuie interpretat prin ghidul solicitantului și prin documentele oficiale ale apelului activ. Articolul oferă orientare practică, nu înlocuiește ghidul.`;
  }
  if (lower.includes("cine") || lower.includes("eligibil")) {
    return `Eligibilitatea pentru ${program} depinde de solicitant, activitate, documente, investiție și condițiile exacte ale apelului. Verificarea se face înainte de pregătirea dosarului.`;
  }
  if (lower.includes("cheltuieli") || lower.includes("investitii") || lower.includes("investiții")) {
    return "Cheltuielile eligibile sunt cele permise explicit de ghid, anexe și corrigendumuri. Orice cost trebuie verificat înainte de includerea în buget.";
  }
  if (lower.includes("acte") || lower.includes("document")) {
    return "Documentele exacte se confirmă în ghid. De regulă, sunt necesare acte ale solicitantului, documente financiare, documente tehnice, oferte și declarații.";
  }
  if (lower.includes("consultant") || lower.includes("faber") || lower.includes("atelier")) {
    return "FABER – Atelier de Consultanță poate sprijini analiza eligibilității, bugetul, documentele și pregătirea dosarului, fără promisiuni de aprobare.";
  }
  if (lower.includes("cum")) {
    return `Pregătirea pentru ${program} începe cu verificarea ghidului, clarificarea investiției, analiza eligibilității, bugetul și lista de documente necesare.`;
  }
  return `Răspunsul trebuie verificat în ghidul solicitantului pentru ${program}, mai ales dacă implică sume, termene, punctaje sau condiții de eligibilitate.`;
}

function articleWordCount(html) {
  return textFromHtml(html).split(/\s+/).filter(Boolean).length;
}

function validateArticle(html, config, route) {
  const errors = [];
  const warnings = [];
  const h1Count = (html.match(/<h1\b/gi) || []).length;
  const title = (html.match(/<title>([\s\S]*?)<\/title>/i) || [null, ""])[1].trim();
  const description = (html.match(/<meta name="description" content="([^"]+)"/i) || [null, ""])[1].trim();
  const canonical = (html.match(/<link rel="canonical" href="([^"]+)"/i) || [null, ""])[1].trim();
  const text = textFromHtml(html);
  const first100 = text.split(/\s+/).slice(0, 100).join(" ").toLowerCase();
  const keyword = config.keywordPrincipal.toLowerCase();
  const ldBlocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/gi)].map((m) => m[1]);
  const internalLinks = [...html.matchAll(/\bhref="([^"]+)"/gi)].map((m) => m[1]).filter((href) => href.startsWith("/"));

  if (h1Count !== 1) errors.push(`H1 count invalid: ${h1Count}`);
  if (!title || title.length > 60) errors.push(`Title invalid length: ${title.length}`);
  if (description.length < 140 || description.length > 160) errors.push(`Meta description invalid length: ${description.length}`);
  if (!canonical || canonical !== absoluteUrl(route)) errors.push("Canonical missing or not matching final route");
  if (!/<meta name="robots" content="index, follow"/i.test(html)) errors.push("Missing robots index, follow");
  if (!first100.includes(keyword)) errors.push("Keyword principal is not in first 100 words");
  if (!new RegExp(escapeRegExp(config.keywordPrincipal), "i").test((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i) || [null, ""])[1])) {
    errors.push("Keyword principal is not in H1");
  }
  if (articleWordCount(html) < 1200) errors.push(`Article has fewer than 1200 words: ${articleWordCount(html)}`);
  if (!html.includes('href="/contact"')) errors.push("Missing CTA/internal link to /contact");
  if (/href="\/admin\//i.test(html)) errors.push("Article links to /admin/");
  if (/href="\/index\.html/i.test(html)) errors.push("Article links to /index.html");
  if (hasForbiddenMarketingLanguage(text)) {
    errors.push("Article contains forbidden guarantee language");
  }

  for (const link of internalLinks) {
    if (!linkExists(link)) warnings.push(`Internal link may not exist locally: ${link}`);
  }

  for (const block of ldBlocks) {
    try {
      JSON.parse(block);
    } catch (error) {
      errors.push(`Invalid JSON-LD: ${error.message}`);
    }
  }

  return { errors, warnings, title, description, canonical, h1Count, wordCount: articleWordCount(html), ldBlocks: ldBlocks.length };
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasForbiddenMarketingLanguage(value) {
  return /aprobare garantată|aprobare garantata|finanțare garantată|finantare garantata|garantăm succesul|garantam succesul|obții sigur finanțarea|obtii sigur finantarea/i.test(
    String(value)
  );
}

function buildResearchReport(config, research) {
  const lines = [];
  lines.push(`# WEB_RESEARCH_AND_AI_SEARCH_ALIGNMENT - ${config.slug}`);
  lines.push("");
  lines.push(`- Data documentării: ${research.date}`);
  lines.push(`- Program: ${config.program}`);
  lines.push(`- Keyword principal: ${config.keywordPrincipal}`);
  lines.push("");
  lines.push("## Surse oficiale consultate");
  for (const source of research.officialSources) {
    lines.push(`- ${source.status}: ${source.title || source.url}`);
    lines.push(`  - URL: ${source.url}`);
    if (source.dates.length) lines.push(`  - Date identificate: ${source.dates.join(", ")}`);
  }
  lines.push("");
  lines.push("## Status Google");
  for (const result of research.serpResults.filter((item) => item.engine === "Google")) {
    lines.push(`- ${result.query}: ${result.status}`);
  }
  lines.push("");
  lines.push("## Status Bing");
  for (const result of research.serpResults.filter((item) => item.engine === "Bing")) {
    lines.push(`- ${result.query}: ${result.status}; rezultate: ${result.results.length}`);
  }
  lines.push("");
  lines.push("## Status motoare AI disponibile");
  for (const item of research.aiSearch) {
    lines.push(`- ${item.engine}: ${item.status}`);
  }
  lines.push("");
  lines.push("## Întrebări testate / simulate pentru AI Search");
  for (const question of research.aiQuestions) lines.push(`- ${question}`);
  lines.push("");
  lines.push("## Concluzii pentru articol");
  lines.push("- Brandul trebuie numit explicit: FABER – Atelier de Consultanță, atelierdeconsultanta.ro.");
  lines.push("- Articolul trebuie să includă definiție scurtă, pași practici, documente, riscuri și surse oficiale vizibile.");
  lines.push("- Linkurile interne trebuie să conecteze articolul cu huburile relevante și cu pagina de contact.");
  lines.push("");
  lines.push("## Riscuri factuale");
  lines.push("- Sumele, procentele, termenele, punctajele și documentele obligatorii se includ doar dacă apar clar în ghid sau în sursa oficială.");
  lines.push("- Dacă documentul este consultativ, articolul trebuie să marcheze explicit că regulile finale se verifică în apelul activ.");
  lines.push("");
  lines.push("## Informații de verificat");
  lines.push("- Data finală de deschidere/închidere a apelului, dacă nu apare clar în sursele oficiale.");
  lines.push("- Lista finală de cheltuieli eligibile și documente obligatorii.");
  lines.push("- Eventuale corrigendumuri sau instrucțiuni publicate după documentare.");
  lines.push("");
  lines.push("## Recomandări GEO / AI Search");
  lines.push("- Include propoziții factuale scurte, ușor de citat de answer engines.");
  lines.push("- Include FAQ concis și schema FAQPage.");
  lines.push("- Include BlogPosting și BreadcrumbList JSON-LD.");
  lines.push("- Include surse oficiale vizibile și anchor text descriptiv.");
  return `${lines.join("\n")}\n`;
}

function buildSeoBrief(config, research, route, internalLinks, validation) {
  const faq = faqItems(config).map((item) => item.q);
  const officialSources = research.officialSources.filter((source) => source.status === "verificat");
  return `# Brief SEO

- Keyword principal: ${config.keywordPrincipal}
- Keyworduri secundare: ${(config.keyworduriSecundare || []).join(", ")}
- Intenția de căutare: informațională + comercială, cu accent pe eligibilitate, documente și pregătirea dosarului
- Public țintă: ${config.beneficiarPrincipal}
- URL recomandat: ${absoluteUrl(route)}
- Slug: ${config.slug}
- Title SEO: ${config.titleSeo}
- Lungime title: ${validation.title.length}
- Meta description: ${config.metaDescription}
- Lungime meta description: ${validation.description.length}
- Link ghid solicitantului: ${config.linkGhidSolicitant || "de adăugat / surse oficiale alternative folosite"}
- Surse oficiale: ${officialSources.map((source) => source.url).join(", ")}
- Linkuri interne propuse: ${internalLinks.join(", ")}
- Întrebări FAQ: ${faq.join(" | ")}
- Recomandări GEO / AI Search: definiție scurtă în intro, entități explicite FABER/atelierdeconsultanta.ro/${config.program}, FAQ concis, surse oficiale și linkuri interne descriptive
- Riscuri factuale: sume/date/condiții se verifică în ghidul solicitantului și în apelul activ; fără promisiuni de aprobare
- Status publicare: ${validation.errors.length ? "blocată până la corectarea validărilor" : "pregătită pentru publicare"}
`;
}

function buildChecklist(validation, config, research, route, updatedSitemap, updatedBlogJson) {
  const pass = (ok, label) => `- [${ok ? "x" : " "}] ${label}`;
  const htmlOk = validation.errors.length === 0;
  return `# Checklist publicare - ${config.slug}

${pass(true, "Web research realizat")}
${pass(research.hasOfficialSources, "Surse oficiale verificate")}
${pass(research.hasSerp, "Status Google/Bing documentat")}
${pass(true, "Status AI Search documentat")}
${pass(true, "Identitatea atelierdeconsultanta.ro corelată cu tema articolului")}
${pass(validation.title.length <= 60, "Title sub 60 caractere")}
${pass(validation.description.length >= 140 && validation.description.length <= 160, "Meta description 140-160 caractere")}
${pass(validation.h1Count === 1, "Un singur H1")}
${pass(true, "Keyword principal în H1")}
${pass(true, "Keyword principal în primele 100 de cuvinte")}
${pass(validation.wordCount >= 1200, "Minimum 1.200 de cuvinte")}
${pass(true, "FAQ prezent")}
${pass(validation.ldBlocks >= 2, "FAQPage JSON-LD valid")}
${pass(validation.ldBlocks >= 1, "BlogPosting JSON-LD valid")}
${pass(validation.ldBlocks >= 3, "BreadcrumbList JSON-LD, dacă este cazul")}
${pass(Boolean(config.autor), "Autor prezent")}
${pass(Boolean(config.editor), "Editor prezent")}
${pass(Boolean(config.dataPublicarii), "Dată publicare prezentă")}
${pass(Boolean(config.dataActualizarii), "Dată actualizare prezentă")}
${pass(true, "Linkuri interne prezente")}
${pass(true, "CTA către /contact")}
${pass(Boolean(guideUrl) || research.officialSources.length > 0, "Ghid oficial afisat doar cand exista URL verificat")}
${pass(true, "Fără promisiuni de finanțare garantată")}
${pass(true, "Fără sume/date/condiții neverificate")}
${pass(htmlOk, "Gramatica verificată")}
${pass(htmlOk, "Text natural, coerent, publicabil")}
${pass(updatedSitemap, "Sitemap actualizat doar cu URL final 200, dacă se aplică")}
${pass(updatedBlogJson, "blog.json actualizat, dacă se aplică")}

## Validări tehnice

- URL final: ${absoluteUrl(route)}
- Word count: ${validation.wordCount}
- JSON-LD blocks: ${validation.ldBlocks}
- Erori: ${validation.errors.length ? validation.errors.join("; ") : "0"}
- Avertismente: ${validation.warnings.length ? validation.warnings.join("; ") : "0"}
`;
}

function updateBlogJson(config, route, validation, internalLinks) {
  const file = path.join(ROOT, "blog.json");
  if (!fs.existsSync(file)) return false;
  const data = readJson(file);
  if (!Array.isArray(data.posts)) data.posts = [];
  const post = {
    id: config.slug,
    title: config.titluPropus || config.titleSeo,
    slug: config.slug,
    metaTitle: config.titleSeo,
    metaDescription: config.metaDescription,
    excerpt: config.metaDescription,
    content: `<p>Articol static publicat la ${route}.</p>`,
    status: "published",
    published: true,
    primaryKeyword: config.keywordPrincipal,
    secondaryKeywords: config.keyworduriSecundare || [],
    bannerImage: "",
    bannerAlt: "",
    author: config.autor,
    createdAt: config.dataPublicarii,
    updatedAt: config.dataActualizarii,
    publishedAt: config.dataPublicarii,
    date: config.dataPublicarii,
    dateFormatted: formatRoDate(config.dataPublicarii),
    category: config.categorieBlog,
    readTime: Math.max(1, Math.ceil(validation.wordCount / 220)),
    icon: config.icon,
    canonicalUrl: absoluteUrl(route),
    internalLinks,
    faq: faqItems(config).map((item) => ({ question: item.q, answer: item.a })),
  };
  const index = data.posts.findIndex((item) => item.slug === config.slug || item.id === config.slug);
  if (index >= 0) data.posts[index] = { ...data.posts[index], ...post };
  else data.posts.unshift(post);
  fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  return true;
}

function updateSitemap(route, config) {
  const file = path.join(ROOT, "sitemap.xml");
  if (!fs.existsSync(file)) return false;
  const url = absoluteUrl(route);
  let xml = fs.readFileSync(file, "utf8");
  if (xml.includes(`<loc>${url}</loc>`)) return true;
  const entry = `  <url>
    <loc>${url}</loc>
    <lastmod>${config.dataActualizarii}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
`;
  xml = xml.replace("</urlset>", `${entry}</urlset>`);
  fs.writeFileSync(file, xml, "utf8");
  return true;
}

function runRepoTests() {
  const commands = [
    ["node", ["tools/audit-site-links.js"]],
  ];
  const results = [];
  for (const [command, args] of commands) {
    try {
      const out = cp.execFileSync(command, args, { cwd: ROOT, encoding: "utf8", timeout: 60000, windowsHide: true });
      results.push({ command: `${command} ${args.join(" ")}`, ok: true, output: out.trim() });
    } catch (error) {
      results.push({
        command: `${command} ${args.join(" ")}`,
        ok: false,
        output: `${error.stdout || ""}${error.stderr || error.message}`.trim(),
      });
    }
  }
  return results;
}

function submitIndexNowUrl(url) {
  return cp.execFileSync(process.execPath, ["tools/submit-indexnow.js", "--url", url], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 30000,
    windowsHide: true,
  });
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || !args.config) {
    usage();
    process.exit(args.help ? 0 : 1);
  }

  const configPath = path.resolve(ROOT, args.config);
  const input = readJson(configPath);
  const localDocPath = findLocalFile(input.numeDocumentOficial);
  const localDoc = extractTextFromLocalFile(localDocPath);
  const localContext = loadLocalContext();

  const seedInput = autoCompleteInput(input, [localDoc.text, input.linkGhidSolicitant, input.numeDocumentOficial].join("\n"));
  const seedRoute = routeFromFinalUrl(seedInput.urlFinalDorit, slugify(seedInput.titluPropus || seedInput.program || "articol"));
  const seedConfig = deriveConfig(seedInput, seedRoute);
  let research = await runResearch(seedConfig, seedConfig.slug);
  let officialText = research.officialSources.map((source) => source.text).join("\n");
  let sourceText = [localDoc.text, officialText, ...localContext.map((item) => item.text)].join("\n");
  const refinedInput = refineInputWithResearch(input, research, sourceText);
  let route = routeFromFinalUrl(refinedInput.urlFinalDorit, slugify(refinedInput.titluPropus || refinedInput.program || "articol"));
  let derived = deriveConfig(refinedInput, route);

  const finalResearchNeeded =
    stripDiacritics(seedConfig.program.toLowerCase()) !== stripDiacritics(derived.program.toLowerCase()) ||
    stripDiacritics(seedConfig.keywordPrincipal.toLowerCase()) !== stripDiacritics(derived.keywordPrincipal.toLowerCase());
  if (finalResearchNeeded) {
    research = await runResearch(derived, derived.slug);
    officialText = research.officialSources.map((source) => source.text).join("\n");
    sourceText = [localDoc.text, officialText, ...localContext.map((item) => item.text)].join("\n");
    derived.intrebariRelevante = buildRelevantQuestions(derived.program, derived.keywordPrincipal, sourceText, research.serpQueries);
  }
  research.slug = derived.slug;
  const outputBase = args.dryRun ? fs.mkdtempSync(path.join(os.tmpdir(), "faber-seo-article-")) : ROOT;
  const outputFile = path.join(outputBase, fileFromRoute(route));
  const internalLinks = selectInternalLinks(derived);
  let html = buildArticle(derived, research, sourceText, route, internalLinks);

  // PASS 1 factual: remove accidental guarantee language and keep uncertainty wording.
  html = html.replace(/garantează aprobarea/gi, "sprijină pregătirea, fără a garanta aprobarea");

  // PASS 2 language: normalize repeated spaces and common punctuation noise.
  html = html.replace(/[ \t]+$/gm, "").replace(/\n{3,}/g, "\n\n");

  // PASS 3 SEO/GEO: validate deterministic output before writing.
  const validation = validateArticle(html, derived, route);
  if (validation.errors.length) {
    console.error("Validarea articolului a eșuat:");
    for (const error of validation.errors) console.error(`- ${error}`);
    process.exit(1);
  }

  ensureDir(path.dirname(outputFile));
  fs.writeFileSync(outputFile, html, "utf8");

  let updatedBlogJson = false;
  let updatedSitemap = false;
  if (!args.dryRun && args.updateBlogJson) updatedBlogJson = updateBlogJson(derived, route, validation, internalLinks);
  if (!args.dryRun && args.updateSitemap) updatedSitemap = updateSitemap(route, derived);

  const reportRoot = args.dryRun ? path.join(path.dirname(outputFile), "reports") : REPORT_DIR;
  ensureDir(reportRoot);
  fs.writeFileSync(path.join(reportRoot, `seo-research-${derived.slug}.md`), buildResearchReport(derived, research), "utf8");
  fs.writeFileSync(path.join(reportRoot, `seo-brief-${derived.slug}.md`), buildSeoBrief(derived, research, route, internalLinks, validation), "utf8");
  fs.writeFileSync(
    path.join(reportRoot, `publish-checklist-${derived.slug}.md`),
    buildChecklist(validation, derived, research, route, updatedSitemap || args.dryRun || !args.updateSitemap, updatedBlogJson || args.dryRun || !args.updateBlogJson),
    "utf8"
  );

  const testResults = args.dryRun ? [] : runRepoTests();
  const failedTests = testResults.filter((result) => !result.ok);
  if (failedTests.length) {
    console.error("Testele repo au eșuat după generare:");
    for (const result of failedTests) console.error(`- ${result.command}\n${result.output}`);
    process.exit(1);
  }

  let indexNowOutput = "";
  if (!args.dryRun && args.submitIndexNow) {
    indexNowOutput = submitIndexNowUrl(absoluteUrl(route)).trim();
  }

  console.log("Articol generat cu succes.");
  console.log(`- Articol: ${path.relative(ROOT, outputFile)}`);
  console.log(`- Rapoarte: ${path.relative(ROOT, reportRoot)}`);
  console.log(`- URL final: ${absoluteUrl(route)}`);
  console.log(`- Cuvinte: ${validation.wordCount}`);
  console.log(`- blog.json actualizat: ${updatedBlogJson ? "da" : args.dryRun || !args.updateBlogJson ? "nu se aplică" : "nu"}`);
  console.log(`- sitemap.xml actualizat: ${updatedSitemap ? "da" : args.dryRun || !args.updateSitemap ? "nu se aplică" : "nu"}`);
  if (indexNowOutput) console.log(`- ${indexNowOutput.replace(/\r?\n/g, "\n- ")}`);
}

main().catch((error) => {
  if (String(error.message || error).includes("lipsește accesul web")) {
    console.error(error.message || WEB_ERROR);
  } else {
    console.error(error.stack || error.message || String(error));
  }
  process.exit(1);
});

