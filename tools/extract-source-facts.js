#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DIR = path.join(ROOT, "reports");
const OUT = path.join(REPORT_DIR, "source-facts.json");
const DEFAULT_DIRS = [
  "/home/oai/share",
  "C:/home/oai/share",
  process.env.FABER_SOURCE_DIR || "",
  path.join(process.env.USERPROFILE || "", "Downloads")
].filter(Boolean);

const KEYWORD_RE = /(dr\s*[- ]?\s*12|dr\s*[- ]?\s*14|afir|energie|modernizare|micro(?:intreprinder|întreprinder)|digitalizare|start[- ]?up|femeia|antreprenor|seo|ghid|pnrr|por|regional)/i;
const EXTENSIONS = new Set([".pdf", ".docx", ".xlsx", ".csv", ".txt", ".md"]);
const MAX_FILES = 80;

function parseArgs() {
  const args = { strict: false, dirs: [] };
  for (let index = 2; index < process.argv.length; index += 1) {
    const arg = process.argv[index];
    if (arg === "--strict") args.strict = true;
    else if (arg === "--dir") args.dirs.push(process.argv[++index]);
  }
  return args;
}

function toPosix(value) {
  return value.replace(/\\/g, "/");
}

function walk(dir, files = []) {
  if (!dir || !fs.existsSync(dir)) return files;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!["node_modules", ".git", "dist"].includes(entry.name)) walk(full, files);
    } else if (EXTENSIONS.has(path.extname(entry.name).toLowerCase()) && KEYWORD_RE.test(entry.name)) {
      files.push(full);
    }
  }
  return files;
}

function pyExtract(file) {
  const script = String.raw`
import sys, json, pathlib, zipfile, re
file = pathlib.Path(sys.argv[1])
ext = file.suffix.lower()
text = ""
try:
    if ext == ".pdf":
        import PyPDF2
        with file.open("rb") as fh:
            reader = PyPDF2.PdfReader(fh)
            parts = []
            for page in reader.pages[:80]:
                try:
                    parts.append(page.extract_text() or "")
                except Exception:
                    pass
            text = "\n".join(parts)
    elif ext == ".docx":
        import docx
        doc = docx.Document(str(file))
        text = "\n".join(p.text for p in doc.paragraphs)
    elif ext == ".xlsx":
        import openpyxl
        wb = openpyxl.load_workbook(str(file), read_only=True, data_only=True)
        parts = []
        for ws in wb.worksheets[:8]:
            for row in ws.iter_rows(max_row=200, values_only=True):
                vals = [str(v) for v in row if v is not None]
                if vals:
                    parts.append(" | ".join(vals))
        text = "\n".join(parts)
    else:
        text = file.read_text(encoding="utf-8", errors="ignore")
except Exception as exc:
    print(json.dumps({"error": str(exc), "text": ""}, ensure_ascii=False))
    sys.exit(0)
print(json.dumps({"error": "", "text": text[:250000]}, ensure_ascii=False))
`;
  try {
    const out = cp.execFileSync("python", ["-", file], {
      input: script,
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 8,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      stdio: ["pipe", "pipe", "ignore"]
    });
    return JSON.parse(out);
  } catch (error) {
    return { error: error.message, text: "" };
  }
}

function extractFacts(text) {
  const normalized = text.replace(/\s+/g, " ").trim();
  const patterns = [
    { type: "amount", re: /(?:pana la|maximum|maxim|valoare|grant|sprijin)[^.!?]{0,120}?(?:\d[\d .]*(?:,\d+)?\s*(?:euro|eur|lei|ron|mw))/gi },
    { type: "percentage", re: /(?:intensitate|cofinantare|nerambursabil|procent)[^.!?]{0,120}?\d{1,3}(?:,\d+)?\s*%/gi },
    { type: "threshold", re: /(?:standard output|so|prag|minimum|minim|maxim|varsta|vechime)[^.!?]{0,120}?\d[\d .]*(?:,\d+)?\s*(?:so|ani|eur|euro|lei|ron|%)/gi },
    { type: "score", re: /(?:punctaj|criteriu|selectie|grila)[^.!?]{0,160}?\d{1,3}\s*(?:puncte|pct|%)/gi },
    { type: "date", re: /\b(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}-\d{2}-\d{2})\b/g }
  ];
  const facts = [];
  for (const { type, re } of patterns) {
    let match;
    while ((match = re.exec(normalized)) && facts.length < 300) {
      facts.push({ type, text: match[0].trim().slice(0, 260) });
    }
  }
  return facts;
}

function inferProgram(file, text) {
  const haystack = `${path.basename(file)} ${text.slice(0, 5000)}`.toLowerCase();
  if (/dr\s*[- ]?\s*12/.test(haystack)) return "dr12";
  if (/dr\s*[- ]?\s*14/.test(haystack)) return "dr14";
  if (/digitalizare|pnrr/.test(haystack)) return "digitalizare";
  if (/energie|modernizare|fotovoltaic/.test(haystack)) return "energie";
  if (/micro/.test(haystack)) return "microintreprinderi";
  if (/start[- ]?up/.test(haystack)) return "startup";
  if (/femeia/.test(haystack)) return "femeia-antreprenor";
  if (/seo/.test(haystack)) return "seo";
  return "general";
}

function main() {
  const args = parseArgs();
  const dirs = (args.dirs.length ? args.dirs : DEFAULT_DIRS).map((dir) => path.resolve(dir));
  const files = [...new Set(dirs.flatMap((dir) => walk(dir)).map((file) => path.resolve(file)))].slice(0, MAX_FILES);
  const sources = [];
  for (const file of files) {
    const extracted = pyExtract(file);
    const text = extracted.text || "";
    sources.push({
      file: toPosix(file),
      program: inferProgram(file, text),
      bytes: fs.statSync(file).size,
      extractedChars: text.length,
      error: extracted.error || "",
      facts: extractFacts(text)
    });
  }
  const report = {
    generatedAt: new Date().toISOString(),
    searchedDirs: dirs.map(toPosix),
    sourceCount: sources.length,
    strict: args.strict,
    note: "Acest fisier este intern. Nu copia sourceRef sau numele fisierelor in continutul public.",
    sources
  };
  fs.mkdirSync(REPORT_DIR, { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  if (args.strict && sources.length === 0) {
    console.error("Nu au fost gasite surse interne. Ruleaza cu --dir sau seteaza FABER_SOURCE_DIR.");
    process.exit(1);
  }
  console.log(`Extracted facts from ${sources.length} source files into ${path.relative(ROOT, OUT)}.`);
}

main();
