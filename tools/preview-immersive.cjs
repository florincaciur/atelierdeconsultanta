"use strict";
// Local static preview, including the extensionless routes used by production.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..", process.argv.includes("--dist") ? "dist" : ".");
const mime = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".json": "application/json", ".webp": "image/webp", ".png": "image/png", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".jpg": "image/jpeg", ".ico": "image/x-icon" };
http.createServer((req, res) => {
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname); } catch { res.writeHead(400).end(); return; }
  const requested = path.resolve(root, "." + pathname);
  if (requested !== root && !requested.startsWith(root + path.sep)) { res.writeHead(403).end(); return; }
  // Directory routes are canonical. Root .html aliases may only redirect to
  // them, so resolving the alias first would create a local redirect loop.
  const file = [path.join(requested, "index.html"), requested, requested + ".html"].find(candidate => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
  if (!file) { res.writeHead(404).end("Not found"); return; }
  res.writeHead(200, { "Content-Type": mime[path.extname(file)] || "application/octet-stream", "Cache-Control": "no-store" });
  fs.createReadStream(file).pipe(res);
}).listen(4173, "127.0.0.1", () => console.log(`FABER preview: http://127.0.0.1:4173 (${root})`));
