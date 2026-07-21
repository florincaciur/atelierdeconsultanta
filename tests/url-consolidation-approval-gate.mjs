import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const config = JSON.parse(await fs.readFile(path.join(ROOT, "config", "url-consolidation-candidates.json"), "utf8"));
const redirects = await fs.readFile(path.join(ROOT, "_redirects"), "utf8");
const inventory = await fs.readFile(path.join(ROOT, "reports", "url-consolidation-inventory-2026-07-21.csv"), "utf8");

assert.equal(config.decisionStatus, "APROBARE_UMANĂ_NECESARĂ");
assert.equal(config.rows.length, 14);
for (const row of config.rows) {
  assert.equal(row.approvalBlockers.length > 0, true, `${row.url}: lipsesc blocajele de aprobare`);
  assert.equal(row.recommendation.length > 0, true, `${row.url}: recomandare lipsă`);
  assert.match(inventory, new RegExp(`"${row.url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`), `${row.url}: lipsește din inventar`);

  const html = await fs.readFile(path.join(ROOT, ...row.file.split("/")), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const canonical = $("link[rel='canonical']").first().attr("href") || "";
  assert.equal(new URL(canonical).pathname.replace(/\/$/u, "") || "/", row.url, `${row.url}: canonicalul a fost modificat înainte de aprobare`);

  if (row.recommendation.startsWith("MERGE_301")) {
    const escaped = row.url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const premature = new RegExp(`^${escaped}/?\\s+https?://atelierdeconsultanta\\.ro${row.target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s+301$`, "mu");
    assert.equal(premature.test(redirects), false, `${row.url}: redirect implementat înainte de aprobare`);
  }
}

console.log("Poarta consolidare URL PASS: 14 decizii cer aprobare; niciun canonical/redirect candidat nu a fost aplicat.");
