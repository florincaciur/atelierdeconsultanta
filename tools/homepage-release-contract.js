"use strict";

const { createHash } = require("node:crypto");

function mainText(html) {
  const main = html.match(/<main\b[^>]*>([\s\S]*?)<\/main>/iu)?.[1];
  if (!main) throw new Error("Homepage: lipsește conținutul main.");
  return main.replace(/<!--[\s\S]*?-->/gu, "")
    .replace(/<[^>]*>/gu, " ")
    .replace(/&(?:nbsp|#160);/giu, " ")
    .replace(/\s+/gu, " ").trim();
}

function homepageAssets(html) {
  const assets = [];
  for (const tag of html.matchAll(/<(?:link|script)\b[^>]*>/giu)) {
    if (!/\bdata-homepage-(?:hero-script|decision-flow-(?:style|script))=/iu.test(tag[0])) continue;
    const url = tag[0].match(/\b(?:src|href)=["']([^"']+)["']/iu)?.[1];
    if (!url?.startsWith("/assets/")) throw new Error("Homepage: resursă fără cale locală validă.");
    assets.push(url);
  }
  if (assets.length !== 3 || new Set(assets).size !== 3) throw new Error("Homepage: resursele hero/flux sunt incomplete sau duplicate.");
  return assets.sort();
}

function verifyHomepageContent(actual, expected) {
  const revision = expected.match(/\bdata-homepage-revision=["']([^"']+)["']/iu)?.[1];
  if (!revision || !actual.includes(`data-homepage-revision="${revision}"`)) throw new Error("Homepage: versiunea vizuală publicată nu corespunde sursei.");
  if (mainText(actual) !== mainText(expected)) throw new Error("Homepage: conținutul publicat diferă de noul homepage din commit.");
  for (const marker of ["data-aeo-primary-answer", "data-aeo-direct-answer", "data-homepage-method-indicator"]) {
    if (!actual.includes(marker)) throw new Error(`Homepage: lipsește ${marker}.`);
  }
  const criticalStyle = (html) => html.match(/<style\b[^>]*id=["']homepage-hero-critical-css["'][^>]*>([\s\S]*?)<\/style>/iu)?.[1]?.trim();
  if (!criticalStyle(actual) || assetDigest(criticalStyle(actual)) !== assetDigest(criticalStyle(expected))) {
    throw new Error("Homepage: stilurile critice ale noului hero nu sunt publicate.");
  }
  const assets = homepageAssets(expected);
  if (JSON.stringify(homepageAssets(actual)) !== JSON.stringify(assets)) throw new Error("Homepage: versiune CSS/JS necorespunzătoare.");
  return { revision, assets };
}

function assetDigest(content) {
  return createHash("sha256").update(String(content).replace(/\r\n/gu, "\n")).digest("hex");
}

module.exports = { assetDigest, verifyHomepageContent };
