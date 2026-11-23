const fs = require("node:fs");
const path = require("node:path");

const privacyRoute = "/confidentialitate-extensie";
const privacyFile = `${privacyRoute.slice(1)}.html`;

function renderChromeExtensionPrivacy() {
  const source = path.join(__dirname, "chrome-extension");
  const html = fs.readFileSync(path.join(source, "privacy.html"), "utf8");
  const css = fs.readFileSync(path.join(source, "popup.css"), "utf8").trimEnd();
  const stylesheet = '<link rel="stylesheet" href="popup.css">';
  if (!html.includes(stylesheet)) throw new Error("The extension privacy page is missing its stylesheet link.");
  return html.replace(stylesheet, () => [
    `<link rel="canonical" href="https://atelierdeconsultanta.ro${privacyRoute}">`,
    '<meta name="robots" content="noindex, follow">',
    `<style>\n${css}\n  </style>`
  ].join("\n  "));
}

module.exports = { privacyRoute, privacyFile, renderChromeExtensionPrivacy };
