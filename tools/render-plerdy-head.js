const fs = require("node:fs");
const path = require("node:path");

const head = fs.readFileSync(path.join(__dirname, "plerdy-head.html"), "utf8").trimEnd();
const excluded = new Set(["404.html", "admin", "partials", "templates"]);

function renderPlerdyHead(html, relativeFile) {
  if (excluded.has(relativeFile.split(path.sep)[0])) return html;
  return html.replace(/<\/head>/i, (closingTag) => `${head}\n${closingTag}`);
}

module.exports = { renderPlerdyHead };
