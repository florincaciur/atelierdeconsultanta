import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { hasMeaningfulHtmlChange, meaningfulHtmlSnapshot } = require("../tools/submit-indexnow.js");

const base = `<!doctype html><html><head>
  <title>GAL AFIR 2026 | FABER</title>
  <meta name="description" content="Verifică apelul local.">
  <meta name="robots" content="index, follow">
  <link rel="canonical" href="https://atelierdeconsultanta.ro/gal-afir">
</head><body><nav><a href="/">Acasă</a></nav><main>
  <h1>GAL AFIR 2026</h1><p>Verifică teritoriul și ghidul local.</p>
  <a href="https://gal.afir.ro/">Platforma oficială</a>
  <img src="/gal.webp" alt="Hartă GAL AFIR">
</main><footer>FABER</footer><script>window.analytics = true;</script></body></html>`;

const globalChromeOnly = base
  .replace("<nav><a href=\"/\">Acasă</a></nav>", "<nav data-release=\"2\"><a href=\"/\">Prima pagină</a></nav>")
  .replace("window.analytics = true", "window.analytics = false");
assert.equal(hasMeaningfulHtmlChange(base, globalChromeOnly), false, "navigația și analytics nu trebuie să retrimită pagina");

const editorialChange = base.replace("Verifică teritoriul și ghidul local.", "Verifică teritoriul, beneficiarul și ghidul local.");
assert.equal(hasMeaningfulHtmlChange(base, editorialChange), true, "o schimbare editorială trebuie trimisă");

const snippetChange = base.replace("Verifică apelul local.", "Verifică apelul GAL și anexele locale.");
assert.equal(hasMeaningfulHtmlChange(base, snippetChange), true, "o schimbare de descriere trebuie trimisă");

const linkChange = base.replace("https://gal.afir.ro/", "https://gal.afir.ro/anunturi");
assert.equal(hasMeaningfulHtmlChange(base, linkChange), true, "o sursă schimbată trebuie trimisă");

assert.equal(meaningfulHtmlSnapshot(base), meaningfulHtmlSnapshot(base), "snapshot-ul trebuie să fie determinist");
console.log("IndexNow semantic changes contract: PASS");
