import assert from "node:assert/strict";
import { handleRequest } from "../cloudflare/domain-seo-redirects.mjs";

async function expectRedirect(source, destination) {
  const response = await handleRequest(new Request(source), async () => {
    throw new Error("Origin must not be called for a redirect case.");
  });
  assert.equal(response.status, 301, source);
  assert.equal(response.headers.get("location"), destination, source);
}

await expectRedirect(
  "http://atelierdeconsultanta.ro/dr12-afir?gsc_protocol_test=1",
  "https://atelierdeconsultanta.ro/dr12-afir?gsc_protocol_test=1"
);
await expectRedirect(
  "http://atelierdeconsultanta.ro/?s=%7Bsearch_term_string%7D",
  "https://atelierdeconsultanta.ro/"
);
await expectRedirect(
  "https://atelierdeconsultanta.ro/?s=%7Bsearch_term_string%7D",
  "https://atelierdeconsultanta.ro/"
);
await expectRedirect(
  "https://www.atelierdeconsultanta.ro/dr12-afir?utm_source=test",
  "https://atelierdeconsultanta.ro/dr12-afir?utm_source=test"
);
await expectRedirect(
  "http://www.atelierdeconsultanta.ro/dr12-afir",
  "https://atelierdeconsultanta.ro/dr12-afir"
);
await expectRedirect(
  "https://www.atelierdeconsultanta.ro/?s=%7Bsearch_term_string%7D",
  "https://atelierdeconsultanta.ro/"
);
await expectRedirect(
  "http://www.atelierdeconsultanta.ro/pnrr.html?utm_source=gsc",
  "https://atelierdeconsultanta.ro/digitalizare-imm-pnrr?utm_source=gsc"
);
await expectRedirect(
  "https://atelierdeconsultanta.ro/granturi-digitalizare-imm/",
  "https://atelierdeconsultanta.ro/digitalizare-imm"
);
await expectRedirect(
  "https://atelierdeconsultanta.ro/fondul-de-modernizare/index.html",
  "https://atelierdeconsultanta.ro/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum"
);
await expectRedirect(
  "https://atelierdeconsultanta.ro/testimoniale.html",
  "https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene"
);
await expectRedirect(
  "https://atelierdeconsultanta.ro/portofoliu/",
  "https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene"
);
await expectRedirect(
  "https://atelierdeconsultanta.ro/blog.html?post=blog-2",
  "https://atelierdeconsultanta.ro/blog"
);
await expectRedirect(
  "https://atelierdeconsultanta.ro/contact?program_slug=dr12-afir&source_page=%2Fdr12-afir&utm_source=chatgpt.com",
  "https://atelierdeconsultanta.ro/contact#program_slug=dr12-afir&source_page=%2Fdr12-afir&utm_source=chatgpt.com"
);
await expectRedirect(
  "http://www.atelierdeconsultanta.ro/contact?program_slug=dr14-afir",
  "https://atelierdeconsultanta.ro/contact#program_slug=dr14-afir"
);

let contactPostReachedOrigin = false;
await handleRequest(
  new Request("https://atelierdeconsultanta.ro/contact?program_slug=dr12-afir", { method: "POST" }),
  async () => {
    contactPostReachedOrigin = true;
    return new Response(null, { status: 204 });
  }
);
assert.equal(contactPostReachedOrigin, true, "non-GET contact requests must not be converted to fragment redirects");

await expectRedirect(
  "https://atelierdeconsultanta.ro/calendar-fonduri-europene/",
  "https://atelierdeconsultanta.ro/calendar-fonduri-europene"
);

let originRequest;
const originResponse = await handleRequest(
  new Request("https://atelierdeconsultanta.ro/calendar-fonduri-europene"),
  async (request) => {
    originRequest = request;
    return new Response(null, { status: 204 });
  }
);
assert.equal(originResponse.status, 204);
assert.equal(originRequest.url, "https://atelierdeconsultanta.ro/calendar-fonduri-europene");
assert.equal(originResponse.headers.get("strict-transport-security"), "max-age=15552000");

console.log("Cloudflare domain SEO worker tests passed.");
