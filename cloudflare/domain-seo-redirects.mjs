"use strict";

const CANONICAL_HOST = "atelierdeconsultanta.ro";
const HSTS_VALUE = "max-age=15552000";

function permanentRedirect(destination) {
  return new Response(null, {
    status: 301,
    headers: {
      location: destination,
      "cache-control": "public, max-age=3600"
    }
  });
}

function isLegacySearchPlaceholder(url) {
  return url.hostname === CANONICAL_HOST
    && url.pathname === "/"
    && (url.searchParams.has("s") || /search_term_string/iu.test(url.search));
}

export async function handleRequest(request, originFetch = fetch) {
  const url = new URL(request.url);

  // This rule comes first so the historical HTTP SearchAction URL resolves in
  // one hop to the canonical homepage, without carrying the obsolete query.
  if (isLegacySearchPlaceholder(url)) {
    return permanentRedirect(`https://${CANONICAL_HOST}/`);
  }

  if (url.protocol === "http:") {
    url.protocol = "https:";
    url.hostname = CANONICAL_HOST;
    url.port = "";
    return permanentRedirect(url.toString());
  }

  const response = await originFetch(request);
  const secured = new Response(response.body, response);
  secured.headers.set("strict-transport-security", HSTS_VALUE);
  return secured;
}

export default {
  fetch(request) {
    return handleRequest(request);
  }
};
