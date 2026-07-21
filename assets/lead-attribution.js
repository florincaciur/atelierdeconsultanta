(function (window, document) {
  "use strict";
  if (window.FaberAttribution) return;

  var STORAGE_KEY = "faber_first_touch_v1";

  function clean(value, maximum) {
    if (typeof value !== "string") return "";
    return value.trim().slice(0, maximum || 500).replace(/[\u0000-\u001f\u007f]/g, "");
  }

  function token(value) {
    return clean(value, 80).toLowerCase().replace(/[^a-z0-9_.-]/g, "_");
  }

  function sourceChannel(value, referrer) {
    var source = token(value);
    if (/chatgpt|openai/.test(source)) return "chatgpt";
    if (/google/.test(source)) return "google";
    if (/bing/.test(source)) return "bing";
    if (/facebook|instagram|meta/.test(source)) return "meta";
    if (/linkedin/.test(source)) return "linkedin";
    if (/newsletter|email|mail/.test(source)) return "email";
    if (source) return "campaign";
    try {
      if (!referrer) return "direct";
      var url = new URL(referrer);
      if (url.origin === window.location.origin) return "internal";
      var classified = sourceChannel(url.hostname, "");
      return classified === "campaign" ? "referral" : classified;
    } catch (_) {
      return "direct";
    }
  }

  function capture() {
    var existing = {};
    try { existing = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY) || "{}"); } catch (_) {}
    if (existing && existing.captured_at) return existing;
    var params;
    try { params = new URLSearchParams(window.location.search || ""); } catch (_) { params = null; }
    var result = {
      utm_source: clean(params ? params.get("utm_source") || "" : "", 160),
      utm_medium: clean(params ? params.get("utm_medium") || "" : "", 160),
      utm_campaign: clean(params ? params.get("utm_campaign") || "" : "", 200),
      utm_term: clean(params ? params.get("utm_term") || "" : "", 200),
      utm_content: clean(params ? params.get("utm_content") || "" : "", 200),
      landing_referrer: clean(document.referrer || "", 500),
      landing_page_path: window.location.pathname || "/",
      captured_at: new Date().toISOString()
    };
    result.source_channel = sourceChannel(result.utm_source, result.landing_referrer);
    try { window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(result)); } catch (_) {}
    return result;
  }

  var attribution = capture();
  window.FaberAttribution = Object.freeze({
    getCrmAttribution: function () { return Object.assign({}, attribution); },
    sourceChannel: function () { return attribution.source_channel || "direct"; }
  });
  try { document.dispatchEvent(new CustomEvent("faber:attribution-ready")); } catch (_) {}
})(window, document);
