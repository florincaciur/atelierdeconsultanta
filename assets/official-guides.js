(function () {
  "use strict";

  var GUIDE_LABEL = "LINK GHID OFICIAL";
  var guidesData = {};

  function asGuide(entry) {
    if (!entry) return {};
    if (typeof entry === "string") return { url: entry };
    return entry;
  }

  function setVisibility(element, visible) {
    if (!element) return;
    if (visible) element.removeAttribute("hidden");
    else element.setAttribute("hidden", "");
  }

  function applyGuides(data) {
    document.querySelectorAll("[data-official-guide-key]").forEach(function (button) {
      var key = button.getAttribute("data-official-guide-key");
      var guide = asGuide(data[key]);
      var url = String(guide.url || "").trim();
      var box = button.closest("[data-official-guide-box]");

      if (!url) {
        button.removeAttribute("href");
        setVisibility(button, false);
        setVisibility(box, false);
        return;
      }

      button.href = url;
      button.target = "_blank";
      button.rel = "noopener noreferrer";
      button.textContent = button.getAttribute("data-official-guide-label") || GUIDE_LABEL;
      setVisibility(button, true);
      setVisibility(box, true);
    });
  }

  var observer = new MutationObserver(function () {
    applyGuides(guidesData);
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  fetch("/official-guides.json", { cache: "no-store" })
    .then(function (response) {
      if (!response.ok) throw new Error("Nu se poate incarca official-guides.json");
      return response.json();
    })
    .then(function (data) {
      guidesData = data || {};
      applyGuides(guidesData);
    })
    .catch(function () {
      applyGuides({});
    });
})();
