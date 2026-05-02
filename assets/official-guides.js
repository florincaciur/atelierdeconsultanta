(function () {
  "use strict";

  var GUIDE_LABEL = "LINK GHID OFICIAL";
  var guidesData = {};
  var applyQueued = false;

  function asGuide(entry) {
    if (!entry) return {};
    if (typeof entry === "string") return { url: entry };
    return entry;
  }

  function setVisibility(element, visible) {
    if (!element) return;
    if (visible && element.hasAttribute("hidden")) element.removeAttribute("hidden");
    if (!visible && !element.hasAttribute("hidden")) element.setAttribute("hidden", "");
  }

  function setAttributeIfChanged(element, name, value) {
    if (element.getAttribute(name) !== value) element.setAttribute(name, value);
  }

  function applyGuides(data) {
    document.querySelectorAll("[data-official-guide-key]").forEach(function (button) {
      var key = button.getAttribute("data-official-guide-key");
      var guide = asGuide(data[key]);
      var url = String(guide.url || "").trim();
      var box = button.closest("[data-official-guide-box]");

      if (!url) {
        if (button.hasAttribute("href")) button.removeAttribute("href");
        setVisibility(button, false);
        setVisibility(box, false);
        return;
      }

      setAttributeIfChanged(button, "href", url);
      setAttributeIfChanged(button, "target", "_blank");
      setAttributeIfChanged(button, "rel", "noopener noreferrer");

      var label = button.getAttribute("data-official-guide-label") || GUIDE_LABEL;
      if (button.textContent !== label) button.textContent = label;

      setVisibility(button, true);
      setVisibility(box, true);
    });
  }

  function scheduleApply() {
    if (applyQueued) return;
    applyQueued = true;

    window.requestAnimationFrame(function () {
      applyQueued = false;
      applyGuides(guidesData);
    });
  }

  document.addEventListener("DOMContentLoaded", scheduleApply);
  window.addEventListener("load", scheduleApply);
  document.addEventListener("official-guides:refresh", scheduleApply);

  [150, 700, 1600, 3000].forEach(function (delay) {
    window.setTimeout(scheduleApply, delay);
  });

  fetch("/official-guides.json", { cache: "no-store" })
    .then(function (response) {
      if (!response.ok) throw new Error("Nu se poate incarca official-guides.json");
      return response.json();
    })
    .then(function (data) {
      guidesData = data || {};
      scheduleApply();
    })
    .catch(function () {
      guidesData = {};
      scheduleApply();
    });
})();
