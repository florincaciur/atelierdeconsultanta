(function () {
  "use strict";

  var GUIDE_LABEL = "LINK GHID OFICIAL";
  var guidesData = {};
  var applyQueued = false;
  var guidesLoaded = false;

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
    if (!guidesLoaded) return;
    if (applyQueued) return;
    applyQueued = true;

    window.requestAnimationFrame(function () {
      applyQueued = false;
      applyGuides(guidesData);
    });
  }

  function afterFirstPaint(callback) {
    var runWhenIdle = function () {
      if ("requestIdleCallback" in window) {
        window.requestIdleCallback(callback, { timeout: 1500 });
      } else {
        window.setTimeout(callback, 400);
      }
    };

    if (document.readyState === "complete") {
      window.requestAnimationFrame(runWhenIdle);
    } else {
      window.addEventListener("load", function () {
        window.requestAnimationFrame(runWhenIdle);
      }, { once: true });
    }
  }

  document.addEventListener("official-guides:refresh", scheduleApply);

  afterFirstPaint(function () {
    fetch("/official-guides.json", { cache: "no-store" })
      .then(function (response) {
        if (!response.ok) throw new Error("Nu se poate incarca official-guides.json");
        return response.json();
      })
      .then(function (data) {
        guidesData = data || {};
        guidesLoaded = true;
        scheduleApply();
      })
      .catch(function () {
        guidesData = {};
        guidesLoaded = true;
        scheduleApply();
      });
  });
})();
