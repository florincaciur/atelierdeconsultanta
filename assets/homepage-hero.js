(function () {
  "use strict";

  var root = document.querySelector("[data-hero-programs]");
  if (!root) return;

  var items = Array.prototype.slice.call(root.querySelectorAll("[data-hero-program-item]"));
  var title = root.querySelector("[data-hero-program-title]");
  var status = root.querySelector("[data-hero-program-status]");
  var link = root.querySelector("[data-hero-program-link]");
  var count = root.querySelector("[data-hero-program-count]");
  var scenes = Array.prototype.slice.call(root.querySelectorAll("[data-program-scene]"));
  var spotlight = root.querySelector(".hero-program-spotlight");
  var activeIndex = 0;

  function setActive(index, focusItem) {
    if (!items.length) return;
    activeIndex = (index + items.length) % items.length;
    var item = items[activeIndex];
    items.forEach(function (entry, entryIndex) {
      if (entryIndex === activeIndex) entry.setAttribute("aria-current", "true");
      else entry.removeAttribute("aria-current");
      entry.setAttribute("aria-pressed", String(entryIndex === activeIndex));
    });
    scenes.forEach(function (scene) {
      var active = scene.getAttribute("data-program-scene") === item.getAttribute("data-program-id");
      scene.hidden = !active;
      scene.classList.toggle("is-active", active);
    });
    if (title) title.textContent = item.getAttribute("data-title") || item.textContent.trim();
    if (status) status.textContent = item.getAttribute("data-status") || "";
    if (link) {
      link.setAttribute("href", item.getAttribute("href") || "/fonduri-europene");
      ["program-slug", "program-family", "cta-id"].forEach(function (name) {
        link.setAttribute("data-analytics-" + name, item.getAttribute("data-analytics-" + name) || "");
      });
      link.setAttribute("data-analytics-event", "program_card_click");
      link.setAttribute("data-analytics-component", "homepage_hero_program_detail");
    }
    if (count) count.textContent = (activeIndex + 1) + " / " + items.length;
    if (focusItem) item.focus();
  }

  items.forEach(function (item, index) {
    // Without JS these remain real links. With JS they select a preview and
    // the separate detail link navigates, consistently for mouse and touch.
    item.setAttribute("role", "button");
    item.setAttribute("aria-controls", "hero-program-spotlight hero-program-visuals");
    item.removeAttribute("data-analytics-event");
    item.addEventListener("focus", function () { if (spotlight) spotlight.setAttribute("aria-live", "polite"); setActive(index, false); });
    item.addEventListener("pointerenter", function (event) {
      if (event.pointerType === "touch") return;
      if (spotlight) spotlight.setAttribute("aria-live", "off");
      setActive(index, false);
    });
    item.addEventListener("click", function (event) { event.preventDefault(); if (spotlight) spotlight.setAttribute("aria-live", "polite"); setActive(index, false); });
    item.addEventListener("keydown", function (event) {
      if (event.key === " ") { event.preventDefault(); setActive(index, false); return; }
      if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) return;
      event.preventDefault();
      setActive(index + (event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 1), true);
    });
  });

  root.classList.add("hero-programs--enhanced");
  setActive(0, false);
})();
