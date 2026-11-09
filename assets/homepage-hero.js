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
  var pages = Array.prototype.slice.call(root.querySelectorAll("[data-hero-program-page]"));
  var pager = root.querySelector("[data-hero-program-pager]");
  var previous = root.querySelector("[data-hero-program-prev]");
  var next = root.querySelector("[data-hero-program-next]");
  var pageCount = root.querySelector("[data-hero-program-page-count]");
  var activePage = 0;
  var activeIndex = 0;

  function showPage(index) {
    if (index < 0 || index >= pages.length) return;
    activePage = index;
    pages.forEach(function (page, pageIndex) { page.hidden = pageIndex !== index; });
    if (previous) previous.setAttribute("aria-disabled", String(index === 0));
    if (next) next.setAttribute("aria-disabled", String(index === pages.length - 1));
    if (pageCount) pageCount.textContent = "Grupul " + (index + 1) + " din " + pages.length;
  }

  function changePage(delta) {
    var index = activePage + delta;
    if (index < 0 || index >= pages.length) return;
    if (spotlight) spotlight.setAttribute("aria-live", "polite");
    setActive(items.indexOf(pages[index].querySelector("[data-hero-program-item]")), false);
  }

  function setActive(index, focusItem) {
    if (!items.length) return;
    activeIndex = (index + items.length) % items.length;
    var item = items[activeIndex];
    var pageIndex = pages.indexOf(item.closest("[data-hero-program-page]"));
    if (pageIndex >= 0 && pageIndex !== activePage) showPage(pageIndex);
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
    // A stationary pointer should not override keyboard focus when the page scrolls.
    item.addEventListener("pointermove", function (event) {
      if (event.pointerType === "touch" || index === activeIndex) return;
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
  if (previous) previous.addEventListener("click", function () { changePage(-1); });
  if (next) next.addEventListener("click", function () { changePage(1); });
  if (pager && pages.length > 1) pager.hidden = false;
  showPage(0);
  setActive(0, false);
})();
