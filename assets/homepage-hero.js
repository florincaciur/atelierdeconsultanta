(function () {
  "use strict";

  var root = document.querySelector("[data-hero-programs]");
  if (!root) return;

  var items = Array.prototype.slice.call(root.querySelectorAll("[data-hero-program-item]"));
  var title = root.querySelector("[data-hero-program-title]");
  var status = root.querySelector("[data-hero-program-status]");
  var link = root.querySelector("[data-hero-program-link]");
  var count = root.querySelector("[data-hero-program-count]");
  var activeIndex = 0;

  function setActive(index, focusItem) {
    if (!items.length) return;
    activeIndex = (index + items.length) % items.length;
    var item = items[activeIndex];
    items.forEach(function (entry, entryIndex) {
      if (entryIndex === activeIndex) entry.setAttribute("aria-current", "true");
      else entry.removeAttribute("aria-current");
    });
    if (title) title.textContent = item.getAttribute("data-title") || item.textContent.trim();
    if (status) status.textContent = item.getAttribute("data-status") || "";
    if (link) link.setAttribute("href", item.getAttribute("href") || "/fonduri-europene");
    if (count) count.textContent = (activeIndex + 1) + " / " + items.length;
    if (focusItem) item.focus();
  }

  items.forEach(function (item, index) {
    item.addEventListener("focus", function () { setActive(index, false); });
    item.addEventListener("pointerenter", function () { setActive(index, false); });
    item.addEventListener("keydown", function (event) {
      if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) return;
      event.preventDefault();
      setActive(index + (event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 1), true);
    });
  });

  setActive(0, false);
})();
