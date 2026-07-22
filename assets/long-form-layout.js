(function () {
  "use strict";

  var toc = document.querySelector("[data-long-form-toc]:not([hidden])");
  if (!toc) return;

  var disclosure = toc.querySelector("details");
  if (disclosure && window.matchMedia("(max-width: 63.99rem)").matches && !window.location.hash) {
    disclosure.removeAttribute("open");
  }
  var summary = disclosure && disclosure.querySelector("summary");
  if (summary) {
    summary.addEventListener("keydown", function (event) {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      disclosure.open = !disclosure.open;
    });
  }

  var links = Array.prototype.slice.call(toc.querySelectorAll("a[data-long-form-toc-link]"));
  var sections = links.map(function (link) {
    var id = decodeURIComponent(link.hash.slice(1));
    return document.getElementById(id);
  }).filter(Boolean);

  function setCurrent(id) {
    links.forEach(function (link) {
      var current = decodeURIComponent(link.hash.slice(1)) === id;
      if (current) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
  }

  links.forEach(function (link) {
    link.addEventListener("click", function () {
      setCurrent(decodeURIComponent(link.hash.slice(1)));
    });
  });

  if ("IntersectionObserver" in window) {
    var visible = new Map();
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) visible.set(entry.target.id, entry.boundingClientRect.top);
        else visible.delete(entry.target.id);
      });
      var current = Array.from(visible.entries()).sort(function (left, right) {
        return Math.abs(left[1]) - Math.abs(right[1]);
      })[0];
      if (current) setCurrent(current[0]);
    }, {
      rootMargin: "-18% 0px -68% 0px",
      threshold: [0, 1]
    });
    sections.forEach(function (section) { observer.observe(section); });
  }

  var initial = window.location.hash ? decodeURIComponent(window.location.hash.slice(1)) : sections[0] && sections[0].id;
  if (initial) setCurrent(initial);
})();
