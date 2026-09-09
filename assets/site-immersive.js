(function () {
  "use strict";

  var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var body = document.body;
  if (!body || !body.hasAttribute("data-site-immersive")) return;

  function readingProgress() {
    var progress = document.createElement("span");
    progress.className = "site-immersive-progress";
    progress.setAttribute("aria-hidden", "true");
    body.appendChild(progress);
    var queued = false;
    function update() {
      var root = document.documentElement;
      var range = Math.max(1, root.scrollHeight - window.innerHeight);
      var value = Math.max(0, Math.min(1, window.scrollY / range));
      root.style.setProperty("--site-reading-progress", String(value));
      queued = false;
    }
    window.addEventListener("scroll", function () {
      if (!queued) {
        queued = true;
        window.requestAnimationFrame(update);
      }
    }, { passive: true });
    window.addEventListener("resize", update, { passive: true });
    update();
  }

  function revealSections() {
    // The homepage owns a scroll-linked reveal system with sticky geometry.
    // Avoid layering a second transform over those sections.
    if (body.classList.contains("page-family-home")) return;
    var nodes = Array.prototype.slice.call(document.querySelectorAll("main > section, main > article, main > figure, main .program-section"));
    nodes.forEach(function (node) { node.setAttribute("data-site-reveal", ""); });
    if (reducedMotion || !("IntersectionObserver" in window)) {
      nodes.forEach(function (node) { node.classList.add("is-visible"); });
      return;
    }
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -8%", threshold: .08 });
    nodes.forEach(function (node) { observer.observe(node); });
  }

  function programVisual(figure) {
    var buttons = Array.prototype.slice.call(figure.querySelectorAll("[data-program-step]"));
    var live = figure.querySelector(".program-visual__live");
    var timer = null;
    var current = 1;
    var paused = false;
    function activate(step, announce) {
      current = Math.max(1, Math.min(buttons.length, Number(step) || 1));
      figure.setAttribute("data-active-step", String(current));
      buttons.forEach(function (button) {
        button.setAttribute("aria-pressed", button.getAttribute("data-program-step") === String(current) ? "true" : "false");
      });
      if (announce && live && buttons[current - 1]) live.textContent = "Reper activ: " + buttons[current - 1].textContent.replace(/^\s*0\d\s*/, "").trim();
    }
    buttons.forEach(function (button) {
      var choose = function () { activate(button.getAttribute("data-program-step"), true); };
      button.addEventListener("click", choose);
      button.addEventListener("pointerenter", choose);
      button.addEventListener("focus", choose);
    });
    figure.addEventListener("pointermove", function (event) {
      if (reducedMotion || event.pointerType === "touch") return;
      var rect = figure.getBoundingClientRect();
      var x = ((event.clientX - rect.left) / Math.max(1, rect.width) - .5) * 12;
      var y = ((event.clientY - rect.top) / Math.max(1, rect.height) - .5) * 8;
      figure.style.setProperty("--program-tilt-x", x.toFixed(2) + "px");
      figure.style.setProperty("--program-tilt-y", y.toFixed(2) + "px");
    }, { passive: true });
    figure.addEventListener("pointerleave", function () {
      figure.style.setProperty("--program-tilt-x", "0px");
      figure.style.setProperty("--program-tilt-y", "0px");
    });
    figure.addEventListener("mouseenter", function () { paused = true; });
    figure.addEventListener("mouseleave", function () { paused = false; });
    figure.addEventListener("focusin", function () { paused = true; });
    figure.addEventListener("focusout", function (event) { if (!figure.contains(event.relatedTarget)) paused = false; });
    if (!reducedMotion && buttons.length > 1) {
      timer = window.setInterval(function () { if (!paused && !document.hidden) activate(current % buttons.length + 1, true); }, 3800);
      window.addEventListener("pagehide", function () { if (timer) window.clearInterval(timer); }, { once: true });
    }
    activate(1, false);
    figure.setAttribute("data-immersive-ready", "true");
  }

  readingProgress();
  revealSections();
  document.querySelectorAll("[data-program-visual='immersive-verification']").forEach(programVisual);
  body.setAttribute("data-immersive-ready", "true");
}());
