(function (window, document) {
  "use strict";

  function track(name, payload) {
    if (window.FaberAnalytics && typeof window.FaberAnalytics.track === "function") {
      window.FaberAnalytics.track(name, payload || {});
    }
  }

  function setSlideFocusability(slide, active) {
    slide.toggleAttribute("inert", !active);
    slide.querySelectorAll("a, button, input, select, textarea, [tabindex]").forEach(function (element) {
      if (!active) {
        if (!element.hasAttribute("data-p108-tabindex")) {
          element.setAttribute("data-p108-tabindex", element.getAttribute("tabindex") || "");
        }
        element.setAttribute("tabindex", "-1");
        return;
      }
      var original = element.getAttribute("data-p108-tabindex");
      if (original === "") element.removeAttribute("tabindex");
      else if (original != null) element.setAttribute("tabindex", original);
      element.removeAttribute("data-p108-tabindex");
    });
  }

  function initializeCarousel(root) {
    var trackElement = root.querySelector("[data-priority-track]");
    var viewport = root.querySelector("[data-priority-viewport]");
    var slides = Array.prototype.slice.call(root.querySelectorAll("[data-priority-slide]"));
    var previous = root.querySelector("[data-priority-previous]");
    var next = root.querySelector("[data-priority-next]");
    var counter = root.querySelector("[data-priority-counter]");
    var index = 0;
    var pointerStart = null;

    if (!trackElement || !viewport || !slides.length || slides.length > 6) return;

    function activeProgram() {
      return slides[index] || null;
    }

    function update(nextIndex) {
      index = (nextIndex + slides.length) % slides.length;
      trackElement.style.transform = "translateX(-" + (index * 100) + "%)";
      slides.forEach(function (slide, slideIndex) {
        var active = slideIndex === index;
        slide.setAttribute("aria-hidden", active ? "false" : "true");
        slide.classList.toggle("is-active", active);
        setSlideFocusability(slide, active);
      });
      if (counter) counter.textContent = (index + 1) + " din " + slides.length;
      var program = activeProgram();
      [previous, next].forEach(function (button) {
        if (!button || !program) return;
        button.setAttribute("data-analytics-program-slug", program.getAttribute("data-program-id") || "");
        button.setAttribute("data-analytics-program-family", program.getAttribute("data-program-family") || "");
      });
    }

    function move(direction, method, manualTracking) {
      update(index + direction);
      if (manualTracking) {
        var program = activeProgram();
        track("carousel_interaction", {
          cta_id: "priority_carousel_" + method + (direction > 0 ? "_next" : "_previous"),
          program_slug: program ? program.getAttribute("data-program-id") || "" : "",
          program_family: program ? program.getAttribute("data-program-family") || "" : ""
        });
      }
    }

    previous.addEventListener("click", function () { move(-1, "button", false); });
    next.addEventListener("click", function () { move(1, "button", false); });

    viewport.addEventListener("keydown", function (event) {
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        move(-1, "keyboard", true);
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        move(1, "keyboard", true);
      } else if (event.key === "Home") {
        event.preventDefault();
        update(0);
        track("carousel_interaction", { cta_id: "priority_carousel_keyboard_home" });
      } else if (event.key === "End") {
        event.preventDefault();
        update(slides.length - 1);
        track("carousel_interaction", { cta_id: "priority_carousel_keyboard_end" });
      }
    });

    viewport.addEventListener("pointerdown", function (event) {
      if (event.pointerType === "mouse" && event.button !== 0) return;
      pointerStart = { x: event.clientX, y: event.clientY };
    });

    viewport.addEventListener("pointerup", function (event) {
      if (!pointerStart) return;
      var deltaX = event.clientX - pointerStart.x;
      var deltaY = event.clientY - pointerStart.y;
      pointerStart = null;
      if (Math.abs(deltaX) < 48 || Math.abs(deltaX) <= Math.abs(deltaY)) return;
      move(deltaX < 0 ? 1 : -1, "touch", true);
    });

    viewport.addEventListener("pointercancel", function () { pointerStart = null; });
    update(0);
  }

  function initializeGrid(root) {
    var form = root.querySelector("[data-program-filter-form]");
    var cards = Array.prototype.slice.call(root.querySelectorAll("[data-program-directory-card]"));
    var result = root.querySelector("[data-program-filter-result]");
    var empty = root.querySelector("[data-program-filter-empty]");
    var reset = root.querySelector("[data-program-filter-reset]");
    if (!form || !cards.length) return;

    function selected(name) {
      var field = form.querySelector('[name="' + name + '"]');
      return field ? field.value : "all";
    }

    function includesToken(value, token) {
      return String(value || "").split(/\s+/).indexOf(token) !== -1;
    }

    function applyFilters() {
      var family = selected("family");
      var status = selected("status");
      var applicant = selected("applicant");
      var visible = 0;

      cards.forEach(function (card) {
        var matches = (family === "all" || card.getAttribute("data-filter-family") === family)
          && (status === "all" || card.getAttribute("data-program-status") === status)
          && (applicant === "all" || includesToken(card.getAttribute("data-filter-applicants"), applicant));
        card.hidden = !matches;
        if (matches) visible += 1;
      });

      if (result) result.textContent = visible === 1 ? "1 program afișat" : visible + " programe afișate";
      if (empty) empty.hidden = visible !== 0;
    }

    form.addEventListener("change", applyFilters);
    if (reset) {
      reset.addEventListener("click", function () {
        form.querySelectorAll("select").forEach(function (select) { select.value = "all"; });
        applyFilters();
      });
    }
    applyFilters();
  }

  function initialize() {
    document.querySelectorAll("[data-priority-carousel]").forEach(initializeCarousel);
    document.querySelectorAll("[data-program-directory]").forEach(initializeGrid);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize, { once: true });
  else initialize();
})(window, document);
