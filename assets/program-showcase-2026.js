(function () {
  "use strict";

  var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function observeReveals() {
    var elements = document.querySelectorAll(".reveal");
    if (!("IntersectionObserver" in window)) {
      elements.forEach(function (element) { element.classList.add("is-visible"); });
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.12 });

    elements.forEach(function (element) { observer.observe(element); });
  }

  function setupJourney(journey) {
    var svg = journey.querySelector("[data-journey-svg]");
    var track = journey.querySelector("[data-journey-track]");
    var progress = journey.querySelector("[data-journey-progress]");
    var steps = Array.prototype.slice.call(journey.querySelectorAll("[data-journey-step]"));
    var selectedIndex = 0;

    if (!svg || !track || !progress || steps.length < 2) return;

    function geometry() {
      var journeyRect = journey.getBoundingClientRect();
      var centers = steps.map(function (step) {
        var numberRect = step.querySelector(".program-step__number").getBoundingClientRect();
        return {
          x: numberRect.left - journeyRect.left + numberRect.width / 2,
          y: numberRect.top - journeyRect.top + numberRect.height / 2
        };
      });
      var width = Math.max(1, journey.clientWidth);
      var height = Math.max(1, journey.clientHeight);
      var path = "M " + centers[0].x.toFixed(2) + " " + centers[0].y.toFixed(2)
        + " L " + centers[centers.length - 1].x.toFixed(2) + " " + centers[centers.length - 1].y.toFixed(2);

      svg.setAttribute("viewBox", "0 0 " + width + " " + height);
      svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
      track.setAttribute("d", path);
      progress.setAttribute("d", path);
      journey._stepCenters = centers;
    }

    function activate(index, persist) {
      var centers = journey._stepCenters;
      var start;
      var end;
      var current;
      var ratio;

      if (!centers || !centers[index]) return;
      if (persist) selectedIndex = index;
      start = centers[0].y;
      end = centers[centers.length - 1].y;
      current = centers[index].y;
      ratio = end === start ? 0 : (current - start) / (end - start);
      journey.style.setProperty("--journey-progress", Math.max(0, Math.min(1, ratio)).toFixed(4));
      steps.forEach(function (step, stepIndex) {
        if (stepIndex === index) step.setAttribute("aria-current", "step");
        else step.removeAttribute("aria-current");
      });
    }

    function refresh() {
      geometry();
      activate(selectedIndex, false);
    }

    steps.forEach(function (step, index) {
      step.addEventListener("mouseenter", function () { activate(index, false); });
      step.addEventListener("focus", function () { activate(index, false); });
      step.addEventListener("click", function () { activate(index, true); });
      step.addEventListener("keydown", function (event) {
        var direction = event.key === "ArrowDown" || event.key === "ArrowRight" ? 1
          : event.key === "ArrowUp" || event.key === "ArrowLeft" ? -1 : 0;
        var target;
        if (!direction) return;
        event.preventDefault();
        target = Math.max(0, Math.min(steps.length - 1, index + direction));
        activate(target, true);
        steps[target].focus();
      });
    });

    journey.addEventListener("mouseleave", function () { activate(selectedIndex, false); });
    journey.addEventListener("focusout", function (event) {
      if (!journey.contains(event.relatedTarget)) activate(selectedIndex, false);
    });

    refresh();
    window.addEventListener("resize", refresh, { passive: true });

    if (!("IntersectionObserver" in window) || reducedMotion) {
      journey.classList.add("is-visible");
      return;
    }

    var journeyObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        journeyObserver.unobserve(entry.target);
      });
    }, { threshold: 0.28 });
    journeyObserver.observe(journey);
  }

  observeReveals();
  document.querySelectorAll("[data-program-journey]").forEach(setupJourney);
}());
