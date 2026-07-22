(function homepageDecisionFlow(window, document) {
  "use strict";

  const wrapIndex = (value, length) => (value + length) % length;

  function initializeSequence(root, options) {
    const tabs = Array.from(root.querySelectorAll(options.tabSelector));
    const frames = Array.from(root.querySelectorAll(options.frameSelector));
    const nodes = Array.from(root.querySelectorAll(options.nodeSelector));
    const marker = root.querySelector(options.markerSelector);
    const viewport = root.querySelector(options.viewportSelector);
    const status = root.querySelector(options.statusSelector);
    const previous = root.querySelector(options.previousSelector);
    const next = root.querySelector(options.nextSelector);

    if (!tabs.length || tabs.length !== frames.length || !viewport) return;

    let activeIndex = 0;
    let pointerStart = null;

    const labelAt = (index) => options.labels[index] || tabs[index].textContent.trim();

    function reportInteraction(direction) {
      if (!window.FaberAnalytics || typeof window.FaberAnalytics.track !== "function") return;
      window.FaberAnalytics.track("carousel_interaction", {
        cta_id: options.analyticsId,
        source_channel: "website",
        step: direction,
        field_name_generic: `frame_${activeIndex + 1}`
      });
    }

    function update(nextIndex, settings) {
      const config = Object.assign({ announce: true, focusTab: false, interaction: "" }, settings);
      activeIndex = wrapIndex(nextIndex, frames.length);

      frames.forEach((frame, index) => {
        const active = index === activeIndex;
        frame.classList.toggle("is-active", active);
        frame.hidden = !active;
        frame.setAttribute("aria-hidden", active ? "false" : "true");
        frame.toggleAttribute("inert", !active);
      });

      tabs.forEach((tab, index) => {
        const active = index === activeIndex;
        tab.setAttribute("aria-selected", active ? "true" : "false");
        tab.tabIndex = active ? 0 : -1;
      });

      nodes.forEach((node, index) => node.classList.toggle("is-active", index === activeIndex));

      if (marker) {
        const point = options.markerPoints[activeIndex];
        marker.style.transform = `translate(${point.x}px, ${point.y}px)`;
      }

      if (status && config.announce) {
        status.textContent = `${options.statusLabel} ${activeIndex + 1} din ${frames.length}: ${labelAt(activeIndex)}`;
      }

      if (config.focusTab) tabs[activeIndex].focus({ preventScroll: true });
      if (config.interaction) reportInteraction(config.interaction);
    }

    function move(delta, interaction) {
      update(activeIndex + delta, { interaction });
    }

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => update(index, { interaction: "tab" }));
      tab.addEventListener("keydown", (event) => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        if (event.key === "Home") update(0, { focusTab: true, interaction: "keyboard" });
        else if (event.key === "End") update(frames.length - 1, { focusTab: true, interaction: "keyboard" });
        else update(activeIndex + (event.key === "ArrowRight" ? 1 : -1), { focusTab: true, interaction: "keyboard" });
      });
    });

    previous?.addEventListener("click", () => move(-1, "previous"));
    next?.addEventListener("click", () => move(1, "next"));

    viewport.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      move(event.key === "ArrowRight" ? 1 : -1, "keyboard");
    });

    viewport.addEventListener("pointerdown", (event) => {
      if (event.pointerType === "mouse" && event.button !== 0) return;
      pointerStart = { id: event.pointerId, x: event.clientX, y: event.clientY };
      viewport.setPointerCapture?.(event.pointerId);
    });

    viewport.addEventListener("pointerup", (event) => {
      if (!pointerStart || event.pointerId !== pointerStart.id) return;
      const horizontal = event.clientX - pointerStart.x;
      const vertical = event.clientY - pointerStart.y;
      pointerStart = null;
      if (Math.abs(horizontal) < 48 || Math.abs(horizontal) <= Math.abs(vertical)) return;
      move(horizontal < 0 ? 1 : -1, "swipe");
    });

    viewport.addEventListener("pointercancel", () => {
      pointerStart = null;
    });

    root.classList.add("is-enhanced");
    update(0, { announce: false });
  }

  function initialize() {
    document.querySelectorAll("[data-homepage-method]").forEach((root) => initializeSequence(root, {
      tabSelector: "[data-homepage-method-tab]",
      frameSelector: "[data-homepage-method-frame]",
      nodeSelector: "[data-homepage-method-node]",
      markerSelector: "[data-homepage-method-marker]",
      viewportSelector: "[data-homepage-method-viewport]",
      statusSelector: "[data-homepage-method-status]",
      previousSelector: "[data-homepage-method-previous]",
      nextSelector: "[data-homepage-method-next]",
      statusLabel: "Etapa",
      analyticsId: "homepage_method",
      labels: ["Solicitant", "Program", "Punctaj", "Buget", "Decizie"],
      markerPoints: [50, 185, 320, 455, 590].map((x) => ({ x, y: 70 }))
    }));

    document.querySelectorAll("[data-homepage-explorer]").forEach((root) => initializeSequence(root, {
      tabSelector: "[data-homepage-explorer-tab]",
      frameSelector: "[data-homepage-explorer-frame]",
      nodeSelector: "[data-homepage-explorer-node]",
      markerSelector: "[data-homepage-explorer-marker]",
      viewportSelector: "[data-homepage-explorer-viewport]",
      statusSelector: "[data-homepage-explorer-status]",
      previousSelector: "[data-homepage-explorer-previous]",
      nextSelector: "[data-homepage-explorer-next]",
      statusLabel: "Secțiunea",
      analyticsId: "homepage_explorer",
      labels: ["Servicii", "Instrumente", "De ce FABER", "Comparație"],
      markerPoints: [70, 230, 390, 550].map((x) => ({ x, y: 58 }))
    }));
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize, { once: true });
  else initialize();
})(window, document);
