(function () {
  "use strict";

  if (window.__globalHeaderInitialized) return;
  window.__globalHeaderInitialized = true;

  Array.prototype.slice.call(document.querySelectorAll('a.skip-link[href="#main-content"]')).forEach(function (skipLink) {
    skipLink.addEventListener("click", function () {
      var target = document.getElementById("main-content");
      if (!target) return;
      window.requestAnimationFrame(function () {
        target.focus({ preventScroll: true });
      });
    });
  });

  var navbar = document.getElementById("navbar");
  var hamburgerBtn = document.getElementById("hamburgerBtn");
  var mobileMenu = document.getElementById("mobileMenu");
  if (!navbar || !hamburgerBtn || !mobileMenu) return;

  var isHomepage = document.body.classList.contains("page-family-home");
  Array.prototype.slice.call(document.querySelectorAll("[data-homepage-navbar-toc]")).forEach(function (toc) {
    toc.hidden = !isHomepage;
    if (isHomepage && toc.closest("#navbar")) {
      toc.setAttribute("data-long-form-toc", "");
      Array.prototype.slice.call(toc.querySelectorAll("[data-homepage-toc-link]")).forEach(function (link) {
        link.setAttribute("data-long-form-toc-link", "");
      });
    }
  });

  var desktopDisclosures = Array.prototype.slice.call(navbar.querySelectorAll("[data-nav-disclosure]"));
  var mobileDisclosures = Array.prototype.slice.call(mobileMenu.querySelectorAll("[data-mobile-disclosure]"));
  var eligibilityDialog = document.getElementById("eligibility-whatsapp-dialog");
  var eligibilityDialogClose = eligibilityDialog ? eligibilityDialog.querySelector("[data-whatsapp-dialog-close]") : null;
  var eligibilityDialogOptions = eligibilityDialog ? Array.prototype.slice.call(eligibilityDialog.querySelectorAll(".eligibility-whatsapp-options a")) : [];
  var eligibilityDialogTrigger = null;
  var scrollTicking = false;

  function disclosureParts(disclosure) {
    var trigger = disclosure.querySelector("button[aria-controls]");
    var panel = trigger ? document.getElementById(trigger.getAttribute("aria-controls")) : null;
    var items = panel ? Array.prototype.slice.call(panel.querySelectorAll("a[href]")) : [];
    return { trigger: trigger, panel: panel, items: items };
  }

  function updateScrollState() {
    scrollTicking = false;
    navbar.classList.toggle("scrolled", window.scrollY > 100);
    if (typeof window.updateBackToTop === "function") window.updateBackToTop();
  }

  window.addEventListener("scroll", function () {
    if (scrollTicking) return;
    scrollTicking = true;
    window.requestAnimationFrame(updateScrollState);
  }, { passive: true });

  function closeDesktopDisclosure(disclosure, restoreFocus) {
    var parts = disclosureParts(disclosure);
    if (!parts.trigger || !parts.panel) return;
    parts.trigger.setAttribute("aria-expanded", "false");
    parts.panel.classList.remove("open");
    parts.panel.hidden = true;
    if (restoreFocus) parts.trigger.focus();
  }

  function closeDesktopDisclosures(except, restoreFocusFor) {
    desktopDisclosures.forEach(function (disclosure) {
      if (disclosure !== except) closeDesktopDisclosure(disclosure, disclosure === restoreFocusFor);
    });
  }

  function openDesktopDisclosure(disclosure, focusItem) {
    var parts = disclosureParts(disclosure);
    if (!parts.trigger || !parts.panel) return;
    closeDesktopDisclosures(disclosure);
    parts.panel.hidden = false;
    parts.panel.classList.add("open");
    parts.trigger.setAttribute("aria-expanded", "true");
    if (focusItem && parts.items.length) {
      var target = focusItem === "last" ? parts.items[parts.items.length - 1] : parts.items[0];
      window.requestAnimationFrame(function () { target.focus(); });
    }
  }

  function desktopDisclosureIsOpen(disclosure) {
    var parts = disclosureParts(disclosure);
    return Boolean(parts.panel && !parts.panel.hidden);
  }

  desktopDisclosures.forEach(function (disclosure) {
    var parts = disclosureParts(disclosure);
    if (!parts.trigger || !parts.panel) return;

    parts.trigger.addEventListener("click", function (event) {
      event.stopPropagation();
      if (desktopDisclosureIsOpen(disclosure)) closeDesktopDisclosure(disclosure);
      else openDesktopDisclosure(disclosure);
    });

    parts.trigger.addEventListener("keydown", function (event) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        openDesktopDisclosure(disclosure, event.key === "ArrowUp" ? "last" : "first");
      } else if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeDesktopDisclosure(disclosure, true);
      }
    });

    parts.panel.addEventListener("keydown", function (event) {
      var index = parts.items.indexOf(document.activeElement);
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeDesktopDisclosure(disclosure, true);
        return;
      }
      if (index < 0) return;
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        var delta = event.key === "ArrowDown" ? 1 : -1;
        parts.items[(index + delta + parts.items.length) % parts.items.length].focus();
      } else if (event.key === "Home") {
        event.preventDefault();
        parts.items[0].focus();
      } else if (event.key === "End") {
        event.preventDefault();
        parts.items[parts.items.length - 1].focus();
      }
    });

    disclosure.addEventListener("focusout", function (event) {
      if (!disclosure.contains(event.relatedTarget)) closeDesktopDisclosure(disclosure);
    });
  });

  window.closeDropdown = function closeDropdown(options) {
    var focusedDisclosure = desktopDisclosures.find(function (disclosure) { return disclosure.contains(document.activeElement); });
    desktopDisclosures.forEach(function (disclosure) {
      closeDesktopDisclosure(disclosure, Boolean(options && options.restoreFocus && disclosure === focusedDisclosure));
    });
  };

  function closeMobileDisclosure(disclosure, restoreFocus) {
    var parts = disclosureParts(disclosure);
    if (!parts.trigger || !parts.panel) return;
    parts.trigger.setAttribute("aria-expanded", "false");
    parts.panel.hidden = true;
    if (restoreFocus) parts.trigger.focus();
  }

  function openMobileDisclosure(disclosure) {
    var parts = disclosureParts(disclosure);
    if (!parts.trigger || !parts.panel) return;
    mobileDisclosures.forEach(function (candidate) {
      if (candidate !== disclosure) closeMobileDisclosure(candidate);
    });
    parts.panel.hidden = false;
    parts.trigger.setAttribute("aria-expanded", "true");
  }

  mobileDisclosures.forEach(function (disclosure) {
    var parts = disclosureParts(disclosure);
    if (!parts.trigger || !parts.panel) return;
    parts.trigger.addEventListener("click", function () {
      if (parts.panel.hidden) openMobileDisclosure(disclosure);
      else closeMobileDisclosure(disclosure);
    });
    parts.panel.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeMobileDisclosure(disclosure, true);
      }
    });
  });

  function currentMobileDisclosure() {
    return mobileDisclosures.find(function (disclosure) { return disclosure.querySelector('a[aria-current="page"]'); });
  }

  function setMobileMenu(open, restoreFocus) {
    mobileMenu.hidden = !open;
    mobileMenu.classList.toggle("open", open);
    hamburgerBtn.classList.toggle("open", open);
    hamburgerBtn.setAttribute("aria-expanded", String(open));
    hamburgerBtn.setAttribute("aria-label", open ? "Închide meniul" : "Deschide meniul");
    if (open) {
      closeDesktopDisclosures();
      var current = currentMobileDisclosure();
      if (current) openMobileDisclosure(current);
    } else {
      mobileDisclosures.forEach(function (disclosure) { closeMobileDisclosure(disclosure); });
      if (restoreFocus) hamburgerBtn.focus();
    }
  }

  window.closeMobileMenu = function closeMobileMenu(options) {
    setMobileMenu(false, Boolean(options && options.restoreFocus));
  };

  hamburgerBtn.addEventListener("click", function () {
    setMobileMenu(mobileMenu.hidden, false);
  });

  mobileMenu.addEventListener("click", function (event) {
    var link = event.target.closest ? event.target.closest("a[href]") : null;
    if (link && !link.hasAttribute("data-whatsapp-dialog-open")) setMobileMenu(false, false);
  });

  function normalizePath(value) {
    var path = String(value || "/").replace(/\/index\.html$/u, "/").replace(/\.html$/u, "");
    return path === "/" ? "/" : path.replace(/\/+$/u, "");
  }

  function markCurrentPage(container) {
    var currentPath = normalizePath(window.location.pathname);
    var currentHash = window.location.hash;
    var candidates = Array.prototype.slice.call(container.querySelectorAll('a[href^="/"]:not(.nav-cta):not(.nav-compact-cta):not(.mobile-cta)'))
      .filter(function (link) {
        var target = new URL(link.getAttribute("href"), window.location.origin);
        return normalizePath(target.pathname) === currentPath;
      });
    if (!candidates.length) return;
    var exactHash = currentHash ? candidates.find(function (link) { return new URL(link.href).hash === currentHash; }) : null;
    var current = exactHash || candidates.find(function (link) { return !new URL(link.href).hash; }) || candidates[0];
    current.setAttribute("aria-current", "page");
    var parent = current.closest("[data-nav-disclosure], [data-mobile-disclosure]");
    if (parent) parent.setAttribute("data-current-group", "true");
  }

  markCurrentPage(navbar);
  markCurrentPage(mobileMenu);

  function dialogFocusableElements() {
    if (!eligibilityDialog) return [];
    return Array.prototype.slice.call(eligibilityDialog.querySelectorAll('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'));
  }

  function openEligibilityDialog(event, opener) {
    if (event) event.preventDefault();
    if (!eligibilityDialog) return;
    var openedFromMobileMenu = opener && mobileMenu.contains(opener);
    eligibilityDialogTrigger = openedFromMobileMenu ? hamburgerBtn : (opener || document.activeElement);
    setMobileMenu(false, false);
    closeDesktopDisclosures();
    eligibilityDialog.hidden = false;
    document.body.style.overflow = "hidden";
    document.dispatchEvent(new CustomEvent("faber:whatsapp-dialog-open"));
    window.requestAnimationFrame(function () { if (eligibilityDialogClose) eligibilityDialogClose.focus(); });
  }

  function closeEligibilityDialog(options) {
    if (!eligibilityDialog || eligibilityDialog.hidden) return;
    eligibilityDialog.hidden = true;
    document.body.style.overflow = "";
    if (!options || options.restoreFocus !== false) {
      if (eligibilityDialogTrigger && typeof eligibilityDialogTrigger.focus === "function") eligibilityDialogTrigger.focus();
    }
  }

  document.addEventListener("click", function (event) {
    var opener = event.target.closest ? event.target.closest("[data-whatsapp-dialog-open]") : null;
    if (opener) return openEligibilityDialog(event, opener);
    if (!event.target.closest || !event.target.closest("[data-nav-disclosure]")) closeDesktopDisclosures();
  });

  if (eligibilityDialogClose) eligibilityDialogClose.addEventListener("click", function () { closeEligibilityDialog(); });
  if (eligibilityDialog) eligibilityDialog.addEventListener("click", function (event) { if (event.target === eligibilityDialog) closeEligibilityDialog(); });
  eligibilityDialogOptions.forEach(function (option) { option.addEventListener("click", function () { closeEligibilityDialog({ restoreFocus: false }); }); });

  document.addEventListener("keydown", function (event) {
    if (eligibilityDialog && !eligibilityDialog.hidden && event.key === "Tab") {
      var focusable = dialogFocusableElements();
      if (!focusable.length) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
      return;
    }
    if (event.key !== "Escape") return;
    if (eligibilityDialog && !eligibilityDialog.hidden) {
      event.preventDefault();
      closeEligibilityDialog();
      return;
    }
    var openDesktop = desktopDisclosures.find(desktopDisclosureIsOpen);
    if (openDesktop) {
      event.preventDefault();
      closeDesktopDisclosure(openDesktop, true);
      return;
    }
    var openMobile = mobileDisclosures.find(function (disclosure) { return !disclosureParts(disclosure).panel.hidden; });
    if (openMobile) {
      event.preventDefault();
      closeMobileDisclosure(openMobile, true);
      return;
    }
    if (!mobileMenu.hidden) {
      event.preventDefault();
      setMobileMenu(false, true);
    }
  });

  window.addEventListener("resize", function () {
    if (window.innerWidth >= 1180 && !mobileMenu.hidden) setMobileMenu(false, false);
  });
})();
