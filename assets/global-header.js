(function () {
  if (window.__globalHeaderInitialized) return;
  window.__globalHeaderInitialized = true;

  var navbar = document.getElementById('navbar');
  var hamburgerBtn = document.getElementById('hamburgerBtn');
  var mobileMenu = document.getElementById('mobileMenu');
  var dropdownBtn = document.getElementById('dropdownBtn');
  var dropdownPanel = document.getElementById('dropdownPanel');
  var dropdownItems = dropdownPanel ? Array.prototype.slice.call(dropdownPanel.querySelectorAll('a')) : [];
  var eligibilityDialog = document.getElementById('eligibility-whatsapp-dialog');
  var eligibilityDialogClose = eligibilityDialog ? eligibilityDialog.querySelector('[data-whatsapp-dialog-close]') : null;
  var eligibilityDialogOptions = eligibilityDialog ? Array.prototype.slice.call(eligibilityDialog.querySelectorAll('.eligibility-whatsapp-options a')) : [];
  var eligibilityDialogTrigger = null;
  var scrollTicking = false;

  function updateScrollState() {
    scrollTicking = false;
    navbar.classList.toggle('scrolled', window.scrollY > 100);
    if (typeof window.updateBackToTop === 'function') window.updateBackToTop();
  }

  window.addEventListener('scroll', function () {
    if (scrollTicking) return;
    scrollTicking = true;
    window.requestAnimationFrame(updateScrollState);
  }, { passive: true });

  window.closeMobileMenu = function closeMobileMenu() {
    mobileMenu.classList.remove('open');
    hamburgerBtn.classList.remove('open');
    hamburgerBtn.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
  };

  hamburgerBtn.addEventListener('click', function () {
    var isOpen = mobileMenu.classList.toggle('open');
    hamburgerBtn.classList.toggle('open', isOpen);
    hamburgerBtn.setAttribute('aria-expanded', String(isOpen));
    document.body.style.overflow = isOpen ? 'hidden' : '';
  });

  function openDropdown(focusTarget) {
    if (!dropdownPanel || !dropdownBtn) return;
    dropdownPanel.hidden = false;
    dropdownPanel.classList.add('open');
    dropdownBtn.setAttribute('aria-expanded', 'true');
    if (focusTarget && dropdownItems.length) {
      window.requestAnimationFrame(function () { focusTarget.focus(); });
    }
  }

  window.closeDropdown = function closeDropdown(options) {
    if (!dropdownPanel || !dropdownBtn) return;
    dropdownPanel.classList.remove('open');
    dropdownPanel.hidden = true;
    dropdownBtn.setAttribute('aria-expanded', 'false');
    if (options && options.restoreFocus) dropdownBtn.focus();
  };

  function toggleDropdown() {
    var shouldOpen = dropdownPanel.hidden || !dropdownPanel.classList.contains('open');
    if (shouldOpen) openDropdown();
    else window.closeDropdown();
  }

  dropdownBtn.addEventListener('click', function (event) {
    event.stopPropagation();
    toggleDropdown();
  });

  dropdownBtn.addEventListener('keydown', function (event) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      openDropdown(dropdownItems[0]);
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      openDropdown(dropdownItems[dropdownItems.length - 1]);
    }
    if (event.key === 'Escape') window.closeDropdown();
  });

  dropdownPanel.addEventListener('keydown', function (event) {
    var currentIndex = dropdownItems.indexOf(document.activeElement);
    if (currentIndex === -1) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      dropdownItems[(currentIndex + 1) % dropdownItems.length].focus();
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      dropdownItems[(currentIndex - 1 + dropdownItems.length) % dropdownItems.length].focus();
    }
    if (event.key === 'Home') {
      event.preventDefault();
      dropdownItems[0].focus();
    }
    if (event.key === 'End') {
      event.preventDefault();
      dropdownItems[dropdownItems.length - 1].focus();
    }
    if (event.key === 'Escape') {
      event.preventDefault();
      window.closeDropdown({ restoreFocus: true });
    }
  });

  dropdownPanel.addEventListener('focusout', function (event) {
    if (!dropdownPanel.contains(event.relatedTarget) && event.relatedTarget !== dropdownBtn) {
      window.closeDropdown();
    }
  });

  function dialogFocusableElements() {
    if (!eligibilityDialog) return [];
    return Array.prototype.slice.call(eligibilityDialog.querySelectorAll('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'));
  }

  function openEligibilityDialog(event, opener) {
    if (event) event.preventDefault();
    if (!eligibilityDialog) return;
    eligibilityDialogTrigger = opener || document.activeElement;
    window.closeMobileMenu();
    window.closeDropdown();
    eligibilityDialog.hidden = false;
    document.body.style.overflow = 'hidden';
    window.requestAnimationFrame(function () {
      if (eligibilityDialogClose) eligibilityDialogClose.focus();
    });
  }

  function closeEligibilityDialog(options) {
    if (!eligibilityDialog || eligibilityDialog.hidden) return;
    eligibilityDialog.hidden = true;
    document.body.style.overflow = '';
    if (!options || options.restoreFocus !== false) {
      if (eligibilityDialogTrigger && typeof eligibilityDialogTrigger.focus === 'function') eligibilityDialogTrigger.focus();
    }
  }

  document.addEventListener('click', function (event) {
    var opener = event.target.closest ? event.target.closest('[data-whatsapp-dialog-open]') : null;
    if (!opener) return;
    openEligibilityDialog(event, opener);
  });
  if (eligibilityDialogClose) eligibilityDialogClose.addEventListener('click', function () { closeEligibilityDialog(); });
  if (eligibilityDialog) {
    eligibilityDialog.addEventListener('click', function (event) {
      if (event.target === eligibilityDialog) closeEligibilityDialog();
    });
  }
  eligibilityDialogOptions.forEach(function (option) {
    option.addEventListener('click', function () { closeEligibilityDialog({ restoreFocus: false }); });
  });

  document.addEventListener('click', function (event) {
    if (!dropdownBtn.contains(event.target) && !dropdownPanel.contains(event.target)) {
      window.closeDropdown();
    }
  });

  document.addEventListener('keydown', function (event) {
    if (eligibilityDialog && !eligibilityDialog.hidden && event.key === 'Tab') {
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
    if (event.key !== 'Escape') return;
    if (eligibilityDialog && !eligibilityDialog.hidden) {
      event.preventDefault();
      closeEligibilityDialog();
      return;
    }
    window.closeMobileMenu();
    window.closeDropdown({ restoreFocus: dropdownPanel && !dropdownPanel.hidden });
  });
})();
