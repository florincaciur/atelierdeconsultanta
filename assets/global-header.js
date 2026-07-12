(function () {
  if (window.__globalHeaderInitialized) return;
  window.__globalHeaderInitialized = true;

  var navbar = document.getElementById('navbar');
  var hamburgerBtn = document.getElementById('hamburgerBtn');
  var mobileMenu = document.getElementById('mobileMenu');
  var dropdownBtn = document.getElementById('dropdownBtn');
  var dropdownPanel = document.getElementById('dropdownPanel');
  var dropdownItems = dropdownPanel ? Array.prototype.slice.call(dropdownPanel.querySelectorAll('a')) : [];
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

  document.addEventListener('click', function (event) {
    if (!dropdownBtn.contains(event.target) && !dropdownPanel.contains(event.target)) {
      window.closeDropdown();
    }
  });

  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Escape') return;
    window.closeMobileMenu();
    window.closeDropdown({ restoreFocus: dropdownPanel && !dropdownPanel.hidden });
  });
})();
