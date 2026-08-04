// ponytail: ~50 lines of vanilla JS, no framework. Everything here is a
// progressive enhancement — every page works with JS disabled.
(function () {
  'use strict';

  // --- theme toggle: OS preference by default, localStorage overrides -------
  var root = document.documentElement;
  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      var current = root.dataset.theme || (systemDark ? 'dark' : 'light');
      var next = current === 'dark' ? 'light' : 'dark';
      root.dataset.theme = next;
      try { localStorage.setItem('macan-theme', next); } catch (e) {}
      toggle.setAttribute('aria-label', next === 'dark' ? 'Ganti ke tema terang' : 'Ganti ke tema gelap');
    });
  }

  // --- mobile drawer -------------------------------------------------------
  var sidebar = document.getElementById('sidebar');
  var burger = document.getElementById('burger');
  var scrim = document.getElementById('scrim');
  function setDrawer(open) {
    if (!sidebar) return;
    sidebar.classList.toggle('is-open', open);
    if (scrim) scrim.classList.toggle('is-open', open);
    if (burger) burger.setAttribute('aria-expanded', String(open));
    document.body.style.overflow = open ? 'hidden' : '';
    if (open) {
      var first = sidebar.querySelector('.nav__link');
      if (first) first.focus();
    } else if (burger) {
      burger.focus();
    }
  }
  if (burger) burger.addEventListener('click', function () { setDrawer(!sidebar.classList.contains('is-open')); });
  if (scrim) scrim.addEventListener('click', function () { setDrawer(false); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && sidebar && sidebar.classList.contains('is-open')) setDrawer(false);
  });

  // --- confirm destructive submits -----------------------------------------
  document.addEventListener('submit', function (e) {
    var form = e.target;
    var message = form.getAttribute('data-confirm');
    if (message && !window.confirm(message)) {
      e.preventDefault();
      return;
    }
    // Disable the submitter so a double-click can't post twice.
    var btn = form.querySelector('button[type="submit"]');
    if (btn && !form.hasAttribute('data-no-lock')) {
      setTimeout(function () {
        btn.disabled = true;
        btn.setAttribute('aria-busy', 'true');
      }, 0);
    }
  });

  // --- auto-dismiss transient notices -------------------------------------
  document.querySelectorAll('[data-autodismiss]').forEach(function (el) {
    setTimeout(function () {
      el.style.transition = 'opacity 200ms';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 220);
    }, 6000);
  });
})();
