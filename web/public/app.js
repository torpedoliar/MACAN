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

  // --- /approvals: client-side pagination + search ------------------------
  // ponytail: no URL state, no round-trip. PENDING_LIST caps 500; per-SSID
  // groups are small enough that row-visibility toggle beats server paging.
  // Progressive: rows all render server-side; JS only hides/shows.
  var approvalsCard = document.getElementById('approvals-card');
  if (approvalsCard) {
    var pageSize = parseInt(approvalsCard.dataset.pageSize, 10) || 10;
    var groups = Array.prototype.slice.call(approvalsCard.querySelectorAll('.rule-group[data-ssid]'));
    var searchInput = document.getElementById('approvals-q');

    function visibleRows(group) {
      return Array.prototype.slice.call(group.querySelectorAll('tbody tr')).filter(function (tr) {
        return tr.style.display !== 'none';
      });
    }
    function applyPaging(group, showAll) {
      var rows = visibleRows(group);
      rows.forEach(function (tr, i) {
        tr.style.display = showAll || i < pageSize ? '' : 'none';
      });
      var more = group.querySelector('[data-more]');
      if (more) more.style.display = (!showAll && rows.length > pageSize) ? '' : 'none';
    }
    function refreshGroups() {
      var q = (searchInput ? searchInput.value.trim().toLowerCase() : '');
      groups.forEach(function (group) {
        var matched = 0;
        group.querySelectorAll('tbody tr').forEach(function (tr) {
          var hit = !q ||
            tr.dataset.mac.indexOf(q) > -1 ||
            (tr.dataset.host && tr.dataset.host.toLowerCase().indexOf(q) > -1) ||
            (tr.dataset.ctrl && tr.dataset.ctrl.toLowerCase().indexOf(q) > -1);
          tr.style.display = hit ? '' : 'none';
          if (hit) matched++;
        });
        // Reset paging per group after a search (show all matches), hide the
        // "more" button text logic to reflect matched count.
        applyPaging(group, q.length > 0);
        var countEl = group.querySelector('[data-count]');
        if (countEl) countEl.textContent = matched;
        // Hide whole group if nothing matched.
        group.style.display = matched > 0 ? '' : 'none';
      });
    }

    // Initial paged render.
    groups.forEach(function (group) { applyPaging(group, false); });

    // "Tampilkan lainnya" — reveal all rows in that group. This is NOT
    // applyPaging(group, true): applyPaging only touches rows that are already
    // visible (visibleRows), so it would re-show the first pageSize rows and
    // leave the rest hidden — the "expand does nothing" bug at >10 rows.
    approvalsCard.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-more-btn]');
      if (!btn) return;
      var group = e.target.closest('.rule-group');
      if (group) {
        group.querySelectorAll('tbody tr').forEach(function (tr) {
          tr.style.display = '';
        });
        var more = group.querySelector('[data-more]');
        if (more) more.style.display = 'none';
      }
    });

    // Search — debounce 120ms.
    var timer;
    if (searchInput) {
      searchInput.addEventListener('input', function () {
        clearTimeout(timer);
        timer = setTimeout(refreshGroups, 120);
      });
    }
  }
})();
