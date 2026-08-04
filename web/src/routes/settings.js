const express = require('express');
const { query } = require('../db');
const { writeAudit } = require('../audit');
const { wrap } = require('../middleware');
const { sendTest } = require('../notifications');
const router = express.Router();

// name -> validator. Numbers get a range so a typo can't disable retention
// (0 days) or spam every tick (window 0).
const NUMERIC = {
  auth_log_retention_days: { min: 1, max: 3650 },
  online_session_timeout_minutes: { min: 1, max: 10080 },
  inactive_after_days: { min: 1, max: 3650 },
  reject_spike_count: { min: 1, max: 10000 },
  reject_spike_window_minutes: { min: 1, max: 1440 },
  notification_dedupe_minutes: { min: 0, max: 10080 }
};
const TEXT = ['notification_webhook_url', 'telegram_bot_token', 'telegram_chat_id'];
const SECRETS = ['telegram_bot_token'];

async function loadSettings() {
  const rows = await query('SELECT name, value FROM settings');
  return rows.reduce((acc, row) => ({ ...acc, [row.name]: row.value }), {});
}

router.get('/', wrap(async (req, res) => {
  const settings = await loadSettings();
  // Never echo the secret back into an input value; show a placeholder instead.
  const masked = { ...settings };
  for (const key of SECRETS) masked[key] = '';
  // Local is named `cfg`, not `settings`: EJS reads `data.settings['view options']`
  // to find its include root, so a local called `settings` shadows Express's own
  // and every absolute include('/partials/…') in the view fails with ENOENT.
  res.render('settings/index', {
    cfg: masked,
    hasSecret: SECRETS.reduce((acc, k) => ({ ...acc, [k]: Boolean(settings[k]) }), {}),
    errors: req.query.error ? [req.query.error] : [],
    saved: req.query.saved,
    tested: req.query.tested
  });
}));

router.post('/', wrap(async (req, res) => {
  const errors = [];
  const updates = [];

  for (const [name, range] of Object.entries(NUMERIC)) {
    if (req.body[name] === undefined) continue;
    const raw = String(req.body[name]).trim();
    if (!/^\d+$/.test(raw)) { errors.push(`${name} harus berupa angka bulat.`); continue; }
    const n = parseInt(raw, 10);
    if (n < range.min || n > range.max) {
      errors.push(`${name} harus antara ${range.min} dan ${range.max}.`);
      continue;
    }
    updates.push([name, String(n)]);
  }

  if (req.body.notification_webhook_url !== undefined) {
    const url = String(req.body.notification_webhook_url).trim();
    if (url && !/^https?:\/\/\S+$/i.test(url)) {
      errors.push('notification_webhook_url harus URL http:// atau https://.');
    } else {
      updates.push(['notification_webhook_url', url]);
    }
  }
  for (const name of TEXT) {
    if (name === 'notification_webhook_url') continue;
    if (req.body[name] === undefined) continue;
    const value = String(req.body[name]).trim();
    // Blank on a secret field means "leave unchanged", not "erase".
    if (SECRETS.includes(name) && value === '') continue;
    updates.push([name, value]);
  }

  if (req.body.maintenance_mode !== undefined) {
    updates.push(['maintenance_mode', req.body.maintenance_mode === '1' ? '1' : '0']);
  }

  if (errors.length) {
    return res.redirect('/settings?error=' + encodeURIComponent(errors.join(' ')));
  }

  const changed = [];
  for (const [name, value] of updates) {
    await query('INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)', [name, value]);
    changed.push(name);
  }
  // Log which keys changed, never their values (tokens live here).
  await writeAudit(req.session.admin.id, 'settings_update', { fields: changed });
  res.redirect('/settings?saved=1');
}));

router.post('/clear-secret', wrap(async (req, res) => {
  const name = String(req.body.name || '');
  if (!SECRETS.includes(name)) return res.redirect('/settings?error=' + encodeURIComponent('Field tidak dikenal.'));
  await query('UPDATE settings SET value = ? WHERE name = ?', ['', name]);
  await writeAudit(req.session.admin.id, 'settings_clear_secret', { field: name });
  res.redirect('/settings?saved=1');
}));

router.post('/test-notification', wrap(async (req, res) => {
  const result = await sendTest();
  await writeAudit(req.session.admin.id, 'notification_test', { ok: result.ok, channels: result.channels });
  res.redirect('/settings?tested=' + encodeURIComponent(result.message));
}));

module.exports = router;
