const express = require('express');
const multer = require('multer');
const os = require('os');
const { query } = require('../db');
const { writeAudit } = require('../audit');
const { wrap, verifyCsrf } = require('../middleware');
const { sendTest } = require('../notifications');
const { setLogo, clearLogo, sniff, getLogo } = require('../logo');
const { refreshOui } = require('../oui');
const { syncAllControllers, testControllers } = require('../unifi');
const router = express.Router();

// Logo upload: temp file, parsed into memory then validated by magic byte.
const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 2 * 1024 * 1024 } });

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
    hasLogo: Boolean(getLogo()),
    errors: req.query.error ? [req.query.error] : [],
    saved: req.query.saved,
    tested: req.query.tested,
    notice: req.query.notice,
    unifiTest: req.session.unifiTest || null
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

  if (req.body.unifi_sync_enabled !== undefined) {
    updates.push(['unifi_sync_enabled', req.body.unifi_sync_enabled === '1' ? '1' : '0']);
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

// Serve the custom logo. Public (mounted before requireAdmin in app.js) so the
// login page can render it. ETag + 1h cache: bust happens via the in-memory
// cache swap on upload, not a query string — the admin's own browser gets the
// new bytes on next nav because the ETag changes.
router.post('/logo', upload.single('logo'), verifyCsrf, wrap(async (req, res) => {
  if (!req.file) return res.redirect('/settings?error=' + encodeURIComponent('Pilih file logo dulu.'));
  const fs = require('fs');
  const buf = fs.readFileSync(req.file.path);
  fs.unlink(req.file.path, () => {});
  const mime = sniff(buf);
  if (!mime) {
    return res.redirect('/settings?error=' + encodeURIComponent('Format file tidak didukung. Pakai PNG, JPG, GIF, WEBP, atau SVG.'));
  }
  const b64 = buf.toString('base64');
  await query("INSERT INTO settings (name, value) VALUES ('logo_mime', ?) ON DUPLICATE KEY UPDATE value = VALUES(value)", [mime]);
  await query("INSERT INTO settings (name, value) VALUES ('logo_data', ?) ON DUPLICATE KEY UPDATE value = VALUES(value)", [b64]);
  setLogo({ mime, buf, etag: '"' + buf.length.toString(16) + '-' + buf.slice(0, 8).toString('hex') + '"' });
  await writeAudit(req.session.admin.id, 'logo_upload', { mime, bytes: buf.length });
  res.redirect('/settings?saved=1');
}));

router.post('/logo/delete', verifyCsrf, wrap(async (req, res) => {
  await query("DELETE FROM settings WHERE name IN ('logo_mime', 'logo_data')");
  clearLogo();
  await writeAudit(req.session.admin.id, 'logo_delete', {});
  res.redirect('/settings?saved=1');
}));

router.post('/oui-refresh', verifyCsrf, wrap(async (req, res) => {
  try {
    const r = await refreshOui();
    await writeAudit(req.session.admin.id, 'oui_refresh', { vendors: r.total });
    res.redirect('/settings?saved=1&notice=' + encodeURIComponent(`OUI: ${r.total} vendor termuat.`));
  } catch (err) {
    res.redirect('/settings?error=' + encodeURIComponent(`OUI refresh gagal: ${err.message}`));
  }
}));

router.post('/unifi-sync', verifyCsrf, wrap(async (req, res) => {
  try {
    const r = await syncAllControllers();
    if (r.error) {
      res.redirect('/settings?error=' + encodeURIComponent(`Sync UniFi: ${r.ok}/${r.controllers} controller OK. Error: ${r.error}`));
    } else {
      await writeAudit(req.session.admin.id, 'unifi_sync_manual', { ok: r.ok, controllers: r.controllers });
      const msg = r.synced > 0
        ? `Sync UniFi: ${r.ok}/${r.controllers} controller, ${r.synced} hostname di-update (${r.skipped} tanpa nama).`
        : r.skipped > 0
          ? `Sync UniFi: ${r.ok}/${r.controllers} controller OK, tapi 0 hostname. ${r.skipped} client tanpa nama di UniFi.`
          : r.classicError
            ? `Sync UniFi: 0 hostname dimuat. Integration v1 hanya ambil device ONLINE — device terdaftar/pending yg lagi offline tidak ter-fetch. Classic API (satu-satunya sumber offline) juga gagal: ${r.classicError}.`
            : `Sync UniFi: ${r.ok}/${r.controllers} controller OK, 0 hostname dimuat. Integration v1 cuma ambil device online. Device terdaftar/pending yg lagi offline tidak ter-fetch — isi Username+Password UniFi (classic) di controller agar offline ikut diambil.`;
      res.redirect('/settings?saved=1&notice=' + encodeURIComponent(msg));
    }
  } catch (err) {
    res.redirect('/settings?error=' + encodeURIComponent(`Sync UniFi gagal: ${err.message}`));
  }
}));

router.post('/unifi-test', verifyCsrf, wrap(async (req, res) => {
  req.session.unifiTest = await testControllers();
  res.redirect('/settings#unifi-test');
}));

module.exports = router;
