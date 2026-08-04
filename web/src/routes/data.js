const express = require('express');
const { query, transaction } = require('../db');
const { writeAudit } = require('../audit');
const { wrap, verifyCsrf } = require('../middleware');
const { normalizeMac } = require('../radius-policy');
const multer = require('multer');
const os = require('os');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// ponytail: JSON backup built from plain SELECTs instead of shelling out to
// mariadb-dump. The web image is node:20-alpine and has no mariadb client, and
// this avoids interpolating DB_PASSWORD into a shell string. Trade-off: config
// tables only (rules/ssids/controllers/settings) — logs and sessions are
// operational data and are not backed up. Add mariadb-client to the image if you
// ever need a full physical dump.
const BACKUP_VERSION = 1;
const TABLES = ['controllers', 'ssids', 'mac_rules', 'settings'];
const SECRET_SETTINGS = ['telegram_bot_token'];
const STATUSES = ['allow', 'deny', 'disabled'];

const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 8 * 1024 * 1024 } });
const STAGING = path.join(os.tmpdir(), 'macan-restore');

async function buildBackup() {
  const data = {};
  for (const table of TABLES) {
    data[table] = await query(`SELECT * FROM \`${table}\``);
  }
  return {
    backup_version: BACKUP_VERSION,
    generated_at: new Date().toISOString(),
    app: 'macan',
    counts: TABLES.reduce((acc, t) => ({ ...acc, [t]: data[t].length }), {}),
    data
  };
}

function validateBackup(parsed) {
  const errors = [];
  if (!parsed || typeof parsed !== 'object') return ['File bukan JSON objek.'];
  if (parsed.app !== 'macan') errors.push('File ini bukan backup MACan.');
  if (parsed.backup_version !== BACKUP_VERSION) {
    errors.push(`Versi backup ${parsed.backup_version} tidak didukung (harus ${BACKUP_VERSION}).`);
  }
  if (!parsed.data || typeof parsed.data !== 'object') {
    errors.push('Bagian "data" tidak ada.');
    return errors;
  }
  for (const table of TABLES) {
    if (!Array.isArray(parsed.data[table])) errors.push(`Tabel "${table}" tidak ada atau bukan array.`);
  }
  if (errors.length) return errors;

  for (const c of parsed.data.controllers) {
    if (!c.name || !c.ip_address || !c.shared_secret) errors.push('Ada controller tanpa name/ip_address/shared_secret.');
  }
  for (const r of parsed.data.mac_rules) {
    if (!normalizeMac(r.mac_address)) errors.push(`MAC tidak valid di backup: ${r.mac_address}`);
    if (!STATUSES.includes(String(r.status))) errors.push(`Status rule tidak valid: ${r.status}`);
  }
  return errors.slice(0, 20);
}

router.get('/', wrap(async (req, res) => {
  const counts = {};
  for (const table of TABLES) {
    const rows = await query(`SELECT COUNT(*) AS count FROM \`${table}\``);
    counts[table] = Number(rows[0].count);
  }
  let staged = null;
  if (req.session.restore && fs.existsSync(req.session.restore.file)) {
    staged = req.session.restore.preview;
  } else {
    delete req.session.restore;
  }
  res.render('data/index', {
    counts, staged,
    error: req.query.error,
    notice: req.query.notice
  });
}));

router.get('/backup', wrap(async (req, res) => {
  const backup = await buildBackup();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="macan-backup-${stamp}.json"`);
  await writeAudit(req.session.admin.id, 'backup_download', { counts: backup.counts });
  res.send(JSON.stringify(backup, null, 2));
}));

// Step 1 of restore: parse, validate, stage on disk, show a preview.
// verifyCsrf runs after multer — see the note in middleware.js.
router.post('/restore/preview', upload.single('backup'), verifyCsrf, wrap(async (req, res) => {
  const bail = msg => {
    if (req.file) { try { fs.unlinkSync(req.file.path); } catch {} }
    return res.redirect('/data?error=' + encodeURIComponent(msg));
  };
  if (!req.file) return bail('File backup tidak ditemukan.');

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(req.file.path, 'utf8'));
  } catch (err) {
    return bail('File tidak bisa dibaca sebagai JSON: ' + err.message);
  }
  const errors = validateBackup(parsed);
  if (errors.length) return bail('Backup tidak valid: ' + errors.join(' | '));

  const current = {};
  for (const table of TABLES) {
    const rows = await query(`SELECT COUNT(*) AS count FROM \`${table}\``);
    current[table] = Number(rows[0].count);
  }

  fs.mkdirSync(STAGING, { recursive: true });
  const staged = path.join(STAGING, `${req.sessionID}.json`);
  fs.renameSync(req.file.path, staged);
  req.session.restore = {
    file: staged,
    preview: {
      generated_at: parsed.generated_at || 'tidak diketahui',
      rows: TABLES.map(t => ({ table: t, incoming: parsed.data[t].length, current: current[t] }))
    }
  };
  res.redirect('/data?notice=' + encodeURIComponent('Backup valid. Periksa ringkasan di bawah, lalu konfirmasi untuk mengganti data.'));
}));

router.post('/restore/cancel', wrap(async (req, res) => {
  if (req.session.restore) {
    try { fs.unlinkSync(req.session.restore.file); } catch {}
    delete req.session.restore;
  }
  res.redirect('/data?notice=' + encodeURIComponent('Restore dibatalkan.'));
}));

// Step 2: the destructive part. Replaces every config table inside one
// transaction, after writing a pre-restore snapshot to disk.
router.post('/restore/confirm', wrap(async (req, res) => {
  if (!req.session.restore || !fs.existsSync(req.session.restore.file)) {
    return res.redirect('/data?error=' + encodeURIComponent('Tidak ada backup yang menunggu konfirmasi. Unggah ulang file.'));
  }
  if (String(req.body.confirm || '').trim().toUpperCase() !== 'GANTI') {
    return res.redirect('/data?error=' + encodeURIComponent('Ketik GANTI untuk mengonfirmasi restore.'));
  }

  const parsed = JSON.parse(fs.readFileSync(req.session.restore.file, 'utf8'));
  const errors = validateBackup(parsed);
  if (errors.length) return res.redirect('/data?error=' + encodeURIComponent('Backup tidak valid: ' + errors.join(' | ')));

  // Safety net: snapshot current state before wiping it.
  const snapshot = await buildBackup();
  fs.mkdirSync(STAGING, { recursive: true });
  const snapshotPath = path.join(STAGING, `pre-restore-${Date.now()}.json`);
  fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));

  await transaction(async conn => {
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    try {
      // Child tables first so FK order never matters even with checks re-enabled.
      await conn.query('DELETE FROM mac_rules');
      await conn.query('DELETE FROM ssids');
      await conn.query('DELETE FROM controllers');

      for (const c of parsed.data.controllers) {
        await conn.execute(
          'INSERT INTO controllers (id, name, ip_address, shared_secret, enabled, note) VALUES (?, ?, ?, ?, ?, ?)',
          [c.id, c.name, c.ip_address, c.shared_secret, c.enabled ? 1 : 0, c.note ?? null]
        );
      }
      for (const s of parsed.data.ssids) {
        await conn.execute(
          'INSERT INTO ssids (id, controller_id, ssid_name, enabled, auto_created, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)',
          [s.id, s.controller_id, s.ssid_name, s.enabled ? 1 : 0, s.auto_created ? 1 : 0, s.last_seen_at ?? null]
        );
      }
      for (const r of parsed.data.mac_rules) {
        await conn.execute(
          `INSERT INTO mac_rules (id, controller_id, ssid_name, mac_address, status, owner_name, device_name, note, last_seen_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [r.id, r.controller_id ?? null, r.ssid_name, normalizeMac(r.mac_address), String(r.status),
           r.owner_name ?? null, r.device_name ?? null, r.note ?? null, r.last_seen_at ?? null]
        );
      }
      for (const s of parsed.data.settings) {
        // A backup taken from a masked export can carry an empty token; don't
        // let it silently wipe a working one.
        if (SECRET_SETTINGS.includes(s.name) && !String(s.value || '').trim()) continue;
        await conn.execute(
          'INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)',
          [s.name, String(s.value ?? '')]
        );
      }
    } finally {
      await conn.query('SET FOREIGN_KEY_CHECKS = 1');
    }
  });

  try { fs.unlinkSync(req.session.restore.file); } catch {}
  delete req.session.restore;
  await writeAudit(req.session.admin.id, 'backup_restore', {
    counts: TABLES.reduce((acc, t) => ({ ...acc, [t]: parsed.data[t].length }), {}),
    snapshot: path.basename(snapshotPath)
  });
  res.redirect('/data?notice=' + encodeURIComponent(
    'Restore selesai. Snapshot sebelum restore disimpan di ' + snapshotPath + '. Restart container radius agar daftar controller terbaca ulang.'
  ));
}));

module.exports = router;
