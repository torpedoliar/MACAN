const express = require('express');
const { query } = require('../db');
const { writeAudit } = require('../audit');
const { wrap } = require('../middleware');
const { isControllerIp } = require('../radius-policy');
const router = express.Router();

const clean = v => {
  const s = String(v === undefined || v === null ? '' : v).trim();
  return s === '' ? null : s;
};

router.get('/', wrap(async (req, res) => {
  const controllers = await query(`
    SELECT c.*,
      (SELECT COUNT(*) FROM ssids s WHERE s.controller_id = c.id) AS ssid_count,
      (SELECT COUNT(*) FROM mac_rules r WHERE r.controller_id = c.id) AS rule_count
    FROM controllers c ORDER BY c.name
  `);
  res.render('controllers/index', {
    controllers,
    error: req.query.error,
    notice: req.query.notice
  });
}));

router.get('/new', (req, res) => res.render('controllers/form', { controller: {}, error: null }));

async function save(req, res, id) {
  const name = clean(req.body.name);
  const ip = clean(req.body.ip_address);
  const secret = clean(req.body.shared_secret);
  const enabled = req.body.enabled === 'on' || req.body.enabled === '1';
  const note = clean(req.body.note);

  const rerender = error => res.status(400).render('controllers/form', {
    controller: { id, name, ip_address: ip, enabled, note }, error
  });
  if (!name) return rerender('Nama controller wajib diisi.');
  if (!ip || !isControllerIp(ip)) return rerender('IP address tidak valid. Isi satu host (192.168.1.10) atau satu subnet (192.168.1.0/24, prefix /8 sampai /32).');
  if (!id && !secret) return rerender('Shared secret wajib diisi saat membuat controller baru.');
  if (secret && secret.length < 8) return rerender('Shared secret minimal 8 karakter.');

  try {
    if (id) {
      if (secret) {
        await query('UPDATE controllers SET name=?, ip_address=?, shared_secret=?, enabled=?, note=? WHERE id=?',
          [name, ip, secret, enabled, note, id]);
      } else {
        await query('UPDATE controllers SET name=?, ip_address=?, enabled=?, note=? WHERE id=?',
          [name, ip, enabled, note, id]);
      }
      await writeAudit(req.session.admin.id, 'controller_update', { id, name, ip_address: ip, secret_changed: Boolean(secret) });
    } else {
      await query('INSERT INTO controllers (name, ip_address, shared_secret, enabled, note) VALUES (?, ?, ?, ?, ?)',
        [name, ip, secret, enabled, note]);
      await writeAudit(req.session.admin.id, 'controller_create', { name, ip_address: ip });
    }
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY' || err.errno === 1062) return rerender(`IP address ${ip} sudah dipakai controller lain.`);
    throw err;
  }
  // FreeRADIUS resolves clients dynamically now (radius/macan_clients.conf), so no
  // restart is needed. A NEW controller works on its first packet; a changed IP or
  // rotated secret takes up to the `lifetime` in radius/clients.conf (300s) because
  // the old client entry is still cached until then.
  res.redirect('/controllers?notice=' + encodeURIComponent(
    id ? 'Tersimpan. Perubahan IP atau shared secret berlaku paling lama 5 menit, tanpa restart.'
       : 'Tersimpan. Controller baru langsung dikenali pada paket pertama, tanpa restart.'
  ));
}

router.post('/', wrap((req, res) => save(req, res, null)));

router.get('/:id/edit', wrap(async (req, res) => {
  const rows = await query('SELECT * FROM controllers WHERE id = ?', [req.params.id]);
  if (!rows.length) return res.redirect('/controllers');
  res.render('controllers/form', { controller: rows[0], error: null });
}));

router.post('/:id', wrap((req, res) => save(req, res, req.params.id)));

router.post('/:id/delete', wrap(async (req, res) => {
  const id = req.params.id;
  const refs = await query(`
    SELECT
      (SELECT COUNT(*) FROM ssids WHERE controller_id = ?) AS ssids,
      (SELECT COUNT(*) FROM mac_rules WHERE controller_id = ?) AS rules,
      (SELECT COUNT(*) FROM auth_logs WHERE controller_id = ?) AS logs
  `, [id, id, id]);
  const { ssids, rules, logs } = refs[0];
  if (Number(ssids) || Number(rules) || Number(logs)) {
    const parts = [];
    if (Number(ssids)) parts.push(`${ssids} SSID`);
    if (Number(rules)) parts.push(`${rules} rule MAC`);
    if (Number(logs)) parts.push(`${logs} baris auth log`);
    return res.redirect('/controllers?error=' + encodeURIComponent(
      `Controller tidak bisa dihapus: masih dipakai oleh ${parts.join(', ')}. Hapus data itu dulu, atau nonaktifkan controller ini.`
    ));
  }
  await query('DELETE FROM controllers WHERE id = ?', [id]);
  await writeAudit(req.session.admin.id, 'controller_delete', { id });
  res.redirect('/controllers?notice=' + encodeURIComponent('Controller dihapus. Paket dari IP itu ditolak paling lama 5 menit lagi.'));
}));

module.exports = router;
