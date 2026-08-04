const express = require('express');
const { query } = require('../db');
const { writeAudit } = require('../audit');
const { wrap } = require('../middleware');
const router = express.Router();

const clean = v => {
  const s = String(v === undefined || v === null ? '' : v).trim();
  return s === '' ? null : s;
};

router.get('/', wrap(async (req, res) => {
  const ssids = await query(`
    SELECT s.*, c.name AS controller_name,
      (SELECT COUNT(*) FROM mac_rules r
        WHERE r.ssid_name = s.ssid_name
          AND (r.controller_id = s.controller_id OR r.controller_id IS NULL)) AS rule_count
    FROM ssids s JOIN controllers c ON s.controller_id = c.id
    ORDER BY c.name, s.ssid_name
  `);
  const controllers = await query('SELECT id, name FROM controllers ORDER BY name');
  res.render('ssids/index', {
    ssids, controllers,
    error: req.query.error,
    notice: req.query.notice
  });
}));

router.post('/', wrap(async (req, res) => {
  const controllerId = clean(req.body.controller_id);
  const ssid = clean(req.body.ssid_name);
  const bail = msg => res.redirect('/ssids?error=' + encodeURIComponent(msg));
  if (!controllerId) return bail('Pilih controller.');
  if (!ssid) return bail('Nama SSID wajib diisi.');
  try {
    await query('INSERT INTO ssids (controller_id, ssid_name, enabled, auto_created) VALUES (?, ?, 1, 0)', [controllerId, ssid]);
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY' || err.errno === 1062) return bail(`SSID ${ssid} sudah terdaftar untuk controller itu.`);
    if (err.code === 'ER_NO_REFERENCED_ROW_2') return bail('Controller tidak ditemukan.');
    throw err;
  }
  await writeAudit(req.session.admin.id, 'ssid_create', { controller_id: controllerId, ssid_name: ssid });
  res.redirect('/ssids?notice=' + encodeURIComponent(`SSID ${ssid} ditambahkan dan aktif.`));
}));

router.post('/:id/toggle', wrap(async (req, res) => {
  const isEnabled = req.body.enabled === '1';
  await query('UPDATE ssids SET enabled = ? WHERE id = ?', [isEnabled, req.params.id]);
  await writeAudit(req.session.admin.id, 'ssid_toggle', { id: req.params.id, enabled: isEnabled });
  res.redirect('/ssids');
}));

router.post('/:id/delete', wrap(async (req, res) => {
  const rows = await query('SELECT * FROM ssids WHERE id = ?', [req.params.id]);
  if (!rows.length) return res.redirect('/ssids');
  const ssid = rows[0];

  // A global rule (controller_id IS NULL) also applies to this SSID, so the old
  // controller-scoped-only count let SSIDs be deleted while rules still matched.
  const counts = await query(`
    SELECT
      SUM(controller_id = ?) AS scoped,
      SUM(controller_id IS NULL) AS global_rules
    FROM mac_rules WHERE ssid_name = ?
  `, [ssid.controller_id, ssid.ssid_name]);
  const scoped = Number(counts[0].scoped || 0);
  const globalRules = Number(counts[0].global_rules || 0);
  if (scoped || globalRules) {
    const parts = [];
    if (scoped) parts.push(`${scoped} rule controller ini`);
    if (globalRules) parts.push(`${globalRules} rule global`);
    return res.redirect('/ssids?error=' + encodeURIComponent(
      `SSID ${ssid.ssid_name} masih dipakai ${parts.join(' dan ')}. Hapus rule itu dulu.`
    ));
  }

  await query('DELETE FROM ssids WHERE id = ?', [req.params.id]);
  await writeAudit(req.session.admin.id, 'ssid_delete', { id: req.params.id, ssid_name: ssid.ssid_name });
  res.redirect('/ssids?notice=' + encodeURIComponent(`SSID ${ssid.ssid_name} dihapus.`));
}));

module.exports = router;
