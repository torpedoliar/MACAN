const express = require('express');
const { query } = require('../db');
const { writeAudit } = require('../audit');
const { normalizeMac } = require('../radius-policy');
const { PENDING_LIST } = require('../pending');
const { wrap } = require('../middleware');
const router = express.Router();

const STATUSES = ['allow', 'deny', 'disabled'];
const clean = v => {
  const s = String(v === undefined || v === null ? '' : v).trim();
  return s === '' ? null : s;
};

router.get('/', wrap(async (req, res) => {
  const pending = await query(PENDING_LIST);
  // Kelompokkan per SSID — pola yang sama dengan /rules. Filter active
  // tetap dipertahankan; grouping cuma menyusun ulang tampilan.
  const pendingBySsid = pending.reduce((acc, p) => {
    const key = p.ssid_name || '(tanpa SSID)';
    (acc[key] = acc[key] || []).push(p);
    return acc;
  }, {});
  res.render('approvals/index', {
    pending,
    pendingBySsid,
    ssids: Object.keys(pendingBySsid).sort(),
    error: req.query.error,
    approved: req.query.approved
  });
}));

router.post('/', wrap(async (req, res) => {
  const mac = normalizeMac(req.body.mac_address);
  const ssid = clean(req.body.ssid_name);
  const status = String(clean(req.body.status) || '').toLowerCase();
  const scope = clean(req.body.scope) || 'controller';
  const controllerId = scope === 'global' ? null : clean(req.body.controller_id);

  const bail = msg => res.redirect('/approvals?error=' + encodeURIComponent(msg));
  if (!mac) return bail('MAC address tidak valid.');
  if (!ssid) return bail('SSID tidak boleh kosong.');
  if (!STATUSES.includes(status)) return bail('Status harus allow, deny, atau disabled.');
  if (scope !== 'global' && !controllerId) return bail('Controller tidak diketahui — pilih scope global atau lengkapi data di halaman Rules.');

  try {
    await query(`INSERT INTO mac_rules (controller_id, ssid_name, mac_address, status, owner_name, device_name)
      VALUES (?, ?, ?, ?, ?, ?)`,
      [controllerId, ssid, mac, status, clean(req.body.owner_name), clean(req.body.device_name)]);
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY' || err.errno === 1062) {
      return bail(`Rule untuk ${mac} di SSID ${ssid} sudah ada.`);
    }
    throw err;
  }
  await writeAudit(req.session.admin.id, 'rule_create_from_approval', { mac, ssid, status, scope });
  res.redirect('/approvals?approved=' + encodeURIComponent(mac));
}));

module.exports = router;
