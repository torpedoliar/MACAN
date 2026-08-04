const express = require('express');
const { parse } = require('csv-parse/sync');
const { query } = require('../db');
const { writeAudit } = require('../audit');
const { normalizeMac } = require('../radius-policy');
const { wrap, verifyCsrf } = require('../middleware');
const multer = require('multer');
const os = require('os');
const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 2 * 1024 * 1024 } });
const fs = require('fs');
const router = express.Router();

const STATUSES = ['allow', 'deny', 'disabled'];
const CSV_HEADER = 'scope,controller,ssid,mac,status,owner,device,note';

// Trims to null so mysql2 never sees `undefined` (it throws on undefined binds).
const clean = v => {
  const s = String(v === undefined || v === null ? '' : v).trim();
  return s === '' ? null : s;
};

function isDuplicate(err) {
  return err && (err.code === 'ER_DUP_ENTRY' || err.errno === 1062);
}

router.get('/', wrap(async (req, res) => {
  const { q, status, controller_id } = req.query;
  const where = [];
  const params = [];
  if (q) {
    // A MAC is stored colon-separated, so a paste of "aabbccddeeff" would never
    // match a plain LIKE. Search the normalized form too when q looks like a MAC.
    const like = `%${q}%`;
    const asMac = normalizeMac(q);
    if (asMac) {
      where.push('(r.mac_address = ? OR r.mac_address LIKE ? OR r.ssid_name LIKE ? OR r.owner_name LIKE ? OR r.device_name LIKE ?)');
      params.push(asMac, like, like, like, like);
    } else {
      where.push('(r.mac_address LIKE ? OR r.ssid_name LIKE ? OR r.owner_name LIKE ? OR r.device_name LIKE ?)');
      params.push(like, like, like, like);
    }
  }
  if (status && STATUSES.includes(status)) {
    where.push('r.status = ?');
    params.push(status);
  }
  if (controller_id === 'global') {
    where.push('r.controller_id IS NULL');
  } else if (controller_id) {
    where.push('r.controller_id = ?');
    params.push(controller_id);
  }
  const rules = await query(`
    SELECT r.*, c.name AS controller_name
    FROM mac_rules r
    LEFT JOIN controllers c ON r.controller_id = c.id
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY r.updated_at DESC
    LIMIT 500
  `, params);
  const controllers = await query('SELECT id, name FROM controllers ORDER BY name');
  res.render('rules/index', {
    rules,
    controllers,
    filters: { q: q || '', status: status || '', controller_id: controller_id || '' },
    imported: req.query.imported,
    skipped: req.query.skipped,
    error: req.query.error
  });
}));

router.get('/template.csv', (req, res) => {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="macan-rules-template.csv"');
  res.send(`${CSV_HEADER}\nglobal,,Office-WiFi,aa:bb:cc:dd:ee:ff,allow,Budi,Laptop Budi,contoh baris\ncontroller,UniFi Pusat,Office-WiFi,aabbccddeeff,deny,,,MAC diblokir\n`);
});

router.get('/export.csv', wrap(async (req, res) => {
  const rules = await query(`
    SELECT r.*, c.name AS controller_name
    FROM mac_rules r LEFT JOIN controllers c ON r.controller_id = c.id
    ORDER BY c.name, r.ssid_name, r.mac_address
  `);
  const esc = v => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [CSV_HEADER];
  for (const r of rules) {
    lines.push([
      r.controller_id ? 'controller' : 'global',
      r.controller_name || '',
      r.ssid_name, r.mac_address, r.status,
      r.owner_name || '', r.device_name || '', r.note || ''
    ].map(esc).join(','));
  }
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="macan-rules.csv"');
  await writeAudit(req.session.admin.id, 'rule_export', { count: rules.length });
  res.send(lines.join('\n') + '\n');
}));

// verifyCsrf runs after multer: the global csrf middleware skips multipart
// bodies because _csrf is still unparsed at that point.
router.post('/import', upload.single('csv'), verifyCsrf, wrap(async (req, res) => {
  if (!req.file) return res.redirect('/rules?error=' + encodeURIComponent('File CSV tidak ditemukan.'));
  let content;
  try {
    content = fs.readFileSync(req.file.path, 'utf8');
  } finally {
    fs.unlinkSync(req.file.path);
  }

  let records;
  try {
    records = parse(content, { skip_empty_lines: true, relax_column_count: true, bom: true, trim: true });
  } catch (err) {
    return res.redirect('/rules?error=' + encodeURIComponent('CSV tidak bisa dibaca: ' + err.message));
  }
  // Drop a header row if present.
  if (records.length && String(records[0][0] || '').toLowerCase() === 'scope') records.shift();

  const controllers = await query('SELECT id, name FROM controllers');
  const byName = new Map(controllers.map(c => [c.name.toLowerCase(), c.id]));

  let imported = 0;
  const errors = [];
  for (let i = 0; i < records.length; i++) {
    const row = records[i];
    const lineNo = i + 2; // +1 for 0-index, +1 for the header we removed
    const [scope, controllerName, ssid, mac, status, owner, device, note] = row.map(clean);
    const fail = msg => errors.push(`Baris ${lineNo}: ${msg}`);

    if (!ssid || !mac || !status) { fail('kolom ssid, mac, dan status wajib diisi'); continue; }
    const normalized = normalizeMac(mac);
    if (!normalized) { fail(`MAC "${mac}" tidak valid`); continue; }
    const statusLower = String(status).toLowerCase();
    if (!STATUSES.includes(statusLower)) { fail(`status "${status}" tidak dikenal (allow/deny/disabled)`); continue; }

    let controllerId = null;
    const scopeLower = (scope || 'global').toLowerCase();
    if (scopeLower === 'controller') {
      if (!controllerName) { fail('scope controller butuh nama controller'); continue; }
      controllerId = byName.get(controllerName.toLowerCase());
      if (!controllerId) { fail(`controller "${controllerName}" tidak ditemukan`); continue; }
    } else if (scopeLower !== 'global') {
      fail(`scope "${scope}" tidak dikenal (global/controller)`); continue;
    }

    try {
      await query(`INSERT INTO mac_rules (controller_id, ssid_name, mac_address, status, owner_name, device_name, note)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE status = VALUES(status), owner_name = VALUES(owner_name),
          device_name = VALUES(device_name), note = VALUES(note)`,
        [controllerId, ssid, normalized, statusLower, owner, device, note]);
      imported++;
    } catch (err) {
      fail('gagal disimpan: ' + err.code);
    }
  }

  await writeAudit(req.session.admin.id, 'rule_import', { imported, failed: errors.length });
  const params = new URLSearchParams({ imported: String(imported) });
  if (errors.length) {
    params.set('skipped', String(errors.length));
    params.set('error', errors.slice(0, 10).join(' | ') + (errors.length > 10 ? ` | (+${errors.length - 10} lainnya)` : ''));
  }
  res.redirect('/rules?' + params.toString());
}));

router.get('/new', wrap(async (req, res) => {
  const controllers = await query('SELECT id, name FROM controllers ORDER BY name');
  res.render('rules/form', { rule: {}, controllers, error: null });
}));

async function saveRule(req, res, id) {
  const controllerId = clean(req.body.controller_id);
  const ssid = clean(req.body.ssid_name);
  const mac = normalizeMac(req.body.mac_address);
  const status = String(clean(req.body.status) || '').toLowerCase();
  const values = [
    controllerId, ssid, mac, status,
    clean(req.body.owner_name), clean(req.body.device_name), clean(req.body.note)
  ];

  const controllers = await query('SELECT id, name FROM controllers ORDER BY name');
  const rerender = error => res.status(400).render('rules/form', {
    rule: { id, controller_id: controllerId, ssid_name: ssid, mac_address: req.body.mac_address, status,
            owner_name: req.body.owner_name, device_name: req.body.device_name, note: req.body.note },
    controllers, error
  });

  if (!ssid) return rerender('SSID wajib diisi.');
  if (!mac) return rerender('MAC address tidak valid. Gunakan 12 karakter hex, contoh aa:bb:cc:dd:ee:ff.');
  if (!STATUSES.includes(status)) return rerender('Status harus allow, deny, atau disabled.');

  try {
    if (id) {
      await query(`UPDATE mac_rules SET controller_id=?, ssid_name=?, mac_address=?, status=?,
        owner_name=?, device_name=?, note=? WHERE id=?`, [...values, id]);
      await writeAudit(req.session.admin.id, 'rule_update', { id, mac, status });
    } else {
      await query(`INSERT INTO mac_rules (controller_id, ssid_name, mac_address, status, owner_name, device_name, note)
        VALUES (?, ?, ?, ?, ?, ?, ?)`, values);
      await writeAudit(req.session.admin.id, 'rule_create', { mac, status });
    }
  } catch (err) {
    if (isDuplicate(err)) return rerender(`Rule untuk ${mac} di SSID ${ssid} pada scope ini sudah ada.`);
    throw err;
  }
  res.redirect('/rules');
}

router.post('/', wrap((req, res) => saveRule(req, res, null)));

router.get('/:id/edit', wrap(async (req, res) => {
  const rules = await query('SELECT * FROM mac_rules WHERE id = ?', [req.params.id]);
  if (!rules.length) return res.redirect('/rules');
  const controllers = await query('SELECT id, name FROM controllers ORDER BY name');
  res.render('rules/form', { rule: rules[0], controllers, error: null });
}));

router.post('/:id', wrap((req, res) => saveRule(req, res, req.params.id)));

router.post('/:id/delete', wrap(async (req, res) => {
  await query('DELETE FROM mac_rules WHERE id = ?', [req.params.id]);
  await writeAudit(req.session.admin.id, 'rule_delete', { id: req.params.id });
  res.redirect('/rules');
}));

module.exports = router;
