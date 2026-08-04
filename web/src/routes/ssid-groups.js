const express = require('express');
const { query } = require('../db');
const { writeAudit } = require('../audit');
const { wrap } = require('../middleware');
const { syncGroup } = require('../ssid-groups');
const router = express.Router();

const clean = v => {
  const s = String(v === undefined || v === null ? '' : v).trim();
  return s === '' ? null : s;
};

router.get('/', wrap(async (req, res) => {
  const groups = await query(`
    SELECT g.*,
      (SELECT COUNT(*) FROM ssid_group_members m WHERE m.group_id = g.id) AS member_count,
      (SELECT COUNT(*) FROM mac_rules r WHERE r.ssid_group_id = g.id) AS rule_count,
      (SELECT GROUP_CONCAT(m.ssid_name ORDER BY m.ssid_name SEPARATOR ', ')
         FROM ssid_group_members m WHERE m.group_id = g.id) AS members
    FROM ssid_groups g ORDER BY g.name
  `);
  // Nama SSID yang sudah dikenal, dari inventaris mana pun controllernya: anggota
  // grup disimpan sebagai nama, bukan FK, jadi duplikat antar controller dilebur.
  const known = await query('SELECT DISTINCT ssid_name FROM ssids ORDER BY ssid_name');
  res.render('ssid-groups/index', {
    groups, known,
    error: req.query.error,
    notice: req.query.notice
  });
}));

router.post('/', wrap(async (req, res) => {
  const name = clean(req.body.name);
  if (!name) return res.redirect('/ssid-groups?error=' + encodeURIComponent('Nama grup wajib diisi.'));
  try {
    const result = await query('INSERT INTO ssid_groups (name, note) VALUES (?, ?)', [name, clean(req.body.note)]);
    await writeAudit(req.session.admin.id, 'ssid_group_create', { id: result.insertId, name });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.redirect('/ssid-groups?error=' + encodeURIComponent(`Grup "${name}" sudah ada.`));
    }
    throw err;
  }
  res.redirect('/ssid-groups?notice=' + encodeURIComponent(`Grup "${name}" dibuat. Pilih anggota SSID-nya.`));
}));

// Anggota diganti seluruhnya, bukan ditambah satu-satu: form mengirim daftar
// lengkap centangan, jadi menghapus centang harus berarti mencabut anggota.
router.post('/:id/members', wrap(async (req, res) => {
  const groups = await query('SELECT * FROM ssid_groups WHERE id = ?', [req.params.id]);
  if (!groups.length) return res.redirect('/ssid-groups?error=' + encodeURIComponent('Grup tidak ditemukan.'));
  const group = groups[0];

  // Satu checkbox tercentang datang sebagai string, banyak sebagai array.
  const raw = req.body.ssid_name === undefined ? [] : [].concat(req.body.ssid_name);
  const names = [...new Set(raw.map(clean).filter(Boolean).map(s => s.slice(0, 128)))];

  await query('DELETE FROM ssid_group_members WHERE group_id = ?', [group.id]);
  for (const name of names) {
    await query('INSERT INTO ssid_group_members (group_id, ssid_name) VALUES (?, ?)', [group.id, name]);
  }
  // Rule yang menargetkan grup ini sudah tersebar sebagai baris per SSID, jadi
  // perubahan anggota harus diperluas ulang sekarang — kalau tidak, MAC-nya tetap
  // bisa masuk ke SSID yang baru dicabut.
  const macs = await syncGroup(group.id);
  await writeAudit(req.session.admin.id, 'ssid_group_members', { id: group.id, members: names.length, macs });
  res.redirect('/ssid-groups?notice=' + encodeURIComponent(
    `Grup "${group.name}": ${names.length} SSID, ${macs} MAC diperbarui.`
  ));
}));

router.post('/:id/delete', wrap(async (req, res) => {
  const groups = await query('SELECT * FROM ssid_groups WHERE id = ?', [req.params.id]);
  if (!groups.length) return res.redirect('/ssid-groups');
  // fk_rules_group ON DELETE SET NULL: baris rule-nya tetap hidup, hanya kehilangan
  // jejak asal. Menghapus grup tidak boleh mencabut akses MAC yang sedang jalan.
  const rows = await query('SELECT COUNT(*) AS count FROM mac_rules WHERE ssid_group_id = ?', [req.params.id]);
  await query('DELETE FROM ssid_groups WHERE id = ?', [req.params.id]);
  await writeAudit(req.session.admin.id, 'ssid_group_delete', { id: req.params.id, orphaned_rules: rows[0].count });
  res.redirect('/ssid-groups?notice=' + encodeURIComponent(
    `Grup "${groups[0].name}" dihapus. ${rows[0].count} rule tetap berlaku, sekarang berdiri sendiri.`
  ));
}));

module.exports = router;
