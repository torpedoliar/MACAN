const { query } = require('./db');

// Satu "rule grup" disimpan sebagai satu baris mac_rules per anggota grup, bukan
// satu baris yang menunjuk ke grup. Konsekuensinya radius/default.conf tidak
// berubah sama sekali: lookup-nya tetap satu SELECT per (mac_address, ssid_name)
// dan tetap memakai idx_rules_mac_ssid. Harganya: perluasan harus dijalankan
// ulang setiap kali anggota grup berubah — itu tugas syncGroup().
//
// ponytail: perluasan, bukan JOIN saat lookup. Kalau nanti satu grup berisi
// ratusan SSID dan jumlah barisnya jadi masalah, pindahkan ke JOIN ke
// ssid_group_members di dalam SELECT tunggal di radius/default.conf — jangan
// pecah jadi query kedua, komentar di file itu menjelaskan sebabnya.

// Menulis satu rule grup untuk satu (scope, MAC): upsert baris untuk setiap
// anggota, lalu buang baris anggota yang sudah dicabut.
async function applyGroupRule({ groupId, controllerId, mac, status, owner, device, note }) {
  const members = await query('SELECT ssid_name FROM ssid_group_members WHERE group_id = ?', [groupId]);
  for (const m of members) {
    // ON DUPLICATE KEY: kalau MAC itu sudah punya rule manual di SSID tersebut,
    // rule grup mengambil alih barisnya, bukan gagal dengan ER_DUP_ENTRY.
    // inactive_since dibersihkan dengan alasan yang sama seperti di rules.js.
    await query(`INSERT INTO mac_rules
        (controller_id, ssid_name, mac_address, status, owner_name, device_name, note, ssid_group_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE status = VALUES(status), owner_name = VALUES(owner_name),
        device_name = VALUES(device_name), note = VALUES(note),
        ssid_group_id = VALUES(ssid_group_id), inactive_since = NULL`,
      [controllerId, m.ssid_name, mac, status, owner, device, note, groupId]);
  }
  // SSID yang dikeluarkan dari grup harus kehilangan aksesnya juga. Hanya baris
  // hasil perluasan grup ini yang dihapus — rule yang diisi manual punya
  // ssid_group_id NULL dan tidak tersentuh.
  const del = await query(`
    DELETE FROM mac_rules
    WHERE ssid_group_id = ? AND IFNULL(controller_id, 0) = IFNULL(?, 0) AND mac_address = ?
      AND ssid_name NOT IN (SELECT ssid_name FROM ssid_group_members WHERE group_id = ?)
  `, [groupId, controllerId, mac, groupId]);
  return { applied: members.length, removed: del.affectedRows };
}

// Dipanggil setelah anggota grup berubah. Kolom selain ssid_name identik dalam
// satu rule grup, jadi baris ber-id terkecil per (scope, MAC) cukup jadi cetakan.
async function syncGroup(groupId) {
  const rows = await query(
    'SELECT * FROM mac_rules WHERE ssid_group_id = ? ORDER BY id', [groupId]);
  const seen = new Set();
  let macs = 0;
  for (const r of rows) {
    const key = `${r.controller_id === null ? 0 : r.controller_id}|${r.mac_address}`;
    if (seen.has(key)) continue;
    seen.add(key);
    await applyGroupRule({
      groupId, controllerId: r.controller_id, mac: r.mac_address, status: r.status,
      owner: r.owner_name, device: r.device_name, note: r.note
    });
    macs++;
  }
  return macs;
}

module.exports = { applyGroupRule, syncGroup };
