// db/schema.sql only runs on an empty volume, so every schema change after the
// first boot has to land here. MariaDB's "IF NOT EXISTS" DDL makes each step
// idempotent — running this on every boot is a no-op once applied.
const { query, raw } = require('./db');

async function migrate() {
  // 1. Global rules (controller_id IS NULL) were never deduped: NULLs compare as
  //    distinct in a UNIQUE key. Collapse existing dupes, then key on IFNULL(...,0).
  await raw(`
    DELETE r FROM mac_rules r
    JOIN mac_rules keep
      ON IFNULL(keep.controller_id, 0) = IFNULL(r.controller_id, 0)
     AND keep.ssid_name = r.ssid_name
     AND keep.mac_address = r.mac_address
     AND keep.id < r.id
  `);
  // MariaDB puts column attributes after the generated-column clause; NOT NULL
  // before AS is a syntax error. IFNULL can't return NULL, so the constraint
  // would be redundant anyway.
  await raw('ALTER TABLE mac_rules ADD COLUMN IF NOT EXISTS scope_key BIGINT AS (IFNULL(controller_id, 0)) STORED');
  await raw('ALTER TABLE mac_rules ADD UNIQUE KEY IF NOT EXISTS uniq_rule_scope_key (scope_key, ssid_name, mac_address)');
  // The old UNIQUE (controller_id, …) is what the FK indexes on; MariaDB refuses
  // to drop it until another index leads with controller_id. Add that first, then
  // drop. Order matters — the reverse fails with ER_DROP_INDEX_FK (1553).
  await raw('ALTER TABLE mac_rules ADD KEY IF NOT EXISTS idx_rules_controller (controller_id)');
  await raw('ALTER TABLE mac_rules DROP INDEX IF EXISTS uniq_rule_scope');

  // 2. Accounting-On/Off arrive on controller reboot and were silently dropped.
  await raw(`ALTER TABLE accounting_logs MODIFY event_type
    ENUM('Start','Stop','Interim-Update','Accounting-On','Accounting-Off','Failed') NOT NULL`);

  // 3. Persistent session store + alert dedupe.
  await raw(`CREATE TABLE IF NOT EXISTS admin_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    expires INT UNSIGNED NOT NULL,
    data MEDIUMTEXT NULL
  )`);
  await raw(`CREATE TABLE IF NOT EXISTS notification_log (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_key VARCHAR(255) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_notif_key (event_key, sent_at)
  )`);

  // 4. Who acted from where. Existing rows keep NULL — the information was never
  //    captured, and inventing it would be worse than admitting the gap.
  await raw('ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45) NULL AFTER action');

  // 5. Inactivity audit: a MAC unseen for N days is flipped to deny and stamped
  //    here. Deliberately NOT a 4th `status` ENUM value — default.conf compares
  //    Tmp-String-2 against the literals allow/deny/disabled, so a fifth value
  //    falls into its else branch, gets logged as "rule tidak ditemukan", and the
  //    MAC reappears in Approvals as if it had never been registered.
  await raw('ALTER TABLE mac_rules ADD COLUMN IF NOT EXISTS inactive_since TIMESTAMP NULL AFTER last_seen_at');
  await raw('ALTER TABLE mac_rules ADD KEY IF NOT EXISTS idx_rules_last_seen (last_seen_at)');

  // 6. Per-admin accounts. Revoking access is a flag — until step 15 made
  //    deletion viable (admin_id is nullable, FK is ON DELETE SET NULL),
  //    disabling was the only way to revoke an admin with audit history.
  await raw('ALTER TABLE admins ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE AFTER password_hash');

  // 7. Rule lookup index. Every Access-Request runs
  //      SELECT status FROM mac_rules WHERE mac_address = ? AND ssid_name = ? AND (...)
  //    and no existing key serves it: uniq_rule_scope_key leads with scope_key,
  //    which is absent from that WHERE, so MariaDB used idx_rules_controller and
  //    scanned every row of the controller (EXPLAIN: ref_or_null, rows≈50k of 200k).
  //    Measured on seeded data — lookup at 500k rules: 270ms without, 0.33ms with;
  //    the last_seen_at UPDATE in the same policy drops to 0.25ms.
  await raw('ALTER TABLE mac_rules ADD KEY IF NOT EXISTS idx_rules_mac_ssid (mac_address, ssid_name)');

  // 8. Settings added after first boot.
  const defaults = {
    auth_log_retention_days: '90',
    online_session_timeout_minutes: '120',
    inactive_after_days: '90',
    reject_spike_count: '5',
    reject_spike_window_minutes: '10',
    notification_webhook_url: '',
    telegram_bot_token: '',
    telegram_chat_id: '',
    notification_dedupe_minutes: '60',
    notification_last_error: '',
    maintenance_mode: '0',
    oui_last_refresh: '',
    unifi_sync_enabled: '0',
    unifi_last_error: ''
  };
  for (const [name, value] of Object.entries(defaults)) {
    await query('INSERT IGNORE INTO settings (name, value) VALUES (?, ?)', [name, value]);
  }

  // 10. Custom application logo. Stored as base64 in settings (rides backup for
  //    free; no volume mount needed). TEXT caps ~48KB binary after base64, too
  //    tight for a 2MB upload — widen value to MEDIUMTEXT (16MB). Idempotent.
  await raw('ALTER TABLE settings MODIFY COLUMN value MEDIUMTEXT NOT NULL');

  // 11. OUI vendor lookup table — refetchable reference data, excluded from
  //     backup. Monthly refresh from IEEE; guard oui_last_refresh prevents a
  //     redownload on every boot (runCron fires once at require time).
  await raw(`CREATE TABLE IF NOT EXISTS oui_vendors (
    oui CHAR(6) PRIMARY KEY,
    vendor VARCHAR(160) NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )`);

  // 12. UniFi hostname cache. Additive to mac_rules identity — operators type
  //     owner_name/device_name deliberately; this is machine-derived. PK on
  //     controller+MAC so a device on two controllers keeps both rows.
  await raw(`CREATE TABLE IF NOT EXISTS device_hosts (
    controller_id BIGINT NOT NULL,
    mac_address CHAR(17) NOT NULL,
    hostname VARCHAR(160) NULL,
    last_sync TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (controller_id, mac_address),
    KEY idx_device_hosts_mac (mac_address),
    CONSTRAINT fk_device_hosts_controller FOREIGN KEY (controller_id) REFERENCES controllers(id) ON DELETE CASCADE
  )`);

  // 13. UniFi Controller REST API credentials. ip_address is the RADIUS source
  //     (often a CIDR of APs), not the API host, so it can't be reused. API key
  //     is plaintext — FreeRADIUS reads shared_secret the same way; masking is
  //     at the UI layer only.
  await raw('ALTER TABLE controllers ADD COLUMN IF NOT EXISTS unifi_host VARCHAR(255) NULL AFTER note');
  await raw("ALTER TABLE controllers ADD COLUMN IF NOT EXISTS unifi_site VARCHAR(64) NULL DEFAULT 'default' AFTER unifi_host");
  await raw('ALTER TABLE controllers ADD COLUMN IF NOT EXISTS unifi_api_key VARCHAR(255) NULL AFTER unifi_site');
  await raw('ALTER TABLE controllers ADD COLUMN IF NOT EXISTS unifi_verify_tls BOOLEAN NOT NULL DEFAULT FALSE AFTER unifi_api_key');

  // 14. Classic API (cookie login UniFi) untuk ambil semua configured client
  //     (offline included). Integration v1 (X-API-KEY) cuma return online.
  await raw('ALTER TABLE controllers ADD COLUMN IF NOT EXISTS unifi_username VARCHAR(160) NULL AFTER unifi_verify_tls');
  await raw('ALTER TABLE controllers ADD COLUMN IF NOT EXISTS unifi_password VARCHAR(255) NULL AFTER unifi_username');

  // 15. Deleting an admin account. The old FK refused it once the account had
  //     audit history, so revoking access could only be a disable flag. admin_id
  //     is already nullable, so the deletion now propagates to audit_logs via
  //     SET NULL — the log survives as "deleted admin", and the UI can delete.
  //     Db/schema.sql:151 says "Does MariaDB support DROP FOREIGN KEY IF EXISTS?"
  //     — yes, since 10.x / it's the same family the dump targets.
  await raw('ALTER TABLE audit_logs DROP FOREIGN KEY IF EXISTS fk_audit_admin');
  await raw('ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_admin FOREIGN KEY IF NOT EXISTS (admin_id) REFERENCES admins(id) ON DELETE SET NULL');

  // 9. Grup SSID. Rule yang menargetkan grup tetap disimpan sebagai satu baris
  //    mac_rules per anggota grup, jadi radius/default.conf tidak berubah sama
  //    sekali: lookup-nya tetap satu SELECT per (mac_address, ssid_name) dan tetap
  //    memakai idx_rules_mac_ssid. ssid_group_id hanya penanda asal — dipakai untuk
  //    memperluas ulang saat anggota grup berubah dan untuk hapus massal.
  await raw(`CREATE TABLE IF NOT EXISTS ssid_groups (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(120) NOT NULL UNIQUE,
    note TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  // Anggota adalah nama SSID, bukan FK ke ssids.id: ssids per controller, rule
  // bisa global, dan nama itulah yang dipakai mac_rules.
  await raw(`CREATE TABLE IF NOT EXISTS ssid_group_members (
    group_id BIGINT NOT NULL,
    ssid_name VARCHAR(128) NOT NULL,
    PRIMARY KEY (group_id, ssid_name),
    CONSTRAINT fk_group_members_group FOREIGN KEY (group_id) REFERENCES ssid_groups(id) ON DELETE CASCADE
  )`);
  await raw('ALTER TABLE mac_rules ADD COLUMN IF NOT EXISTS ssid_group_id BIGINT NULL AFTER note');
  await raw('ALTER TABLE mac_rules ADD KEY IF NOT EXISTS idx_rules_group (ssid_group_id)');
  // SET NULL, bukan CASCADE: menghapus grup tidak boleh ikut mencabut akses MAC
  // yang sudah berjalan. Barisnya tetap, hanya kehilangan jejak asalnya.
  // IF NOT EXISTS menempel pada FOREIGN KEY, bukan pada ADD CONSTRAINT — MariaDB
  // menolak "ADD CONSTRAINT IF NOT EXISTS nama" dengan ER_PARSE_ERROR.
  await raw(`ALTER TABLE mac_rules ADD CONSTRAINT fk_rules_group
    FOREIGN KEY IF NOT EXISTS (ssid_group_id) REFERENCES ssid_groups(id) ON DELETE SET NULL`);
}

module.exports = { migrate };
