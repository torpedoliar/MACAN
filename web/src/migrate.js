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

  // 4. Settings added after first boot.
  const defaults = {
    auth_log_retention_days: '90',
    online_session_timeout_minutes: '120',
    reject_spike_count: '5',
    reject_spike_window_minutes: '10',
    notification_webhook_url: '',
    telegram_bot_token: '',
    telegram_chat_id: '',
    notification_dedupe_minutes: '60',
    notification_last_error: '',
    maintenance_mode: '0'
  };
  for (const [name, value] of Object.entries(defaults)) {
    await query('INSERT IGNORE INTO settings (name, value) VALUES (?, ?)', [name, value]);
  }
}

module.exports = { migrate };
