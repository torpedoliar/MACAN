CREATE TABLE admins (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  -- Disabling beats deleting: audit_logs.fk_audit_admin blocks removing an
  -- account that has history, so revoking access has to be a flag.
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE controllers (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(120) NOT NULL,
  ip_address VARCHAR(45) NOT NULL UNIQUE,
  shared_secret VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  note TEXT NULL,
  -- UniFi Controller REST API (integration v1, X-API-KEY). ip_address is the
  -- RADIUS source (often a CIDR of APs), not the API host, so it can't be reused.
  unifi_host VARCHAR(255) NULL,
  unifi_site VARCHAR(64) NULL DEFAULT 'default',
  unifi_api_key VARCHAR(255) NULL,
  unifi_verify_tls BOOLEAN NOT NULL DEFAULT FALSE,
  -- Classic API (cookie login) untuk ambil semua configured client (offline
  -- included). Integration v1 (X-API-KEY) cuma return online. User/pass UniFi
  -- disimpan plaintext — sama kayak unifi_api_key/shared_secret, masking di UI.
  unifi_username VARCHAR(160) NULL,
  unifi_password VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE ssids (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  controller_id BIGINT NOT NULL,
  ssid_name VARCHAR(128) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  auto_created BOOLEAN NOT NULL DEFAULT TRUE,
  last_seen_at TIMESTAMP NULL,
  UNIQUE KEY uniq_ssid_controller_name (controller_id, ssid_name),
  CONSTRAINT fk_ssids_controller FOREIGN KEY (controller_id) REFERENCES controllers(id)
);

-- Sekumpulan SSID yang diperlakukan sama. Rule MAC yang menargetkan grup
-- diperluas menjadi satu baris mac_rules per anggota, jadi FreeRADIUS tetap
-- membaca satu baris per (MAC, SSID) dan default.conf tidak perlu tahu soal grup.
CREATE TABLE ssid_groups (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(120) NOT NULL UNIQUE,
  note TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Anggota disimpan sebagai nama SSID, bukan FK ke ssids.id: ssids bersifat per
-- controller sementara rule bisa global, jadi nama adalah satu-satunya kunci
-- yang dipakai mac_rules juga.
CREATE TABLE ssid_group_members (
  group_id BIGINT NOT NULL,
  ssid_name VARCHAR(128) NOT NULL,
  PRIMARY KEY (group_id, ssid_name),
  CONSTRAINT fk_group_members_group FOREIGN KEY (group_id) REFERENCES ssid_groups(id) ON DELETE CASCADE
);

CREATE TABLE mac_rules (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  controller_id BIGINT NULL,
  ssid_name VARCHAR(128) NOT NULL,
  mac_address CHAR(17) NOT NULL,
  status ENUM('allow','deny','disabled') NOT NULL,
  owner_name VARCHAR(160) NULL,
  device_name VARCHAR(160) NULL,
  note TEXT NULL,
  -- Penanda asal: baris ini hasil perluasan grup SSID, bukan diisi satu per satu.
  -- FreeRADIUS tidak pernah membacanya — gunanya hanya untuk memperluas ulang
  -- ketika anggota grup berubah, dan untuk menampilkan asalnya di panel.
  ssid_group_id BIGINT NULL,
  last_seen_at TIMESTAMP NULL,
  -- Stamped by cron when last_seen_at falls past inactive_after_days. A marker
  -- column, not a 4th status value: FreeRADIUS compares status to the literals
  -- allow/deny/disabled and treats anything else as "no rule found".
  inactive_since TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  -- NULL controller_id would make UNIQUE non-enforcing (NULLs compare distinct),
  -- so dedupe on a 0-coalesced generated column instead.
  scope_key BIGINT AS (IFNULL(controller_id, 0)) STORED,
  UNIQUE KEY uniq_rule_scope_key (scope_key, ssid_name, mac_address),
  KEY idx_rules_controller (controller_id),
  KEY idx_rules_last_seen (last_seen_at),
  -- The one index every Access-Request depends on. default.conf looks a rule up by
  -- mac_address + ssid_name; uniq_rule_scope_key can't serve that because its
  -- leading column (scope_key) isn't in the WHERE. Without this key MariaDB falls
  -- back to idx_rules_controller and scans every row belonging to the controller:
  -- measured 0.33ms vs 270ms at 500k rules.
  KEY idx_rules_mac_ssid (mac_address, ssid_name),
  KEY idx_rules_group (ssid_group_id),
  CONSTRAINT fk_rules_controller FOREIGN KEY (controller_id) REFERENCES controllers(id),
  -- SET NULL, bukan CASCADE: menghapus grup tidak boleh ikut mencabut akses MAC
  -- yang sudah berjalan. Barisnya tetap, hanya kehilangan jejak asalnya.
  CONSTRAINT fk_rules_group FOREIGN KEY (ssid_group_id) REFERENCES ssid_groups(id) ON DELETE SET NULL
);

CREATE TABLE auth_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  controller_id BIGINT NULL,
  ssid_name VARCHAR(128) NULL,
  mac_address CHAR(17) NULL,
  result ENUM('accept','reject') NOT NULL,
  reason VARCHAR(255) NOT NULL,
  raw_attrs JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_auth_created (created_at),
  KEY idx_auth_pending (result, ssid_name, mac_address),
  CONSTRAINT fk_auth_controller FOREIGN KEY (controller_id) REFERENCES controllers(id)
);

CREATE TABLE accounting_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  controller_id BIGINT NULL,
  ssid_name VARCHAR(128) NULL,
  mac_address CHAR(17) NULL,
  session_id VARCHAR(255) NULL,
  event_type ENUM('Start','Stop','Interim-Update','Accounting-On','Accounting-Off','Failed') NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_acct_session (session_id),
  CONSTRAINT fk_acct_controller FOREIGN KEY (controller_id) REFERENCES controllers(id)
);

CREATE TABLE sessions (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  controller_id BIGINT NULL,
  ssid_name VARCHAR(128) NULL,
  mac_address CHAR(17) NOT NULL,
  session_id VARCHAR(255) NOT NULL,
  started_at TIMESTAMP NOT NULL,
  last_update_at TIMESTAMP NOT NULL,
  stopped_at TIMESTAMP NULL,
  UNIQUE KEY uniq_session (session_id),
  CONSTRAINT fk_sessions_controller FOREIGN KEY (controller_id) REFERENCES controllers(id)
);

CREATE TABLE audit_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  admin_id BIGINT NULL,
  action VARCHAR(120) NOT NULL,
  ip_address VARCHAR(45) NULL,
  details JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_audit_admin FOREIGN KEY (admin_id) REFERENCES admins(id)
);

CREATE TABLE settings (
  name VARCHAR(120) PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- express-mysql-session manages its own rows; we pre-create so the app can run
-- with a DB user that has no CREATE privilege.
CREATE TABLE admin_sessions (
  session_id VARCHAR(128) PRIMARY KEY,
  expires INT UNSIGNED NOT NULL,
  data MEDIUMTEXT NULL
);

-- Suppresses duplicate alerts across cron ticks.
CREATE TABLE notification_log (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  event_key VARCHAR(255) NOT NULL,
  channel VARCHAR(32) NOT NULL,
  sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_notif_key (event_key, sent_at)
);

-- OUI vendor lookup. 6-hex prefix (no separator) -> vendor name. Refreshed
-- monthly from the IEEE OUI file; refetchable reference data, excluded from
-- backup so it doesn't bloat every export by megabytes.
CREATE TABLE oui_vendors (
  oui CHAR(6) PRIMARY KEY,
  vendor VARCHAR(160) NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Hostname cache from UniFi Controller API. Additive — never overwrites
-- mac_rules.owner_name/device_name (operator-typed). PK on controller+MAC so a
-- device seen on two controllers keeps both rows; FK CASCADE so deleting a
-- controller clears its stale hostnames.
CREATE TABLE device_hosts (
  controller_id BIGINT NOT NULL,
  mac_address CHAR(17) NOT NULL,
  hostname VARCHAR(160) NULL,
  last_sync TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (controller_id, mac_address),
  KEY idx_device_hosts_mac (mac_address),
  CONSTRAINT fk_device_hosts_controller FOREIGN KEY (controller_id) REFERENCES controllers(id) ON DELETE CASCADE
);

INSERT INTO settings (name, value) VALUES
('auth_log_retention_days', '90'),
('online_session_timeout_minutes', '120'),
('inactive_after_days', '90'),
('reject_spike_count', '5'),
('reject_spike_window_minutes', '10'),
('notification_webhook_url', ''),
('telegram_bot_token', ''),
('telegram_chat_id', ''),
('notification_dedupe_minutes', '60'),
('notification_last_error', ''),
('maintenance_mode', '0'),
('oui_last_refresh', ''),
('unifi_sync_enabled', '0'),
('unifi_last_error', '');
