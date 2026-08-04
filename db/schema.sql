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

CREATE TABLE mac_rules (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  controller_id BIGINT NULL,
  ssid_name VARCHAR(128) NOT NULL,
  mac_address CHAR(17) NOT NULL,
  status ENUM('allow','deny','disabled') NOT NULL,
  owner_name VARCHAR(160) NULL,
  device_name VARCHAR(160) NULL,
  note TEXT NULL,
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
  CONSTRAINT fk_rules_controller FOREIGN KEY (controller_id) REFERENCES controllers(id)
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
('maintenance_mode', '0');
