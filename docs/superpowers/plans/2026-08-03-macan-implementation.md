# MACan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build MACan, a Docker Compose UniFi MAC Authentication system with FreeRADIUS, MariaDB, and a Node.js Express admin UI.

**Architecture:** FreeRADIUS owns RADIUS protocol handling and reads dynamic clients plus auth rules from MariaDB. Express renders Indonesian admin pages and manages controllers, SSIDs, MAC rules, logs, accounting sessions, settings, notifications, backup, and restore. MariaDB is the single data source.

**Tech Stack:** Docker Compose, FreeRADIUS, MariaDB, Node.js, Express, EJS, mysql2, bcrypt, express-session, connect-mysql2, multer, csv-parse, node-cron, chart.js served locally.

## Global Constraints

- Target deployment is one Linux server in the same network segment as UniFi Controller instances.
- Web UI listens on `880/tcp`; Nginx Proxy Manager handles external TLS.
- RADIUS auth listens on `1812/udp`; accounting listens on `1813/udp`.
- MariaDB is internal only.
- Unknown devices are denied by default.
- UI language is Indonesian.
- Unknown or disabled controllers are rejected.
- SSID inventory is per controller; auto-created SSIDs start `disabled`.
- Rules can be global by SSID name or controller-specific; controller-specific rules win.
- Auth log retention default is `90` days.
- Online session timeout default is `120` minutes.
- Reject spike default is `5` rejects within `10` minutes.
- One admin account only.
- No billing, voucher, captive portal, Omada, RBAC, HA, or public API.

---

## File Structure

- `compose.yaml`: app, MariaDB, FreeRADIUS services and ports.
- `.env.example`: required bootstrap values and ports.
- `db/schema.sql`: MariaDB schema, indexes, seed settings.
- `radius/clients.sql`: FreeRADIUS dynamic client query.
- `radius/mods-available/sql`: FreeRADIUS SQL module config.
- `radius/sites-enabled/default`: auth and accounting flow.
- `web/package.json`: Node scripts and dependencies.
- `web/src/app.js`: Express app bootstrap.
- `web/src/db.js`: MariaDB pool and transaction helper.
- `web/src/auth.js`: admin session and password hashing.
- `web/src/radius-policy.js`: MAC normalization, SSID parse, auth decision helpers.
- `web/src/audit.js`: audit writer.
- `web/src/notifications.js`: in-app, webhook, Telegram notification helpers.
- `web/src/maintenance.js`: maintenance mode guard.
- `web/src/routes/*.js`: route modules.
- `web/src/views/*.ejs`: server-rendered UI pages.
- `web/public/app.css`: responsive light/dark UI.
- `web/test/self-check.js`: assert-based checks for non-trivial policy logic.

---

### Task 1: Compose And Database Foundation

**Files:**
- Create: `compose.yaml`
- Create: `.env.example`
- Create: `db/schema.sql`
- Create: `web/package.json`
- Create: `web/src/db.js`

**Interfaces:**
- Produces: MariaDB tables used by every later task.
- Produces: `query(sql, params)` and `transaction(callback)` from `web/src/db.js`.

- [ ] **Step 1: Create Compose services**

```yaml
services:
  db:
    image: mariadb:11
    environment:
      MARIADB_DATABASE: macan
      MARIADB_USER: macan
      MARIADB_PASSWORD: ${DB_PASSWORD}
      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}
    volumes:
      - db_data:/var/lib/mysql
      - ./db/schema.sql:/docker-entrypoint-initdb.d/001-schema.sql:ro
    networks: [internal]

  web:
    build: ./web
    environment:
      DB_HOST: db
      DB_NAME: macan
      DB_USER: macan
      DB_PASSWORD: ${DB_PASSWORD}
      SESSION_SECRET: ${SESSION_SECRET}
      ADMIN_EMAIL: ${ADMIN_EMAIL}
      ADMIN_PASSWORD: ${ADMIN_PASSWORD}
    ports:
      - "880:880"
    depends_on: [db]
    networks: [internal]

  radius:
    image: freeradius/freeradius-server:latest
    ports:
      - "1812:1812/udp"
      - "1813:1813/udp"
    depends_on: [db]
    networks: [internal]

networks:
  internal:

volumes:
  db_data:
```

- [ ] **Step 2: Create env example**

```env
DB_PASSWORD=change-me
DB_ROOT_PASSWORD=change-root
SESSION_SECRET=change-session-secret
ADMIN_EMAIL=admin@example.local
ADMIN_PASSWORD=change-admin-password
```

- [ ] **Step 3: Create schema**

```sql
CREATE TABLE admins (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
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
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_rule_scope (controller_id, ssid_name, mac_address),
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
  event_type ENUM('Start','Stop','Interim-Update') NOT NULL,
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
  details JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_audit_admin FOREIGN KEY (admin_id) REFERENCES admins(id)
);

CREATE TABLE settings (
  name VARCHAR(120) PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT INTO settings (name, value) VALUES
('auth_log_retention_days', '90'),
('online_session_timeout_minutes', '120'),
('reject_spike_count', '5'),
('reject_spike_window_minutes', '10'),
('notification_webhook_url', ''),
('telegram_bot_token', ''),
('telegram_chat_id', ''),
('maintenance_mode', '0');
```

- [ ] **Step 4: Create Node package**

```json
{
  "name": "macan",
  "private": true,
  "scripts": {
    "start": "node src/app.js",
    "self-check": "node test/self-check.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.1",
    "connect-mysql2": "^2.3.0",
    "csv-parse": "^5.5.6",
    "ejs": "^3.1.10",
    "express": "^4.19.2",
    "express-session": "^1.18.0",
    "multer": "^1.4.5-lts.1",
    "mysql2": "^3.11.0",
    "node-cron": "^3.0.3"
  }
}
```

- [ ] **Step 5: Create DB helper**

```js
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'db',
  user: process.env.DB_USER || 'macan',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'macan',
  waitForConnections: true,
  connectionLimit: 10
});

async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

async function transaction(callback) {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const result = await callback(connection);
    await connection.commit();
    return result;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

module.exports = { pool, query, transaction };
```

- [ ] **Step 6: Run schema smoke check**

Run: `docker compose up -d db`

Expected: MariaDB starts and creates tables.

---

### Task 2: Auth Session And App Shell

**Files:**
- Create: `web/src/app.js`
- Create: `web/src/auth.js`
- Create: `web/src/audit.js`
- Create: `web/src/views/layout.ejs`
- Create: `web/src/views/login.ejs`
- Create: `web/public/app.css`

**Interfaces:**
- Consumes: `query` from `web/src/db.js`.
- Produces: `requireAdmin(req, res, next)`.
- Produces: `writeAudit(adminId, action, details)`.

- [ ] **Step 1: Implement admin bootstrap and session guard**

```js
const bcrypt = require('bcrypt');
const { query } = require('./db');

async function ensureAdmin() {
  const rows = await query('SELECT id FROM admins LIMIT 1');
  if (rows.length) return;
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD required for first run');
  const hash = await bcrypt.hash(password, 12);
  await query('INSERT INTO admins (email, password_hash) VALUES (?, ?)', [email, hash]);
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  res.redirect('/login');
}

module.exports = { ensureAdmin, requireAdmin };
```

- [ ] **Step 2: Implement audit helper**

```js
const { query } = require('./db');

async function writeAudit(adminId, action, details = {}) {
  await query('INSERT INTO audit_logs (admin_id, action, details) VALUES (?, ?, ?)', [
    adminId || null,
    action,
    JSON.stringify(details)
  ]);
}

module.exports = { writeAudit };
```

- [ ] **Step 3: Implement Express app**

```js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const { ensureAdmin, requireAdmin } = require('./auth');
const { query } = require('./db');
const { writeAudit } = require('./audit');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
  const rows = await query('SELECT * FROM admins WHERE email = ?', [req.body.email]);
  const admin = rows[0];
  if (!admin || !(await bcrypt.compare(req.body.password || '', admin.password_hash))) {
    return res.status(401).render('login', { error: 'Email atau password salah' });
  }
  req.session.admin = { id: admin.id, email: admin.email };
  await writeAudit(admin.id, 'login', {});
  res.redirect('/');
});
app.post('/logout', requireAdmin, async (req, res) => {
  const adminId = req.session.admin.id;
  req.session.destroy(async () => {
    await writeAudit(adminId, 'logout', {});
    res.redirect('/login');
  });
});
app.get('/', requireAdmin, async (req, res) => res.render('dashboard', { admin: req.session.admin }));

ensureAdmin().then(() => app.listen(880, () => console.log('MACan web listening on 880')));
```

- [ ] **Step 4: Add minimal Indonesian views and CSS**

Use form labels: `Email`, `Password`, `Masuk`, `Keluar`, `Dashboard`.

- [ ] **Step 5: Run app smoke check**

Run: `npm --prefix web start`

Expected: app listens on port `880` and `/login` renders.

---

### Task 3: Radius Policy Helpers With Self-Check

**Files:**
- Create: `web/src/radius-policy.js`
- Create: `web/test/self-check.js`

**Interfaces:**
- Produces: `normalizeMac(value)`.
- Produces: `parseSsid(calledStationId)`.
- Produces: `chooseRule(localRule, globalRule)`.

- [ ] **Step 1: Implement policy helpers**

```js
function normalizeMac(value) {
  const hex = String(value || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g).join(':');
}

function parseSsid(calledStationId) {
  const text = String(calledStationId || '');
  const colon = text.lastIndexOf(':');
  if (colon === -1) return text.trim() || null;
  return text.slice(colon + 1).trim() || null;
}

function chooseRule(localRule, globalRule) {
  const rule = localRule || globalRule || null;
  if (!rule) return { result: 'reject', reason: 'rule tidak ditemukan' };
  if (rule.status === 'allow') return { result: 'accept', reason: 'rule allow' };
  if (rule.status === 'deny') return { result: 'reject', reason: 'rule deny' };
  return { result: 'reject', reason: 'rule disabled' };
}

module.exports = { normalizeMac, parseSsid, chooseRule };
```

- [ ] **Step 2: Add assert self-check**

```js
const assert = require('assert');
const { normalizeMac, parseSsid, chooseRule } = require('../src/radius-policy');

assert.equal(normalizeMac('AA-BB-CC-DD-EE-FF'), 'aa:bb:cc:dd:ee:ff');
assert.equal(normalizeMac('bad'), null);
assert.equal(parseSsid('aa:bb:cc:dd:ee:ff:Office'), 'Office');
assert.deepEqual(chooseRule({ status: 'deny' }, { status: 'allow' }), { result: 'reject', reason: 'rule deny' });
assert.deepEqual(chooseRule(null, { status: 'allow' }), { result: 'accept', reason: 'rule allow' });
assert.deepEqual(chooseRule(null, null), { result: 'reject', reason: 'rule tidak ditemukan' });

console.log('self-check passed');
```

- [ ] **Step 3: Run self-check**

Run: `npm --prefix web run self-check`

Expected: `self-check passed`.

---

### Task 4: Controller, SSID, Rule, And Settings UI

**Files:**
- Create: `web/src/routes/controllers.js`
- Create: `web/src/routes/ssids.js`
- Create: `web/src/routes/rules.js`
- Create: `web/src/routes/settings.js`
- Create: matching EJS views in `web/src/views/`

**Interfaces:**
- Consumes: `requireAdmin`, `query`, `transaction`, `writeAudit`, `normalizeMac`.
- Produces: CRUD pages used by operators.

- [ ] **Step 1: Register routes in `app.js`**

```js
app.use('/controllers', requireAdmin, require('./routes/controllers'));
app.use('/ssids', requireAdmin, require('./routes/ssids'));
app.use('/rules', requireAdmin, require('./routes/rules'));
app.use('/settings', requireAdmin, require('./routes/settings'));
```

- [ ] **Step 2: Implement controller CRUD**

Routes:
- `GET /controllers`
- `GET /controllers/new`
- `POST /controllers`
- `GET /controllers/:id/edit`
- `POST /controllers/:id`
- `POST /controllers/:id/delete`

Validation:
- `name`, `ip_address`, and `shared_secret` required on create.
- `shared_secret` optional on edit; empty keeps old value.
- Delete blocked if SSIDs or rules reference controller.

- [ ] **Step 3: Implement SSID inventory UI**

Routes:
- `GET /ssids`
- `POST /ssids/:id/toggle`
- `POST /ssids/:id/delete`

Delete SQL must fail when rule exists:

```sql
SELECT COUNT(*) AS count FROM mac_rules WHERE controller_id = ? AND ssid_name = ?;
```

If count is not zero, show `SSID masih memiliki rule MAC`.

- [ ] **Step 4: Implement MAC rules UI**

Routes:
- `GET /rules`
- `GET /rules/new`
- `POST /rules`
- `GET /rules/:id/edit`
- `POST /rules/:id`
- `POST /rules/:id/delete`

Rule creation normalizes MAC and validates status in `allow`, `deny`, `disabled`.

- [ ] **Step 5: Implement settings UI**

Settings fields:
- `auth_log_retention_days`
- `online_session_timeout_minutes`
- `reject_spike_count`
- `reject_spike_window_minutes`
- `notification_webhook_url`
- `telegram_bot_token`
- `telegram_chat_id`

Use numeric validation for integer settings. Audit every update.

- [ ] **Step 6: Manual browser check**

Run: `docker compose up -d db && npm --prefix web start`

Expected: admin can create controller, see SSID list, create global rule, create controller rule, and update settings.

---

### Task 5: RADIUS Integration

**Files:**
- Create: `radius/mods-available/sql`
- Create: `radius/sites-enabled/default`
- Create: `radius/queries.conf`
- Modify: `compose.yaml`

**Interfaces:**
- Consumes: DB tables `controllers`, `ssids`, `mac_rules`, `auth_logs`, `accounting_logs`, `sessions`, `settings`.
- Produces: FreeRADIUS auth accept/reject and accounting writes.

- [ ] **Step 1: Mount FreeRADIUS config**

Add to radius service:

```yaml
    volumes:
      - ./radius:/etc/freeradius
```

- [ ] **Step 2: Configure SQL module**

Use MariaDB connection:

```text
driver = "rlm_sql_mysql"
server = "db"
port = 3306
login = "macan"
password = "${DB_PASSWORD}"
radius_db = "macan"
```

- [ ] **Step 3: Configure dynamic clients query**

Query:

```sql
SELECT id, ip_address AS nasname, shared_secret AS secret, 'other' AS type
FROM controllers
WHERE enabled = TRUE
```

- [ ] **Step 4: Configure authorize logic**

Policy must:
- Normalize `Calling-Station-Id`.
- Parse SSID from `Called-Station-Id`.
- Ensure controller exists and enabled.
- Upsert SSID inventory as disabled when first seen.
- Reject if SSID disabled.
- Check local rule, then global rule.
- Accept only status `allow`.
- Insert `auth_logs`.

- [ ] **Step 5: Configure accounting logic**

Accounting must:
- Insert `accounting_logs`.
- Upsert `sessions` on `Start` and `Interim-Update`.
- Set `stopped_at` on `Stop`.
- Update matching `mac_rules.last_seen_at`.

- [ ] **Step 6: Test with `radtest`**

Run:

```bash
radtest aa:bb:cc:dd:ee:ff aa:bb:cc:dd:ee:ff 127.0.0.1 0 secret
```

Expected before rule: Access-Reject.

Expected after allow rule: Access-Accept.

---

### Task 6: Logs, Dashboard, Approval, And Online Devices

**Files:**
- Create: `web/src/routes/dashboard.js`
- Create: `web/src/routes/auth-logs.js`
- Create: `web/src/routes/approval.js`
- Create: `web/src/routes/accounting.js`
- Create: related EJS views

**Interfaces:**
- Consumes: existing DB tables and helpers.
- Produces: operator workflow pages.

- [ ] **Step 1: Dashboard queries**

Show:
- total controllers
- active/inactive SSIDs
- MAC rules by status
- pending approval count
- rejects today
- hourly auth count last 24 hours
- top rejected MACs
- recent auth attempts

- [ ] **Step 2: Auth log page**

Filters:
- date range
- result
- SSID
- MAC
- controller

- [ ] **Step 3: Pending approval page**

Query rejects where no allow rule exists for local or global scope. Actions:
- `Allow Cepat`
- `Deny`

`Allow Cepat` creates a rule with empty owner/device allowed and writes audit.

- [ ] **Step 4: Online devices page**

Query sessions where `stopped_at IS NULL` and `last_update_at` is within configured timeout. Show duration as `NOW() - started_at`.

- [ ] **Step 5: Manual workflow check**

Expected:
- rejected unknown device appears in pending approval.
- `Allow Cepat` creates rule.
- incomplete owner/device label appears.
- accounting Start shows device online.
- Stop removes online status.

---

### Task 7: CSV Import, Backup, Restore, Notifications, And Retention

**Files:**
- Create: `web/src/routes/import.js`
- Create: `web/src/routes/backup.js`
- Create: `web/src/notifications.js`
- Create: `web/src/maintenance.js`
- Modify: `web/src/app.js`

**Interfaces:**
- Consumes: settings and core tables.
- Produces: CSV import, manual backup/restore, notification senders, cleanup job.

- [ ] **Step 1: CSV import route**

CSV columns:

```csv
scope,controller,ssid,mac_address,status,owner_name,device_name,note
```

Behavior:
- `scope=global` requires empty `controller`.
- `scope=controller` requires existing controller name.
- `status` must be `allow`, `deny`, or `disabled`.
- Valid rows upsert.
- Invalid rows are listed after import.

- [ ] **Step 2: Backup download**

Use `mysqldump` from container or MariaDB client image. Include metadata JSON:

```json
{
  "app": "MACan",
  "backup_version": 1,
  "created_at": "ISO-8601 timestamp"
}
```

Audit `backup_download`.

- [ ] **Step 3: Restore UI**

Flow:
- Upload backup.
- Validate metadata says `app=MACan` and `backup_version=1`.
- Show preview.
- On confirm, set `maintenance_mode=1`.
- Create pre-restore backup.
- Restore DB.
- Set `maintenance_mode=0`.
- Audit success or failure.

- [ ] **Step 4: Maintenance guard**

Admin UI:
- Blocks write routes while maintenance is on, except restore completion.

RADIUS:
- Reads `maintenance_mode`.
- Rejects auth while value is `1`.

- [ ] **Step 5: Notification sender**

Implement:
- Generic webhook POST JSON.
- Telegram `sendMessage`.
- Last error shown in settings.

Events:
- pending approval created.
- reject spike threshold crossed.
- disabled or unknown controller attempt.

- [ ] **Step 6: Retention cron**

Daily task:

```sql
DELETE FROM auth_logs
WHERE created_at < NOW() - INTERVAL ? DAY;
```

Use `auth_log_retention_days` from settings.

- [ ] **Step 7: Final system check**

Run:

```bash
docker compose up --build
npm --prefix web run self-check
```

Expected:
- web available on `880`.
- DB internal only.
- RADIUS ports `1812/udp` and `1813/udp` published.
- unknown MAC rejects.
- allow rule accepts.
- accounting updates online devices.
- backup downloads.
- restore enters and exits maintenance.

---

## Self-Review

- Spec coverage: controllers, SSID inventory, global/local rules, default deny, auth/accounting logs, online devices, dashboard, approval, notifications, backup/restore, audit, settings, deployment, and security are covered by tasks.
- Placeholder scan: plan contains concrete values, paths, commands, and code blocks for each task.
- Type consistency: helpers are named once and consumed with matching names.
