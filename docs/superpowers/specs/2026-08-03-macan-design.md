# MACan Design Spec

**Name:** MACan, MAC Authentication Network

**Goal:** Build a simple container-based UniFi MAC Authentication system with FreeRADIUS, MariaDB, and a Node.js Express admin web UI.

## Scope

MACan manages MAC address access per SSID and per UniFi Controller. Unknown devices are denied by default. Operators can approve devices from rejected auth logs, maintain allow/deny rules, view online devices from accounting, and back up or restore data from the UI.

## Stack

- FreeRADIUS for RADIUS authentication and accounting.
- MariaDB as the single data store.
- Node.js with Express for server-rendered admin UI.
- Docker Compose for deployment.
- Nginx Proxy Manager handles external TLS and reverse proxy.

## Deployment

- Target: one Linux server in the same network segment as UniFi Controller instances.
- Web UI listens on `880/tcp`.
- Optional app HTTPS on `4443/tcp` is not required when Nginx Proxy Manager terminates TLS.
- RADIUS auth listens on `1812/udp`.
- RADIUS accounting listens on `1813/udp`.
- MariaDB is internal only.

## Admin UI

- UI language: Indonesian.
- Theme: light/dark toggle stored in browser `localStorage`; default follows `prefers-color-scheme`.
- Admin model: one global admin account.
- First admin bootstrap can use env values, but operational settings are managed from UI.
- Passwords are stored as hashes.

## Controllers

Operators manage multiple UniFi Controllers from UI.

Controller fields:
- `name`
- `ip_address`
- `shared_secret`
- `enabled`
- `note`

FreeRADIUS reads dynamic clients from MariaDB. Unknown controllers are rejected. Disabled controllers are rejected. Shared secrets are stored in DB and should not be displayed in plain text after save.

## SSID Inventory

SSIDs are tracked per controller for inventory.

Behavior:
- When auth traffic shows a new SSID for a known controller, MACan creates an SSID inventory row for that controller.
- Auto-created SSIDs start as `disabled`.
- Disabled SSIDs deny auth.
- Operators can enable or delete SSIDs.
- Deleting an SSID is blocked while MAC rules exist under that SSID.

## MAC Rules

Unknown devices are denied by default.

Rules can be:
- Global by `ssid_name`, applying to all controllers with that SSID name.
- Controller-specific by `controller_id + ssid_name`.

Lookup order:
1. Controller-specific rule.
2. Global rule.
3. Deny.

Rule fields:
- `controller_id`, nullable for global rule.
- `ssid_name`
- `mac_address`, normalized as lowercase colon format, example `aa:bb:cc:dd:ee:ff`.
- `status`: `allow`, `deny`, or `disabled`.
- `owner_name`
- `device_name`
- `note`
- `last_seen_at`

Rule behavior:
- Same MAC can have different status per SSID.
- Same SSID name can share global rules across locations.
- More specific controller rule wins over global rule.
- `allow` accepts access.
- `deny`, `disabled`, missing rule, disabled SSID, disabled controller, or unknown controller rejects access.

## Device Input

Operators can add rules by:
- Manual form.
- CSV import.
- Pending approval page based on rejected auth logs.

CSV format:

```csv
scope,controller,ssid,mac_address,status,owner_name,device_name,note
global,,Office,AA:BB:CC:DD:EE:FF,allow,Budi,Laptop Budi,Staff
controller,Jakarta,Office,11:22:33:44:55:66,deny,,Unknown device,Blocked
```

CSV import uses upsert:
- New `scope + controller + ssid + mac_address` inserts a rule.
- Existing row updates `status`, `owner_name`, `device_name`, and `note`.
- Invalid rows are reported; valid rows still import.

## Approval

Pending approval is a view over rejected auth logs for devices without an allow rule.

Actions:
- `Allow Cepat`: creates an allow rule with owner/device fields optional.
- `Deny`: creates a deny rule.
- Rules missing `owner_name` or `device_name` show label `Data belum lengkap`.
- UI provides filter for incomplete data.

## Authentication Logging

Every auth attempt is logged with:
- timestamp
- controller
- SSID
- MAC
- result
- reason
- compact raw attributes for troubleshooting

Retention:
- Configurable from UI.
- Default `90` days.
- Purging old auth logs does not clear `last_seen_at`.

## Accounting

MACan accepts RADIUS accounting.

Accounting features:
- Store `Start`, `Stop`, and `Interim-Update`.
- Show “Perangkat Online”.
- Track MAC, SSID, controller, owner, device, start time, last update, and simple duration.
- `Stop` marks offline.
- `Interim-Update` extends online state.
- If `Stop` never arrives, session is considered offline after configurable timeout.
- Default timeout: `120` minutes.

No billing, quota, or complex reporting is in scope.

## Dashboard

Dashboard shows:
- Total controllers.
- Active/inactive SSIDs.
- MAC rules by status.
- Pending approval count.
- Rejects today.
- Auth chart for last 24 hours.
- Top rejected MACs.
- Recent auth attempts.

## Notifications

Notification channels:
- In-app badges.
- Generic HTTP POST JSON webhook.
- Telegram built-in using bot token and chat ID.

Events:
- New MAC pending approval.
- Reject spike from same MAC.
- Disabled or unknown controller attempt.

Reject spike threshold:
- Configurable from UI.
- Default: `5` rejects within `10` minutes.

## Backup And Restore

Backup:
- Manual download from UI.
- Includes full DB dump and metadata with app version and timestamp.
- Action is audited.

Restore:
- UI upload.
- Validate backup format and version.
- Preview timestamp and record counts.
- Require confirmation.
- Create a pre-restore backup automatically.
- Enter maintenance mode during restore.
- During maintenance, admin UI blocks writes and RADIUS fails closed.
- Restore overwrites DB.
- Exit maintenance mode after restore.
- Action is audited.

## Audit Log

Audit log records:
- Login/logout.
- Controller create/update/delete.
- SSID create/update/delete.
- MAC rule create/update/delete.
- CSV import.
- Backup download.
- Restore.
- Settings changes.
- Notification changes.
- Allow/Deny from pending approval.

## Error Handling

- Unknown controller: reject, log, notify if configured.
- Disabled controller: reject, log, notify if configured.
- Disabled SSID: reject, log.
- Missing MAC rule: reject, log, add to pending approval.
- Invalid CSV rows: skip invalid rows, show row-level errors.
- Restore failure: keep pre-restore backup available, leave clear error in UI, audit failure.
- Notification failure: keep app working, show last error in settings.

## Security

- Only expose `880/tcp`, `1812/udp`, and `1813/udp` as needed.
- DB is not exposed externally.
- Reverse proxy handles TLS.
- Controller IPs are explicitly registered.
- Shared secrets are stored server-side and hidden after save.
- Admin session uses secure cookies behind proxy.
- Restore is protected by admin login and confirmation.

## Out Of Scope

- Multi-tenant organizations.
- Billing, vouchers, captive portal, quota.
- Omada support.
- Auto-discover UniFi Controllers.
- Complex role-based access control.
- High availability cluster.
- Public API.
