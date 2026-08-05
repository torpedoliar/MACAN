const https = require('https');
const { query } = require('./db');
const { normalizeMac } = require('./radius-policy');

// UniFi Network Local Application API (integration v1, X-API-KEY). Stateless,
// no cookie/session dance. Endpoint prefix on UniFi OS:
//   https://<host>/proxy/network/integration/v1/...
// Path pattern: /integration/v1/* (the /proxy/network part is the OS reverse
// proxy to the Network app). Sites are UUID-keyed here, not the classic 'default'.
const TIMEOUT = 8000;
const MAX_BYTES = 8 * 1024 * 1024;
const PAGE_LIMIT = 1000;

// GET one JSON endpoint with X-API-KEY. rejectUnauthorized is per-controller:
// UniFi ships a self-signed cert, so verify is opt-in. Never set
// NODE_TLS_REJECT_UNAUTHORIZED=0 — that would also silence the Telegram cert.
function apiGet(host, path, apiKey, verifyTls) {
  return new Promise((resolve, reject) => {
    let base;
    try { base = new URL(host); }
    catch { return reject(new Error('unifi_host URL tidak valid')); }
    if (base.protocol !== 'https:' && base.protocol !== 'http:') {
      return reject(new Error('unifi_host harus http(s)'));
    }
    const full = new URL('/proxy/network/integration/v1' + path, base);
    const isHttps = full.protocol === 'https:';
    const lib = isHttps ? https : require('http');
    const req = lib.request(full, {
      method: 'GET',
      headers: { 'X-API-KEY': apiKey, 'Accept': 'application/json' },
      timeout: TIMEOUT,
      rejectUnauthorized: Boolean(verifyTls)
    }, res => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks = [];
      let size = 0;
      res.on('data', c => {
        size += c.length;
        if (size > MAX_BYTES) { res.destroy(); return reject(new Error('respons melebihi batas ukuran')); }
        chunks.push(c);
      });
      res.on('end', () => {
        const txt = Buffer.concat(chunks).toString('utf8');
        try { resolve(JSON.parse(txt)); }
        catch { reject(new Error('respons bukan JSON valid')); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout setelah 8s')));
    req.on('error', reject);
    req.end();
  });
}

// Fetch all clients across all sites of one controller, upsert MAC->hostname.
// Per-site pagination via offset+limit. Returns {sites, clients}. Throws on
// auth/network failure — caller wraps in try/catch so one offline controller
// doesn't abort the others.
async function syncController(ctrl) {
  if (!ctrl.unifi_host || !ctrl.unifi_api_key) {
    throw new Error('unifi_host atau unifi_api_key kosong');
  }
  const siteWanted = (ctrl.unifi_site || 'default').trim();
  const sites = await apiGet(ctrl.unifi_host, '/sites', ctrl.unifi_api_key, ctrl.unifi_verify_tls);
  const siteList = Array.isArray(sites) ? sites : (sites.data || []);
  // Match by short name (e.g. 'default'); fall back to all sites if none matches,
  // since a mistyped site name is a common config error and syncing nothing is
  // worse than syncing extra.
  let targets = siteList.filter(s => s.name === siteWanted);
  if (!targets.length) targets = siteList;
  if (!targets.length) throw new Error(`tidak ada site di controller (cari: '${siteWanted}')`);

  let synced = 0;
  for (const site of targets) {
    const siteId = site.id || site._id;
    if (!siteId) continue;
    let offset = 0;
    // Cap total pages so a runaway loop can't hammer a misbehaving controller.
    for (let page = 0; page < 100; page++) {
      const res = await apiGet(ctrl.unifi_host, `/sites/${encodeURIComponent(siteId)}/clients?limit=${PAGE_LIMIT}&offset=${offset}`,
        ctrl.unifi_api_key, ctrl.unifi_verify_tls);
      const clients = Array.isArray(res) ? res : (res.data || []);
      // Collect rows with a non-empty hostname: a client without a name carries
      // no identity value, and upserting NULL would overwrite a previously-known
      // hostname when UniFi momentarily returns an empty name (rename, API lag).
      const rows = [];
      for (const c of clients) {
        const mac = normalizeMac(c.macAddress || c.mac || '');
        const hostname = (c.name || c.hostname || '').slice(0, 160);
        if (!mac || !hostname) continue;
        rows.push([ctrl.id, mac, hostname]);
      }
      // Bulk upsert in chunks — 1000 devices = 2 statements, not 1000 round-trips.
      // The per-row INSERT that was here before would contend with RADIUS queries
      // at >1k clients; this keeps the sync off the DB connection for most of it.
      for (let i = 0; i < rows.length; i += 500) {
        const chunk = rows.slice(i, i + 500);
        const values = chunk.map(() => '(?, ?, ?)').join(', ');
        await query(
          `INSERT INTO device_hosts (controller_id, mac_address, hostname) VALUES ${values} ON DUPLICATE KEY UPDATE hostname = VALUES(hostname), last_sync = CURRENT_TIMESTAMP`,
          chunk.flat()
        );
      }
      synced += rows.length;
      if (clients.length < PAGE_LIMIT) break;
      offset += PAGE_LIMIT;
    }
  }
  return { sites: targets.length, clients: synced };
}

// Sync every enabled controller that has UniFi creds. Per-controller try/catch:
// an unreachable controller records its error and moves on, so the rest still
// refresh. Clears unifi_last_error only when all succeed.
async function syncAllControllers() {
  const ctrls = await query(
    "SELECT id, unifi_host, unifi_site, unifi_api_key, unifi_verify_tls FROM controllers WHERE enabled = 1 AND unifi_host IS NOT NULL AND unifi_api_key IS NOT NULL AND unifi_host <> '' AND unifi_api_key <> ''"
  );
  let lastErr = '';
  let ok = 0;
  for (const c of ctrls) {
    try {
      await syncController(c);
      ok++;
    } catch (err) {
      lastErr = `${new Date().toLocaleString('sv-SE')} ${c.unifi_host}: ${err.message}`;
    }
  }
  await query('INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)',
    ['unifi_last_error', lastErr]);
  return { controllers: ctrls.length, ok, error: lastErr };
}

// Single MAC lookup. Used by routes that already have controller_id in scope.
async function getHostname(controllerId, mac) {
  const rows = await query('SELECT hostname FROM device_hosts WHERE controller_id = ? AND mac_address = ?',
    [controllerId, mac]);
  return rows.length ? rows[0].hostname : null;
}

module.exports = { syncController, syncAllControllers, getHostname };
