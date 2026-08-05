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
async function syncController(ctrl, known) {
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

  let synced = 0, skipped = 0, unknown = 0;
  for (const site of targets) {
    const siteId = site.id || site._id;
    if (!siteId) continue;
    let offset = 0;
    let fetched = 0, withName = 0, withHostname = 0, withDisplay = 0;
    let sample = null;
    // Cap total pages so a runaway loop can't hammer a misbehaving controller.
    for (let page = 0; page < 100; page++) {
      const res = await apiGet(ctrl.unifi_host, `/sites/${encodeURIComponent(siteId)}/clients?limit=${PAGE_LIMIT}&offset=${offset}`,
        ctrl.unifi_api_key, ctrl.unifi_verify_tls);
      const clients = Array.isArray(res) ? res : (res.data || []);
      if (!sample && clients[0]) sample = JSON.stringify(clients[0]).slice(0, 400);
      // Collect rows with a non-empty hostname: a client without a name carries
      // no identity value, and upserting NULL would overwrite a previously-known
      // hostname when UniFi momentarily returns an empty name (rename, API lag).
      // Field fallback: integration v1 list clients resmi cuma `name`, tapi
      // firmware/wrapper beda bisa expose `hostname`/`display_name` — fallback
      // murah, tanpa biaya request.
      // known-scope: hanya upsert MAC yang sudah muncul di aplikasi. MAC asing
      // (device UniFi yg belum pernah auth ke RADIUS) diabaikan supaya
      // device_hosts tidak menumpuk data yg tidak relevan.
      const rows = [];
      for (const c of clients) {
        const mac = normalizeMac(c.macAddress || c.mac || '');
        const name = (c.name || '').slice(0, 160);
        const hostname = (c.hostname || '').slice(0, 160);
        const displayName = (c.display_name || c.displayName || '').slice(0, 160);
        if (name) withName++;
        if (hostname) withHostname++;
        if (displayName) withDisplay++;
        const chosen = (name || hostname || displayName || '').slice(0, 160);
        if (!mac) continue;
        if (!known.has(mac)) { unknown++; continue; }
        if (!chosen) { skipped++; continue; }
        rows.push([ctrl.id, mac, chosen]);
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
      fetched += clients.length;
      if (clients.length < PAGE_LIMIT) break;
      offset += PAGE_LIMIT;
    }
    // Diagnostic per-site: kalau hostname kosong di UI, output ini tunjukkin
    // kenapa — field mana yang terisi, berapa di-skip/unknown, sample client aktual.
    console.error(`unifi sync ${ctrl.unifi_host} site=${siteId}: fetched=${fetched} name=${withName} hostname=${withHostname} displayName=${withDisplay} synced=${synced} skipped=${skipped} unknown=${unknown} sample=${sample}`);
  }
  return { sites: targets.length, clients: synced, skipped, unknown };
}

// Sync every enabled controller that has UniFi creds. Per-controller try/catch:
// an unreachable controller records its error and moves on, so the rest still
// refresh. Clears unifi_last_error only when all succeed.
async function syncAllControllers() {
  const ctrls = await query(
    "SELECT id, unifi_host, unifi_site, unifi_api_key, unifi_verify_tls FROM controllers WHERE enabled = 1 AND unifi_host IS NOT NULL AND unifi_api_key IS NOT NULL AND unifi_host <> '' AND unifi_api_key <> ''"
  );
  // Known-MAC scope: upsert hostname hanya untuk MAC yang sudah muncul di
  // aplikasi — auth_logs (pernah auth, termasuk pending), sessions (online),
  // mac_rules (rule). device_hosts tidak diisi MAC asing yang tidak pernah
  // tampil, supaya sinkronisasi tidak menumpuk data tidak relevan. MAC yang
  // sudah berhenti muncul tetap ada di device_hosts (cache), tapi tidak
  // ditambah yang baru.
  // ponytail: satu UNION per sync, bukan per controller. Kalau auth_logs
  // mencapai jutaan row, tambah index pada mac_address saja — DISTINCT tanpa
  // index akan full-scan.
  const knownRows = await query(`
    SELECT mac_address FROM (
      SELECT DISTINCT mac_address FROM auth_logs WHERE mac_address IS NOT NULL
      UNION
      SELECT DISTINCT mac_address FROM sessions WHERE mac_address IS NOT NULL
      UNION
      SELECT DISTINCT mac_address FROM mac_rules
    ) m
  `);
  const known = new Set(knownRows.map(r => r.mac_address));
  let lastErr = '';
  let ok = 0, synced = 0, skipped = 0, unknown = 0;
  for (const c of ctrls) {
    try {
      const r = await syncController(c, known);
      ok++;
      synced += r.clients;
      skipped += r.skipped;
      unknown += r.unknown;
    } catch (err) {
      lastErr = `${new Date().toLocaleString('sv-SE')} ${c.unifi_host}: ${err.message}`;
    }
  }
  await query('INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)',
    ['unifi_last_error', lastErr]);
  return { controllers: ctrls.length, ok, synced, skipped, unknown, known: known.size, error: lastErr };
}

// Single MAC lookup. Used by routes that already have controller_id in scope.
async function getHostname(controllerId, mac) {
  const rows = await query('SELECT hostname FROM device_hosts WHERE controller_id = ? AND mac_address = ?',
    [controllerId, mac]);
  return rows.length ? rows[0].hostname : null;
}

// Probe every controller with UniFi creds: fetch /v1/sites only, no upsert.
// Returns one entry per controller with status + the site names/IDs available,
// so the admin can see what to put in the `unifi_site` field (UDM Pro Max often
// has no site named "default" — its site name is whatever was set at adoption).
async function testControllers() {
  const ctrls = await query(
    "SELECT id, name, unifi_host, unifi_site, unifi_api_key, unifi_verify_tls FROM controllers WHERE enabled = 1 AND unifi_host IS NOT NULL AND unifi_api_key IS NOT NULL AND unifi_host <> '' AND unifi_api_key <> ''"
  );
  const out = [];
  for (const c of ctrls) {
    try {
      const sites = await apiGet(c.unifi_host, '/sites', c.unifi_api_key, c.unifi_verify_tls);
      const siteList = Array.isArray(sites) ? sites : (sites.data || []);
      out.push({
        name: c.name, host: c.unifi_host, ok: true,
        sites: siteList.map(s => ({ name: s.name, id: s.id || s._id })),
        configured_site: c.unifi_site || 'default',
        matched: siteList.some(s => s.name === (c.unifi_site || 'default'))
      });
    } catch (err) {
      out.push({ name: c.name, host: c.unifi_host, ok: false, error: err.message });
    }
  }
  return out;
}

module.exports = { syncController, syncAllControllers, getHostname, testControllers };
