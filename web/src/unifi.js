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

// Classic controller API (cookie login). Endpoint prefix on UniFi OS:
//   https://<host>/proxy/network/api/s/<site>/...
// Login: POST /api/auth/login (UDM Pro/UCG path) → Set-Cookie session. Unlike
// integration v1 this returns ALL configured clients (offline included), so it
// fills the gap X-API-KEY leaves (online-only). Unofficial but stable surface.
// ponytail: manual Set-Cookie parse, no cookie-jar dep. Cukup untuk 1 login + N
// GET per sync; tough-cookie only if session refresh/expiry gets complex.
function apiClassicLogin(host, username, password, verifyTls) {
  return new Promise((resolve, reject) => {
    let base;
    try { base = new URL(host); }
    catch { return reject(new Error('unifi_host URL tidak valid')); }
    const full = new URL('/api/auth/login', base);
    const isHttps = full.protocol === 'https:';
    const lib = isHttps ? https : require('http');
    const body = JSON.stringify({ username, password, remember: true });
    const req = lib.request(full, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: TIMEOUT,
      rejectUnauthorized: Boolean(verifyTls)
    }, res => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`login HTTP ${res.statusCode}`));
      }
      const cookies = (res.headers['set-cookie'] || []).map(c => c.split(';')[0]).filter(Boolean);
      const csrf = res.headers['x-csrf-token'] || '';
      res.resume();
      if (!cookies.length) return reject(new Error('login tidak mengembalikan cookie'));
      resolve({ cookies, csrf });
    });
    req.on('timeout', () => req.destroy(new Error('login timeout setelah 8s')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// GET one classic endpoint with a session cookie. path includes /api/s/<site>/...
// Retry-once on 401 handled by caller (syncControllerClassic) yang pegang credential
// untuk re-login. ponytail: retry-once, no exponential backoff.
function apiClassicGet(host, path, cookies, verifyTls) {
  return new Promise((resolve, reject) => {
    let base;
    try { base = new URL(host); }
    catch { return reject(new Error('unifi_host URL tidak valid')); }
    const full = new URL('/proxy/network' + path, base);
    const isHttps = full.protocol === 'https:';
    const lib = isHttps ? https : require('http');
    const req = lib.request(full, {
      method: 'GET',
      headers: { 'Cookie': cookies.join('; '), 'Accept': 'application/json' },
      timeout: TIMEOUT,
      rejectUnauthorized: Boolean(verifyTls)
    }, res => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        const err = new Error(`HTTP ${res.statusCode}`);
        err.statusCode = res.statusCode;
        return reject(err);
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
  if (!ctrl.unifi_host) {
    throw new Error('unifi_host kosong');
  }
  // Integration v1 (X-API-KEY) untuk online client. Skip kalau tidak ada api_key
  // — controller classic-only (user/pass) tetap dapat sync lewat classic tahap.
  let synced = 0, skipped = 0, unknown = 0, targets = [];
  if (ctrl.unifi_api_key) {
    const siteWanted = (ctrl.unifi_site || 'default').trim();
    const sites = await apiGet(ctrl.unifi_host, '/sites', ctrl.unifi_api_key, ctrl.unifi_verify_tls);
    const siteList = Array.isArray(sites) ? sites : (sites.data || []);
    // Match by short name (e.g. 'default'); fall back to all sites if none matches,
    // since a mistyped site name is a common config error and syncing nothing is
    // worse than syncing extra.
    targets = siteList.filter(s => s.name === siteWanted);
    if (!targets.length) targets = siteList;
    if (!targets.length) throw new Error(`tidak ada site di controller (cari: '${siteWanted}')`);
  }

  let fetched = 0, withName = 0, withHostname = 0, withDisplay = 0, sample = null;
  for (const site of targets) {
    const siteId = site.id || site._id;
    if (!siteId) continue;
    let offset = 0;
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
  // Classic API (cookie login) untuk ambil semua configured client (offline
  // included) — integration v1 cuma return online. Tahap terpisah supaya
  // gagal classic tidak merusak sync online. Known-scope tetap: device_hosts
  // hanya diisi MAC yg muncul di aplikasi.
  let classic = { fetched: 0, synced: 0, skipped: 0, unknown: 0 };
  if (ctrl.unifi_username && ctrl.unifi_password) {
    try { classic = await syncControllerClassic(ctrl, known); }
    catch (err) {
      console.error(`unifi classic sync ${ctrl.unifi_host} gagal: ${err.message}`);
    }
  }
  return {
    sites: targets.length,
    clients: synced + classic.synced,
    skipped: skipped + classic.skipped,
    unknown: unknown + classic.unknown,
    classicFetched: classic.fetched,
    classicSynced: classic.synced
  };
}

// Classic API sync: login UniFi user/pass → fetch /rest/user (semua configured
// client, offline included). Field hostname (DHCP/mDNS) || name (operator). Site
// classic pakai short name (s.name), bukan UUID integration. Retry login sekali
// kalau GET kena 401 (session expired). Throws on failure — caller try/catch.
async function syncControllerClassic(ctrl, known) {
  let session = await apiClassicLogin(ctrl.unifi_host, ctrl.unifi_username, ctrl.unifi_password, ctrl.unifi_verify_tls);
  const siteName = (ctrl.unifi_site || 'default').trim();
  const path = `/api/s/${encodeURIComponent(siteName)}/rest/user`;
  let res;
  try {
    res = await apiClassicGet(ctrl.unifi_host, path, session.cookies, ctrl.unifi_verify_tls);
  } catch (err) {
    if (err.statusCode !== 401) throw err;
    // ponytail: retry-once on 401. Classic session bisa expire antar login+
    // GET kalau controller lambat; re-login sekali, bukan backoff.
    session = await apiClassicLogin(ctrl.unifi_host, ctrl.unifi_username, ctrl.unifi_password, ctrl.unifi_verify_tls);
    res = await apiClassicGet(ctrl.unifi_host, path, session.cookies, ctrl.unifi_verify_tls);
  }
  // Classic API return shape: { data: [...clients], meta: {...} }
  const clients = Array.isArray(res) ? res : (res.data || []);
  let fetched = 0, synced = 0, skipped = 0, unknown = 0;
  const rows = [];
  for (const c of clients) {
    const mac = normalizeMac(c.mac || c.macAddress || '');
    const hostname = (c.hostname || c.name || '').slice(0, 160);
    fetched++;
    if (!mac) continue;
    if (!known.has(mac)) { unknown++; continue; }
    if (!hostname) { skipped++; continue; }
    rows.push([ctrl.id, mac, hostname]);
  }
  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500);
    const values = chunk.map(() => '(?, ?, ?)').join(', ');
    await query(
      `INSERT INTO device_hosts (controller_id, mac_address, hostname) VALUES ${values} ON DUPLICATE KEY UPDATE hostname = VALUES(hostname), last_sync = CURRENT_TIMESTAMP`,
      chunk.flat()
    );
  }
  synced += rows.length;
  console.error(`unifi classic sync ${ctrl.unifi_host} site=${siteName}: fetched=${fetched} synced=${synced} skipped=${skipped} unknown=${unknown}`);
  return { fetched, synced, skipped, unknown };
}

// Sync every enabled controller that has UniFi creds. Per-controller try/catch:
// an unreachable controller records its error and moves on, so the rest still
// refresh. Clears unifi_last_error only when all succeed.
async function syncAllControllers() {
  const ctrls = await query(
    "SELECT id, unifi_host, unifi_site, unifi_api_key, unifi_verify_tls, unifi_username, unifi_password FROM controllers WHERE enabled = 1 AND unifi_host IS NOT NULL AND unifi_host <> '' AND ((unifi_api_key IS NOT NULL AND unifi_api_key <> '') OR (unifi_username IS NOT NULL AND unifi_username <> ''))"
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
    "SELECT id, name, unifi_host, unifi_site, unifi_api_key, unifi_verify_tls, unifi_username, unifi_password FROM controllers WHERE enabled = 1 AND unifi_host IS NOT NULL AND unifi_host <> '' AND ((unifi_api_key IS NOT NULL AND unifi_api_key <> '') OR (unifi_username IS NOT NULL AND unifi_username <> ''))"
  );
  const out = [];
  for (const c of ctrls) {
    // Tahap 1: integration v1 (X-API-KEY) — kalau ada api_key.
    let sites = [], v1Ok = false, v1Err = '';
    if (c.unifi_api_key) {
      try {
        const res = await apiGet(c.unifi_host, '/sites', c.unifi_api_key, c.unifi_verify_tls);
        sites = Array.isArray(res) ? res : (res.data || []);
        v1Ok = true;
      } catch (err) { v1Err = err.message; }
    }
    // Tahap 2: classic login (user/pass) — kalau ada. Tes login + GET /rest/user
    // untuk konfirmasi site classic (short name) benar dan akun punya akses.
    let classicOk = null, classicErr = '', classicSite = c.unifi_site || 'default';
    if (c.unifi_username && c.unifi_password) {
      try {
        const session = await apiClassicLogin(c.unifi_host, c.unifi_username, c.unifi_password, c.unifi_verify_tls);
        // Cek site short-name valid: GET /api/s/{site}/self. 404 = site salah.
        await apiClassicGet(c.unifi_host, `/api/s/${encodeURIComponent(classicSite)}/self`, session.cookies, c.unifi_verify_tls);
        classicOk = true;
      } catch (err) { classicOk = false; classicErr = err.message; }
    }
    // ok = minimal satu tahap sukses. Gagal total = alert merah.
    const ok = v1Ok || classicOk === true;
    out.push({
      name: c.name, host: c.unifi_host, ok,
      // v1 detail
      sites: sites.map(s => ({ name: s.name, id: s.id || s._id })),
      configured_site: c.unifi_site || 'default',
      matched: sites.some(s => s.name === (c.unifi_site || 'default')),
      v1Skipped: !c.unifi_api_key,
      v1Error: v1Err,
      // classic detail
      classicSkipped: !c.unifi_username || !c.unifi_password,
      classicOk, classicSite, classicError: classicErr
    });
  }
  return out;
}

module.exports = { syncController, syncAllControllers, getHostname, testControllers };
