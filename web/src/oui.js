const https = require('https');
const { query } = require('./db');

// IEEE OUI registry. ~35k prefixes, ~5MB text. Refetchable reference data.
// Host: linuxnet.ca — mirror OUI resmi IEEE, format file identik (xx-xx-xx (hex)
// Vendor), jadi parser di bawah tidak berubah. standards-oui.ieee.org diblokir
// oleh DNS korporat di beberapa jaringan (SERVFAIL/NXDOMAIN walau public
// resolver bisa resolve); Docker embedded DNS ikut gagal karena proxy-nya.
// linuxnet.ca resolve normal di host yg memblokir IEEE. Fallback darurat:
// https://api.maclookup.app/v2/macs/<mac> (per-MAC, bukan bulk).
const OUI_URL = 'https://www.linuxnet.ca/ieee/oui/oui.txt';
const MAX_BYTES = 8 * 1024 * 1024;

// ponytail: in-memory Map for sync vendor lookup. Loaded once at boot; the table
// only changes on monthly refresh. EJS can't await, so a sync lookup is the only
// shape that works in templates. ~35k entries, a few MB RAM — fine single container.
// Upgrade: if replicas or memory pressure, drop the Map and do a per-lookup SELECT.
const vendors = new Map();

async function loadVendors() {
  vendors.clear();
  const rows = await query('SELECT oui, vendor FROM oui_vendors');
  for (const r of rows) vendors.set(r.oui, r.vendor);
  return vendors;
}

// First 3 octets -> 6 hex, no separator. Canonical MAC is lowercase aa:bb:cc:...
// so slice(0,8) + strip non-hex gives 'aabbcc'. Returns '' when unknown.
function vendorOf(mac) {
  if (!mac) return '';
  const oui = String(mac).slice(0, 8).replace(/[^0-9a-f]/g, '');
  if (oui.length !== 6) return '';
  return vendors.get(oui) || '';
}

// Fetch the OUI text file, parse "xx-xx-xx   (hex)   Vendor Name" lines, bulk
// upsert. Returns {fetched, total}. Parses synchronously — 4MB text in <1s.
async function refreshOui() {
  const body = await fetchText(OUI_URL, MAX_BYTES);
  const rows = [];
  const seen = new Set();
  // Lines look like:   00-1B-44   (hex)		D-Link Systems
  // The (base 16) line right below repeats the same prefix in hex; skip it.
  for (const line of body.split('\n')) {
    const m = /^\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$/.exec(line);
    if (!m) continue;
    const oui = m[1].replace(/-/g, '').toLowerCase();
    if (seen.has(oui)) continue;
    seen.add(oui);
    rows.push([oui, m[2].slice(0, 160)]);
  }
  if (!rows.length) throw new Error('OUI file terparse 0 entri — format berubah?');

  // Batch upsert in chunks to avoid sending 35k rows in one statement.
  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500);
    const values = chunk.map(() => '(?, ?)').join(', ');
    const params = chunk.flat();
    await query(
      `INSERT INTO oui_vendors (oui, vendor) VALUES ${values} ON DUPLICATE KEY UPDATE vendor = VALUES(vendor)`,
      params
    );
  }
  const stamp = new Date().toLocaleString('sv-SE');
  await query('INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)',
    ['oui_last_refresh', stamp]);
  await loadVendors(); // reload Map so new vendors show up without a restart
  return { fetched: body.length, total: rows.length };
}

// node:https GET with body accumulation + size cap + timeout. Mirrors the
// notifications.js post() shape but reads the response instead of draining it.
// Retries on transient DNS errors (EAI_AGAIN / EAI_EAGAIN): Docker's embedded
// resolver (127.0.0.11) intermittently times out on lookups — the connection
// itself succeeds on retry, so a single EAI_AGAIN must not fail the whole fetch.
const RETRYABLE_DNS = new Set(['EAI_AGAIN', 'EAI_EAGAIN', 'EAI_NODATA']);

function fetchTextOnce(url, maxBytes) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(url); }
    catch { return reject(new Error('URL tidak valid')); }
    if (target.protocol !== 'https:') return reject(new Error('hanya https'));
    const req = https.request(target, {
      method: 'GET',
      headers: { 'Accept': 'text/plain' },
      timeout: 30000
    }, res => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks = [];
      let size = 0;
      res.on('data', c => {
        size += c.length;
        if (size > maxBytes) { res.destroy(); return reject(new Error('respons melebihi batas ukuran')); }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('timeout', () => req.destroy(new Error('timeout setelah 30s')));
    req.on('error', reject);
    req.end();
  });
}

async function fetchText(url, maxBytes) {
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await fetchTextOnce(url, maxBytes);
    } catch (err) {
      lastErr = err;
      // Only retry transient DNS resolver hiccups; HTTP 4xx/5xx or size cap
      // errors are deterministic and won't change on retry.
      if (!RETRYABLE_DNS.has(err.code)) break;
      await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
    }
  }
  throw lastErr;
}

module.exports = { loadVendors, vendorOf, refreshOui };
