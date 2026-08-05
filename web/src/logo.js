const { query } = require('./db');

// ponytail: in-memory cache {mime, buf, etag}. Logo changes rarely; one row per
// page view × every route is wasteful. Load once at boot, invalidate on upload.
// Upgrade: if replicas ever run, each caches independently — set a short TTL or
// move to a shared invalidation signal. Single container, one cache is enough.
let cache = null;

async function loadLogo() {
  const rows = await query("SELECT name, value FROM settings WHERE name IN ('logo_mime', 'logo_data')");
  if (!rows.length) { cache = null; return null; }
  const map = rows.reduce((a, r) => ({ ...a, [r.name]: r.value }), {});
  if (!map.logo_data) { cache = null; return null; }
  const buf = Buffer.from(map.logo_data, 'base64');
  const etag = '"' + buf.length.toString(16) + '-' + buf.slice(0, 8).toString('hex') + '"';
  cache = { mime: map.logo_mime || 'image/png', buf, etag };
  return cache;
}

function getLogo() { return cache; }

function setLogo(logo) { cache = logo; }
function clearLogo() { cache = null; }

// Magic-byte sniff — client mimetype is spoofable. Only web-safe raster/SVG
// accepted. Returns {mime, ext} or null when unknown/forbidden.
const SIGS = [
  { bytes: [0x89, 0x50, 0x4E, 0x47], mime: 'image/png' },
  { bytes: [0xFF, 0xD8, 0xFF], mime: 'image/jpeg' },
  { bytes: [0x47, 0x49, 0x46, 0x38], mime: 'image/gif' },
  { bytes: [0x52, 0x49, 0x46, 0x46], mime: 'image/webp' }, // RIFF…WEBP
  { bytes: [0x3C, 0x73, 0x76, 0x67], mime: 'image/svg+xml' }, // <svg
  { bytes: [0x3C, 0x3F, 0x78, 0x6D], mime: 'image/svg+xml' }  // <?xml …<svg
];
const ALLOWED = new Set(SIGS.map(s => s.mime));

function sniff(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return null;
  for (const s of SIGS) {
    if (s.bytes.every((b, i) => buf[i] === b)) {
      // WEBP: RIFF header alone is also WAV/AVI — confirm the VP8 form tag.
      if (s.mime === 'image/webp' && buf.slice(8, 12).toString('ascii') !== 'WEBP') continue;
      return s.mime;
    }
  }
  return null;
}

module.exports = { loadLogo, getLogo, setLogo, clearLogo, sniff, ALLOWED };
