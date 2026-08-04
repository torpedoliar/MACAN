const crypto = require('crypto');
const session = require('express-session');
const { query } = require('./db');

// ponytail: ~40-line store on the existing mysql2 pool instead of adding
// express-mysql-session. Upgrade if you need clustering-aware TTL sweeps.
class MysqlStore extends session.Store {
  constructor(ttlSeconds = 8 * 3600) {
    super();
    this.ttl = ttlSeconds;
    // Sweep hourly; unref so the timer never holds the process open.
    this.timer = setInterval(() => this.reap().catch(() => {}), 3600 * 1000);
    if (this.timer.unref) this.timer.unref();
  }
  async reap() {
    await query('DELETE FROM admin_sessions WHERE expires < ?', [Math.floor(Date.now() / 1000)]);
  }
  expiryOf(sess) {
    const ms = sess && sess.cookie && sess.cookie.expires
      ? new Date(sess.cookie.expires).getTime()
      : Date.now() + this.ttl * 1000;
    return Math.floor(ms / 1000);
  }
  get(sid, cb) {
    query('SELECT data, expires FROM admin_sessions WHERE session_id = ?', [sid])
      .then(rows => {
        if (!rows.length) return cb(null, null);
        if (rows[0].expires < Math.floor(Date.now() / 1000)) return cb(null, null);
        cb(null, JSON.parse(rows[0].data));
      })
      .catch(cb);
  }
  set(sid, sess, cb) {
    query(
      'INSERT INTO admin_sessions (session_id, expires, data) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE expires = VALUES(expires), data = VALUES(data)',
      [sid, this.expiryOf(sess), JSON.stringify(sess)]
    ).then(() => cb(null)).catch(cb);
  }
  touch(sid, sess, cb) {
    query('UPDATE admin_sessions SET expires = ? WHERE session_id = ?', [this.expiryOf(sess), sid])
      .then(() => cb(null)).catch(cb);
  }
  destroy(sid, cb) {
    query('DELETE FROM admin_sessions WHERE session_id = ?', [sid]).then(() => cb(null)).catch(cb);
  }
}

// ponytail: in-memory counters instead of a rate-limit package. Single web
// container, so one Map is enough; move to a table or redis if you ever run
// replicas — each would count separately and the cap would multiply.
const FAILS = new Map();
const MAX_FAILS = 10;
const LOCK_MS = 15 * 60 * 1000;

// Two buckets per attempt. The IP bucket stops one host hammering. The email
// bucket survives IP rotation: `trust proxy` is on, so a client can put anything
// in X-Forwarded-For and mint a fresh req.ip per request — but brute-forcing a
// given account still has to send that account's email.
function loginKeys(req) {
  return [`ip:${req.ip}`, `email:${String(req.body && req.body.email || '').toLowerCase().slice(0, 255)}`];
}

// Returns minutes remaining while locked, 0 when allowed.
function loginLockedFor(req) {
  const now = Date.now();
  let max = 0;
  for (const key of loginKeys(req)) {
    const hit = FAILS.get(key);
    if (hit && hit.n >= MAX_FAILS && hit.until > now) {
      max = Math.max(max, Math.ceil((hit.until - now) / 60000));
    }
  }
  return max;
}

function loginFailed(req) {
  const now = Date.now();
  // Bounded cleanup: expired entries only, and only once the map is large.
  if (FAILS.size > 10000) {
    for (const [key, hit] of FAILS) if (hit.until <= now) FAILS.delete(key);
  }
  for (const key of loginKeys(req)) {
    const hit = FAILS.get(key);
    // Sliding window: every failure pushes the expiry out again.
    FAILS.set(key, { n: hit && hit.until > now ? hit.n + 1 : 1, until: now + LOCK_MS });
  }
}

function loginSucceeded(req) {
  for (const key of loginKeys(req)) FAILS.delete(key);
}

// Compares the submitted _csrf against the session token. Split out from `csrf`
// because multipart routes can only run it after multer has parsed the body.
function verifyCsrf(req, res, next) {
  const sent = Buffer.from(String(req.body && req.body._csrf || ''));
  const want = Buffer.from(String(req.session && req.session.csrfToken || ''));
  if (!want.length || sent.length !== want.length || !crypto.timingSafeEqual(sent, want)) {
    const err = new Error('Token CSRF tidak valid. Muat ulang halaman dan coba lagi.');
    err.status = 403;
    return next(err);
  }
  next();
}

// Synchronizer-token CSRF. Token lives in the session, echoed in a hidden field
// on every POST form; timing-safe compared here.
function csrf(req, res, next) {
  if (!req.session) return next();
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  // A multipart body is parsed by multer inside the route, so _csrf does not
  // exist yet here. Those routes must call verifyCsrf themselves right after the
  // upload middleware — self-check.js asserts that they do.
  if (/^multipart\/form-data/i.test(req.headers['content-type'] || '')) return next();
  verifyCsrf(req, res, next);
}

// Maintenance mode is a fail-closed switch for RADIUS; on the web side it only
// blocks mutations so an operator can still read state and turn it back off.
async function maintenanceGuard(req, res, next) {
  try {
    const rows = await query('SELECT value FROM settings WHERE name = ?', ['maintenance_mode']);
    const on = rows.length && rows[0].value === '1';
    res.locals.maintenance = on;
    if (!on) return next();
    const writing = req.method !== 'GET' && req.method !== 'HEAD';
    const allowed = req.path.startsWith('/settings') || req.path === '/logout' || req.path === '/login';
    if (writing && !allowed) {
      const err = new Error('Mode maintenance aktif. Perubahan data dinonaktifkan sementara.');
      err.status = 503;
      return next(err);
    }
    next();
  } catch (err) {
    next(err);
  }
}

// Wraps async handlers so a rejected promise reaches the error middleware
// instead of killing the process (Express 4 has no native async support).
function wrap(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

// ponytail: length limits enforced by the column definitions plus `maxlength` on
// the inputs, not by a per-field check in every route. STRICT_TRANS_TABLES turns
// over-length data into ER_DATA_TOO_LONG (1406) instead of a silent truncation,
// so mapping that one errno here covers every column — including ones added
// later. Upgrade path: if a field ever needs a limit the column does not express
// (a business rule, not a storage bound), validate it in its own route.
function dataTooLong(err) {
  if (err.errno !== 1406) return null;
  // Only the column name is echoed back; the full sqlMessage carries the query.
  const column = /column '([^']+)'/.exec(err.sqlMessage || '');
  return column
    ? `Isi kolom "${column[1]}" terlalu panjang. Perpendek lalu simpan lagi.`
    : 'Salah satu isian terlalu panjang. Perpendek lalu simpan lagi.';
}

function errorHandler(err, req, res, next) {
  const tooLong = dataTooLong(err);
  if (tooLong) {
    err = Object.assign(new Error(tooLong), { status: 400 });
  }
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  const message = status >= 500
    ? 'Terjadi kesalahan pada server. Coba lagi atau cek log aplikasi.'
    : err.message;
  if (res.headersSent) return next(err);
  res.status(status);
  if (req.accepts('html')) return res.render('error', { status, message });
  res.json({ error: message });
}

module.exports = {
  MysqlStore, csrf, verifyCsrf, maintenanceGuard, wrap, errorHandler,
  loginLockedFor, loginFailed, loginSucceeded, MAX_FAILS
};
