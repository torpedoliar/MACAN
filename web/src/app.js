const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const { ensureAdmin, requireAdmin } = require('./auth');
const { query } = require('./db');
const { migrate } = require('./migrate');
const { writeAudit, auditContext } = require('./audit');
const { pendingCount } = require('./pending');
const { MysqlStore, csrf, maintenanceGuard, wrap, errorHandler,
        loginLockedFor, loginFailed, loginSucceeded } = require('./middleware');
const { pool } = require('./db');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// EJS resolves an absolute include ('/partials/head') against options.root, and
// Express never sets it — without this every include lands on the filesystem
// root. Views live in subdirectories, so relative includes are not an option.
app.set('view options', { root: path.join(__dirname, 'views') });
// Behind the compose port mapping / any reverse proxy: needed for secure cookies.
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));
// Cache-bust static assets: ?v=<mtime> changes whenever the file changes, so a
// browser never serves stale CSS/JS after a deploy. mtime of public/ at boot.
const fs = require('fs');
app.locals.assetVer = String(fs.statSync(path.join(__dirname, '..', 'public')).mtimeMs).slice(0, 10);
app.use(express.static(path.join(__dirname, '..', 'public'), { maxAge: '1y', immutable: true }));
// Before session: a probe every few seconds would otherwise mint a session row
// per hit. Unauthenticated on purpose — it leaks only up/down, which any port
// scan already reveals. No version, no counts, no error text.
app.get('/health', (req, res) => {
  pool.query('SELECT 1')
    .then(() => res.json({ status: 'ok' }))
    .catch(() => res.status(503).json({ status: 'degraded' }));
});
app.use(session({
  name: 'macan.sid',
  secret: process.env.SESSION_SECRET,
  store: new MysqlStore(),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    // Set COOKIE_SECURE=1 once served over HTTPS; leaving it on for plain HTTP
    // would make the cookie undeliverable and lock everyone out.
    secure: process.env.COOKIE_SECURE === '1',
    maxAge: 8 * 3600 * 1000
  }
}));
app.use(auditContext);
app.use(csrf);
app.use((req, res, next) => {
  res.locals.admin = req.session && req.session.admin ? req.session.admin : null;
  res.locals.currentPath = req.path;
  res.locals.maintenance = false;
  res.locals.pendingCount = 0;
  next();
});
app.use(maintenanceGuard);
// Sidebar badge. One indexed aggregate per page view; skipped for anonymous
// requests and static assets (which never reach here).
app.use(wrap(async (req, res, next) => {
  if (!req.session.admin) return next();
  try {
    res.locals.pendingCount = await pendingCount();
  } catch {
    res.locals.pendingCount = 0;
  }
  next();
}));

app.get('/login', (req, res) => {
  if (req.session.admin) return res.redirect('/');
  res.render('login', { error: null });
});

app.post('/login', wrap(async (req, res) => {
  // Brute-force brake. Checked before the bcrypt compare so a locked-out client
  // also stops costing ~100ms of CPU per attempt.
  const locked = loginLockedFor(req);
  if (locked) {
    return res.status(429).render('login', {
      error: `Terlalu banyak percobaan gagal. Coba lagi dalam ${locked} menit.`
    });
  }
  // enabled = 1 in the WHERE, not a branch after: a disabled account must give
  // the same "email atau password salah" as a nonexistent one, and must not
  // reveal itself by taking bcrypt-compare time.
  const rows = await query('SELECT * FROM admins WHERE email = ? AND enabled = 1', [req.body.email || '']);
  const admin = rows[0];
  if (!admin || !(await bcrypt.compare(req.body.password || '', admin.password_hash))) {
    loginFailed(req);
    return res.status(401).render('login', { error: 'Email atau password salah' });
  }
  loginSucceeded(req);
  const token = req.session.csrfToken;
  // Rotate the session id on privilege change (session fixation).
  req.session.regenerate(err => {
    if (err) throw err;
    req.session.csrfToken = token;
    req.session.admin = { id: admin.id, email: admin.email };
    writeAudit(admin.id, 'login', {}).catch(() => {});
    res.redirect('/');
  });
}));

app.post('/logout', requireAdmin, wrap(async (req, res) => {
  const adminId = req.session.admin.id;
  await writeAudit(adminId, 'logout', {});
  req.session.destroy(() => res.redirect('/login'));
}));

app.use('/', requireAdmin, require('./routes/dashboard'));
app.use('/controllers', requireAdmin, require('./routes/controllers'));
app.use('/ssids', requireAdmin, require('./routes/ssids'));
app.use('/ssid-groups', requireAdmin, require('./routes/ssid-groups'));
app.use('/rules', requireAdmin, require('./routes/rules'));
app.use('/settings', requireAdmin, require('./routes/settings'));
app.use('/logs', requireAdmin, require('./routes/logs'));
app.use('/approvals', requireAdmin, require('./routes/approvals'));
app.use('/sessions', requireAdmin, require('./routes/sessions'));
app.use('/audit', requireAdmin, require('./routes/audit'));
app.use('/data', requireAdmin, require('./routes/data'));
app.use('/admins', requireAdmin, require('./routes/admins'));

app.use((req, res) => res.status(404).render('error', {
  status: 404,
  message: 'Halaman tidak ditemukan.'
}));
app.use(errorHandler);

const PORT = parseInt(process.env.PORT, 10) || 880;

migrate()
  .then(ensureAdmin)
  .then(() => {
    require('./cron');
    const server = app.listen(PORT, () => console.log(`MACan web listening on ${PORT}`));
    // Docker sends SIGTERM on stop/restart. Without this, Node dies immediately
    // and any in-flight request — including a restore transaction — is cut off.
    // Second signal or 10s timeout forces the exit so a stuck socket can't hang
    // the container until Docker's own SIGKILL.
    let closing = false;
    const shutdown = signal => {
      if (closing) return process.exit(1);
      closing = true;
      console.log(`${signal} diterima, menutup...`);
      const force = setTimeout(() => process.exit(1), 10000);
      force.unref();
      server.close(() => pool.end().catch(() => {}).then(() => process.exit(0)));
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  })
  .catch(err => {
    console.error('Startup gagal:', err);
    process.exit(1);
  });
