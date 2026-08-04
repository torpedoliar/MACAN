const express = require('express');
const bcrypt = require('bcrypt');
const { query } = require('../db');
const { writeAudit } = require('../audit');
const { wrap } = require('../middleware');
const router = express.Router();

// Same cost as auth.js seeds the first admin with; a mismatch would make one
// account measurably cheaper to attack than the others.
const BCRYPT_COST = 12;
const MIN_PASSWORD = 8;

const clean = v => {
  const s = String(v === undefined || v === null ? '' : v).trim();
  return s === '' ? null : s;
};

router.get('/', wrap(async (req, res) => {
  const accounts = await query(`
    SELECT a.id, a.email, a.enabled, a.created_at,
      (SELECT MAX(l.created_at) FROM audit_logs l WHERE l.admin_id = a.id AND l.action = 'login') AS last_login
    FROM admins a ORDER BY a.email
  `);
  res.render('admins/index', {
    accounts,
    error: req.query.error,
    notice: req.query.notice
  });
}));

// Local is `account`, not `admin`: res.locals.admin is the logged-in user the
// sidebar and header read, and a render local of that name shadows it.
router.get('/new', (req, res) => res.render('admins/form', { account: {}, error: null }));

async function save(req, res, id) {
  const email = (clean(req.body.email) || '').toLowerCase() || null;
  const password = clean(req.body.password);
  const confirm = clean(req.body.password_confirm);
  const enabled = req.body.enabled === 'on' || req.body.enabled === '1';

  const rerender = error => res.status(400).render('admins/form', {
    account: { id, email, enabled }, error
  });
  if (!email) return rerender('Email wajib diisi.');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return rerender('Format email tidak valid.');
  if (!id && !password) return rerender('Password wajib diisi saat membuat admin baru.');
  if (password && password.length < MIN_PASSWORD) return rerender(`Password minimal ${MIN_PASSWORD} karakter.`);
  if (password && password !== confirm) return rerender('Konfirmasi password tidak sama.');

  // Locking yourself out is a one-click mistake with no undo from the UI.
  if (id && !enabled && Number(id) === Number(req.session.admin.id)) {
    return rerender('Tidak bisa menonaktifkan akun Anda sendiri.');
  }
  if (id && !enabled) {
    const others = await query('SELECT COUNT(*) AS count FROM admins WHERE enabled = 1 AND id <> ?', [id]);
    if (!Number(others[0].count)) return rerender('Ini satu-satunya admin aktif. Aktifkan admin lain dulu sebelum menonaktifkan yang ini.');
  }

  try {
    if (id) {
      if (password) {
        const hash = await bcrypt.hash(password, BCRYPT_COST);
        await query('UPDATE admins SET email=?, password_hash=?, enabled=? WHERE id=?', [email, hash, enabled, id]);
      } else {
        await query('UPDATE admins SET email=?, enabled=? WHERE id=?', [email, enabled, id]);
      }
      await writeAudit(req.session.admin.id, 'admin_update',
        { id, email, enabled, password_changed: Boolean(password) });
      // The session carries a cached copy for the sidebar; refresh it after a
      // self-edit so the footer doesn't keep showing the old address.
      if (Number(id) === Number(req.session.admin.id)) req.session.admin.email = email;
    } else {
      const hash = await bcrypt.hash(password, BCRYPT_COST);
      await query('INSERT INTO admins (email, password_hash, enabled) VALUES (?, ?, ?)', [email, hash, enabled]);
      await writeAudit(req.session.admin.id, 'admin_create', { email, enabled });
    }
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY' || err.errno === 1062) return rerender(`Email ${email} sudah dipakai admin lain.`);
    throw err;
  }
  res.redirect('/admins?notice=' + encodeURIComponent('Tersimpan.'));
}

router.post('/', wrap((req, res) => save(req, res, null)));

router.get('/:id/edit', wrap(async (req, res) => {
  const rows = await query('SELECT id, email, enabled FROM admins WHERE id = ?', [req.params.id]);
  if (!rows.length) return res.redirect('/admins');
  res.render('admins/form', { account: rows[0], error: null });
}));

router.post('/:id', wrap((req, res) => save(req, res, req.params.id)));

module.exports = router;
