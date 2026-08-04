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
