const express = require('express');
const { query } = require('../db');
const { wrap } = require('../middleware');
const router = express.Router();

const PER_PAGE = 50;

router.get('/', wrap(async (req, res) => {
  const { action, admin_id } = req.query;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const where = [];
  const params = [];
  if (action) { where.push('l.action LIKE ?'); params.push(`%${action}%`); }
  if (admin_id) { where.push('l.admin_id = ?'); params.push(admin_id); }
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const totalRows = await query(`SELECT COUNT(*) AS count FROM audit_logs l ${clause}`, params);
  const total = Number(totalRows[0].count);
  const pages = Math.max(1, Math.ceil(total / PER_PAGE));
  const offset = (Math.min(page, pages) - 1) * PER_PAGE;

  const logs = await query(`
    SELECT l.*, a.email AS admin_email
    FROM audit_logs l LEFT JOIN admins a ON l.admin_id = a.id
    ${clause}
    ORDER BY l.created_at DESC
    LIMIT ${PER_PAGE} OFFSET ${offset}
  `, params);

  const admins = await query('SELECT id, email FROM admins ORDER BY email');
  res.render('audit/index', {
    logs, admins, total, page: Math.min(page, pages), pages,
    filters: { action: action || '', admin_id: admin_id || '' }
  });
}));

module.exports = router;
