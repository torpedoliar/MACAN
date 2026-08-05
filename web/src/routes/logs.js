const express = require('express');
const { query } = require('../db');
const { wrap } = require('../middleware');
const router = express.Router();

const RESULTS = ['accept', 'reject'];
const PER_PAGE = 50;

router.get('/', wrap(async (req, res) => {
  const { mac, ssid, result, controller_id, from, to } = req.query;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const where = [];
  const params = [];
  if (mac) { where.push('a.mac_address LIKE ?'); params.push(`%${mac}%`); }
  if (ssid) { where.push('a.ssid_name LIKE ?'); params.push(`%${ssid}%`); }
  if (result && RESULTS.includes(result)) { where.push('a.result = ?'); params.push(result); }
  if (controller_id) { where.push('a.controller_id = ?'); params.push(controller_id); }
  if (from) { where.push('a.created_at >= ?'); params.push(from); }
  if (to) { where.push('a.created_at <= ?'); params.push(to); }
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const totalRows = await query(`SELECT COUNT(*) AS count FROM auth_logs a ${clause}`, params);
  const total = Number(totalRows[0].count);
  const pages = Math.max(1, Math.ceil(total / PER_PAGE));
  const offset = (Math.min(page, pages) - 1) * PER_PAGE;

  const logs = await query(`
    SELECT a.*, c.name AS controller_name, h.hostname
    FROM auth_logs a LEFT JOIN controllers c ON a.controller_id = c.id
    LEFT JOIN device_hosts h ON h.controller_id = a.controller_id AND h.mac_address = a.mac_address
    ${clause}
    ORDER BY a.created_at DESC
    LIMIT ${PER_PAGE} OFFSET ${offset}
  `, params);

  const controllers = await query('SELECT id, name FROM controllers ORDER BY name');
  res.render('logs/index', {
    logs, controllers, total,
    page: Math.min(page, pages), pages,
    filters: {
      mac: mac || '', ssid: ssid || '', result: result || '',
      controller_id: controller_id || '', from: from || '', to: to || ''
    }
  });
}));

module.exports = router;
