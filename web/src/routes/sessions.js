const express = require('express');
const { query } = require('../db');
const { wrap } = require('../middleware');
const router = express.Router();

router.get('/', wrap(async (req, res) => {
  const timeoutRows = await query('SELECT value FROM settings WHERE name = ?', ['online_session_timeout_minutes']);
  const timeout = parseInt(timeoutRows.length ? timeoutRows[0].value : '120', 10) || 120;
  const show = req.query.show === 'all' ? 'all' : 'online';

  const sessions = await query(`
    SELECT s.*, c.name AS controller_name,
           TIMESTAMPDIFF(SECOND, s.started_at, IFNULL(s.stopped_at, NOW())) AS duration_seconds,
           (s.stopped_at IS NULL AND s.last_update_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)) AS is_online
    FROM sessions s LEFT JOIN controllers c ON s.controller_id = c.id
    ${show === 'online' ? 'WHERE s.stopped_at IS NULL AND s.last_update_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)' : ''}
    ORDER BY s.last_update_at DESC
    LIMIT 500
  `, show === 'online' ? [timeout, timeout] : [timeout]);

  res.render('sessions/index', { sessions, timeout, show });
}));

module.exports = router;
