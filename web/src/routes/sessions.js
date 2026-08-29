const express = require('express');
const { query } = require('../db');
const { wrap } = require('../middleware');
const router = express.Router();

router.get('/', wrap(async (req, res) => {
  const timeoutRows = await query('SELECT value FROM settings WHERE name = ?', ['online_session_timeout_minutes']);
  const timeout = parseInt(timeoutRows.length ? timeoutRows[0].value : '120', 10) || 120;
  const show = req.query.show === 'all' ? 'all' : 'online';
  // Filter per controller. The is_online placeholder precedes the WHERE clause,
  // so params must be ordered [timeout, (online? timeout), (controllerId?)].
  const controllerId = req.query.controller_id ? Number(req.query.controller_id) : null;
  if (controllerId !== null && Number.isNaN(controllerId)) {
    return res.redirect('/sessions?show=' + show);
  }

  const sessions = await query(`
    SELECT s.*, c.name AS controller_name,
           r.owner_name, r.device_name, r.status AS rule_status,
           h.hostname,
           TIMESTAMPDIFF(SECOND, s.started_at, IFNULL(s.stopped_at, NOW())) AS duration_seconds,
           (s.stopped_at IS NULL AND s.last_update_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)) AS is_online
    FROM sessions s
    LEFT JOIN controllers c ON s.controller_id = c.id
    -- Who is on the network: identity lives in mac_rules, not in the accounting
    -- packet. Joined via a sub-select, not ON (r.controller_id = s.controller_id
    -- OR r.controller_id IS NULL): a MAC with both a scoped and a global rule
    -- would match twice and duplicate the session row. Same precedence as
    -- default.conf — controller-scoped wins over global.
    LEFT JOIN mac_rules r ON r.id = (
      SELECT r2.id FROM mac_rules r2
      WHERE r2.mac_address = s.mac_address AND r2.ssid_name = s.ssid_name
        AND (r2.controller_id = s.controller_id OR r2.controller_id IS NULL)
      ORDER BY r2.controller_id IS NULL ASC, r2.id ASC LIMIT 1
    )
    LEFT JOIN (SELECT mac_address, MIN(hostname) AS hostname FROM device_hosts GROUP BY mac_address) h ON h.mac_address = s.mac_address
    ${show === 'online' ? 'WHERE s.stopped_at IS NULL AND s.last_update_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)' : ''}
    ${controllerId !== null ? (show === 'online' ? 'AND s.controller_id = ?' : 'WHERE s.controller_id = ?') : ''}
    ORDER BY s.last_update_at DESC
    LIMIT 500
  `, show === 'online'
    ? (controllerId !== null ? [timeout, timeout, controllerId] : [timeout, timeout])
    : (controllerId !== null ? [timeout, controllerId] : [timeout]));

  const controllers = await query('SELECT id, name FROM controllers ORDER BY name');
  res.render('sessions/index', { sessions, timeout, show, controllers, controller_id: req.query.controller_id || '' });
}));

module.exports = router;
