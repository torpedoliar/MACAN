const express = require('express');
const { query } = require('../db');
const { pendingCount } = require('../pending');
const { wrap } = require('../middleware');
const router = express.Router();

router.get('/', wrap(async (req, res) => {
  const timeoutRows = await query('SELECT value FROM settings WHERE name = ?', ['online_session_timeout_minutes']);
  const timeout = parseInt(timeoutRows.length ? timeoutRows[0].value : '120', 10) || 120;

  const [online, rules, controllers, ssids, auth24, pending] = await Promise.all([
    query('SELECT COUNT(*) AS count FROM sessions WHERE stopped_at IS NULL AND last_update_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)', [timeout]),
    query(`SELECT
             COUNT(*) AS total,
             SUM(status = 'allow') AS allow_count,
             SUM(status = 'deny') AS deny_count,
             SUM(status = 'disabled') AS disabled_count
           FROM mac_rules`),
    query('SELECT COUNT(*) AS total, SUM(enabled = 1) AS enabled_count FROM controllers'),
    query('SELECT COUNT(*) AS total, SUM(enabled = 1) AS enabled_count FROM ssids'),
    query(`SELECT SUM(result = 'accept') AS accepts, SUM(result = 'reject') AS rejects
           FROM auth_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)`),
    pendingCount()
  ]);

  // 24 buckets, oldest first. LEFT JOIN against a generated hour series so empty
  // hours render as 0 instead of collapsing the chart.
  const buckets = await query(`
    SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') AS hour,
           SUM(result = 'accept') AS accepts,
           SUM(result = 'reject') AS rejects
    FROM auth_logs
    WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    GROUP BY hour ORDER BY hour
  `);
  const byHour = new Map(buckets.map(b => [b.hour, b]));
  const chart = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600 * 1000);
    const pad = n => String(n).padStart(2, '0');
    const key = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:00`;
    const hit = byHour.get(key);
    chart.push({
      label: `${pad(d.getHours())}:00`,
      accepts: hit ? Number(hit.accepts) : 0,
      rejects: hit ? Number(hit.rejects) : 0
    });
  }

  const recent = await query(`
    SELECT a.*, c.name AS controller_name
    FROM auth_logs a LEFT JOIN controllers c ON a.controller_id = c.id
    ORDER BY a.created_at DESC LIMIT 10
  `);

  res.render('dashboard', {
    stats: {
      online: Number(online[0].count),
      pending,
      rulesTotal: Number(rules[0].total),
      rulesAllow: Number(rules[0].allow_count || 0),
      rulesDeny: Number(rules[0].deny_count || 0),
      rulesDisabled: Number(rules[0].disabled_count || 0),
      controllers: Number(controllers[0].total),
      controllersEnabled: Number(controllers[0].enabled_count || 0),
      ssids: Number(ssids[0].total),
      ssidsEnabled: Number(ssids[0].enabled_count || 0),
      accepts24: Number(auth24[0].accepts || 0),
      rejects24: Number(auth24[0].rejects || 0)
    },
    chart,
    recent
  });
}));

module.exports = router;
