const { query } = require('./db');

// A MAC is "pending approval" when it was rejected and no rule covers it in
// either scope. Matching on the reject *reason* string would break the moment
// the RADIUS policy reworded it, so check rule absence directly.
const PENDING_FROM = `
  FROM auth_logs a
  WHERE a.result = 'reject'
    AND a.mac_address IS NOT NULL AND a.ssid_name IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM mac_rules r
      WHERE r.mac_address = a.mac_address
        AND r.ssid_name = a.ssid_name
        AND (r.controller_id = a.controller_id OR r.controller_id IS NULL)
    )
`;

const PENDING_LIST = `
  SELECT a.mac_address, a.ssid_name, a.controller_id,
         (SELECT c.name FROM controllers c WHERE c.id = a.controller_id) AS controller_name,
         h.hostname,
         MAX(a.created_at) AS last_seen, COUNT(*) AS hit_count
  ${PENDING_FROM}
  LEFT JOIN device_hosts h ON h.controller_id = a.controller_id AND h.mac_address = a.mac_address
  GROUP BY a.mac_address, a.ssid_name, a.controller_id, h.hostname
  ORDER BY last_seen DESC
  LIMIT 500
`;

async function pendingCount() {
  const rows = await query(`SELECT COUNT(*) AS count FROM (
    SELECT 1 ${PENDING_FROM} GROUP BY a.mac_address, a.ssid_name, a.controller_id
  ) t`);
  return rows[0].count;
}

module.exports = { PENDING_FROM, PENDING_LIST, pendingCount };
