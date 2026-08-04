const { query } = require('./db');

async function writeAudit(adminId, action, details = {}) {
  await query('INSERT INTO audit_logs (admin_id, action, details) VALUES (?, ?, ?)', [
    adminId || null,
    action,
    JSON.stringify(details)
  ]);
}

module.exports = { writeAudit };
