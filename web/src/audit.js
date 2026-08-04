const { AsyncLocalStorage } = require('node:async_hooks');
const { query } = require('./db');

// ponytail: request context via AsyncLocalStorage (stdlib) instead of threading a
// `req` argument through every writeAudit call site. Any call site added later
// records the IP for free. A call made outside a request (cron, startup) has no
// store, so the column stays NULL — the honest answer, not an invented one.
// Upgrade path: if more than the IP is ever needed, put it in the same store
// object rather than growing the writeAudit signature.
const context = new AsyncLocalStorage();

function auditContext(req, res, next) {
  // `trust proxy` is on, so this can be spoofed via X-Forwarded-For. Good enough
  // for "was that us?" on a trusted LAN; not evidence.
  context.run({ ip: String(req.ip || '').slice(0, 45) || null }, next);
}

async function writeAudit(adminId, action, details = {}) {
  const store = context.getStore();
  await query('INSERT INTO audit_logs (admin_id, action, ip_address, details) VALUES (?, ?, ?, ?)', [
    adminId || null,
    action,
    (store && store.ip) || null,
    JSON.stringify(details)
  ]);
}

module.exports = { writeAudit, auditContext };
