const cron = require('node-cron');
const { query } = require('./db');
const { writeAudit } = require('./audit');
const { notify, loadSettings } = require('./notifications');
const { pendingCount } = require('./pending');
const { refreshOui } = require('./oui');
const { syncAllControllers } = require('./unifi');

// A rule nobody has connected with for `inactive_after_days` is stale access:
// flip it to deny and stamp inactive_since so the page can say why. Only allow
// rules are touched — a deny stays deny.
//
// Two clocks, both must be past the threshold:
//   last_seen_at — when the device last authenticated (NULL = never; fall back to
//                  updated_at so a rule registered today isn't denied tomorrow).
//   updated_at   — when an admin last touched the row. Without this, re-allowing a
//                  rule the sweep denied would be undone on the next tick, because
//                  its last_seen_at is still months old. The admin's edit IS the
//                  activity signal.
const INACTIVE_WHERE = `
  WHERE status = 'allow' AND inactive_since IS NULL
    AND IFNULL(last_seen_at, updated_at) < DATE_SUB(NOW(), INTERVAL ? DAY)
    AND updated_at < DATE_SUB(NOW(), INTERVAL ? DAY)
`;

async function sweepInactive(days) {
  const stale = await query(`SELECT id, mac_address, ssid_name FROM mac_rules ${INACTIVE_WHERE}`, [days, days]);
  if (!stale.length) return 0;
  await query(`UPDATE mac_rules SET status = 'deny', inactive_since = NOW() ${INACTIVE_WHERE}`, [days, days]);
  // admin_id NULL: cron acted, not a person. The trail matters more than the actor.
  await writeAudit(null, 'rule_auto_inactive', {
    days,
    count: stale.length,
    macs: stale.slice(0, 50).map(r => `${r.mac_address}@${r.ssid_name}`)
  });
  return stale.length;
}

async function runCron() {
  const settings = await loadSettings();
  const retention = parseInt(settings.auth_log_retention_days, 10) || 90;
  const timeout = parseInt(settings.online_session_timeout_minutes, 10) || 120;
  const inactiveDays = parseInt(settings.inactive_after_days, 10) || 90;

  await query('DELETE FROM auth_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [retention]);
  await query('DELETE FROM accounting_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [retention]);
  // Sessions with no accounting update inside the timeout are stale, not online.
  await query('UPDATE sessions SET stopped_at = last_update_at WHERE stopped_at IS NULL AND last_update_at < DATE_SUB(NOW(), INTERVAL ? MINUTE)', [timeout]);
  await query('DELETE FROM notification_log WHERE sent_at < DATE_SUB(NOW(), INTERVAL 30 DAY)');

  const flipped = await sweepInactive(inactiveDays);
  if (flipped > 0) {
    await notify('rule_inactive', `MACan: ${flipped} MAC tidak terhubung lebih dari ${inactiveDays} hari, status diubah jadi deny (Inactive).`, settings);
  }

  const window = parseInt(settings.reject_spike_window_minutes, 10) || 10;
  const threshold = parseInt(settings.reject_spike_count, 10) || 5;

  const spikes = await query(`
    SELECT mac_address, ssid_name, COUNT(*) AS hits
    FROM auth_logs
    WHERE result = 'reject' AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)
    GROUP BY mac_address, ssid_name
    HAVING hits >= ?
  `, [window, threshold]);

  for (const spike of spikes) {
    await notify(
      `reject_spike:${spike.mac_address}:${spike.ssid_name}`,
      `MACan: ${spike.mac_address} ditolak ${spike.hits}x di SSID ${spike.ssid_name} dalam ${window} menit.`,
      settings
    );
  }

  const unknown = await query(`
    SELECT COUNT(*) AS count FROM ssids
    WHERE auto_created = 1 AND enabled = 0 AND last_seen_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
  `);
  if (Number(unknown[0].count) > 0) {
    await notify('unknown_ssid', `MACan: ${unknown[0].count} SSID baru terdeteksi dan masih disabled. Cek halaman SSID.`, settings);
  }

  const pending = await pendingCount();
  if (pending > 0) {
    await notify('pending_approval', `MACan: ${pending} MAC menunggu approval.`, settings);
  }
}

// Hourly at minute 7 — off the top of the hour so it doesn't stack with
// everything else in the environment that fires at :00.
cron.schedule('7 * * * *', () => {
  runCron().catch(err => console.error('cron gagal:', err.message));
});

// UniFi hostname sync every 15 minutes — a client's hostname shows up only
// after it has connected to the controller, and changes when renamed. Guarded
// by unifi_sync_enabled so it's a no-op until the admin opts in. Own try/catch:
// an offline controller must not abort log retention or the inactive sweep.
cron.schedule('*/15 * * * *', () => {
  (async () => {
    const settings = await loadSettings();
    if (settings.unifi_sync_enabled !== '1') return;
    await syncAllControllers();
  })().catch(err => console.error('unifi sync gagal:', err.message));
});

// OUI vendor table refresh — monthly on the 1st at 03:07. Guarded by
// oui_last_refresh so a container restart never redownloads the 4MB file:
// only refresh if the last one was >30 days ago (or never). Own try/catch.
cron.schedule('7 3 1 * *', () => {
  (async () => {
    const settings = await loadSettings();
    const last = settings.oui_last_refresh || '';
    if (last) {
      const age = Date.now() - new Date(last).getTime();
      if (age < 30 * 86400 * 1000) return;
    }
    const r = await refreshOui();
    console.log(`OUI refresh: ${r.total} vendor, ${r.fetched} byte`);
  })().catch(err => console.error('OUI refresh gagal:', err.message));
});

runCron().catch(err => console.error('cron gagal:', err.message));

module.exports = { runCron, sweepInactive };
