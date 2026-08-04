const cron = require('node-cron');
const { query } = require('./db');
const { notify, loadSettings } = require('./notifications');
const { pendingCount } = require('./pending');

async function runCron() {
  const settings = await loadSettings();
  const retention = parseInt(settings.auth_log_retention_days, 10) || 90;
  const timeout = parseInt(settings.online_session_timeout_minutes, 10) || 120;

  await query('DELETE FROM auth_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [retention]);
  await query('DELETE FROM accounting_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [retention]);
  // Sessions with no accounting update inside the timeout are stale, not online.
  await query('UPDATE sessions SET stopped_at = last_update_at WHERE stopped_at IS NULL AND last_update_at < DATE_SUB(NOW(), INTERVAL ? MINUTE)', [timeout]);
  await query('DELETE FROM notification_log WHERE sent_at < DATE_SUB(NOW(), INTERVAL 30 DAY)');

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

runCron().catch(err => console.error('cron gagal:', err.message));

module.exports = { runCron };
