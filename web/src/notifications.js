const https = require('https');
const http = require('http');
const { query } = require('./db');

// ponytail: node's own http/https instead of adding axios/node-fetch polyfill.
// Node 20 has global fetch, but it has no per-request timeout without an
// AbortController dance, so a 30-line raw request is the smaller path.
function post(url, body) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(url);
    } catch {
      return reject(new Error('URL tidak valid'));
    }
    const client = target.protocol === 'https:' ? https : http;
    if (target.protocol !== 'https:' && target.protocol !== 'http:') {
      return reject(new Error(`Protokol ${target.protocol} tidak didukung`));
    }
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const req = client.request(target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length },
      timeout: 8000
    }, res => {
      res.resume(); // drain so the socket can be reused/closed
      if (res.statusCode >= 200 && res.statusCode < 300) return resolve();
      reject(new Error(`HTTP ${res.statusCode}`));
    });
    req.on('timeout', () => req.destroy(new Error('timeout setelah 8s')));
    req.on('error', reject);
    req.end(payload);
  });
}

async function loadSettings() {
  const rows = await query('SELECT name, value FROM settings');
  return rows.reduce((acc, row) => ({ ...acc, [row.name]: row.value }), {});
}

async function recordError(message) {
  await query('INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)',
    ['notification_last_error', message ? `${new Date().toISOString()} ${message}` : '']);
}

// Returns false when this event_key was already sent inside the dedupe window.
async function claim(eventKey, channel, dedupeMinutes) {
  if (dedupeMinutes > 0) {
    const seen = await query(
      'SELECT id FROM notification_log WHERE event_key = ? AND channel = ? AND sent_at > DATE_SUB(NOW(), INTERVAL ? MINUTE) LIMIT 1',
      [eventKey, channel, dedupeMinutes]
    );
    if (seen.length) return false;
  }
  await query('INSERT INTO notification_log (event_key, channel) VALUES (?, ?)', [eventKey, channel]);
  return true;
}

// Sends `text` to every configured channel. eventKey null = no dedupe (test sends).
async function notify(eventKey, text, settingsIn) {
  const settings = settingsIn || await loadSettings();
  const dedupe = eventKey ? (parseInt(settings.notification_dedupe_minutes, 10) || 0) : 0;
  const sent = [];
  const failures = [];

  if (settings.telegram_bot_token && settings.telegram_chat_id) {
    if (!eventKey || await claim(eventKey, 'telegram', dedupe)) {
      try {
        await post(`https://api.telegram.org/bot${settings.telegram_bot_token}/sendMessage`, {
          chat_id: settings.telegram_chat_id,
          text
        });
        sent.push('telegram');
      } catch (err) {
        failures.push(`telegram: ${err.message}`);
      }
    }
  }

  if (settings.notification_webhook_url) {
    if (!eventKey || await claim(eventKey, 'webhook', dedupe)) {
      try {
        await post(settings.notification_webhook_url, { source: 'macan', text, at: new Date().toISOString() });
        sent.push('webhook');
      } catch (err) {
        failures.push(`webhook: ${err.message}`);
      }
    }
  }

  if (failures.length) await recordError(failures.join('; '));
  else if (sent.length) await recordError('');
  return { sent, failures };
}

async function sendTest() {
  const settings = await loadSettings();
  const configured = Boolean(settings.telegram_bot_token && settings.telegram_chat_id) || Boolean(settings.notification_webhook_url);
  if (!configured) return { ok: false, channels: [], message: 'Belum ada channel notifikasi yang dikonfigurasi.' };
  const { sent, failures } = await notify(null, 'MACan: tes notifikasi berhasil.', settings);
  if (failures.length) {
    return { ok: false, channels: sent, message: `Gagal: ${failures.join('; ')}` };
  }
  return { ok: true, channels: sent, message: `Terkirim ke ${sent.join(', ')}.` };
}

module.exports = { notify, sendTest, loadSettings, recordError };
