function normalizeMac(value) {
  const hex = String(value || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g).join(':');
}

function parseSsid(calledStationId) {
  const text = String(calledStationId || '');
  const colon = text.lastIndexOf(':');
  if (colon === -1) return text.trim() || null;
  return text.slice(colon + 1).trim() || null;
}

function chooseRule(localRule, globalRule) {
  const rule = localRule || globalRule || null;
  if (!rule) return { result: 'reject', reason: 'rule tidak ditemukan' };
  if (rule.status === 'allow') return { result: 'accept', reason: 'rule allow' };
  if (rule.status === 'deny') return { result: 'reject', reason: 'rule deny' };
  return { result: 'reject', reason: 'rule disabled' };
}

// Host IPv4 only, no CIDR. radius/default.conf matches the sender with
// `ip_address = '%{Packet-Src-IP-Address}'` — exact string equality, so a subnet
// row can never match and every packet from it is rejected as "controller tidak
// dikenal". Octet ranges are checked too, otherwise 999.1.1.1 would be stored.
// ponytail: no IPv6 — UniFi sends RADIUS from IPv4. Add a second branch here if
// that changes; the policy comparison itself needs no change.
const HOST_IP_RE = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const isHostIp = value => HOST_IP_RE.test(String(value || ''));

module.exports = { normalizeMac, parseSsid, chooseRule, isHostIp };
