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

// Controller source address: one host (10.10.0.100) or one subnet (10.10.0.0/24).
// A UniFi AP sends the RADIUS packet itself, so the source IP is the AP's, not the
// controller's — a subnet row is the only practical way to cover a fleet of them.
// radius/default.conf matches both, and FreeRADIUS' rlm_sql client list accepts a
// CIDR nasname natively, so the socket layer needs no separate rule.
//
// Octet ranges are checked, otherwise 999.1.1.1 would be stored. Prefix is capped
// at /8: anything wider makes the shared secret usable from practically any source
// address, which is a blast radius no LAN needs.
// ponytail: no IPv6 — UniFi sends RADIUS from IPv4. Add a second branch here and an
// INET6_ATON arm in default.conf if that changes.
const OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const CONTROLLER_IP_RE = new RegExp(`^(${OCTET}\\.){3}${OCTET}(/(3[0-2]|2\\d|1\\d|[89]))?$`);
const isControllerIp = value => CONTROLLER_IP_RE.test(String(value || ''));

module.exports = { normalizeMac, parseSsid, chooseRule, isControllerIp };
