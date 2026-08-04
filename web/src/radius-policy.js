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

module.exports = { normalizeMac, parseSsid, chooseRule };
