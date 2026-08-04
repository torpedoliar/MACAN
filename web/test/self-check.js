const assert = require('assert');
const fs = require('fs');
const path = require('path');
const ejs = require('ejs');
const { normalizeMac, parseSsid, chooseRule, isControllerIp } = require('../src/radius-policy');
const { loginLockedFor, loginFailed, loginSucceeded, MAX_FAILS } = require('../src/middleware');

assert.equal(normalizeMac('AA-BB-CC-DD-EE-FF'), 'aa:bb:cc:dd:ee:ff');
assert.equal(normalizeMac('aabbccddeeff'), 'aa:bb:cc:dd:ee:ff');
assert.equal(normalizeMac('bad'), null);
assert.equal(parseSsid('aa:bb:cc:dd:ee:ff:Office'), 'Office');
assert.deepEqual(chooseRule({ status: 'deny' }, { status: 'allow' }), { result: 'reject', reason: 'rule deny' });
assert.deepEqual(chooseRule(null, { status: 'allow' }), { result: 'accept', reason: 'rule allow' });
assert.deepEqual(chooseRule(null, null), { result: 'reject', reason: 'rule tidak ditemukan' });

// Tmp-Integer-0 holds the controller id from SQL. FreeRADIUS coerces an empty
// result for an *integer* attribute to 0, never "". A `== ""` test is therefore
// dead code: an unknown NAS falls through, every INSERT below carries
// controller_id 0, and the FK rejects it (ERROR 1452) — the operator sees
// "SSID disabled" with nothing at all in auth_logs.
const policy = fs.readFileSync(path.join(__dirname, '..', '..', 'radius', 'default.conf'), 'utf8');
assert.ok(!/Tmp-Integer-0\}"\s*==\s*""/.test(policy),
  'default.conf: Tmp-Integer-0 dibandingkan dengan "" — hasil SQL kosong jadi 0, cabang itu mati');
assert.ok(/"%\{control:Tmp-Integer-0\}"\s*==\s*"0"/.test(policy),
  'default.conf: cabang "controller tidak dikenal" hilang');

// Controller source address: host or subnet. A UniFi AP sends the RADIUS packet
// itself, so the source IP is the AP's — a subnet row is what covers a fleet.
// default.conf must therefore carry the containment arm in BOTH sections; without
// it a /24 row can never match and every AP is dropped as "controller tidak
// dikenal", which is exactly the bug this replaced.
const subnetMatch = policy.match(/INSTR\(ip_address, '\/'\) > 0 AND INET_ATON/g) || [];
assert.equal(subnetMatch.length, 2,
  `default.conf: cabang pencocokan subnet ada ${subnetMatch.length}x, harus 2 (authorize + accounting)`);
// Host rows must still win over a subnet containing them, else a per-AP override
// silently loses to the fleet-wide row.
assert.equal((policy.match(/ORDER BY INSTR\(ip_address, '\/'\) ASC/g) || []).length, 2,
  'default.conf: urutan host-dulu-baru-subnet hilang');

assert.ok(isControllerIp('192.168.1.10'));
assert.ok(isControllerIp('10.0.0.1'));
assert.ok(isControllerIp('10.10.0.0/24'), 'subnet /24 ditolak — AP tidak akan bisa didaftarkan');
assert.ok(isControllerIp('10.0.0.0/8'));
assert.ok(isControllerIp('192.168.1.10/32'));
assert.ok(!isControllerIp('10.0.0.0/0'), 'prefix /0 diterima — secret berlaku untuk semua IP');
assert.ok(!isControllerIp('10.0.0.0/7'), 'prefix lebih lebar dari /8 diterima');
assert.ok(!isControllerIp('10.0.0.0/33'), 'prefix di luar 0-32 diterima');
assert.ok(!isControllerIp('999.1.1.1'), 'oktet di luar 0-255 diterima');
assert.ok(!isControllerIp('192.168.1'), 'IP tidak lengkap diterima');
assert.ok(!isControllerIp('192.168.1.0/24/8'));
assert.ok(!isControllerIp(''));

// Login brake. Two buckets, so an attacker rotating X-Forwarded-For must still
// trip the email bucket — that is the whole point of the second key and the part
// that would silently rot if someone "simplified" loginKeys back to one.
const attempt = (ip, email) => ({ ip, body: { email } });
for (let i = 0; i < MAX_FAILS; i++) {
  assert.equal(loginLockedFor(attempt('1.1.1.1', 'a@b.c')), 0, `terkunci terlalu cepat di percobaan ${i + 1}`);
  loginFailed(attempt('1.1.1.1', 'a@b.c'));
}
assert.ok(loginLockedFor(attempt('1.1.1.1', 'a@b.c')) > 0, 'tidak terkunci setelah MAX_FAILS');
// Same account from a fresh IP: still locked, via the email bucket.
assert.ok(loginLockedFor(attempt('9.9.9.9', 'a@b.c')) > 0, 'ganti IP bisa lolos — bucket email tidak jalan');
// Same IP, different account: locked too, via the IP bucket.
assert.ok(loginLockedFor(attempt('1.1.1.1', 'z@b.c')) > 0, 'bucket IP tidak jalan');
// An unrelated client is unaffected.
assert.equal(loginLockedFor(attempt('2.2.2.2', 'c@d.e')), 0, 'klien lain ikut terkunci');
loginSucceeded(attempt('1.1.1.1', 'a@b.c'));
assert.equal(loginLockedFor(attempt('1.1.1.1', 'a@b.c')), 0, 'login sukses tidak menghapus hitungan');
// Case-insensitive: A@B.C and a@b.c are the same account.
loginSucceeded(attempt('1.1.1.1', 'A@B.C'));
for (let i = 0; i < MAX_FAILS; i++) loginFailed(attempt('3.3.3.3', 'MiXeD@b.c'));
assert.ok(loginLockedFor(attempt('4.4.4.4', 'mixed@b.c')) > 0, 'email tidak dinormalkan ke lowercase');

// Every view must compile, and every POST form must carry a CSRF field. Both
// classes of bug only surface at request time otherwise, and a broken view means
// a blank page after login — which is exactly how this app failed before.
const VIEWS = path.join(__dirname, '..', 'src', 'views');
const files = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.ejs')) files.push(full);
  }
})(VIEWS);
assert.ok(files.length >= 15, `hanya ${files.length} view ditemukan`);

for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  const rel = path.relative(VIEWS, file).replace(/\\/g, '/');
  // Syntax only — rendering happens below with sample locals.
  ejs.compile(src, { filename: file, root: VIEWS, views: [VIEWS] });

  // Partial includes must be absolute from the views root; a relative include
  // resolves against the including file's directory and breaks in subfolders.
  for (const m of src.matchAll(/include\(\s*'([^']+)'/g)) {
    assert.ok(m[1].startsWith('/'), `${rel}: include('${m[1]}') harus absolut, mis. '/partials/head'`);
  }

  const forms = src.match(/<form[^>]*method="POST"[\s\S]*?<\/form>/gi) || [];
  forms.forEach((form, i) => {
    assert.ok(form.includes('name="_csrf"'), `${rel}: form POST #${i + 1} tidak punya field _csrf`);
  });

  // The Telegram token is masked by routes/settings.js on purpose; echoing it
  // back into an input would undo that.
  assert.ok(!/name="telegram_bot_token"[^>]*value=/.test(src),
    `${rel}: nilai telegram_bot_token tidak boleh dikembalikan ke input`);
}

// Over-length input hits STRICT_TRANS_TABLES and comes back as a 500 page unless
// the browser stops it first, so every free-text field that lands in a VARCHAR
// must carry maxlength — and it must match the column, not merely exist.
const MAXLEN = {
  'controllers/form': { name: 120, ip_address: 45, shared_secret: 255, note: 65535 },
  'rules/form': { mac_address: 17, ssid_name: 128, owner_name: 160, device_name: 160 },
  'ssids/index': { ssid_name: 128 }
};
for (const [view, fields] of Object.entries(MAXLEN)) {
  // Strip EJS tags first: a `value="<%= x %>"` attribute contains a ">" that ends
  // the [^>]* scan early, hiding attributes written after it.
  const src = fs.readFileSync(path.join(VIEWS, view + '.ejs'), 'utf8').replace(/<%[\s\S]*?%>/g, '');
  for (const [field, limit] of Object.entries(fields)) {
    // TEXT columns (65535) are effectively unbounded for a form; skip those.
    if (limit === 65535) continue;
    const tag = new RegExp(`<(?:input|textarea)[^>]*name="${field}"[^>]*>`).exec(src);
    assert.ok(tag, `${view}.ejs: field "${field}" tidak ditemukan`);
    const found = /maxlength="(\d+)"/.exec(tag[0]);
    assert.ok(found, `${view}.ejs: "${field}" tanpa maxlength — over-length jadi error 500`);
    assert.equal(Number(found[1]), limit,
      `${view}.ejs: maxlength "${field}" = ${found[1]}, kolomnya ${limit}`);
  }
}

// Every route's res.render target must exist.
const ROUTES = path.join(__dirname, '..', 'src');
const rendered = new Set();
(function walkJs(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name !== 'views') walkJs(full);
    else if (entry.name.endsWith('.js')) {
      const src = fs.readFileSync(full, 'utf8');
      for (const m of src.matchAll(/res\.render\(\s*'([^']+)'/g)) rendered.add(m[1]);
      // The global csrf middleware cannot check a multipart body — multer parses
      // it later, inside the route — so every upload route must call verifyCsrf
      // itself right after the upload middleware. Missing it = unprotected POST.
      for (const m of src.matchAll(/router\.post\(([^;]*?upload\.single\([^)]*\)[^;]*?),\s*wrap/g)) {
        assert.ok(m[1].includes('verifyCsrf'),
          `${entry.name}: route upload tanpa verifyCsrf — ${m[1].slice(0, 60)}`);
      }
    }
  }
})(ROUTES);
for (const view of rendered) {
  assert.ok(fs.existsSync(path.join(VIEWS, view + '.ejs')), `view "${view}" dirender tapi filenya tidak ada`);
}

// Express merges app.settings into the render data under the key `settings`, and
// EJS reads data.settings['view options'] to find its include root. A local of
// that name shadows it and every absolute include() in the view dies with ENOENT
// — at request time only, which is how it slipped through once already.
const RESERVED = ['settings', 'cache', 'filename', '_locals'];
(function walkLocals(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name !== 'views') walkLocals(full);
    else if (entry.name.endsWith('.js')) {
      const src = fs.readFileSync(full, 'utf8');
      for (const m of src.matchAll(/res\.render\(\s*'[^']+',\s*\{([\s\S]{0,600}?)\n\s*\}\)/g)) {
        for (const name of RESERVED) {
          assert.ok(!new RegExp(`(^|[\\s,{])${name}\\s*[:,]`).test(m[1]),
            `${path.basename(full)}: local "${name}" bentrok dengan internal Express/EJS — ganti namanya`);
        }
      }
    }
  }
})(ROUTES);

// Render each page with plausible locals, then again with every array emptied,
// so both the populated and the empty-state branch execute. A template that
// throws at request time is what turned "after login" into a blank page before.
const now = new Date().toISOString();
const shell = { title: 'X', csrfToken: 'tok', currentPath: '/', admin: { id: 1, email: 'a@b.c' },
                maintenance: true, pendingCount: 2 };
const CASES = {
  'login': { error: 'salah' },
  'error': { status: 404, message: 'nope' },
  'dashboard': {
    stats: { online: 1, pending: 2, rulesTotal: 3, rulesAllow: 2, rulesDeny: 1, rulesDisabled: 0,
             controllers: 1, controllersEnabled: 1, ssids: 2, ssidsEnabled: 1, accepts24: 5, rejects24: 1 },
    chart: [{ label: '01:00', accepts: 2, rejects: 1 }, { label: '02:00', accepts: 0, rejects: 0 }],
    recent: [{ created_at: now, mac_address: 'aa:bb:cc:dd:ee:ff', ssid_name: 'S',
               controller_name: 'C', result: 'accept', reason: 'rule allow' }]
  },
  'rules/index': {
    rules: [{ id: 1, mac_address: 'aa:bb:cc:dd:ee:ff', ssid_name: 'S', controller_id: null,
              controller_name: null, status: 'allow', owner_name: 'B', device_name: 'D',
              note: 'n', updated_at: now, last_seen_at: now }],
    controllers: [{ id: 1, name: 'C' }], filters: { q: '', status: '', controller_id: '' },
    imported: '3', skipped: '1', error: 'e'
  },
  'rules/form': { rule: {}, controllers: [{ id: 1, name: 'C' }], error: 'e' },
  'approvals/index': {
    pending: [{ mac_address: 'aa:bb:cc:dd:ee:ff', ssid_name: 'S', controller_id: 1,
                controller_name: 'C', last_seen: now, hit_count: 3 }],
    error: 'e', approved: '1'
  },
  'controllers/index': {
    controllers: [{ id: 1, name: 'C', ip_address: '10.0.0.1', enabled: 1, note: 'n',
                    ssid_count: 1, rule_count: 2 }], error: 'e', notice: 'n'
  },
  'controllers/form': { controller: {}, error: 'e' },
  'ssids/index': {
    ssids: [{ id: 1, ssid_name: 'S', controller_name: 'C', enabled: 1, auto_created: 1,
              rule_count: 1, last_seen_at: now }],
    controllers: [{ id: 1, name: 'C' }], error: 'e', notice: 'n'
  },
  'logs/index': {
    logs: [{ created_at: now, mac_address: 'aa:bb:cc:dd:ee:ff', ssid_name: 'S',
             controller_name: 'C', result: 'reject', reason: 'r' }],
    controllers: [{ id: 1, name: 'C' }], total: 1, page: 2, pages: 3,
    filters: { mac: '', ssid: '', result: '', controller_id: '', from: '', to: '' }
  },
  'sessions/index': {
    sessions: [{ mac_address: 'aa:bb:cc:dd:ee:ff', ssid_name: 'S', controller_name: 'C',
                 session_id: 'sid', started_at: now, last_update_at: now, stopped_at: null,
                 duration_seconds: 4000, is_online: 1 }],
    timeout: 120, show: 'all'
  },
  'audit/index': {
    logs: [{ created_at: now, admin_email: 'a@b.c', ip_address: '10.0.0.5', action: 'login', details: { a: 1 } },
           { created_at: now, admin_email: null, ip_address: null, action: 'x', details: 'str' }],
    admins: [{ id: 1, email: 'a@b.c' }], total: 2, page: 1, pages: 1,
    filters: { action: '', admin_id: '' }
  },
  'settings/index': {
    cfg: { auth_log_retention_days: '90', online_session_timeout_minutes: '120',
           reject_spike_count: '5', reject_spike_window_minutes: '10',
           notification_dedupe_minutes: '60', notification_webhook_url: '',
           telegram_bot_token: '', telegram_chat_id: '', maintenance_mode: '1' },
    hasSecret: { telegram_bot_token: true }, errors: ['e'], saved: '1', tested: 'ok'
  },
  'data/index': {
    counts: { controllers: 1, ssids: 2, mac_rules: 3, settings: 9 },
    staged: { generated_at: now, rows: [{ table: 'controllers', incoming: 1, current: 1 }] },
    error: 'e', notice: 'n'
  }
};

for (const [view, locals] of Object.entries(CASES)) {
  const file = path.join(VIEWS, view + '.ejs');
  const src = fs.readFileSync(file, 'utf8');
  const emptied = Object.fromEntries(Object.entries(locals)
    .map(([k, v]) => [k, Array.isArray(v) ? [] : (k === 'staged' ? null : v)]));
  for (const variant of [locals, emptied]) {
    try {
      ejs.render(src, { ...shell, ...variant }, { filename: file, root: VIEWS, views: [VIEWS] });
    } catch (err) {
      throw new Error(`render ${view} gagal: ${err.message}`);
    }
  }
}
assert.equal(Object.keys(CASES).length, rendered.size,
  `${rendered.size} view dirender oleh route, tapi hanya ${Object.keys(CASES).length} punya kasus render`);

// The audit IP travels through AsyncLocalStorage instead of a `req` argument, so
// nothing at the call site shows whether it still works. Intercept at the pool —
// audit.js destructures `query` at require time, so stubbing db.query would be
// too late to be seen.
const db = require('../src/db');
const captured = [];
db.pool.execute = async (sql, params) => { captured.push(params); return [[]]; };
const { writeAudit, auditContext } = require('../src/audit');

// Inside a request the IP must survive an await boundary — that is where a naive
// module-level global would lose it and where ALS earns its place. Outside any
// request (cron, startup) there is no store and the column must be NULL, not a
// leftover from whichever request last ran on this tick.
const auditChecks = new Promise(resolve => {
  auditContext({ ip: '203.0.113.9' }, null, () => {
    resolve((async () => {
      await new Promise(r => setImmediate(r));
      await writeAudit(1, 'login', {});
      assert.equal(captured[0][2], '203.0.113.9', 'IP tidak terbawa lewat AsyncLocalStorage');
    })());
  });
}).then(() => writeAudit(2, 'cron', {})).then(() => {
  assert.strictEqual(captured[1][2], null, 'IP bocor ke pemanggil di luar request');
});

auditChecks.then(() => {
  console.log(`self-check passed — ${files.length} view compile, ${rendered.size} view render (isi + kosong)`);
  // The mysql2 pool was created by requiring db.js; nothing connected, but close
  // it so the process exits on its own.
  return db.pool.end().catch(() => {});
});

