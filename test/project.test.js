const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const vm = require('vm');
const { once } = require('events');
const { createApp } = require('../server');
const { createReceiver } = require('../receiver');
const format = require('../public/package-format');
const { validatePackage } = require('../package-format');
const { changePassphrase } = require('../scripts/change-passphrase');
const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'internal-docs' };
if (fs.existsSync('.env')) process.loadEnvFile('.env');

async function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'atbm-test-'));
  let server, app;
  const mysql = require('mysql2/promise');
  const { databaseConfig } = require('../store');
  const dbConfig = { ...databaseConfig(process.env), database: 'atbm_test_' + crypto.randomBytes(8).toString('hex') };
  t.after(async () => {
    if (server?.listening) await new Promise(resolve => server.close(resolve));
    if (app) await app.close();
    const connection = await mysql.createConnection({ ...dbConfig, database: undefined });
    try {
      assert.match(dbConfig.database, /^atbm_test_[a-f0-9]{16}$/);
      await connection.query('DROP DATABASE IF EXISTS `' + dbConfig.database + '`');
    } finally { await connection.end(); }
    // root được tạo riêng bằng mkdtemp, không dùng thư mục dữ liệu thật.
    fs.rmSync(root, { recursive: true, force: true });
  });
  const dataDir = path.join(root, 'storage'), keyDir = path.join(root, 'keys');
  app = await createApp({ env: {}, dataDir, keyDir, dbConfig, ...options });
  server = app.server;
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = 'http://127.0.0.1:' + server.address().port;
  async function call(route, body, cookie, extra = {}) {
    return fetch(base + route, { method: body === undefined ? 'GET' : 'POST',
      headers: { ...headers, ...(cookie ? { Cookie: cookie } : {}), ...extra },
      ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }) });
  }
  async function login(username, password) {
    const response = await call('/api/login', { username, password });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('set-cookie'), /HttpOnly; SameSite=Strict; Max-Age=/);
    return response.headers.get('set-cookie').split(';')[0];
  }
  return { ...app, root, dataDir, keyDir, dbConfig, call, login, base };
}
function legacyPackage(pem, content) {
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(content), cipher.final(), cipher.getAuthTag()]);
  return { sender: 'Nhân viên A', title: 'Tài liệu cũ', category: 'Khác', filename: 'old.txt',
    encKey: crypto.publicEncrypt({ key: pem, oaepHash: 'sha256' }, key).toString('base64'),
    iv: iv.toString('base64'), data: data.toString('base64') };
}

test('Luồng gửi/nhận bằng mã Web Crypto thực tế và các tình huống bảo mật', async t => {
  const app = await fixture(t);
  const employee = await app.login('nhanvien', '123456');
  const boss = await app.login('boss', 'admin123');
  const key = await (await app.call('/api/public-key', undefined, employee)).json();
  await t.test('Trang chủ và liên kết thương hiệu đi đúng vai trò', async () => {
    const redirect = await fetch(app.base + '/', { headers: { Cookie: boss }, redirect: 'manual' });
    assert.equal(redirect.status, 302);
    assert.equal(redirect.headers.get('location'), '/admin');
    for (const route of ['/admin', '/tool']) {
      const response = await app.call(route, undefined, boss);
      assert.equal(response.status, 200);
      assert.match(await response.text(), /class="brand" href="\/admin"/);
    }
    const employeeHome = await app.call('/', undefined, employee);
    assert.equal(employeeHome.status, 200);
    assert.match(await employeeHome.text(), /class="brand" href="\/"/);
    const anonymous = await fetch(app.base + '/', { redirect: 'manual' });
    assert.equal(anonymous.headers.get('location'), '/login');
    assert.equal((await app.call('/api/upload', {}, boss)).status, 403);
  });
  let packageSent, lastId;
  const browser = vm.createContext({ window: { crypto: crypto.webcrypto }, crypto: crypto.webcrypto,
    PackageFormat: format, Uint8Array, TextEncoder, btoa,
    App: {
      bytes: value => Uint8Array.from(atob(value), c => c.charCodeAt(0)),
      async request(route, body) {
        if (route === '/api/upload') packageSent = structuredClone(body);
        const response = await app.call(route, body, employee), result = await response.json();
        if (!response.ok) throw Error(result.error);
        if (route === '/api/upload') lastId = result.id;
        return result;
      }
    }
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/sender.js'), 'utf8'), browser);
  for (const [name, content] of [['empty.txt', Buffer.alloc(0)], ['tiếng Việt.txt', Buffer.from('Báo cáo có dấu tiếng Việt')], ['binary.bin', crypto.randomBytes(4096)]]) {
    await t.test('Mã hoá rồi giải mã: ' + name, async () => {
      const file = { name, size: content.length, arrayBuffer: async () => Uint8Array.from(content).buffer };
      await browser.encryptAndSend(file, { title: 'Báo cáo', category: 'Khác' }, () => {});
      const response = await app.call('/api/decrypt', { id: lastId, passphrase: 'boss123' }, boss);
      assert.equal(response.status, 200);
      assert.deepEqual(Buffer.from((await response.json()).data, 'base64'), content);
      const stored = JSON.parse(fs.readFileSync(path.join(app.dataDir, lastId + '.json')));
      assert.equal(stored.senderUsername, 'nhanvien'); assert.equal(stored.version, 3);
      assert.equal(stored.passphrase, undefined);
      packageSent = stored;
    });
  }
  await t.test('Phân quyền và giới hạn HTTP method', async () => {
    assert.equal((await app.call('/api/list')).status, 401);
    assert.equal((await app.call('/api/list', undefined, employee)).status, 403);
    assert.equal((await app.call('/api/decrypt', { id: lastId, passphrase: 'boss123' }, employee)).status, 403);
    assert.equal((await app.call('/api/upload', undefined, employee)).status, 405);
    assert.equal((await app.call('/logout', undefined, boss)).status, 405);
    assert.equal((await app.call('/keystore/receiver/boss_private.pem', undefined, boss)).status, 404);
  });
  await t.test('Chặn giả danh, JSON lỗi và gói sai cấu trúc', async () => {
    assert.equal((await app.call('/api/upload', { ...packageSent, sender: 'Boss', senderUsername: 'boss' }, employee)).status, 400);
    assert.equal((await app.call('/api/upload', '{broken', employee)).status, 400);
    for (const mutation of [{ iv: 'bad' }, { encKey: '!!!' }, { filename: '../x' }, { fileSize: -1 }, { fileSize: format.MAX_FILE_BYTES + 1 }, { version: 99 }])
      assert.equal((await app.call('/api/upload', { ...packageSent, ...mutation }, employee)).status, 400);
    assert.equal((await app.call('/api/raw?id=../../receiver', undefined, boss)).status, 400);
    assert.equal((await app.call('/api/raw?id=1794737203890-ffffff', undefined, boss)).status, 404);
  });
  await t.test('Sai passphrase, sửa metadata và sửa ciphertext đều thất bại', async () => {
    assert.equal((await app.call('/api/decrypt', { id: lastId, passphrase: 'wrong' }, boss)).status, 422);
    for (const mutation of [{ title: 'Đã sửa' }, { filename: 'changed.bin' }, { senderUsername: 'boss' },
      { sender: 'Boss' }, { category: format.CATEGORIES[0] }, { keyId: '0'.repeat(64) }]) {
      assert.equal((await app.call('/api/decrypt', { pkg: { ...packageSent, ...mutation }, passphrase: 'boss123' }, boss)).status, 422);
    }
    for (const field of ['data', 'iv', 'encKey']) {
      const bytes = Buffer.from(packageSent[field], 'base64'); bytes[0] ^= 1;
      assert.equal((await app.call('/api/decrypt', { pkg: { ...packageSent, [field]: bytes.toString('base64') }, passphrase: 'boss123' }, boss)).status, 422);
    }
    const downgraded = { ...packageSent }; delete downgraded.version;
    assert.equal((await app.call('/api/decrypt', { pkg: downgraded, passphrase: 'boss123' }, boss)).status, 422);
  });
  await t.test('Gói cũ được mở nhưng không được upload như tài liệu mới', async () => {
    const legacy = legacyPackage(key.pem, Buffer.from('legacy data'));
    const response = await app.call('/api/decrypt', { pkg: legacy, passphrase: 'boss123' }, boss);
    assert.equal(response.status, 200);
    const result = await response.json(); assert.equal(result.legacy, true);
    assert.equal(Buffer.from(result.data, 'base64').toString(), 'legacy data');
    assert.equal((await app.call('/api/upload', legacy, employee)).status, 400);
  });
  await t.test('Một file hỏng không làm mất toàn bộ hộp thư; size là byte gốc', async () => {
    fs.writeFileSync(path.join(app.dataDir, '1794737203890-deadbe.json'), '{bad');
    const admin = await app.login('quantri', 'quantri123');
    assert.equal((await app.call('/api/maintenance/reindex', {}, admin)).status, 200);
    const response = await app.call('/api/list', undefined, boss);
    assert.equal(response.status, 200);
    const result = await response.json(); assert.equal(result.skipped, 1);
    assert.equal(result.documents.length, 3);
    assert.equal(result.documents.find(p => p.id === lastId).size, 4096);
    assert.equal(result.documents[0].encKey, undefined);
  });
  await t.test('Chặn request từ origin khác và content type không hợp lệ', async () => {
    assert.equal((await app.call('/api/upload', packageSent, employee, { Origin: 'https://attacker.example' })).status, 403);
    assert.equal((await app.call('/api/upload', packageSent, employee, { 'Content-Type': 'text/plain' })).status, 415);
    const response = await app.call('/api/me', undefined, employee);
    assert.match(response.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });
  await t.test('Đổi passphrase giữ nguyên khoá và mở được dữ liệu cũ', async () => {
    const next = 'new-strong-passphrase';
    changePassphrase(app.keyDir, 'boss123', next);
    assert.throws(() => app.receiver.ensureKeys('boss123'));
    assert.equal(app.receiver.ensureKeys(next), key.keyId);
    assert.equal((await app.call('/api/decrypt', { id: lastId, passphrase: next }, boss)).status, 200);
    assert.throws(() => changePassphrase(app.keyDir, 'wrong', 'another-long-pass'));
    assert.equal(app.receiver.ensureKeys(next), key.keyId);
  });
  await t.test('Đăng xuất vô hiệu hoá session', async () => {
    assert.equal((await app.call('/logout', {}, boss)).status, 200);
    assert.equal((await app.call('/api/me', undefined, boss)).status, 401);
  });
  await t.test('Payload quá lớn trả 413 thay vì ngắt socket', async () => {
    const response = await app.call('/api/upload', 'x'.repeat(15 * 1024 * 1024), employee);
    assert.equal(response.status, 413);
    assert.match((await response.json()).error, /quá lớn/);
  });
});

test('Phiên hết hạn được kiểm tra ở server', async t => {
  const app = await fixture(t, { sessionTtlMs: 100 });
  const cookie = await app.login('boss', 'admin123');
  await new Promise(resolve => setTimeout(resolve, 140));
  assert.equal((await app.call('/api/me', undefined, cookie)).status, 401);
});
test('Giới hạn thử đăng nhập và không crash với tên tài khoản đặc biệt', async t => {
  const app = await fixture(t);
  for (let i = 0; i < 10; i++)
    assert.equal((await app.call('/api/login', { username: '__proto__', password: 'wrong' })).status, 401);
  assert.equal((await app.call('/api/login', { username: 'boss', password: 'wrong' })).status, 429);
});
test('Giới hạn giải mã và thay session khi đăng nhập lại', async t => {
  const app = await fixture(t);
  const first = await app.login('boss', 'admin123');
  const response = await app.call('/api/login', { username: 'boss', password: 'admin123' }, first);
  const next = response.headers.get('set-cookie').split(';')[0];
  assert.notEqual(first, next);
  assert.equal((await app.call('/api/me', undefined, first)).status, 401);
  for (let i = 0; i < 30; i++)
    assert.equal((await app.call('/api/decrypt', {}, next)).status, 400);
  const limited = await app.call('/api/decrypt', {}, next);
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
});
test('Kiểm tra và khôi phục public key an toàn', async t => {
  const app = await fixture(t);
  const before = app.receiver.keyId, privateBytes = fs.readFileSync(app.receiver.PRIV);
  fs.unlinkSync(app.receiver.PUB);
  assert.equal(app.receiver.ensureKeys('boss123'), before);
  const other = createReceiver(path.join(app.root, 'other')); other.ensureKeys('other-pass');
  fs.copyFileSync(other.PUB, app.receiver.PUB);
  assert.throws(() => app.receiver.ensureKeys('boss123'), /không khớp/);
  assert.deepEqual(fs.readFileSync(app.receiver.PRIV), privateBytes);
  fs.unlinkSync(app.receiver.PRIV);
  assert.throws(() => app.receiver.ensureKeys('boss123'), /Thiếu private key/);
});
test('Production từ chối cấu hình thiếu HTTPS và mật khẩu riêng', async () => {
  await assert.rejects(createApp({ env: { NODE_ENV: 'production' } }), /Production cần HTTPS/);
});
test('Không sinh khoá mới khi tài liệu còn nhưng private key mất', async t => {
  const app = await fixture(t);
  fs.writeFileSync(path.join(app.dataDir, '1794737203890-deadbe.json'), '{}');
  fs.unlinkSync(app.receiver.PRIV);
  await assert.rejects(createApp({ env: {}, dataDir: app.dataDir, keyDir: app.keyDir, dbConfig: app.dbConfig }), /Có tài liệu cũ/);
});
test('Gói ở giới hạn 10 MiB được kiểm tra mà không tràn regex', () => {
  const p = { version: 2, algorithm: format.ALGORITHM, keyId: '0'.repeat(64), senderUsername: 'nhanvien',
    sender: 'Nhân viên A', title: '', category: 'Khác', filename: 'max.bin', fileSize: format.MAX_FILE_BYTES,
    encKey: Buffer.alloc(256).toString('base64'), iv: Buffer.alloc(12).toString('base64'),
    data: Buffer.alloc(format.MAX_FILE_BYTES + 16).toString('base64') };
  assert.equal(validatePackage(p).data.length, format.MAX_FILE_BYTES + 16);
});

test('Tài khoản riêng, quyền theo tài liệu, quota, phiên bản và thu hồi', async t => {
  const app = await fixture(t);
  const admin = await app.login('quantri', 'quantri123'), employee = await app.login('nhanvien', '123456'), boss = await app.login('boss', 'admin123');
  const tempPass = 'temporary-pass-123', ownPass = 'recipient-password-123', keyPass = 'recipient-key-pass-123';
  let receiverCookie;
  await t.test('Quản trị tạo người nhận; tài khoản phải đổi mật khẩu tạm', async () => {
    assert.equal((await app.call('/api/users/create', { username: 'truongphong', name: 'Trưởng phòng', role: 'boss', password: tempPass, keyPassphrase: keyPass }, employee)).status, 403);
    assert.equal((await app.call('/api/users/create', { username: 'truongphong', name: 'Trưởng phòng', role: 'boss', password: tempPass, keyPassphrase: keyPass }, admin)).status, 201);
    const temp = await app.login('truongphong', tempPass);
    assert.equal((await app.call('/api/list', undefined, temp)).status, 403);
    assert.equal((await app.call('/api/account/password', { currentPassword: tempPass, newPassword: ownPass }, temp)).status, 200);
    assert.equal((await app.call('/api/me', undefined, temp)).status, 401);
    receiverCookie = await app.login('truongphong', ownPass);
  });
  const key = await (await app.call('/api/public-key?recipient=truongphong', undefined, employee)).json();
  function makePackage({ previousId = null, expiresAt = null, title = 'Báo cáo bộ phận', size = 100 } = {}) {
    const p = { version: 3, algorithm: format.ALGORITHM, keyId: key.keyId, senderUsername: 'nhanvien', sender: 'Nhân viên A', recipientUsername: 'truongphong',
      title, category: 'Khác', filename: 'report.txt', fileSize: size, previousId, expiresAt };
    const aes = crypto.randomBytes(32), iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', aes, iv);
    cipher.setAAD(Buffer.from(format.aadText(p)));
    const data = Buffer.concat([cipher.update(Buffer.alloc(size, 65)), cipher.final(), cipher.getAuthTag()]);
    return { ...p, encKey: crypto.publicEncrypt({ key: key.pem, oaepHash: 'sha256' }, aes).toString('base64'), iv: iv.toString('base64'), data: data.toString('base64') };
  }
  const p = makePackage(), sent = await app.call('/api/upload', p, employee);
  assert.equal(sent.status, 201); const id = (await sent.json()).id;
  await t.test('Người nhận khác và quản trị không thể đọc hoặc giải mã', async () => {
    assert.equal((await app.call('/api/decrypt', { id, passphrase: keyPass }, boss)).status, 403);
    assert.equal((await app.call('/api/decrypt', { id, passphrase: keyPass }, admin)).status, 403);
    assert.equal((await app.call('/api/raw?id=' + id, undefined, boss)).status, 403);
    assert.equal((await app.call('/api/raw?id=' + id, undefined, admin)).status, 403);
    const response = await app.call('/api/decrypt', { id, passphrase: keyPass }, receiverCookie);
    assert.equal(response.status, 200); assert.equal(Buffer.from((await response.json()).data, 'base64').length, 100);
    const status = await (await app.call('/api/sent', undefined, employee)).json();
    assert.ok(status.documents.find(d => d.id === id).opened_at);
  });
  await t.test('Tìm kiếm, phiên bản, thu hồi và hạn mức', async () => {
    const response = await app.call('/api/upload', makePackage({ previousId: id, title: 'Bản cập nhật' }), employee);
    assert.equal(response.status, 201);
    const list = await (await app.call('/api/list?q=' + encodeURIComponent('cập nhật'), undefined, receiverCookie)).json();
    assert.equal(list.total, 1); assert.equal(list.documents[0].previous_id, id);
    assert.equal((await app.call('/api/revoke', { id }, receiverCookie)).status, 403);
    assert.equal((await app.call('/api/revoke', { id }, employee)).status, 200);
    assert.equal((await app.call('/api/decrypt', { id, passphrase: keyPass }, receiverCookie)).status, 410);
    const stored = JSON.parse(fs.readFileSync(path.join(app.dataDir, id + '.json')));
    assert.equal((await app.call('/api/decrypt', { pkg: stored, passphrase: keyPass }, receiverCookie)).status, 410);
    delete stored.id;
    assert.equal((await app.call('/api/decrypt', { pkg: stored, passphrase: keyPass }, receiverCookie)).status, 400);
    assert.equal((await app.call('/api/users/update', { username: 'nhanvien', enabled: true, quotaMB: 1 }, admin)).status, 200);
    const relogin = await app.login('nhanvien', '123456');
    assert.equal((await app.call('/api/upload', makePackage({ size: 900000 }), relogin)).status, 413);
  });
  await t.test('Khoá tài khoản thu hồi ngay mọi phiên', async () => {
    assert.equal((await app.call('/api/users/update', { username: 'truongphong', enabled: false, quotaMB: 100 }, admin)).status, 200);
    assert.equal((await app.call('/api/me', undefined, receiverCookie)).status, 401);
    assert.equal((await app.call('/api/users/update', { username: 'truongphong', enabled: true, quotaMB: 100 }, admin)).status, 200);
    receiverCookie = await app.login('truongphong', ownPass);
  });
  await t.test('Luân chuyển khoá giữ khả năng mở bản cũ bằng passphrase cũ', async () => {
    const nextPass = 'new-key-passphrase-123';
    const rotated = await app.call('/api/keys/rotate', { password: ownPass, currentPassphrase: keyPass, newPassphrase: nextPass }, receiverCookie);
    assert.equal(rotated.status, 200); assert.notEqual((await rotated.json()).keyId, key.keyId);
    const remaining = await (await app.call('/api/list', undefined, receiverCookie)).json();
    const active = remaining.documents.find(d => !d.revoked_at);
    assert.equal((await app.call('/api/decrypt', { id: active.id, passphrase: keyPass }, receiverCookie)).status, 200);
    assert.equal((await app.call('/api/decrypt', { id: active.id, passphrase: nextPass }, receiverCookie)).status, 422);
  });
  assert.equal(await app.store.verifyAudit(), true);
  await assert.rejects(app.store.run('DELETE FROM audit'), /append-only/);
});

test('Scanner phát hiện nguy cơ sẽ chặn bản rõ, lỗi quét không được bỏ qua', async t => {
  const { AppError } = require('../package-format');
  const app = await fixture(t, { scanner: async () => { throw new AppError(422, 'infected'); } });
  const employee = await app.login('nhanvien', '123456'), boss = await app.login('boss', 'admin123');
  const { pem } = await (await app.call('/api/public-key', undefined, employee)).json();
  const response = await app.call('/api/decrypt', { pkg: legacyPackage(pem, Buffer.from('test')), passphrase: 'boss123' }, boss);
  assert.equal(response.status, 422); assert.equal((await response.json()).data, undefined);
});

test('Sao lưu mã hoá và phục hồi sang database/thư mục mới', async t => {
  const app = await fixture(t), { createBackup, readBackup, restoreBackup } = require('../scripts/backup');
  const employee = await app.login('nhanvien', '123456'), boss = await app.login('boss', 'admin123');
  const key = await (await app.call('/api/public-key', undefined, employee)).json();
  const old = { ...legacyPackage(key.pem, Buffer.from('backup content')), id: '1794737203890-abcdef', time: new Date().toISOString() };
  fs.writeFileSync(path.join(app.dataDir, old.id + '.json'), JSON.stringify(old));
  await app.documents.importFiles(app.receiver.keyId);
  const output = path.join(app.root, 'test.atbm-backup'), password = 'backup-password-123456';
  await assert.rejects(createBackup({ store: app.store, keyDir: app.keyDir, dataDir: app.dataDir, password, output }), /Server hoặc tác vụ/);
  await new Promise(resolve => app.server.close(resolve)); await app.close();
  const { Store } = require('../store'), store = await Store.open(app.dbConfig);
  try { await createBackup({ store, keyDir: app.keyDir, dataDir: app.dataDir, password, output }); } finally { await store.close(); }
  await assert.rejects(readBackup(output, 'wrong-password-12345'), /Không xác thực/);
  const snapshot = await readBackup(output, password);
  const config = { ...app.dbConfig, database: 'atbm_test_' + crypto.randomBytes(8).toString('hex') };
  t.after(async () => {
    const c = await require('mysql2/promise').createConnection({ ...config, database: undefined });
    try { assert.match(config.database, /^atbm_test_[a-f0-9]{16}$/); await c.query('DROP DATABASE IF EXISTS `' + config.database + '`'); } finally { await c.end(); }
  });
  const result = await restoreBackup(snapshot, config, path.join(app.root, 'restored'));
  assert.ok(result.files >= 3);
  assert.equal(result.documents, 1);
  const recoveredKey = createReceiver(path.join(app.root, 'restored/keystore')); recoveredKey.loadKeys();
  assert.equal(recoveredKey.decryptPackage(old, 'boss123', { allowLegacy: true }).toString(), 'backup content');
  const restored = await Store.open(config);
  try { assert.equal(await restored.verifyAudit(), true); assert.equal((await restored.get('SELECT COUNT(*) AS n FROM users')).n, 3); }
  finally { await restored.close(); }
});

test('Tài khoản, mật khẩu và session tồn tại qua lần khởi động lại', async t => {
  const app = await fixture(t), employee = await app.login('nhanvien', '123456');
  await new Promise(resolve => app.server.close(resolve)); await app.close();
  const next = await createApp({ env: { EMPLOYEE_PASSWORD: 'different-environment-pass' }, dataDir: app.dataDir, keyDir: app.keyDir, dbConfig: app.dbConfig });
  try {
    next.server.listen(0, '127.0.0.1'); await once(next.server, 'listening');
    const base = 'http://127.0.0.1:' + next.server.address().port;
    const response = await fetch(base + '/api/me', { headers: { Cookie: employee } });
    assert.equal(response.status, 200); assert.equal((await response.json()).username, 'nhanvien');
    const records = await next.store.all('SELECT token_hash FROM sessions');
    assert.ok(records.every(record => !employee.includes(record.token_hash)));
    const login = await fetch(base + '/api/login', { method: 'POST', headers, body: JSON.stringify({ username: 'nhanvien', password: '123456' }) });
    assert.equal(login.status, 200);
  } finally { await new Promise(resolve => next.server.close(resolve)); await next.close(); }
});

test('Hai quản trị viên không thể đồng thời khoá hết quản trị viên', async t => {
  const app = await fixture(t), first = await app.login('quantri', 'quantri123');
  const temp = 'admin-temporary-123', permanent = 'admin-permanent-123';
  assert.equal((await app.call('/api/users/create', { username: 'admin_two', name: 'Quản trị hai', role: 'admin', password: temp }, first)).status, 201);
  const initial = await app.login('admin_two', temp);
  assert.equal((await app.call('/api/account/password', { currentPassword: temp, newPassword: permanent }, initial)).status, 200);
  const second = await app.login('admin_two', permanent);
  const responses = await Promise.all([
    app.call('/api/users/update', { username: 'admin_two', enabled: false, quotaMB: 100 }, first),
    app.call('/api/users/update', { username: 'quantri', enabled: false, quotaMB: 100 }, second)
  ]);
  assert.equal(responses.filter(response => response.status === 200).length, 1);
  assert.equal(Number((await app.store.get("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND enabled=1")).n), 1);
});

test('Bỏ xác thực hai bước: đăng nhập chỉ dùng mật khẩu và nâng cấp database cũ', async t => {
  const app = await fixture(t);
  // Giả lập schema cũ đã có tài khoản bật MFA; ứng dụng mới không còn yêu cầu OTP.
  await app.store.run('ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(512), ADD COLUMN mfa_step BIGINT DEFAULT -1');
  await app.store.run('ALTER TABLE sessions ADD COLUMN pending_mfa VARCHAR(512)');
  await app.store.run("UPDATE users SET mfa_secret='obsolete-secret' WHERE username='boss'");
  const boss = await app.login('boss', 'admin123');
  const profile = await (await app.call('/api/me', undefined, boss)).json();
  assert.equal(Object.hasOwn(profile, 'mfaEnabled'), false);
  assert.equal((await app.call('/api/mfa/setup', {}, boss)).status, 404);
  assert.doesNotMatch(await (await app.call('/login')).text(), /id="otp"|Authenticator|MFA/);
  assert.doesNotMatch(await (await app.call('/account', undefined, boss)).text(), /mfaState|Authenticator|TOTP/);
  await new Promise(resolve => app.server.close(resolve)); await app.close();
  const migrated = await require('../store').Store.open(app.dbConfig);
  try {
    assert.ok((await migrated.all('SHOW COLUMNS FROM users')).every(column => !column.Field.startsWith('mfa_')));
    assert.ok((await migrated.all('SHOW COLUMNS FROM sessions')).every(column => column.Field !== 'pending_mfa'));
    assert.equal((await migrated.get("SELECT username FROM users WHERE username='boss'")).username, 'boss');
  } finally { await migrated.close(); }
});
