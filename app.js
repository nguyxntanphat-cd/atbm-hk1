const http = require('http');
const https = require('https');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { Worker } = require('worker_threads');
const { Store, databaseConfig } = require('./store');
const security = require('./security');
const { createReceiver } = require('./receiver');
const { Documents } = require('./documents');
const { createScanner } = require('./scanner');
const { changePassphrase } = require('./scripts/change-passphrase');
const { acquireLock } = require('./lifecycle');
const { AppError, check, validatePackage, MAX_FILE_BYTES, aadText } = require('./package-format');
const { readBody, send, redirect } = require('./http-utils');
const home = user => user.role === 'admin' ? '/manage' : user.role === 'boss' ? '/admin' : '/';
const safeUser = user => ({ username: user.username, name: user.name, role: user.role,
  enabled: !!user.enabled, mustChangePassword: !!user.must_change, quota: user.quota });
const now = () => new Date().toISOString();

async function createApp(options = {}) {
  const env = options.env || process.env, production = env.NODE_ENV === 'production';
  const tls = options.tls || (env.TLS_KEY && env.TLS_CERT ? { key: fs.readFileSync(env.TLS_KEY), cert: fs.readFileSync(env.TLS_CERT) } : null);
  if (!!env.TLS_KEY !== !!env.TLS_CERT) throw new Error('Cần cả TLS_KEY và TLS_CERT.');
  if (production && (!tls || !env.BOSS_PASS || env.BOSS_PASS.length < 12 || !env.SCANNER_COMMAND && !options.scanner))
    throw new Error('Production cần HTTPS, BOSS_PASS riêng tối thiểu 12 ký tự và SCANNER_COMMAND.');
  const dataDir = path.resolve(options.dataDir || env.DATA_DIR || path.join(__dirname, 'storage'));
  const keyDir = path.resolve(options.keyDir || env.KEYSTORE_DIR || path.join(__dirname, 'keystore'));
  await fsp.mkdir(dataDir, { recursive: true }); await fsp.mkdir(keyDir, { recursive: true });
  const receiver = createReceiver(keyDir);
  if (!fs.existsSync(receiver.PRIV) && (await fsp.readdir(dataDir)).some(f => f.endsWith('.json')))
    throw new Error('Có tài liệu cũ nhưng thiếu private key. Cần khôi phục bản sao lưu.');
  const releaseLock = acquireLock(keyDir);
  let store;
  try { store = options.store || await Store.open(options.dbConfig || databaseConfig(env), { createDatabase: !production, initialize: !production }); }
  catch (error) { releaseLock(); throw error; }
  try {
    if (!(await store.get("SELECT username FROM users WHERE username='boss'"))) {
      receiver.ensureKeys(env.BOSS_PASS || 'boss123');
      const initialUsers = [];
      for (const [username, password, role, name] of [
        ['nhanvien', env.EMPLOYEE_PASSWORD || '123456', 'employee', 'Nhân viên A'],
        ['boss', env.BOSS_PASSWORD || 'admin123', 'boss', 'Boss'],
        ['quantri', env.ADMIN_PASSWORD || 'quantri123', 'admin', 'Quản trị hệ thống']
      ]) {
        if (production) security.validatePassword(password);
        const record = await security.passwordRecord(password);
        initialUsers.push([username, name, role, record.salt, record.hash, now()]);
      }
      await store.transaction(async tx => {
        for (const row of initialUsers) await tx.run('INSERT INTO users(username,name,role,salt,hash,created_at) VALUES(?,?,?,?,?,?)', ...row);
        await tx.run('INSERT INTO key_records(key_id,username,directory,created_at) VALUES(?,?,?,?)', receiver.keyId, 'boss', '.', now());
        await tx.audit('system', 'initialize');
      });
    } else receiver.loadKeys();
    if (production) {
      for (const [username, demoPassword] of [['nhanvien', '123456'], ['boss', 'admin123'], ['quantri', 'quantri123']]) {
        const account = await store.get('SELECT * FROM users WHERE username=?', username);
        if (account?.enabled && await security.verifyPassword(demoPassword, account))
          throw new Error(`Tài khoản ${username} còn dùng mật khẩu demo. Đổi trong trang Tài khoản trước khi chạy production.`);
      }
      let demoPrivateKey = false;
      try { crypto.createPrivateKey({ key: fs.readFileSync(receiver.PRIV), passphrase: 'boss123' }); demoPrivateKey = true; } catch {}
      if (demoPrivateKey) throw new Error('Private key ban đầu còn dùng boss123. Đổi passphrase trước khi chạy production.');
    }
    const documents = new Documents(store, dataDir);
    let skipped = await documents.importFiles(receiver.keyId);
    const scanner = options.scanner || createScanner(env, path.join(dataDir, '.quarantine'));
    const allowedExtensions = (env.ALLOWED_EXTENSIONS || (production ? '.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.png,.jpg,.jpeg' : ''))
      .split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
    check(allowedExtensions.every(value => /^\.[a-z0-9]{1,12}$/.test(value)), 'ALLOWED_EXTENSIONS cần danh sách đuôi file như .pdf,.docx,.txt');
    const storageQuota = Number(env.STORAGE_QUOTA_MB || 1024) * 1048576;
    check(Number.isSafeInteger(storageQuota) && storageQuota > 0, 'STORAGE_QUOTA_MB không hợp lệ.');
    const sessionTtl = options.sessionTtlMs || 30 * 60 * 1000;
    const attempts = new Map(); let decrypting = 0;
    function throttle(key, maximum, duration) {
      const time = Date.now(); let entry = attempts.get(key);
      if (!entry || entry.until <= time) { entry = { count: 0, until: time + duration }; attempts.set(key, entry); }
      if (entry.count >= maximum) {
        const error = new AppError(429, 'Quá nhiều yêu cầu. Vui lòng thử lại sau.');
        error.retryAfter = Math.ceil((entry.until - time) / 1000); throw error;
      }
      entry.count++;
      return entry;
    }
    const cookie = (sid, maxAge) => `sid=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${tls ? '; Secure' : ''}`;
    const token = req => (req.headers.cookie || '').match(/(?:^|;\s*)sid=([a-f0-9]{48})(?:;|$)/)?.[1];
    async function session(req) {
      return store.get(`SELECT u.*,s.expires_at,s.token_hash FROM sessions s
        JOIN users u ON u.username=s.username WHERE s.token_hash=? AND s.expires_at>? AND u.enabled=1`, security.tokenHash(token(req)), Date.now());
    }
    async function keyRecord(username, keyId) {
      const row = keyId ? await store.get('SELECT * FROM key_records WHERE username=? AND key_id=?', username, keyId)
        : await store.get('SELECT * FROM key_records WHERE username=? AND active=1', username);
      if (!row) throw new AppError(422, 'Không tìm thấy khoá của người nhận.');
      const directory = path.resolve(keyDir, row.directory);
      if (directory !== keyDir && !directory.startsWith(keyDir + path.sep)) throw new AppError(500, 'Đường dẫn khoá không hợp lệ.');
      const selected = createReceiver(directory);
      if (selected.loadKeys() !== row.key_id) throw new AppError(503, 'Khoá lưu trữ không khớp chỉ mục.');
      return { ...row, directory, receiver: selected };
    }
    async function passwordCheck(user, password) {
      check(typeof password === 'string' && password.length <= 256, 'Nhập mật khẩu hiện tại.');
      if (!await security.verifyPassword(password, user)) throw new AppError(403, 'Mật khẩu hiện tại không đúng.');
    }
    async function decrypt(pkg, passphrase, directory) {
      if (decrypting >= 2) throw new AppError(503, 'Hệ thống đang giải mã tài liệu khác. Vui lòng thử lại.');
      decrypting++;
      try {
        return await new Promise((resolve, reject) => {
          const worker = new Worker(path.join(__dirname, 'decrypt-worker.js'), { workerData: { pkg, passphrase, keyDir: directory } });
          const timeout = setTimeout(() => { worker.terminate(); reject(new AppError(503, 'Giải mã vượt thời gian cho phép.')); }, 15000);
          worker.once('message', result => {
            clearTimeout(timeout);
            if (result.error) reject(new AppError(result.status, result.error)); else resolve(Buffer.from(result.bytes));
          });
          worker.once('error', () => { clearTimeout(timeout); reject(new AppError(503, 'Không chạy được tiến trình giải mã.')); });
          worker.once('exit', code => { clearTimeout(timeout); if (code) reject(new AppError(503, 'Tiến trình giải mã bị ngắt.')); });
        });
      } finally { decrypting--; }
    }
    const pages = { '/': 'employee.html', '/admin': 'admin.html', '/tool': 'tool.html', '/login': 'login.html', '/manage': 'manage.html', '/account': 'account.html' };
    const scripts = new Set(['sender.js', 'package-format.js', 'client.js', 'login.js', 'employee.js', 'admin.js', 'tool.js', 'manage.js', 'account.js']);
    const methods = { '/api/login': 'POST', '/logout': 'POST', '/api/me': 'GET', '/api/recipients': 'GET', '/api/public-key': 'GET',
      '/api/upload': 'POST', '/api/list': 'GET', '/api/sent': 'GET', '/api/raw': 'GET', '/api/decrypt': 'POST', '/api/revoke': 'POST',
      '/api/users': 'GET', '/api/users/create': 'POST', '/api/users/update': 'POST', '/api/audit': 'GET', '/api/health': 'GET',
      '/api/account/password': 'POST',
      '/api/keys': 'GET', '/api/keys/rotate': 'POST', '/api/keys/passphrase': 'POST', '/api/maintenance/reindex': 'POST' };
    const cleanup = setInterval(() => {
      store.run('DELETE FROM sessions WHERE expires_at<=?', Date.now()).catch(() => {});
      for (const [key, entry] of attempts) if (entry.until <= Date.now()) attempts.delete(key);
    }, 60000); cleanup.unref();
    const handler = async (req, res) => {
      res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
      if (tls) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      let user, route, documentId = null;
      try {
        const url = new URL(req.url, 'http://localhost'); route = url.pathname;
        if (methods[route] && methods[route] !== req.method) { res.setHeader('Allow', methods[route]); throw new AppError(405, 'Phương thức không được hỗ trợ.'); }
        if (req.method === 'POST') {
          if (req.headers['x-requested-with'] !== 'internal-docs' || !/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || ''))
            throw new AppError(415, 'Yêu cầu phải dùng JSON và header của ứng dụng.');
          if (req.headers['sec-fetch-site'] === 'cross-site' || req.headers.origin && req.headers.origin !== `${tls ? 'https' : 'http'}://${req.headers.host}`)
            throw new AppError(403, 'Origin không hợp lệ.');
        }
        if (route === '/api/health') {
          await store.get('SELECT 1 AS ok'); return send(res, 200, { ok: true });
        }
        user = await session(req);
        if (route === '/api/login') {
          const b = await readBody(req, 4096);
          check(typeof b.username === 'string' && b.username.length <= 64 && typeof b.password === 'string' && b.password.length <= 256, 'Thông tin đăng nhập không hợp lệ.');
          throttle('login-volume:' + req.socket.remoteAddress, 60, 60000);
          const loginLimit = throttle('login:' + req.socket.remoteAddress, 10, 15 * 60000);
          const account = await store.get('SELECT * FROM users WHERE username=?', b.username);
          const valid = await security.verifyPassword(b.password, account);
          if (!valid || !account.enabled) { await store.audit('anonymous', 'login', null, 'denied', req.socket.remoteAddress); throw new AppError(401, 'Sai tài khoản hoặc mật khẩu; tài khoản có thể đã bị khoá.'); }
          loginLimit.count = Math.max(0, loginLimit.count - 1);
          const sid = crypto.randomBytes(24).toString('hex');
          await store.transaction(async tx => {
            await tx.run('DELETE FROM sessions WHERE token_hash=?', security.tokenHash(token(req)));
            await tx.run('INSERT INTO sessions(token_hash,username,expires_at) VALUES(?,?,?)', security.tokenHash(sid), account.username, Date.now() + sessionTtl);
            await tx.audit(account.username, 'login', null, 'ok', req.socket.remoteAddress);
          });
          res.setHeader('Set-Cookie', cookie(sid, Math.floor(sessionTtl / 1000)));
          return send(res, 200, { ok: true, redirect: account.must_change ? '/account' : home(account) });
        }
        if (route === '/logout') {
          await readBody(req, 1024); await store.run('DELETE FROM sessions WHERE token_hash=?', security.tokenHash(token(req)));
          if (user) await store.audit(user.username, 'logout', null, 'ok', req.socket.remoteAddress);
          res.setHeader('Set-Cookie', cookie('', 0)); return send(res, 200, { ok: true });
        }
        if (req.method === 'GET' && scripts.has(route.slice(1))) return send(res, 200, await fsp.readFile(path.join(__dirname, 'public', route.slice(1))), 'text/javascript; charset=utf-8');
        if (req.method === 'GET' && pages[route]) {
          if (route !== '/login' && !user) return redirect(res, '/login');
          if (user && route === '/' && user.role !== 'employee') return redirect(res, home(user));
          if (user && user.must_change && !['/account', '/login'].includes(route)) return redirect(res, '/account');
          if (user && (['/admin', '/tool'].includes(route) && user.role !== 'boss' || route === '/manage' && user.role !== 'admin')) return redirect(res, home(user));
          let html = await fsp.readFile(path.join(__dirname, 'public', pages[route]), 'utf8');
          if (user) html = html.replace('class="brand" href="/"', `class="brand" href="${home(user)}"`);
          if (production) html = html.replace(/<div class="demo">[\s\S]*?<!-- end-demo -->/, '');
          return send(res, 200, html, 'text/html; charset=utf-8');
        }
        if (!methods[route]) throw new AppError(404, 'Không tìm thấy đường dẫn.');
        if (!user) throw new AppError(401, 'Phiên đăng nhập đã hết hạn.');
        if (user.must_change && !['/api/me', '/api/account/password'].includes(route)) throw new AppError(403, 'Cần đổi mật khẩu tạm tại trang Tài khoản trước khi tiếp tục.');
        const ip = req.socket.remoteAddress;
        const adminOnly = ['/api/users', '/api/users/create', '/api/users/update', '/api/audit', '/api/maintenance/reindex'];
        if (adminOnly.includes(route) && user.role !== 'admin') throw new AppError(403, 'Chỉ quản trị viên được dùng chức năng này.');
        if (['/api/list', '/api/decrypt', '/api/keys', '/api/keys/rotate', '/api/keys/passphrase'].includes(route) && user.role !== 'boss') throw new AppError(403, 'Chỉ người nhận được dùng chức năng này.');
        if (route === '/api/keys') return send(res, 200, await store.all('SELECT key_id,active,created_at FROM key_records WHERE username=? ORDER BY active DESC,created_at DESC', user.username));
        if (route === '/api/me') return send(res, 200, { ...safeUser(user), expiresAt: user.expires_at, maxFileBytes: MAX_FILE_BYTES, home: home(user), scannerConfigured: !!scanner });
        if (route === '/api/recipients') return send(res, 200, await store.all("SELECT username,name FROM users WHERE role='boss' AND enabled=1 ORDER BY name"));
        if (route === '/api/public-key') {
          const username = url.searchParams.get('recipient') || 'boss';
          const target = await store.get("SELECT username FROM users WHERE username=? AND role='boss' AND enabled=1", username);
          if (!target) throw new AppError(404, 'Người nhận không sẵn sàng.');
          const key = await keyRecord(username);
          return send(res, 200, { pem: await fsp.readFile(key.receiver.PUB, 'utf8'), keyId: key.key_id, recipientUsername: username });
        }
        if (route === '/api/upload') {
          if (user.role !== 'employee') throw new AppError(403, 'Chỉ nhân viên được gửi tài liệu.');
          const p = await readBody(req); validatePackage(p);
          check(p.version === 3, 'Tài liệu mới cần gói phiên bản 3. Hãy tải lại trang.');
          check(!allowedExtensions.length || allowedExtensions.includes(path.extname(p.filename).toLowerCase()), 'Loại file không nằm trong danh sách cho phép.');
          check(p.sender === user.name && p.senderUsername === user.username, 'Danh tính người gửi không khớp phiên đăng nhập.');
          const target = await store.get("SELECT username FROM users WHERE username=? AND role='boss' AND enabled=1", p.recipientUsername);
          check(!!target, 'Người nhận không sẵn sàng.');
          const key = await keyRecord(target.username);
          check(p.keyId === key.key_id, 'Khoá đã đổi. Hãy mã hoá và gửi lại.');
          if (p.expiresAt) check(p.expiresAt > now(), 'Thời hạn cần nằm trong tương lai.');
          if (p.previousId) {
            const previous = await documents.record(p.previousId);
            check(previous.sender_username === user.username && previous.recipient_username === target.username,
              'Chỉ được cập nhật phiên bản tài liệu của mình gửi cho cùng người nhận.');
          }
          const id = Date.now() + '-' + crypto.randomBytes(8).toString('hex'); documentId = id;
          const pkg = { version: 3, algorithm: p.algorithm, keyId: key.key_id, id,
            senderUsername: user.username, sender: user.name, recipientUsername: target.username,
            title: p.title, category: p.category, filename: p.filename, fileSize: p.fileSize,
            previousId: p.previousId, expiresAt: p.expiresAt, time: now(), encKey: p.encKey, iv: p.iv, data: p.data };
          const bytes = Buffer.from(JSON.stringify(pkg));
          await documents.exclusive(async () => {
            const used = await store.get('SELECT COALESCE(SUM(stored_bytes),0) AS total,COALESCE(SUM(IF(sender_username=?,stored_bytes,0)),0) AS personal FROM documents', user.username);
            if (Number(used.total) + bytes.length > storageQuota || Number(used.personal) + bytes.length > user.quota)
              throw new AppError(413, 'Đã vượt hạn mức lưu trữ. Liên hệ quản trị viên.');
            const filename = path.join(dataDir, id + '.json'), temp = filename + '.tmp';
            await fsp.writeFile(temp, bytes, { flag: 'wx', mode: 0o600 });
            await fsp.rename(temp, filename);
            try {
              await store.transaction(async tx => {
                const indexer = new Documents(tx, dataDir); await indexer.index(pkg, bytes, receiver.keyId);
                await tx.audit(user.username, 'upload', id, 'ok', ip);
              });
            } catch (error) { await fsp.unlink(filename).catch(() => {}); throw error; }
          });
          return send(res, 201, { ok: true, id });
        }
        if (route === '/api/list' || route === '/api/sent') {
          if (route === '/api/sent' && user.role !== 'employee') throw new AppError(403, 'Chỉ nhân viên có hộp thư đã gửi.');
          return send(res, 200, { ...await documents.list(user, url, route === '/api/sent'), skipped });
        }
        if (route === '/api/raw') {
          const row = await documents.record(url.searchParams.get('id')); documentId = row.id;
          documents.authorize(row, user, { sender: true });
          const pkg = await documents.read(row);
          await store.audit(user.username, 'download-encrypted', row.id, 'ok', ip);
          res.setHeader('Content-Disposition', `attachment; filename="${row.id}.enc.json"`);
          return send(res, 200, pkg);
        }
        if (route === '/api/decrypt') {
          throttle('decrypt:' + user.username, 30, 60000);
          const b = await readBody(req);
          check(typeof b.passphrase === 'string' && b.passphrase.length > 0 && b.passphrase.length <= 1024, 'Vui lòng nhập passphrase (tối đa 1024 ký tự).');
          let pkg, row;
          if (b.pkg === undefined) {
            row = await documents.record(b.id); documentId = row.id; documents.authorize(row, user); pkg = await documents.read(row);
          } else {
            pkg = b.pkg; validatePackage(pkg, { allowLegacy: true });
            if (pkg.version === 3) check(typeof pkg.id === 'string', 'Gói phiên bản 3 cần ID tài liệu đã lưu trên hệ thống.');
            // Nếu gói có ID đã biết thì vẫn thực thi thu hồi/hết hạn và kiểm tra hash.
            if (pkg.id) {
              row = await documents.record(pkg.id); documentId = row.id; documents.authorize(row, user);
              const original = await documents.read(row);
              const identity = p => JSON.stringify([aadText(p), p.encKey, p.iv, p.data, p.id, p.time]);
              if (identity(original) !== identity(pkg)) throw new AppError(422, 'Gói nhập đã thay đổi so với tài liệu gốc.');
            }
          }
          validatePackage(pkg, { allowLegacy: true });
          if (pkg.version === 3 && pkg.recipientUsername !== user.username) throw new AppError(403, 'Gói không được gửi cho bạn.');
          if (pkg.version !== 3 && user.username !== 'boss') throw new AppError(403, 'Gói cũ chỉ thuộc hộp thư Boss ban đầu.');
          if (pkg.expiresAt && pkg.expiresAt <= now()) throw new AppError(410, 'Tài liệu đã hết hạn.');
          const key = await keyRecord(user.username, pkg.keyId || receiver.keyId);
          const plain = await decrypt(pkg, b.passphrase, key.directory);
          try {
            let scanStatus;
            try { scanStatus = scanner ? await scanner(plain) : 'not-configured'; }
            catch (error) {
              if (row) await store.run('UPDATE documents SET scan_status=? WHERE id=?', error.status === 422 ? 'blocked' : 'scan-error', row.id);
              throw error;
            }
            if (row) await store.run('UPDATE documents SET opened_at=COALESCE(opened_at,?),scan_status=? WHERE id=?', now(), scanStatus, row.id);
            await store.audit(user.username, 'decrypt', row?.id || null, 'ok', ip);
            return send(res, 200, { filename: pkg.filename, data: plain.toString('base64'), legacy: !pkg.version, scanStatus });
          } finally { plain.fill(0); }
        }
        if (route === '/api/revoke') {
          const b = await readBody(req, 4096), row = await documents.record(b.id); documentId = row.id;
          if (row.sender_username !== user.username) throw new AppError(403, 'Chỉ người gửi được thu hồi tài liệu của mình.');
          await store.transaction(async tx => {
            await tx.run('UPDATE documents SET revoked_at=COALESCE(revoked_at,?) WHERE id=?', now(), row.id);
            await tx.audit(user.username, 'revoke', row.id, 'ok', ip);
          });
          return send(res, 200, { ok: true });
        }
        if (route === '/api/users') return send(res, 200, await store.all('SELECT username,name,role,enabled,must_change,quota,created_at FROM users ORDER BY created_at,username'));
        if (route === '/api/users/create') {
          const b = await readBody(req, 8192);
          check(typeof b.username === 'string' && /^[a-z][a-z0-9_]{2,31}$/.test(b.username), 'Tài khoản cần 3–32 ký tự thường, số hoặc dấu gạch dưới.');
          check(typeof b.name === 'string' && b.name.trim().length > 0 && b.name.length <= 100 && !/[\u0000-\u001f]/.test(b.name), 'Tên hiển thị không hợp lệ.');
          check(['employee', 'boss', 'admin'].includes(b.role), 'Vai trò không hợp lệ.');
          security.validatePassword(b.password);
          if (await store.get('SELECT username FROM users WHERE username=?', b.username)) throw new AppError(409, 'Tài khoản đã tồn tại.');
          const record = await security.passwordRecord(b.password);
          let generated;
          if (b.role === 'boss') {
            security.validatePassword(b.keyPassphrase);
            const relative = `users/${b.username}/${crypto.randomBytes(8).toString('hex')}`;
            const r = createReceiver(path.join(keyDir, relative)); r.ensureKeys(b.keyPassphrase);
            generated = { relative, keyId: r.keyId };
          }
          await store.transaction(async tx => {
            await tx.run('INSERT INTO users(username,name,role,salt,hash,must_change,created_at) VALUES(?,?,?,?,?,1,?)', b.username, b.name.trim(), b.role, record.salt, record.hash, now());
            if (generated) await tx.run('INSERT INTO key_records(key_id,username,directory,created_at) VALUES(?,?,?,?)', generated.keyId, b.username, generated.relative, now());
            await tx.audit(user.username, 'create-user:' + b.username, null, 'ok', ip);
          });
          return send(res, 201, { ok: true });
        }
        if (route === '/api/users/update') {
          const b = await readBody(req, 4096), target = await store.get('SELECT * FROM users WHERE username=?', b.username);
          if (!target) throw new AppError(404, 'Không tìm thấy tài khoản.');
          check(target.username !== user.username, 'Không tự khoá/đặt lại tài khoản quản trị hiện tại. Dùng trang Tài khoản để đổi mật khẩu.');
          check(typeof b.enabled === 'boolean' && Number.isSafeInteger(b.quotaMB) && b.quotaMB >= 1 && b.quotaMB <= 102400, 'Trạng thái hoặc hạn mức không hợp lệ.');
          let replacement;
          if (b.password) { security.validatePassword(b.password); replacement = await security.passwordRecord(b.password); }
          await store.transaction(async tx => {
            if (!b.enabled && target.role === 'admin') {
              const enabledAdmins = await tx.all("SELECT username FROM users WHERE role='admin' AND enabled=1 FOR UPDATE");
              check(enabledAdmins.some(account => account.username !== target.username), 'Không được khoá quản trị viên cuối cùng.');
            }
            await tx.run('UPDATE users SET enabled=?,quota=? WHERE username=?', b.enabled ? 1 : 0, b.quotaMB * 1048576, target.username);
            if (replacement) await tx.run('UPDATE users SET salt=?,hash=?,must_change=1 WHERE username=?', replacement.salt, replacement.hash, target.username);
            await tx.run('DELETE FROM sessions WHERE username=?', target.username);
            await tx.audit(user.username, 'update-user:' + target.username, null, 'ok', ip);
          });
          return send(res, 200, { ok: true });
        }
        if (route === '/api/account/password') {
          throttle('settings:' + user.username, 10, 60000);
          const b = await readBody(req, 4096); await passwordCheck(user, b.currentPassword); security.validatePassword(b.newPassword);
          check(b.currentPassword !== b.newPassword, 'Mật khẩu mới phải khác mật khẩu hiện tại.');
          const record = await security.passwordRecord(b.newPassword);
          await store.transaction(async tx => {
            await tx.run('UPDATE users SET salt=?,hash=?,must_change=0 WHERE username=?', record.salt, record.hash, user.username);
            await tx.run('DELETE FROM sessions WHERE username=?', user.username);
            await tx.audit(user.username, 'change-password', null, 'ok', ip);
          });
          res.setHeader('Set-Cookie', cookie('', 0)); return send(res, 200, { ok: true, loginRequired: true });
        }
        if (route === '/api/keys/rotate' || route === '/api/keys/passphrase') {
          throttle('settings:' + user.username, 10, 60000);
          const b = await readBody(req, 8192); await passwordCheck(user, b.password);
          security.validatePassword(b.newPassphrase);
          const key = await keyRecord(user.username, b.keyId);
          try { key.receiver.ensureKeys(b.currentPassphrase); }
          catch { throw new AppError(422, 'Passphrase khoá hiện tại không đúng.'); }
          if (route === '/api/keys/passphrase') {
            changePassphrase(key.directory, b.currentPassphrase, b.newPassphrase);
            await store.audit(user.username, 'change-key-passphrase', null, 'ok', ip);
            return send(res, 200, { ok: true, keyId: key.key_id });
          }
          check(key.active === 1, 'Chỉ luân chuyển từ khoá đang hoạt động.');
          const directory = `users/${user.username}/${crypto.randomBytes(8).toString('hex')}`;
          const next = createReceiver(path.join(keyDir, directory)); next.ensureKeys(b.newPassphrase);
          await store.transaction(async tx => {
            await tx.run('UPDATE key_records SET active=0 WHERE username=?', user.username);
            await tx.run('INSERT INTO key_records(key_id,username,directory,created_at) VALUES(?,?,?,?)', next.keyId, user.username, directory, now());
            await tx.audit(user.username, 'rotate-key', null, 'ok', ip);
          });
          return send(res, 200, { ok: true, keyId: next.keyId });
        }
        if (route === '/api/audit') {
          const page = Math.max(1, Math.min(100000, Number(url.searchParams.get('page')) || 1)); check(Number.isInteger(page), 'Trang không hợp lệ.');
          return send(res, 200, { events: await store.all(`SELECT seq,time,actor,action,document_id,result,ip FROM audit ORDER BY seq DESC LIMIT 30 OFFSET ${(page - 1) * 30}`), page,
            total: Number((await store.get('SELECT COUNT(*) AS n FROM audit')).n) });
        }
        if (route === '/api/maintenance/reindex') {
          await readBody(req, 1024); skipped = await documents.exclusive(() => documents.importFiles(receiver.keyId));
          await store.audit(user.username, 'reindex', null, 'ok', ip); return send(res, 200, { ok: true, skipped });
        }
      } catch (error) {
        if (res.destroyed || res.headersSent) return;
        const status = error instanceof AppError ? error.status : 500;
        if (status === 500) console.error('Lỗi xử lý:', error.code || error.name);
        if (user && [403, 410, 422].includes(status)) await store.audit(user.username, route?.slice(1) || 'request', documentId, 'denied', req.socket.remoteAddress).catch(() => {});
        if (status === 429) res.setHeader('Retry-After', String(error.retryAfter));
        send(res, status, { error: status === 500 ? 'Lỗi hệ thống hoặc database. Vui lòng thử lại sau.' : error.message });
      }
    };
    const server = tls ? https.createServer(tls, handler) : http.createServer(handler);
    server.requestTimeout = 30000; server.headersTimeout = 10000;
    let closePromise;
    function close() {
      if (!closePromise) closePromise = (async () => { clearInterval(cleanup); try { await store.close(); } finally { releaseLock(); } })();
      return closePromise;
    }
    server.on('close', () => close().catch(() => {}));
    return { server, receiver, store, documents, close, keyDir, dataDir };
  } catch (error) { try { await store.close(); } finally { releaseLock(); } throw error; }
}
module.exports = { createApp };
