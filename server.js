// Đồ án ATBM - Ứng dụng mã hoá RSA và AES trong truyền tải dữ liệu nội bộ
// Chạy: node server.js   (không cần cài thư viện)
// Mã bên gửi:  public/sender.js   | key: keystore/sender/boss_public.pem
// Mã bên nhận: receiver.js        | key: keystore/receiver/boss_private.pem
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const receiver = require('./receiver');
const accountStore = require('./account-store');

const PORT = 3000;
const DATA_DIR = path.join(__dirname, 'storage');      // chỉ chứa bản MÃ HOÁ
const AUDIT_FILE = path.join(DATA_DIR, 'activity.json');
const QUICK_LOGIN_FILE = path.join(DATA_DIR, 'quick-logins.json');
const KEY_SETTINGS_FILE = path.join(DATA_DIR, 'key-settings.json');
const PASSPHRASE = process.env.BOSS_PASS;  // passphrase bảo vệ private key Boss
const EMP_PASSPHRASE = process.env.EMP_PASS || 'nv123'; // passphrase bảo vệ private key Nhân viên
fs.mkdirSync(DATA_DIR, { recursive: true });
receiver.ensureKeys(PASSPHRASE, EMP_PASSPHRASE);
accountStore.ensure(DATA_DIR);
const sessions = new Map();

function readAudit() {
  try {
    const parsed = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8'));
    if (Array.isArray(parsed)) return parsed;
    // Older PowerShell formatting wrapped the event array as { value, Count }.
    if (parsed && Array.isArray(parsed.value)) return parsed.value;
    return [];
  }
  catch { return []; }
}
function readQuickLogins() {
  try {
    const entries = JSON.parse(fs.readFileSync(QUICK_LOGIN_FILE, 'utf8'));
    if (!Array.isArray(entries)) return [];
    return entries.filter(entry => entry && typeof entry.id === 'string' &&
      typeof entry.label === 'string' && typeof entry.username === 'string' &&
      typeof entry.password === 'string');
  } catch { return []; }
}
function readKeyPassphrase() {
  try {
    const settings = JSON.parse(fs.readFileSync(KEY_SETTINGS_FILE, 'utf8'));
    if (typeof settings.privateKeyPassphrase === 'string' && settings.privateKeyPassphrase) {
      return settings.privateKeyPassphrase;
    }
  } catch { /* use the environment setting when present */ }
  return PASSPHRASE || '';
}
function logActivity(actor, role, action, detail = '') {
  const events = readAudit();
  events.push({ id: crypto.randomBytes(8).toString('hex'), time: new Date().toISOString(), actor, role, action, detail });
  fs.writeFileSync(AUDIT_FILE, JSON.stringify(events.slice(-5000), null, 2));
}

function getSession(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([^;]+)/);
  if (!m) return null;
  const session = sessions.get(m[1]);
  if (!session) return null;
  const account = accountStore.find(DATA_DIR, session.username);
  if (!account || !account.active) { sessions.delete(m[1]); return null; }
  session.name = account.name;
  session.role = account.role;
  return session;
}

const send = (res, code, body, type = 'application/json') => {
  res.writeHead(code, { 'Content-Type': type });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};
const redirect = (res, loc, cookie) => {
  const h = { Location: loc };
  if (cookie) h['Set-Cookie'] = cookie;
  res.writeHead(302, h);
  res.end();
};
const readBody = req => new Promise((ok, fail) => {
  let s = ''; req.on('data', c => { s += c; if (s.length > 30e6) req.destroy(); });
  req.on('end', () => { try { ok(JSON.parse(s || '{}')); } catch (e) { fail(e); } });
});
const pages = { '/': 'employee.html', '/send': 'send.html', '/admin': 'admin.html', '/tool': 'tool.html', '/history': 'history.html', '/activity': 'activity.html', '/accounts': 'accounts.html' };

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    const sess = getSession(req);

    if (req.method === 'GET' && url.pathname === '/login')
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'public', 'login.html')), 'text/html; charset=utf-8');

    if (url.pathname === '/api/login' && req.method === 'POST') {
      const { username, password } = await readBody(req);
      const u = accountStore.authenticate(DATA_DIR, username, password);
      if (!u) {
        const attempted = accountStore.find(DATA_DIR, username);
        logActivity(username || 'Không rõ', attempted?.role || 'unknown', 'login_failed', 'Đăng nhập thất bại');
        return send(res, 401, { error: 'Sai tên đăng nhập hoặc mật khẩu' });
      }
      const sid = crypto.randomBytes(24).toString('hex');
      sessions.set(sid, { username: u.username, role: u.role, name: u.name });
      logActivity(u.name, u.role, 'login', 'Đăng nhập thành công');
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `sid=${sid}; Path=/; HttpOnly` });
      return res.end(JSON.stringify({ ok: true, role: u.role, name: u.name, redirect: u.role === 'boss' ? '/admin' : '/' }));
    }

    if (url.pathname === '/api/quick-logins' && req.method === 'GET') {
      return send(res, 200, readQuickLogins().map(({ id, label, username }) => ({ id, label, username })));
    }

    if (url.pathname === '/api/quick-login' && req.method === 'POST') {
      const { id } = await readBody(req);
      const entry = readQuickLogins().find(item => item.id === id);
      if (!entry) return send(res, 404, { error: 'Không tìm thấy cấu hình đăng nhập nhanh' });
      const u = accountStore.authenticate(DATA_DIR, entry.username, entry.password);
      if (!u) return send(res, 401, { error: 'Tài khoản đăng nhập nhanh không còn hợp lệ' });
      const sid = crypto.randomBytes(24).toString('hex');
      sessions.set(sid, { username: u.username, role: u.role, name: u.name });
      logActivity(u.name, u.role, 'quick_login', 'Đăng nhập nhanh');
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `sid=${sid}; Path=/; HttpOnly` });
      return res.end(JSON.stringify({ ok: true, role: u.role, name: u.name, redirect: u.role === 'boss' ? '/admin' : '/' }));
    }

    if (req.method === 'GET' && url.pathname === '/logout') {
      const m = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([^;]+)/);
      if (m) {
        const user = sessions.get(m[1]);
        if (user) logActivity(user.name, user.role, 'logout', 'Đăng xuất');
        sessions.delete(m[1]);
      }
      return redirect(res, '/login', 'sid=; Path=/; Max-Age=0; HttpOnly');
    }

    if (url.pathname === '/api/me') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      return send(res, 200, sess);
    }

    if (url.pathname === '/api/key-passphrase' && req.method === 'GET') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role === 'employee') return send(res, 200, { passphrase: EMP_PASSPHRASE });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền truy cập passphrase' });
      const passphrase = readKeyPassphrase();
      if (!passphrase) return send(res, 404, { error: 'Chưa cấu hình passphrase local' });
      return send(res, 200, { passphrase });
    }

    if (req.method === 'GET' && pages[url.pathname]) {
      if (!sess) return redirect(res, '/login');
      if ((url.pathname === '/admin' || url.pathname === '/tool' || url.pathname === '/activity' || url.pathname === '/accounts') && sess.role !== 'boss') return redirect(res, '/login');
      if ((url.pathname === '/history' || url.pathname === '/send') && sess.role !== 'employee') return redirect(res, '/admin');
      if (url.pathname === '/' && sess.role !== 'employee') return redirect(res, '/admin');
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'public', pages[url.pathname])), 'text/html; charset=utf-8');
    }
    if (url.pathname === '/sender.js')
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'public', 'sender.js')), 'text/javascript; charset=utf-8');
    if (url.pathname === '/style.css')
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'public', 'style.css')), 'text/css; charset=utf-8');

    // UC2 – Cung cấp khoá công khai (chỉ public key, không bao giờ lộ private key)
    if (url.pathname === '/api/public-key') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      const target = url.searchParams.get('target') === 'employee' ? receiver.EMP_PUB : receiver.PUB;
      return send(res, 200, fs.readFileSync(target, 'utf8'), 'text/plain');
    }

    // UC10/11 – Nhận & lưu gói mã hoá
    if (url.pathname === '/api/upload' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      const p = await readBody(req);
      if (!p.encKey || !p.iv || !p.data) return send(res, 400, { error: 'Gói tin không hợp lệ' });
      const id = Date.now() + '-' + crypto.randomBytes(3).toString('hex');
      const recipientRole = p.recipientRole === 'employee' ? 'employee' : 'boss';
      const pkg = { id, sender: p.sender || sess.name, title: p.title, category: p.category, filename: p.filename,
        owner: sess.username, recipientRole, targetUser: p.targetUser || null, replyTo: p.replyTo || null,
        time: new Date().toISOString(), encKey: p.encKey, iv: p.iv, data: p.data };
      fs.writeFileSync(path.join(DATA_DIR, id + '.json'), JSON.stringify(pkg, null, 2));
      logActivity(sess.name, sess.role, 'upload', `${pkg.filename || 'Tài liệu'} · ${pkg.title || pkg.category || ''}`);
      return send(res, 200, { ok: true, id });
    }

    if (url.pathname === '/api/list') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền truy cập' });
      const list = fs.readdirSync(DATA_DIR).filter(f => /^\d+-[a-f0-9]+\.json$/.test(f)).map(f => {
        const { data, ...meta } = JSON.parse(fs.readFileSync(path.join(DATA_DIR, f)));
        return { ...meta, size: data.length };
      }).filter(pkg => pkg.recipientRole !== 'employee').sort((a, b) => b.time.localeCompare(a.time));
      return send(res, 200, list);
    }

    if (url.pathname === '/api/my-inbox') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'employee') return send(res, 403, { error: 'Chỉ nhân viên xem được hộp thư nhận' });
      const list = fs.readdirSync(DATA_DIR).filter(f => /^\d+-[a-f0-9]+\.json$/.test(f)).map(f => {
        const { data, ...meta } = JSON.parse(fs.readFileSync(path.join(DATA_DIR, f)));
        return { ...meta, size: data.length };
      }).filter(pkg => pkg.recipientRole === 'employee' && (!pkg.targetUser || pkg.targetUser === sess.username))
        .sort((a, b) => b.time.localeCompare(a.time));
      return send(res, 200, list);
    }

    if (url.pathname === '/api/my-documents') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'employee') return send(res, 403, { error: 'Chỉ nhân viên xem được lịch sử cá nhân' });
      const list = fs.readdirSync(DATA_DIR).filter(f => /^\d+-[a-f0-9]+\.json$/.test(f)).map(f => JSON.parse(fs.readFileSync(path.join(DATA_DIR, f))))
        .filter(pkg => pkg.owner === sess.username).map(({ data, encKey, iv, ...meta }) => ({ ...meta, size: data.length }))
        .sort((a, b) => b.time.localeCompare(a.time));
      return send(res, 200, list);
    }

    if (url.pathname === '/api/my-activity') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'employee') return send(res, 403, { error: 'Chỉ nhân viên xem được hoạt động cá nhân' });
      return send(res, 200, readAudit().filter(e => e.actor === sess.name || e.actor === sess.username).slice().reverse());
    }

    if (url.pathname === '/api/activity') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền xem nhật ký hệ thống' });
      return send(res, 200, readAudit().slice().reverse());
    }

    if (url.pathname === '/api/accounts') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền quản lý tài khoản' });
      const role = url.searchParams.get('role');
      if (!['employee', 'boss'].includes(role)) return send(res, 400, { error: 'Loại tài khoản không hợp lệ' });
      return send(res, 200, accountStore.list(DATA_DIR, role));
    }

    if (url.pathname === '/api/accounts/update' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền quản lý tài khoản' });
      const b = await readBody(req);
      try {
        const updated = accountStore.update(DATA_DIR, b.username, b);
        if (!updated) return send(res, 404, { error: 'Không tìm thấy tài khoản' });
        logActivity(sess.name, sess.role, 'account_update', `${updated.role} · ${updated.username}`);
        return send(res, 200, updated);
      } catch (e) { return send(res, 400, { error: e.message }); }
    }

    if (url.pathname === '/api/accounts/status' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền quản lý tài khoản' });
      const b = await readBody(req);
      if (typeof b.active !== 'boolean') return send(res, 400, { error: 'Trạng thái tài khoản không hợp lệ' });
      if (String(b.username).toLocaleLowerCase('vi') === sess.username.toLocaleLowerCase('vi') && b.active === false) {
        return send(res, 400, { error: 'Bạn không thể khóa tài khoản admin đang đăng nhập' });
      }
      try {
        const updated = accountStore.setActive(DATA_DIR, b.username, b.active === true);
        if (!updated) return send(res, 404, { error: 'Không tìm thấy tài khoản' });
        logActivity(sess.name, sess.role, 'account_status', `${updated.username} · ${updated.active ? 'mở khóa' : 'khóa'}`);
        return send(res, 200, updated);
      } catch (e) { return send(res, 400, { error: e.message }); }
    }

    if (url.pathname === '/api/accounts/delete' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền quản lý tài khoản' });
      const b = await readBody(req);
      if (String(b.username).toLocaleLowerCase('vi') === sess.username.toLocaleLowerCase('vi')) {
        return send(res, 400, { error: 'Bạn không thể xóa tài khoản admin đang đăng nhập' });
      }
      try {
        const removed = accountStore.remove(DATA_DIR, b.username);
        if (!removed) return send(res, 404, { error: 'Không tìm thấy tài khoản' });
        logActivity(sess.name, sess.role, 'account_delete', `${removed.role} · ${removed.username}`);
        return send(res, 200, { ok: true });
      } catch (e) { return send(res, 400, { error: e.message }); }
    }

    if (url.pathname === '/api/raw') { // tải bản mã gốc
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền truy cập' });
      const id = path.basename(url.searchParams.get('id') || '');
      res.setHeader('Content-Disposition', `attachment; filename="${id}.enc.json"`);
      return send(res, 200, fs.readFileSync(path.join(DATA_DIR, id + '.json')));
    }

    if (url.pathname === '/api/delete' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền xóa tài liệu' });
      const { id: requestedId } = await readBody(req);
      const id = path.basename(String(requestedId || ''));
      if (!/^\d+-[a-f0-9]+$/.test(id)) return send(res, 400, { error: 'Mã tài liệu không hợp lệ' });
      const target = path.join(DATA_DIR, id + '.json');
      if (!fs.existsSync(target)) return send(res, 404, { error: 'Không tìm thấy tài liệu' });
      const removed = JSON.parse(fs.readFileSync(target, 'utf8'));
      logActivity(sess.name, sess.role, 'delete', `${removed.filename || id} · ${removed.title || ''}`);
      fs.unlinkSync(target);
      return send(res, 200, { ok: true });
    }

    // UC12 – Giải mã (gọi sang receiver.js)
    if (url.pathname === '/api/decrypt' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      const b = await readBody(req);
      const pkg = b.pkg || JSON.parse(fs.readFileSync(path.join(DATA_DIR, path.basename(b.id) + '.json')));
      const pkgRole = pkg.recipientRole === 'employee' ? 'employee' : 'boss';
      if (sess.role !== pkgRole) return send(res, 403, { error: 'Không có quyền giải mã gói tin này' });
      try {
        const plain = receiver.decryptPackage(pkg, b.passphrase, pkgRole);
        logActivity(sess.name, sess.role, 'decrypt', `${pkg.filename || 'Tài liệu'} · ${pkg.title || ''}`);
        return send(res, 200, { filename: pkg.filename, data: plain.toString('base64') });
      } catch (e) { return send(res, 401, { error: 'Giải mã thất bại: sai passphrase/khoá hoặc dữ liệu bị sửa đổi' }); }
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { send(res, 500, { error: e.message }); }
}).listen(PORT, () => console.log(`Đăng nhập: http://localhost:${PORT}/login\nNhân viên: http://localhost:${PORT}\nBoss:      http://localhost:${PORT}/admin\nCông cụ:   http://localhost:${PORT}/tool`));
