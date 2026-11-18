// Đồ án ATBM - Ứng dụng mã hoá RSA và AES trong truyền tải dữ liệu nội bộ
// Chạy: node server.js   (không cần cài thư viện)
// Mã bên gửi:  public/sender.js   | key: keystore/sender/boss_public.pem
// Mã bên nhận: receiver.js        | key: keystore/receiver/boss_private.pem
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const receiver = require('./receiver');

const PORT = 3000;
const DATA_DIR = path.join(__dirname, 'storage');      // chỉ chứa bản MÃ HOÁ
const AUDIT_FILE = path.join(DATA_DIR, 'activity.json');
const SIGNER_KEYS_DIR = path.join(__dirname, 'keystore', 'signers');
const PASSPHRASE = process.env.BOSS_PASS || 'boss123';  // passphrase bảo vệ private key
fs.mkdirSync(DATA_DIR, { recursive: true });
receiver.ensureKeys(PASSPHRASE);

const USERS = {
  nhanvien: { pass: '123456', role: 'employee', name: 'Nhân viên A' },
  boss: { pass: 'admin123', role: 'boss', name: 'Boss' }
};
const sessions = new Map();

function readAudit() {
  try { return JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8')); }
  catch { return []; }
}
function logActivity(actor, role, action, detail = '') {
  const events = readAudit();
  events.push({ id: crypto.randomBytes(8).toString('hex'), time: new Date().toISOString(), actor, role, action, detail });
  fs.writeFileSync(AUDIT_FILE, JSON.stringify(events.slice(-5000)));
}

function getSession(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([^;]+)/);
  return m ? sessions.get(m[1]) || null : null;
}

function signerKeyPath(username) {
  if (!/^[a-z0-9_-]+$/i.test(username || '')) throw new Error('Tài khoản không hợp lệ');
  return path.join(SIGNER_KEYS_DIR, `${username}.pem`);
}
function packageSigningContent(pkg) {
  return JSON.stringify([pkg.filename || '', pkg.sender || '', pkg.title || '', pkg.category || '', pkg.encKey, pkg.iv, pkg.data]);
}
function verifyPackageSignature(pkg) {
  if (!pkg.signature || !pkg.owner) return false;
  const keyFile = signerKeyPath(pkg.owner);
  if (!fs.existsSync(keyFile)) return false;
  return crypto.verify('sha256', Buffer.from(packageSigningContent(pkg)), {
    key: fs.readFileSync(keyFile, 'utf8'),
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  }, Buffer.from(pkg.signature, 'base64'));
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
const pages = { '/': 'employee.html', '/send': 'send.html', '/admin': 'admin.html', '/tool': 'tool.html', '/history': 'history.html', '/activity': 'activity.html' };

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    const sess = getSession(req);

    if (req.method === 'GET' && url.pathname === '/login')
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'public', 'login.html')), 'text/html; charset=utf-8');

    if (url.pathname === '/api/login' && req.method === 'POST') {
      const { username, password } = await readBody(req);
      const u = USERS[username];
      if (!u || u.pass !== password) {
        logActivity(username || 'Không rõ', u?.role || 'unknown', 'login_failed', 'Đăng nhập thất bại');
        return send(res, 401, { error: 'Sai tên đăng nhập hoặc mật khẩu' });
      }
      const sid = crypto.randomBytes(24).toString('hex');
      sessions.set(sid, { username, role: u.role, name: u.name });
      logActivity(u.name, u.role, 'login', 'Đăng nhập thành công');
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

    if (req.method === 'GET' && pages[url.pathname]) {
      if (!sess) return redirect(res, '/login');
      if ((url.pathname === '/admin' || url.pathname === '/tool' || url.pathname === '/activity') && sess.role !== 'boss') return redirect(res, '/login');
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
      return send(res, 200, fs.readFileSync(receiver.PUB, 'utf8'), 'text/plain');
    }

    // The employee creates and retains the private signing key in the browser.
    // This endpoint registers only the public key, once per account.
    if (url.pathname === '/api/signing-key' && req.method === 'GET') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'employee') return send(res, 403, { error: 'Chỉ nhân viên có khóa ký số' });
      const file = signerKeyPath(sess.username);
      return send(res, 200, { publicKey: fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null });
    }
    if (url.pathname === '/api/signing-key' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'employee') return send(res, 403, { error: 'Chỉ nhân viên có khóa ký số' });
      const { publicKey } = await readBody(req);
      let key;
      try { key = crypto.createPublicKey(publicKey); }
      catch { return send(res, 400, { error: 'Khóa công khai không hợp lệ' }); }
      if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 2048)
        return send(res, 400, { error: 'Khóa ký phải là RSA tối thiểu 2048 bit' });
      fs.mkdirSync(SIGNER_KEYS_DIR, { recursive: true });
      const file = signerKeyPath(sess.username);
      if (fs.existsSync(file)) return send(res, 409, { error: 'Khóa công khai đã được đăng ký' });
      fs.writeFileSync(file, key.export({ type: 'spki', format: 'pem' }), { flag: 'wx' });
      return send(res, 201, { ok: true });
    }

    // UC10/11 – Nhận & lưu gói mã hoá
    if (url.pathname === '/api/upload' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      const p = await readBody(req);
      if (sess.role !== 'employee') return send(res, 403, { error: 'Chỉ nhân viên được gửi tài liệu' });
      if (!p.encKey || !p.iv || !p.data || !p.signature) return send(res, 400, { error: 'Gói tin thiếu chữ ký số hoặc dữ liệu mã hóa' });
      if (p.sender !== sess.name) return send(res, 400, { error: 'Tên người gửi phải khớp tài khoản đăng nhập' });
      const signedPackage = { ...p, owner: sess.username };
      try {
        if (!verifyPackageSignature(signedPackage)) return send(res, 400, { error: 'Chữ ký số không hợp lệ hoặc khóa công khai chưa đăng ký' });
      } catch { return send(res, 400, { error: 'Không thể xác minh chữ ký số' }); }
      const id = Date.now() + '-' + crypto.randomBytes(3).toString('hex');
      const pkg = { id, sender: p.sender || sess.name, title: p.title, category: p.category, filename: p.filename,
        owner: sess.username, time: new Date().toISOString(), encKey: p.encKey, iv: p.iv, data: p.data, signature: p.signature };
      fs.writeFileSync(path.join(DATA_DIR, id + '.json'), JSON.stringify(pkg));
      logActivity(sess.name, sess.role, 'upload', `${pkg.filename || 'Tài liệu'} · ${pkg.title || pkg.category || ''}`);
      return send(res, 200, { ok: true, id });
    }

    if (url.pathname === '/api/list') {
      if (!sess) return send(res, 401, { error: 'Chưa đăng nhập' });
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền truy cập' });
      const list = fs.readdirSync(DATA_DIR).filter(f => /^\d+-[a-f0-9]+\.json$/.test(f)).map(f => {
        const { data, ...meta } = JSON.parse(fs.readFileSync(path.join(DATA_DIR, f)));
        return { ...meta, size: data.length };
      }).sort((a, b) => b.time.localeCompare(a.time));
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
      if (sess.role !== 'boss') return send(res, 403, { error: 'Không có quyền giải mã' });
      const b = await readBody(req);
      const pkg = b.pkg || JSON.parse(fs.readFileSync(path.join(DATA_DIR, path.basename(b.id) + '.json')));
      try {
        let signatureStatus = 'unsigned';
        if (pkg.signature) {
          if (!verifyPackageSignature(pkg)) return send(res, 400, { error: 'Chữ ký số không hợp lệ: tài liệu hoặc thông tin người gửi có thể đã bị sửa đổi' });
          signatureStatus = 'verified';
        }
        const plain = receiver.decryptPackage(pkg, b.passphrase);
        logActivity(sess.name, sess.role, 'decrypt', `${pkg.filename || 'Tài liệu'} · ${pkg.title || ''}`);
        return send(res, 200, { filename: pkg.filename, data: plain.toString('base64'), signatureStatus });
      } catch (e) { return send(res, 401, { error: 'Giải mã thất bại: sai passphrase/khoá hoặc dữ liệu bị sửa đổi' }); }
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { send(res, 500, { error: e.message }); }
}).listen(PORT, () => console.log(`Đăng nhập: http://localhost:${PORT}/login\nNhân viên: http://localhost:${PORT}\nBoss:      http://localhost:${PORT}/admin\nCông cụ:   http://localhost:${PORT}/tool`));
