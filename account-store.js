const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROLES = new Set(['employee', 'boss']);
const passwordHash = (password, salt) => crypto.scryptSync(password, salt, 64).toString('hex');
const publicAccount = ({ passwordHash: _hash, salt: _salt, ...account }) => account;

function accountFile(dataDir) { return path.join(dataDir, 'accounts.json'); }
function activityFile(dataDir) { return path.join(dataDir, 'activity.json'); }
function read(dataDir) {
  return JSON.parse(fs.readFileSync(accountFile(dataDir), 'utf8'));
}
function write(dataDir, db) {
  fs.writeFileSync(accountFile(dataDir), JSON.stringify(db, null, 2), { mode: 0o600 });
}
function makeAccount({ name, username, phone, email, password, role }) {
  const salt = crypto.randomBytes(16).toString('hex');
  return {
    id: crypto.randomUUID(), name: name.trim(), username: username.trim(), phone: phone.trim(), email: email.trim(),
    role, passwordHash: passwordHash(password, salt), salt, active: true, createdAt: new Date().toISOString()
  };
}

function ensure(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = accountFile(dataDir);
  if (fs.existsSync(file)) {
    const db = read(dataDir);
    if (!Array.isArray(db.accounts)) throw new Error('Tệp storage/accounts.json không đúng định dạng');
    return;
  }
  write(dataDir, { accounts: [] });
}

function find(dataDir, username) {
  const normalized = String(username || '').trim().toLocaleLowerCase('vi');
  return read(dataDir).accounts.find(a => a.username.toLocaleLowerCase('vi') === normalized) || null;
}
function authenticate(dataDir, username, password) {
  const account = find(dataDir, username);
  if (!account || !account.active || typeof password !== 'string') return null;
  const actual = Buffer.from(passwordHash(password, account.salt), 'hex');
  const expected = Buffer.from(account.passwordHash, 'hex');
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  return publicAccount(account);
}
function list(dataDir, role) {
  if (!ROLES.has(role)) throw new Error('Vai trò không hợp lệ');
  return read(dataDir).accounts.filter(a => a.role === role).map(publicAccount)
    .sort((a, b) => a.name.localeCompare(b.name, 'vi'));
}
function create(dataDir, input) {
  if (!ROLES.has(input.role)) throw new Error('Chọn loại tài khoản user hoặc admin');
  const name = String(input.name || '').trim();
  const username = String(input.username || '').trim();
  const phone = String(input.phone || '').trim();
  const email = String(input.email || '').trim();
  const password = String(input.password || '');
  if (name.length < 2 || name.length > 100) throw new Error('Tên phải từ 2 đến 100 ký tự');
  if (!/^[a-zA-Z0-9._-]{3,32}$/.test(username)) throw new Error('Tên tài khoản cần 3–32 ký tự: chữ, số, dấu chấm, gạch dưới hoặc gạch ngang');
  if (!/^[+()\d.\-\s]{7,24}$/.test(phone) || phone.replace(/\D/g, '').length < 7) throw new Error('Số điện thoại không hợp lệ');
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Địa chỉ email không hợp lệ');
  if (password.length < 8 || password.length > 128) throw new Error('Mật khẩu phải từ 8 đến 128 ký tự');
  const db = read(dataDir);
  if (db.accounts.some(a => a.username.toLocaleLowerCase('vi') === username.toLocaleLowerCase('vi'))) {
    throw new Error('Tên tài khoản đã tồn tại');
  }
  const account = makeAccount({ name, username, phone, email, password, role: input.role });
  db.accounts.push(account);
  write(dataDir, db);
  return publicAccount(account);
}
function update(dataDir, username, changes) {
  const db = read(dataDir);
  const account = db.accounts.find(a => a.username.toLocaleLowerCase('vi') === String(username || '').toLocaleLowerCase('vi'));
  if (!account) return null;
  const name = String(changes.name || '').trim();
  const phone = String(changes.phone || '').trim();
  const email = String(changes.email || '').trim();
  if (name.length < 2 || name.length > 100) throw new Error('Tên phải từ 2 đến 100 ký tự');
  if (!/^[+()\d.\-\s]{7,24}$/.test(phone) || phone.replace(/\D/g, '').length < 7) throw new Error('Số điện thoại không hợp lệ');
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Địa chỉ email không hợp lệ');
  Object.assign(account, { name, phone, email, updatedAt: new Date().toISOString() });
  write(dataDir, db);
  return publicAccount(account);
}
function setActive(dataDir, username, active) {
  const db = read(dataDir);
  const account = db.accounts.find(a => a.username.toLocaleLowerCase('vi') === String(username || '').toLocaleLowerCase('vi'));
  if (!account) return null;
  if (account.role === 'boss' && !active && db.accounts.filter(a => a.role === 'boss' && a.active).length <= 1) {
    throw new Error('Không thể khóa admin cuối cùng còn hoạt động');
  }
  account.active = active;
  account.updatedAt = new Date().toISOString();
  write(dataDir, db);
  return publicAccount(account);
}
function remove(dataDir, username) {
  const db = read(dataDir);
  const index = db.accounts.findIndex(a => a.username.toLocaleLowerCase('vi') === String(username || '').toLocaleLowerCase('vi'));
  if (index < 0) return null;
  const [account] = db.accounts.splice(index, 1);
  if (account.role === 'boss' && !db.accounts.some(a => a.role === 'boss' && a.active)) {
    throw new Error('Không thể xóa admin cuối cùng còn hoạt động');
  }
  write(dataDir, db);
  return publicAccount(account);
}
function logActivity(dataDir, actor, role, action, detail) {
  const file = activityFile(dataDir);
  let events = [];
  try { events = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* nhật ký chưa có */ }
  events.push({ id: crypto.randomBytes(8).toString('hex'), time: new Date().toISOString(), actor, role, action, detail });
  fs.writeFileSync(file, JSON.stringify(events.slice(-5000), null, 2));
}

module.exports = { ensure, find, authenticate, list, create, update, setActive, remove, logActivity };
