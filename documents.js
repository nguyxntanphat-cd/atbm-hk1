const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { AppError, check, validatePackage } = require('./package-format');
const ID = /^\d{13}-[a-f0-9]{6,16}$/;
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
class Documents {
  constructor(store, dataDir) { this.store = store; this.dataDir = dataDir; this.tail = Promise.resolve(); }
  exclusive(fn) {
    const job = this.tail.then(fn); this.tail = job.catch(() => {}); return job;
  }
  async index(pkg, bytes, defaultKeyId) {
    const parsed = validatePackage(pkg, { allowLegacy: true });
    check(ID.test(pkg.id) && typeof pkg.time === 'string' && Number.isFinite(Date.parse(pkg.time)), 'Metadata lưu trữ không hợp lệ.');
    const recipient = pkg.version === 3 ? pkg.recipientUsername : 'boss';
    const keyId = pkg.version ? pkg.keyId : defaultKeyId;
    const key = await this.store.get('SELECT username FROM key_records WHERE key_id=?', keyId);
    check(key?.username === recipient, 'Khoá không thuộc người nhận.');
    await this.store.run(`INSERT INTO documents(id,sender_username,recipient_username,sender,title,category,
      filename,size,stored_bytes,key_id,version,time,expires_at,previous_id,sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    pkg.id, pkg.senderUsername || 'nhanvien', recipient, pkg.sender, pkg.title, pkg.category,
    pkg.filename, parsed.data.length - 16, bytes.length, keyId, pkg.version || 1, pkg.time,
    pkg.expiresAt || null, pkg.previousId || null, sha256(bytes));
  }
  async importFiles(defaultKeyId) {
    let skipped = 0;
    for (const filename of await fs.promises.readdir(this.dataDir)) {
      if (!filename.endsWith('.json')) continue;
      const id = filename.slice(0, -5);
      if (await this.store.get('SELECT id FROM documents WHERE id=?', id)) continue;
      try {
        check(ID.test(id), 'ID không hợp lệ.');
        const file = path.join(this.dataDir, filename);
        check((await fs.promises.stat(file)).size <= 15 * 1024 * 1024, 'Gói quá lớn.');
        const bytes = await fs.promises.readFile(file), pkg = JSON.parse(bytes.toString('utf8'));
        check(pkg.id === id, 'ID không khớp file.');
        await this.index(pkg, bytes, defaultKeyId);
      } catch { skipped++; }
    }
    return skipped;
  }
  async record(id) {
    check(typeof id === 'string' && ID.test(id), 'ID tài liệu không hợp lệ.');
    const row = await this.store.get('SELECT * FROM documents WHERE id=?', id);
    if (!row) throw new AppError(404, 'Không tìm thấy tài liệu.');
    return row;
  }
  authorize(row, user, { sender = false } = {}) {
    if (row.recipient_username !== user.username && !(sender && row.sender_username === user.username))
      throw new AppError(403, 'Bạn không có quyền truy cập tài liệu này.');
    if (row.revoked_at) throw new AppError(410, 'Tài liệu đã được thu hồi. Bản đã tải xuống không thể thu hồi từ xa.');
    if (row.expires_at && row.expires_at <= new Date().toISOString()) throw new AppError(410, 'Tài liệu đã hết hạn truy cập.');
  }
  async read(row) {
    try {
      const filename = path.join(this.dataDir, row.id + '.json');
      const stat = await fs.promises.stat(filename);
      if (stat.size !== row.stored_bytes || stat.size > 15 * 1024 * 1024) throw new AppError(422, 'Kích thước gói lưu trữ đã thay đổi.');
      const bytes = await fs.promises.readFile(filename);
      if (sha256(bytes) !== row.sha256) throw new AppError(422, 'Gói lưu trữ đã bị thay đổi so với chỉ mục.');
      return JSON.parse(bytes.toString('utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') throw new AppError(404, 'File tài liệu không còn trong kho.');
      if (error instanceof SyntaxError) throw new AppError(422, 'Gói lưu trữ bị hỏng.');
      throw error;
    }
  }
  async list(user, url, sent = false) {
    const page = Math.max(1, Math.min(100000, Number(url.searchParams.get('page')) || 1));
    const limit = 10, q = (url.searchParams.get('q') || '').slice(0, 200);
    check(Number.isInteger(page), 'Trang không hợp lệ.');
    const field = sent ? 'sender_username' : 'recipient_username';
    let where = `${field}=?`; const args = [user.username];
    // INSTR không coi %/_ do người dùng nhập là wildcard.
    if (q) { where += ' AND (INSTR(title,?)>0 OR INSTR(filename,?)>0 OR INSTR(sender,?)>0)'; args.push(q, q, q); }
    const category = url.searchParams.get('category');
    if (category) { where += ' AND category=?'; args.push(category); }
    const total = Number((await this.store.get(`SELECT COUNT(*) AS total FROM documents WHERE ${where}`, ...args)).total);
    const rows = await this.store.all(`SELECT id,sender,sender_username,recipient_username,title,category,filename,size,
      version,time,opened_at,revoked_at,expires_at,previous_id,scan_status FROM documents WHERE ${where}
      ORDER BY time DESC,id DESC LIMIT ${limit} OFFSET ${(page - 1) * limit}`, ...args);
    return { documents: rows.map(row => ({ ...row, legacy: row.version === 1 })), total, page, pages: Math.max(1, Math.ceil(total / limit)) };
  }
}
module.exports = { Documents, sha256, ID };
