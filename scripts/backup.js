const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const { Store, databaseConfig } = require('../store');
const { acquireLock } = require('../lifecycle');
const { sha256, ID } = require('../documents');
const { createReceiver } = require('../receiver');
const derive = require('util').promisify(crypto.scrypt);
const TABLES = ['settings','users','key_records','documents','audit'];
function passwordCheck(password) {
  if (typeof password !== 'string' || password.length < 16 || password.length > 256) throw new Error('BACKUP_PASSWORD cần 16–256 ký tự.');
}
function walk(directory, area, relative = '') {
  const files = [];
  for (const item of fs.readdirSync(path.join(directory, relative), { withFileTypes: true })) {
    if (item.isSymbolicLink() || item.name.endsWith('.tmp') || item.name.startsWith('.')) continue;
    const name = path.posix.join(relative, item.name);
    if (item.isDirectory()) files.push(...walk(directory, area, name));
    else if (area === 'storage' && item.name.endsWith('.json') || area === 'keystore' && item.name.endsWith('.pem')) {
      const bytes = fs.readFileSync(path.join(directory, name));
      files.push({ area, name, sha256: sha256(bytes), data: bytes.toString('base64') });
    }
  }
  return files;
}
async function createBackup({ store, keyDir, dataDir, password, output }) {
  passwordCheck(password); const release = acquireLock(keyDir);
  try {
    const files = [...walk(keyDir, 'keystore'), ...walk(dataDir, 'storage')];
    if (files.reduce((sum, file) => sum + file.data.length, 0) > 180 * 1048576) throw new Error('Backup vượt giới hạn công cụ nhóm nhỏ (~128 MiB dữ liệu). Cần công cụ sao lưu streaming chuyên dụng.');
    const tables = await store.transaction(async tx => {
      const result = {};
      for (const table of TABLES) {
        result[table] = await tx.all('SELECT * FROM ' + table);
        if (table === 'key_records') for (const row of result[table]) delete row.active_owner;
      }
      return result;
    });
    const plain = Buffer.from(JSON.stringify({ version: 1, createdAt: new Date().toISOString(), tables, files }));
    const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12), key = await derive(password, salt, 32);
    try {
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(Buffer.from('ATBM-BACKUP-1'));
      const data = Buffer.concat([cipher.update(plain), cipher.final()]);
      const envelope = { version: 1, salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
      fs.mkdirSync(path.dirname(output), { recursive: true });
      fs.writeFileSync(output, JSON.stringify(envelope), { flag: 'wx', mode: 0o600 });
    } finally { key.fill(0); plain.fill(0); }
    return { files: files.length, documents: tables.documents.length };
  } finally { release(); }
}
async function readBackup(filename, password) {
  passwordCheck(password);
  if (fs.statSync(filename).size > 300 * 1048576) throw new Error('Backup quá lớn cho công cụ này.');
  const envelope = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (envelope.version !== 1) throw new Error('Phiên bản backup không được hỗ trợ.');
  const key = await derive(password, Buffer.from(envelope.salt, 'base64'), 32);
  let plain;
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    d.setAAD(Buffer.from('ATBM-BACKUP-1')); d.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    plain = Buffer.concat([d.update(Buffer.from(envelope.data, 'base64')), d.final()]);
    const snapshot = JSON.parse(plain.toString('utf8'));
    for (const file of snapshot.files) {
      if (!['storage','keystore'].includes(file.area) || !/^[a-zA-Z0-9_./-]+$/.test(file.name)
        || file.name.split('/').some(part => !part || part === '.' || part === '..') || path.isAbsolute(file.name)
        || sha256(Buffer.from(file.data, 'base64')) !== file.sha256) throw new Error('Manifest backup không hợp lệ.');
    }
    return snapshot;
  } catch { throw new Error('Không xác thực được backup: sai mật khẩu hoặc dữ liệu đã bị sửa.'); }
  finally { key.fill(0); if (plain) plain.fill(0); }
}
async function restoreBackup(snapshot, config, target) {
  if (fs.existsSync(target)) throw new Error('Thư mục phục hồi phải chưa tồn tại.');
  if (!/^atbm_(restore|test)_[a-zA-Z0-9_]+$/.test(config.database)) throw new Error('Database phục hồi phải có tên atbm_restore_... để tránh ghi nhầm database thật.');
  const admin = await mysql.createConnection({ ...config, database: undefined });
  try {
    if ((await admin.execute('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?', [config.database]))[0].length)
      throw new Error('Database phục hồi đã tồn tại. Không ghi đè.');
  } finally { await admin.end(); }
  const store = await Store.open(config, { createDatabase: true });
  try {
    fs.mkdirSync(target, { recursive: true });
    for (const file of snapshot.files) {
      const filename = path.join(target, file.area, file.name);
      fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, Buffer.from(file.data, 'base64'), { flag: 'wx', mode: 0o600 });
    }
    await store.transaction(async tx => {
      await tx.run('DELETE FROM settings');
      for (const table of TABLES) for (const row of snapshot.tables[table]) {
        // Archive từ phiên bản trước có thể chứa các cột tính năng đã loại bỏ.
        if (table === 'users') { delete row.mfa_secret; delete row.mfa_step; }
        const columns = Object.keys(row);
        // Tên cột phải thuộc cấu trúc bảng thực tế, không được chèn SQL từ archive.
        const allowed = (await tx.all('SHOW COLUMNS FROM ' + table)).map(c => c.Field);
        if (!columns.every(column => allowed.includes(column))) throw new Error('Cột backup không hợp lệ.');
        await tx.run(`INSERT INTO ${table} (${columns.map(c => '`' + c + '`').join(',')}) VALUES(${columns.map(() => '?').join(',')})`, ...columns.map(c => row[c]));
      }
    });
    if (!await store.verifyAudit()) throw new Error('Chuỗi nhật ký phục hồi không hợp lệ.');
    for (const record of await store.all('SELECT * FROM key_records')) {
      const root = path.resolve(target, 'keystore'), directory = path.resolve(root, record.directory);
      if (directory !== root && !directory.startsWith(root + path.sep)) throw new Error('Đường dẫn khoá phục hồi không hợp lệ.');
      const r = createReceiver(directory);
      if (r.loadKeys() !== record.key_id) throw new Error('Khoá phục hồi không khớp.');
    }
    for (const row of await store.all('SELECT id,sha256 FROM documents'))
      if (!ID.test(row.id) || sha256(fs.readFileSync(path.join(target, 'storage', row.id + '.json'))) !== row.sha256) throw new Error('Tài liệu phục hồi không khớp.');
    return { files: snapshot.files.length, documents: snapshot.tables.documents.length };
  } finally { await store.close(); }
}
if (require.main === module) {
  if (fs.existsSync('.env')) process.loadEnvFile('.env');
  (async () => {
    const [command, filename, dbName] = process.argv.slice(2), password = process.env.BACKUP_PASSWORD;
    if (command === 'create') {
      const store = await Store.open(databaseConfig());
      try {
        const output = path.resolve(filename || path.join('backups', new Date().toISOString().replace(/[:.]/g, '-') + '.atbm-backup'));
        console.log(await createBackup({ store, password, output, keyDir: path.resolve(process.env.KEYSTORE_DIR || 'keystore'), dataDir: path.resolve(process.env.DATA_DIR || 'storage') }));
        console.log('Backup đã mã hoá:', output);
      } finally { await store.close(); }
    } else if (command === 'verify' || command === 'restore') {
      const snapshot = await readBackup(filename, password);
      if (command === 'verify') console.log('Backup xác thực hợp lệ:', snapshot.files.length, 'file. Để kiểm tra phục hồi đầy đủ, chạy restore vào database mới.');
      else {
        const target = path.resolve('runtime', dbName || '');
        console.log(await restoreBackup(snapshot, { ...databaseConfig(), database: dbName || '' }, target));
        console.log('Đã phục hồi vào database mới và thư mục:', target, '(không phục hồi session đăng nhập)');
      }
    } else throw new Error('Dùng: backup.js create [file] | verify <file> | restore <file> <atbm_restore_ten>');
  })().catch(error => { console.error(error.message); process.exitCode = 1; });
}
module.exports = { createBackup, readBackup, restoreBackup };
