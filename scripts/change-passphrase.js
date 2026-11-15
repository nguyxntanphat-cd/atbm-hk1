// Chỉ đổi lớp mã hoá private key, không sinh cặp RSA mới.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createReceiver } = require('../receiver');
function changePassphrase(keyDir, oldPass, newPass) {
  if (typeof oldPass !== 'string' || !oldPass || typeof newPass !== 'string' || newPass.length < 12)
    throw new Error('Cần BOSS_PASS hiện tại và NEW_BOSS_PASS mới dài tối thiểu 12 ký tự.');
  if (oldPass === newPass) throw new Error('Passphrase mới phải khác passphrase hiện tại.');
  const receiver = createReceiver(keyDir);
  if (!fs.existsSync(receiver.PRIV)) throw new Error('Không tìm thấy private key hiện tại.');
  const before = receiver.ensureKeys(oldPass);
  const key = crypto.createPrivateKey({ key: fs.readFileSync(receiver.PRIV), passphrase: oldPass });
  const pem = key.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: newPass });
  const verified = crypto.createPrivateKey({ key: pem, passphrase: newPass });
  const after = crypto.createHash('sha256').update(crypto.createPublicKey(verified).export({ type: 'spki', format: 'der' })).digest('hex');
  if (before !== after) throw new Error('Khoá sau khi đổi không khớp. Không ghi thay đổi.');
  const temp = receiver.PRIV + '.tmp';
  fs.writeFileSync(temp, pem, { flag: 'wx', mode: 0o600 });
  fs.renameSync(temp, receiver.PRIV);
  return after;
}
if (require.main === module) {
  let release;
  try {
    if (fs.existsSync('.env')) process.loadEnvFile('.env');
    const keyDir = path.resolve(process.env.KEYSTORE_DIR || path.join(__dirname, '..', 'keystore'));
    release = require('../lifecycle').acquireLock(keyDir);
    changePassphrase(keyDir, process.env.BOSS_PASS, process.env.NEW_BOSS_PASS);
    console.log('Đã đổi passphrase. Cặp RSA không đổi; tài liệu cũ vẫn mở bằng passphrase mới. Cập nhật BOSS_PASS trước khi chạy lại server.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
  finally { if (release) release(); }
}
module.exports = { changePassphrase };
