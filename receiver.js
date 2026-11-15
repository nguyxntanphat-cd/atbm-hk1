// Private key và giải mã nằm ở server tin cậy.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { validatePackage, aadText, AppError } = require('./package-format');

function createReceiver(keyDir = path.join(__dirname, 'keystore')) {
  const PRIV = path.join(keyDir, 'receiver', 'boss_private.pem');
  const PUB = path.join(keyDir, 'sender', 'boss_public.pem');
  let keyId;
  function loadKeys() {
    if (!fs.existsSync(PRIV) || !fs.existsSync(PUB)) throw new Error('Thiếu cặp khoá. Cần khôi phục bản sao lưu.');
    const publicKey = crypto.createPublicKey(fs.readFileSync(PUB));
    if (publicKey.asymmetricKeyType !== 'rsa' || publicKey.asymmetricKeyDetails.modulusLength !== 2048)
      throw new Error('Cặp khoá phải dùng RSA-2048.');
    keyId = crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    return keyId;
  }
  function ensureKeys(passphrase) {
    if (typeof passphrase !== 'string' || !passphrase) throw new Error('BOSS_PASS không được để trống.');
    fs.mkdirSync(path.dirname(PRIV), { recursive: true });
    fs.mkdirSync(path.dirname(PUB), { recursive: true });
    const hasPrivate = fs.existsSync(PRIV), hasPublic = fs.existsSync(PUB);
    if (!hasPrivate && hasPublic) throw new Error('Thiếu private key. Hãy khôi phục bản sao lưu; không tự sinh đè khoá.');
    if (!hasPrivate) {
      const pair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
      });
      fs.writeFileSync(PRIV, pair.privateKey, { mode: 0o600, flag: 'wx' });
      fs.writeFileSync(PUB, pair.publicKey, { flag: 'wx' });
    }
    let privateKey;
    try { privateKey = crypto.createPrivateKey({ key: fs.readFileSync(PRIV), passphrase }); }
    catch { throw new Error('Không mở được private key. Kiểm tra BOSS_PASS và bản sao lưu; khoá hiện tại được giữ nguyên.'); }
    if (privateKey.asymmetricKeyType !== 'rsa' || privateKey.asymmetricKeyDetails.modulusLength !== 2048)
      throw new Error('Đồ án yêu cầu cặp khoá RSA-2048.');
    const derived = crypto.createPublicKey(privateKey);
    const der = derived.export({ type: 'spki', format: 'der' });
    if (fs.existsSync(PUB)) {
      const existing = crypto.createPublicKey(fs.readFileSync(PUB)).export({ type: 'spki', format: 'der' });
      if (!der.equals(existing)) throw new Error('Public key không khớp private key. Hãy khôi phục đúng cặp khoá.');
    } else fs.writeFileSync(PUB, derived.export({ type: 'spki', format: 'pem' }), { flag: 'wx' });
    keyId = crypto.createHash('sha256').update(der).digest('hex');
    return keyId;
  }
  function decryptPackage(pkg, passphrase, { allowLegacy = false } = {}) {
    const parsed = validatePackage(pkg, { allowLegacy });
    if (!parsed.legacy && pkg.keyId !== keyId) throw new AppError(422, 'Tài liệu thuộc cặp khoá khác. Cần khôi phục đúng private key.');
    let aesKey;
    try {
      aesKey = crypto.privateDecrypt({ key: fs.readFileSync(PRIV), passphrase,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, parsed.encKey);
      const d = crypto.createDecipheriv('aes-256-gcm', aesKey, parsed.iv);
      if (!parsed.legacy) d.setAAD(Buffer.from(aadText(pkg), 'utf8'));
      d.setAuthTag(parsed.data.subarray(-16));
      return Buffer.concat([d.update(parsed.data.subarray(0, -16)), d.final()]);
    } catch {
      throw new AppError(422, 'Giải mã thất bại: sai passphrase, sai khoá hoặc dữ liệu/metadata đã bị sửa.');
    } finally { if (aesKey) aesKey.fill(0); }
  }
  return { ensureKeys, loadKeys, decryptPackage, PUB, PRIV, get keyId() { return keyId; } };
}
module.exports = { createReceiver };
