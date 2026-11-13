// ===== BÊN NHẬN (Boss) – Use Case 12, 13, 14 =====
// Chỉ file này được đọc PRIVATE KEY trong keystore/receiver/
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const RECV_DIR = path.join(__dirname, 'keystore', 'receiver');   // KHO KEY BÊN NHẬN (bí mật)
const SEND_DIR = path.join(__dirname, 'keystore', 'sender');     // KHO KEY BÊN GỬI (công khai)
const PRIV = path.join(RECV_DIR, 'boss_private.pem');
const PUB = path.join(SEND_DIR, 'boss_public.pem');

// Use Case 1 – Tạo cặp khoá RSA; Use Case 2 – Cung cấp khoá công khai cho bên gửi
function ensureKeys(passphrase) {
  fs.mkdirSync(RECV_DIR, { recursive: true });
  fs.mkdirSync(SEND_DIR, { recursive: true });
  if (fs.existsSync(PRIV)) return;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    // private key được mã hoá AES-256-CBC bằng passphrase (PKCS#8)
    privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase },
  });
  fs.writeFileSync(PRIV, privateKey, { mode: 0o600 }); // -> chỉ bên nhận giữ
  fs.writeFileSync(PUB, publicKey);                     // -> cấp cho bên gửi
  console.log('Đã sinh RSA-2048:\n  keystore/receiver/boss_private.pem (bí mật)\n  keystore/sender/boss_public.pem (công khai)');
}

// Use Case 12 – Giải mã dữ liệu đã nhận
function decryptPackage(pkg, passphrase) {
  // UC13 – Giải mã khoá AES bằng RSA-OAEP (private key)
  const aesKey = crypto.privateDecrypt(
    { key: fs.readFileSync(PRIV, 'utf8'), passphrase,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(pkg.encKey, 'base64'));
  // UC14 – Giải mã nội dung bằng AES-256-GCM (16 byte cuối là tag xác thực)
  const buf = Buffer.from(pkg.data, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(pkg.iv, 'base64'));
  d.setAuthTag(buf.subarray(buf.length - 16));
  return Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]);
}

module.exports = { ensureKeys, decryptPackage, PUB };

