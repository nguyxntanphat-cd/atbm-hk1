// ===== BÊN GỬI (Nhân viên) – Use Case 3, 6, 7, 8, 9, 10 =====
// Chạy trên trình duyệt: dữ liệu được mã hoá TRƯỚC khi rời máy nhân viên.
// Bên gửi chỉ dùng PUBLIC KEY lấy từ keystore/sender/.
const toB64 = buf => { let s = '', u = new Uint8Array(buf); for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };
const signedContent = (filename, meta, encKey, iv, data) => JSON.stringify([
  filename, meta.sender || '', meta.title || '', meta.category || '', encKey, iv, data
]);

// The signing private key stays in this employee's browser. The server only keeps
// the registered public key needed to verify uploaded packages.
async function getSigningPrivateKey() {
  const me = await (await fetch('/api/me')).json();
  const storageKey = `aether-signing-key:${me.username}`;
  const saved = localStorage.getItem(storageKey);
  const registered = await (await fetch('/api/signing-key')).json();
  if (saved) {
    const record = JSON.parse(saved);
    if (registered.publicKey && record.publicKey !== registered.publicKey.replace(/-----[^-]+-----|\s/g, ''))
      throw new Error('Khóa ký trên trình duyệt không khớp khóa công khai đã đăng ký.');
    if (!registered.publicKey) {
      const r = await fetch('/api/signing-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: record.publicPem }) });
      if (!r.ok) throw new Error('Không thể đăng ký khóa công khai ký số.');
    }
    return crypto.subtle.importKey('jwk', record.privateKey, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
  }
  if (registered.publicKey) throw new Error('Không tìm thấy khóa bí mật ký số trên trình duyệt này. Hãy dùng trình duyệt đã tạo khóa.');
  const pair = await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const privateKey = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicDer = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const publicKey = toB64(publicDer);
  const publicPem = `-----BEGIN PUBLIC KEY-----\n${publicKey.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
  localStorage.setItem(storageKey, JSON.stringify({ privateKey, publicKey, publicPem }));
  const r = await fetch('/api/signing-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: publicPem }) });
  if (!r.ok) throw new Error('Không thể đăng ký khóa công khai ký số.');
  return pair.privateKey;
}

// UC3 – Xác định khoá công khai người nhận
async function getRecipientPublicKey() {
  const pem = await (await fetch('/api/public-key')).text();
  const der = Uint8Array.from(atob(pem.replace(/-----[^-]+-----|\s/g, '')), c => c.charCodeAt(0));
  return crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

// UC6 – Gửi dữ liệu bảo mật
async function encryptAndSend(file, meta, log) {
  const account = await (await fetch('/api/me')).json();
  meta = { ...meta, sender: account.name };
  const pub = await getRecipientPublicKey();
  log('1. Lấy public key RSA-2048 của người nhận');
  // UC7 – Sinh khoá AES-256 mới cho mỗi lần gửi
  const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  log('2. Sinh khoá AES-256 ngẫu nhiên + IV 96-bit');
  // UC8 – Mã hoá dữ liệu bằng AES-GCM
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, await file.arrayBuffer());
  log('3. Mã hoá file bằng AES-256-GCM (' + file.size + ' bytes)');
  // UC9 – Mã hoá khoá AES bằng RSA-OAEP
  const encKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, await crypto.subtle.exportKey('raw', aes));
  log('4. Mã hoá khoá AES bằng RSA-OAEP:\n   ' + toB64(encKey).slice(0, 100) + '...');
  const encKeyB64 = toB64(encKey), ivB64 = toB64(iv), dataB64 = toB64(ct);
  const signingKey = await getSigningPrivateKey();
  const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, signingKey,
    new TextEncoder().encode(signedContent(file.name, meta, encKeyB64, ivB64, dataB64)));
  log('5. Ký gói dữ liệu bằng RSA-PSS/SHA-256');
  // UC10 – Truyền gói dữ liệu mã hoá
  const r = await fetch('/api/upload', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...meta, filename: file.name, encKey: encKeyB64, iv: ivB64, data: dataB64, signature: toB64(signature) }) });
  const result = await r.json();
  if (!r.ok) throw new Error(result.error || 'Lỗi truyền gói mã hóa');
  log('6. ✅ Đã gửi gói mã hóa có chữ ký số. ID: ' + result.id);
}

