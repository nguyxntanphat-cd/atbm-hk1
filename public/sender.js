// ===== BÊN GỬI (Nhân viên) – Use Case 3, 6, 7, 8, 9, 10 =====
// Chạy trên trình duyệt: dữ liệu được mã hoá TRƯỚC khi rời máy nhân viên.
// Bên gửi chỉ dùng PUBLIC KEY lấy từ keystore/sender/.
const toB64 = buf => { let s = '', u = new Uint8Array(buf); for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };

// UC3 – Xác định khoá công khai người nhận
async function getRecipientPublicKey() {
  const pem = await (await fetch('/api/public-key')).text();
  const der = Uint8Array.from(atob(pem.replace(/-----[^-]+-----|\s/g, '')), c => c.charCodeAt(0));
  return crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

// UC6 – Gửi dữ liệu bảo mật
async function encryptAndSend(file, meta, log) {
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
  // UC10 – Truyền gói dữ liệu mã hoá
  const r = await fetch('/api/upload', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...meta, filename: file.name, encKey: toB64(encKey), iv: toB64(iv), data: toB64(ct) }) });
  log(r.ok ? '5. ✅ Đã gửi gói mã hoá. ID: ' + (await r.json()).id : '❌ Lỗi truyền');
}

