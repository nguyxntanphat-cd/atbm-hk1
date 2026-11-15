// Bên gửi chỉ sử dụng public key, mã hoá trước khi dữ liệu rời trình duyệt.
'use strict';
function toB64(buffer) {
  const bytes = new Uint8Array(buffer); let value = '';
  for (let i = 0; i < bytes.length; i += 0x8000)
    value += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(value);
}
async function encryptAndSend(file, meta, log) {
  if (!window.crypto?.subtle) throw new Error('Trình duyệt cần HTTPS hoặc localhost để dùng Web Crypto.');
  if (file.size > PackageFormat.MAX_FILE_BYTES) throw new Error('File tối đa 10 MiB.');
  if (meta.title.length > 200) throw new Error('Tiêu đề tối đa 200 ký tự.');
  const [user, recipient] = await Promise.all([App.request('/api/me'), App.request('/api/public-key?recipient=' + encodeURIComponent(meta.recipientUsername || 'boss'))]);
  const der = App.bytes(recipient.pem.replace(/-----[^-]+-----|\s/g, ''));
  const publicKey = await crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  log('1. Đã lấy public key của người nhận.');
  const pkg = { version: PackageFormat.VERSION, algorithm: PackageFormat.ALGORITHM,
    keyId: recipient.keyId, senderUsername: user.username, sender: user.name,
    recipientUsername: recipient.recipientUsername, title: meta.title, category: meta.category, filename: file.name, fileSize: file.size,
    previousId: meta.previousId || null, expiresAt: meta.expiresAt || null };
  const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  log('2. Đã sinh khoá AES-256 và IV mới cho file này.');
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128,
    additionalData: new TextEncoder().encode(PackageFormat.aadText(pkg)) }, aes, await file.arrayBuffer());
  log('3. Đã mã hoá file và ràng buộc thông tin tài liệu bằng AES-GCM.');
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', aes));
  let encKey;
  try { encKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, raw); }
  finally { raw.fill(0); }
  log('4. Đã bọc khoá AES bằng RSA-OAEP/SHA-256.');
  const result = await App.request('/api/upload', { ...pkg, encKey: toB64(encKey), iv: toB64(iv), data: toB64(data) });
  log('5. Đã gửi tài liệu. Mã: ' + result.id);
}
