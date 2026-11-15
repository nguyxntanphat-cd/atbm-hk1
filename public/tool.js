'use strict';
const button = document.getElementById('decryptButton');
const output = document.getElementById('out');
button.addEventListener('click', async () => {
  const file = document.getElementById('f').files[0];
  const pass = document.getElementById('pass');
  output.textContent = ''; button.disabled = true;
  try {
    if (!file) throw new Error('Vui lòng chọn file .enc.json.');
    if (!pass.value) throw new Error('Vui lòng nhập passphrase.');
    if (file.size > Math.ceil((PackageFormat.MAX_FILE_BYTES + 16) / 3) * 4 + 8192)
      throw new Error('Gói quá lớn. File gốc tối đa 10 MiB.');
    let pkg;
    try { pkg = JSON.parse(await file.text()); }
    catch { throw new Error('File không phải JSON hợp lệ.'); }
    output.textContent = 'Đang kiểm tra và giải mã gói tin…';
    const result = await App.request('/api/decrypt', { pkg, passphrase: pass.value });
    App.download(result);
    output.textContent = 'Đã giải mã và tải file: ' + result.filename
      + (result.legacy ? '\nLưu ý: gói cũ chưa xác thực metadata.' : '\nNội dung và metadata đã vượt qua kiểm tra AES-GCM.');
  } catch (error) { output.textContent = error.message; }
  finally { button.disabled = false; }
});
