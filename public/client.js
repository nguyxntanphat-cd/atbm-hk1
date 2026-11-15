'use strict';
const App = {
  async request(url, body) {
    const options = body === undefined ? {} : {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'internal-docs' },
      body: JSON.stringify(body)
    };
    let response;
    try { response = await fetch(url, options); }
    catch { throw new Error('Không kết nối được server. Kiểm tra kết nối và thử lại.'); }
    let result;
    try { result = await response.json(); }
    catch { throw new Error('Server trả dữ liệu không hợp lệ. Kiểm tra server và database đang chạy.'); }
    if (!response.ok) {
      if (response.status === 401 && url !== '/api/login') {
        sessionStorage.removeItem('pass');
        location.replace('/login');
      }
      const error = new Error(result.error || 'Yêu cầu thất bại.');
      error.status = response.status;
      throw error;
    }
    return result;
  },
  bytes(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); },
  download(document) {
    const url = URL.createObjectURL(new Blob([App.bytes(document.data)], { type: 'application/octet-stream' }));
    const link = window.document.createElement('a');
    link.href = url; link.download = document.filename;
    window.document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
};
// Dọn passphrase do phiên bản trước từng lưu. Phiên bản mới chỉ giữ trong input.
sessionStorage.removeItem('pass');
document.querySelectorAll('a[href="/logout"]').forEach(link => {
  link.addEventListener('click', async event => {
    event.preventDefault();
    try { await App.request('/logout', {}); location.replace('/login'); }
    catch (error) { alert(error.message); }
  });
});
window.addEventListener('pagehide', () => {
  document.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
});
// Không khôi phục trang chứa dữ liệu nhạy cảm từ back/forward cache sau đăng xuất.
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
