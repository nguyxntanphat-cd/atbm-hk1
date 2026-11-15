'use strict';
const passInput = document.getElementById('pass');
const autoInput = document.getElementById('auto');
const tableBody = document.getElementById('tb');
const statusBox = document.getElementById('listStatus');
const viewBox = document.getElementById('view');
const titleBox = document.getElementById('vt');
const cache = new Map();
let documents = [], loading = false, timer, secretGeneration = 0, currentPage = 1;
const sizeLabel = size => size < 1024 ? size + ' B' : size < 1048576 ? (size / 1024).toFixed(1) + ' KiB' : (size / 1048576).toFixed(1) + ' MiB';
function render() {
  tableBody.replaceChildren();
  if (!documents.length) {
    const cell = document.createElement('td'); cell.colSpan = 6;
    cell.textContent = 'Chưa có tài liệu nào trong hộp thư.';
    const row = document.createElement('tr'); row.append(cell); tableBody.append(row);
  }
  for (const item of documents) {
    const row = document.createElement('tr');
    const state = item.revoked_at ? ' · Đã thu hồi' : item.expires_at && item.expires_at <= new Date().toISOString() ? ' · Hết hạn' : '';
    const fields = [new Date(item.time).toLocaleString('vi-VN'), item.sender, item.category,
      item.title || '(Không có tiêu đề)', `${item.filename} · ${sizeLabel(item.size)}${cache.has(item.id) ? ' · Đã mở' : ''}${item.legacy ? ' · Gói cũ' : ''}${state}`];
    for (const value of fields) {
      const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
    }
    const actions = document.createElement('td');
    for (const [label, action] of [['Xem', viewDoc], ['Lưu', saveDoc]]) {
      const button = document.createElement('button'); button.textContent = label;
      button.disabled = !!state;
      button.addEventListener('click', async () => {
        button.disabled = true;
        try { await action(item.id); }
        catch (error) { statusBox.textContent = error.message; }
        finally { button.disabled = false; }
      });
      actions.append(button, document.createTextNode(' '));
    }
    const link = document.createElement('a');
    link.href = '/api/raw?id=' + encodeURIComponent(item.id); link.textContent = 'Bản mã';
    if (!state) actions.append(link); row.append(actions); tableBody.append(row);
  }
}
async function decrypt(id) {
  // Luôn hỏi server để kiểm tra thu hồi/hết hạn, kể cả file từng mở.
  if (!passInput.value) throw new Error('Nhập passphrase để mở tài liệu.');
  const generation = secretGeneration;
  const result = await App.request('/api/decrypt', { id, passphrase: passInput.value });
  if (generation !== secretGeneration) throw new Error('Passphrase đã thay đổi. Hãy mở lại tài liệu.');
  // Giữ tối đa 3 file trong bộ nhớ, tránh giữ toàn bộ hộp thư bản rõ.
  if (cache.size >= 3) cache.delete(cache.keys().next().value);
  cache.set(id, result);
  opened.add(id);
  return result;
}
async function viewDoc(id) {
  const result = await decrypt(id);
  titleBox.textContent = result.filename;
  viewBox.textContent = /\.(txt|md|csv|json|html?|js)$/i.test(result.filename)
    ? new TextDecoder().decode(App.bytes(result.data)) : 'File nhị phân — chọn Lưu để tải về và mở.';
  statusBox.textContent = (result.legacy ? 'Gói cũ: metadata chưa được xác thực bằng AES-GCM.' : 'Đã giải mã và xác thực nội dung cùng metadata.')
    + (result.scanStatus === 'clean' ? ' Đã quét file.' : ' Chưa cấu hình quét mã độc.');
  render();
}
async function saveDoc(id) {
  const result = await decrypt(id); App.download(result); render();
  statusBox.textContent = result.legacy ? 'Đã tải file. Gói cũ chưa bảo vệ metadata.' : 'Đã tải file sau khi xác thực nội dung và metadata.';
}
passInput.addEventListener('input', () => {
  secretGeneration++; cache.clear(); opened.clear(); viewBox.textContent = ''; titleBox.textContent = ''; render();
});
async function load() {
  if (loading) return;
  loading = true;
  try {
    const search = document.getElementById('inboxSearch');
    const result = await App.request('/api/list?page=' + currentPage + '&q=' + encodeURIComponent(search?.value || ''));
    documents = result.documents;
    for (const item of documents) if (item.revoked_at || item.expires_at && item.expires_at <= new Date().toISOString()) {
      cache.delete(item.id); if (titleBox.textContent === item.filename) { titleBox.textContent = ''; viewBox.textContent = ''; }
    }
    render();
    const pageBox = document.getElementById('inboxPage');
    if (pageBox) {
      pageBox.textContent = `${result.page}/${result.pages} · ${result.total} tài liệu`;
      document.getElementById('inboxPrev').disabled = currentPage <= 1;
      document.getElementById('inboxNext').disabled = currentPage >= result.pages;
    }
    statusBox.textContent = result.skipped
      ? `Đã nhận ${documents.length} tài liệu. Bỏ qua ${result.skipped} gói lỗi; cần kiểm tra kho lưu trữ.`
      : `${documents.length} tài liệu · Cập nhật lúc ${new Date().toLocaleTimeString('vi-VN')}`;
  } catch (error) { statusBox.textContent = error.message; }
  finally { loading = false; clearTimeout(timer); timer = setTimeout(load, 5000); }
}
// Tự động mở một tài liệu mới nhất trong mỗi lần cập nhật; giới hạn 12 lần/phút.
const opened = new Set();
let autoBusy = false;
async function autoDecrypt() {
  if (autoBusy || !autoInput.checked || !passInput.value) return;
  const next = documents.find(item => !opened.has(item.id) && !item.revoked_at && (!item.expires_at || item.expires_at > new Date().toISOString()));
  if (!next) return;
  autoBusy = true;
  try { await viewDoc(next.id); opened.add(next.id); }
  catch (error) { autoInput.checked = false; statusBox.textContent = error.message + ' Đã dừng tự động giải mã.'; }
  finally { autoBusy = false; }
}
const autoTimer = setInterval(autoDecrypt, 5000);
window.addEventListener('pagehide', () => { secretGeneration++; clearTimeout(timer); clearInterval(autoTimer); cache.clear(); opened.clear(); viewBox.textContent = ''; titleBox.textContent = ''; });
load();
document.getElementById('inboxPrev')?.addEventListener('click', () => { currentPage--; load(); });
document.getElementById('inboxNext')?.addEventListener('click', () => { currentPage++; load(); });
document.getElementById('inboxSearchButton')?.addEventListener('click', () => { currentPage = 1; load(); });
