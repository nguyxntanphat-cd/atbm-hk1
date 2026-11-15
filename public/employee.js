'use strict';
const senderInput = document.getElementById('sender');
const sendButton = document.getElementById('sendButton');
const logBox = document.getElementById('log');
senderInput.readOnly = true;
App.request('/api/me').then(user => { senderInput.value = user.name; })
  .catch(error => { logBox.textContent = error.message; });
const recipientInput = document.getElementById('recipient');
recipientInput.replaceChildren(); sendButton.disabled = true;
App.request('/api/recipients').then(recipients => {
  for (const recipient of recipients) {
    const option = document.createElement('option'); option.value = recipient.username;
    option.textContent = recipient.name + ' (' + recipient.username + ')'; recipientInput.append(option);
  }
  sendButton.disabled = !recipients.length;
  if (!recipients.length) logBox.textContent = 'Chưa có người nhận đang hoạt động.';
}).catch(error => { logBox.textContent = error.message; });
document.getElementById('title').maxLength = 200;
sendButton.addEventListener('click', async () => {
  const file = document.getElementById('file').files[0];
  logBox.textContent = '';
  if (!file) { logBox.textContent = 'Vui lòng chọn file cần gửi.'; return; }
  sendButton.disabled = true;
  try {
    await encryptAndSend(file, {
      title: document.getElementById('title').value.trim(),
      category: document.getElementById('category').value,
      recipientUsername: recipientInput.value,
      previousId: document.getElementById('previousId').value.trim() || null,
      expiresAt: document.getElementById('expiresAt').value ? new Date(document.getElementById('expiresAt').value).toISOString() : null
    }, message => { logBox.textContent += message + '\n'; });
    await loadSent();
  } catch (error) { logBox.textContent += 'Không gửi được: ' + error.message; }
  finally { sendButton.disabled = false; }
});
let sentPage = 1;
async function loadSent() {
  const result = await App.request('/api/sent?page=' + sentPage + '&q=' + encodeURIComponent(document.getElementById('sentSearch').value));
  const body = document.getElementById('sentBody'); body.replaceChildren();
  document.getElementById('sentPage').textContent = `${result.page}/${result.pages} · ${result.total} tài liệu`;
  for (const item of result.documents) {
    const row = document.createElement('tr');
    const state = item.revoked_at ? 'Đã thu hồi' : item.expires_at && item.expires_at <= new Date().toISOString()
      ? 'Hết hạn' : item.opened_at ? 'Đã mở' : 'Đã nhận';
    for (const text of [item.title || item.filename, item.recipient_username, state, new Date(item.time).toLocaleString('vi-VN')]) {
      const cell = document.createElement('td'); cell.textContent = text; row.append(cell);
    }
    const cell = document.createElement('td');
    const version = document.createElement('button'); version.textContent = 'Bản mới';
    version.addEventListener('click', () => {
      document.getElementById('previousId').value = item.id; recipientInput.value = item.recipient_username;
      document.getElementById('title').value = item.title; window.scrollTo({ top: 0, behavior: 'smooth' });
    }); cell.append(version);
    if (!item.revoked_at) {
      const revoke = document.createElement('button'); revoke.textContent = 'Thu hồi';
      revoke.addEventListener('click', async () => {
        if (!confirm('Thu hồi quyền truy cập trên hệ thống? File người nhận đã tải xuống vẫn còn.')) return;
        try { await App.request('/api/revoke', { id: item.id }); await loadSent(); }
        catch (error) { logBox.textContent = error.message; }
      }); cell.append(document.createTextNode(' '), revoke);
    }
    row.append(cell); body.append(row);
  }
  document.getElementById('sentPrev').disabled = sentPage <= 1;
  document.getElementById('sentNext').disabled = sentPage >= result.pages;
}
document.getElementById('sentPrev').addEventListener('click', () => { sentPage--; refreshSent(); });
document.getElementById('sentNext').addEventListener('click', () => { sentPage++; refreshSent(); });
document.getElementById('sentSearchButton').addEventListener('click', () => { sentPage = 1; refreshSent(); });
function refreshSent() { loadSent().catch(error => { logBox.textContent = error.message; }); }
refreshSent();
