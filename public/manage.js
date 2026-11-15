'use strict';
const status = document.getElementById('manageStatus');
let auditPage = 1;
function value(id) { return document.getElementById(id).value; }
async function loadUsers() {
  const users = await App.request('/api/users'), body = document.getElementById('usersBody'); body.replaceChildren();
  for (const user of users) {
    const row = document.createElement('tr');
    for (const text of [user.name + ' (' + user.username + ')', user.role]) {
      const cell = document.createElement('td'); cell.textContent = text; row.append(cell);
    }
    const enabled = document.createElement('input'); enabled.type = 'checkbox'; enabled.checked = !!user.enabled;
    const quota = document.createElement('input'); quota.type = 'number'; quota.min = '1'; quota.max = '102400'; quota.value = user.quota / 1048576; quota.className = 'compact';
    const password = document.createElement('input'); password.type = 'password'; password.placeholder = 'Để trống nếu giữ'; password.autocomplete = 'new-password'; password.className = 'compact';
    for (const input of [enabled, quota, password]) { const cell = document.createElement('td'); cell.append(input); row.append(cell); }
    const cell = document.createElement('td'), button = document.createElement('button'); button.textContent = 'Lưu';
    button.addEventListener('click', async () => {
      button.disabled = true;
      try { await App.request('/api/users/update', { username: user.username, enabled: enabled.checked, quotaMB: Number(quota.value), password: password.value }); status.textContent = 'Đã cập nhật ' + user.username; await loadUsers(); await loadAudit(); }
      catch (error) { status.textContent = error.message; }
      finally { button.disabled = false; }
    }); cell.append(button); row.append(cell); body.append(row);
  }
}
async function loadAudit() {
  const result = await App.request('/api/audit?page=' + auditPage), body = document.getElementById('auditBody'); body.replaceChildren();
  for (const item of result.events) {
    const row = document.createElement('tr');
    for (const text of [new Date(item.time).toLocaleString('vi-VN'), item.actor, item.action, item.document_id || '—', item.result, item.ip]) {
      const cell = document.createElement('td'); cell.textContent = text; row.append(cell);
    } body.append(row);
  }
  document.getElementById('auditPage').textContent = `${auditPage} · ${result.total} sự kiện`;
  document.getElementById('auditPrev').disabled = auditPage <= 1;
  document.getElementById('auditNext').disabled = auditPage * 30 >= result.total;
}
document.getElementById('createUser').addEventListener('submit', async event => {
  event.preventDefault(); const form = event.currentTarget, button = form.querySelector('button'); button.disabled = true;
  try {
    await App.request('/api/users/create', { username: value('newUsername'), name: value('newName'), role: value('newRole'), password: value('newPassword'), keyPassphrase: value('newKeyPass') });
    form.reset(); status.textContent = 'Đã tạo tài khoản. Người dùng cần đổi mật khẩu tạm khi đăng nhập.'; await loadUsers(); await loadAudit();
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
});
document.getElementById('auditPrev').addEventListener('click', () => { auditPage--; refreshAudit(); });
document.getElementById('auditNext').addEventListener('click', () => { auditPage++; refreshAudit(); });
document.getElementById('reloadAudit').addEventListener('click', refreshAudit);
function refreshAudit() { loadAudit().catch(error => { status.textContent = error.message; }); }
loadUsers().catch(error => { status.textContent = error.message; }); refreshAudit();
