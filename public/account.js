'use strict';
const status = document.getElementById('accountStatus');
const value = id => document.getElementById(id).value;
async function refresh() {
  const user = await App.request('/api/me');
  document.getElementById('accountInfo').textContent = `${user.name} (${user.username}) · ${user.role}`
    + (user.mustChangePassword ? ' · Bạn cần đổi mật khẩu tạm để tiếp tục.' : '');
  document.getElementById('keysPanel').hidden = user.role !== 'boss';
  if (user.role === 'boss' && !user.mustChangePassword) {
    const keys = await App.request('/api/keys'), select = document.getElementById('keyId'); select.replaceChildren();
    for (const key of keys) {
      const option = document.createElement('option'); option.value = key.key_id;
      option.textContent = (key.active ? 'Đang dùng' : 'Khoá cũ') + ' · ' + key.key_id.slice(0, 16); select.append(option);
    }
  }
}
function bind(id, event, task) {
  document.getElementById(id).addEventListener(event, async e => {
    e.preventDefault();
    try { await task(); } catch (error) { status.textContent = error.message; }
  });
}
bind('passwordForm', 'submit', async () => {
  await App.request('/api/account/password', { currentPassword: value('currentPassword'), newPassword: value('nextPassword') });
  location.replace('/login');
});
bind('keysForm', 'submit', async () => {
  const result = await App.request('/api/keys/' + value('keyAction'), { keyId: value('keyId'), password: value('keyPassword'), currentPassphrase: value('oldKeyPass'), newPassphrase: value('nextKeyPass') });
  status.textContent = 'Đã cập nhật khoá: ' + result.keyId.slice(0, 16) + '. Hãy cập nhật bản sao lưu khoá.';
  document.getElementById('keysForm').reset(); await refresh();
});
refresh().catch(error => { status.textContent = error.message; });
