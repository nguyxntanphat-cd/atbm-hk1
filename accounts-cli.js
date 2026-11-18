const path = require('path');
const readline = require('readline');
const accountStore = require('./account-store');

const DATA_DIR = path.join(__dirname, 'storage');
accountStore.ensure(DATA_DIR);
const input = process.stdin;
const output = process.stdout;
const isInteractive = input.isTTY && typeof input.setRawMode === 'function';
const rl = isInteractive ? null : readline.createInterface({ input, output });
if (isInteractive) readline.emitKeypressEvents(input);
function ask(prompt, hidden = false) {
  if (!isInteractive) return new Promise(resolve => rl.question(prompt, value => resolve(value.trim())));
  return new Promise((resolve, reject) => {
    input.setRawMode(true);
    input.resume();
    output.write(prompt);
    let value = '';
    const finish = error => {
      input.removeListener('keypress', onKey);
      input.setRawMode(false);
      input.pause();
      output.write('\n');
      error ? reject(error) : resolve(value.trim());
    };
    const onKey = (char, key = {}) => {
      if (key.ctrl && key.name === 'c') return finish(new Error('Đã hủy'));
      if (key.name === 'return' || key.name === 'enter') return finish();
      if (key.name === 'backspace') {
        if (value.length) { value = value.slice(0, -1); if (!hidden) output.write('\b \b'); }
        return;
      }
      if (char && !key.ctrl && !key.meta) { value += char; output.write(hidden ? '*' : char); }
    };
    input.on('keypress', onKey);
  });
}

async function main() {
  console.log('\n=== TẠO TÀI KHOẢN AETHER VAULT ===');
  console.log('1. Người dùng (user)\n2. Quản trị viên (admin)');
  const kind = await ask('Loại tài khoản [1/2]: ');
  const role = kind === '1' ? 'employee' : kind === '2' ? 'boss' : '';
  if (!role) throw new Error('Loại tài khoản không hợp lệ');
  const name = await ask('Họ và tên: ');
  const username = await ask('Tên tài khoản: ');
  const phone = await ask('Số điện thoại: ');
  const email = await ask('Email: ');
  const password = await ask('Mật khẩu (8 ký tự trở lên): ', true);
  const confirmation = await ask('Nhập lại mật khẩu: ', true);
  if (password !== confirmation) throw new Error('Hai mật khẩu không khớp');
  const account = accountStore.create(DATA_DIR, { name, username, phone, email, password, role });
  accountStore.logActivity(DATA_DIR, 'CLI terminal', 'system', 'account_create', `${role} · ${account.username} · ${account.name}`);
  console.log('\nĐã tạo tài khoản thành công:');
  console.log(`Loại: ${role === 'boss' ? 'Admin' : 'User'}`);
  console.log(`Tên: ${account.name}`);
  console.log(`Tên tài khoản: ${account.username}`);
  console.log(`SĐT: ${account.phone}`);
  console.log(`Email: ${account.email}`);
  console.log(`Trạng thái: ${account.active ? 'Đang hoạt động' : 'Đã khóa'}`);
}

main().catch(error => {
  console.error(`\nKhông thể tạo tài khoản: ${error.message}`);
  process.exitCode = 1;
}).finally(() => { if (rl) rl.close(); });
