const fs = require('fs');
const path = require('path');
function acquireLock(keyDir) {
  fs.mkdirSync(keyDir, { recursive: true });
  const file = path.join(keyDir, '.service.lock');
  const marker = JSON.stringify({ pid: process.pid, token: require('crypto').randomBytes(16).toString('hex') });
  try { fs.writeFileSync(file, marker, { flag: 'wx', mode: 0o600 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    let existing;
    try { existing = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { throw new Error('Lock ứng dụng không hợp lệ. Kiểm tra server đã dừng trước khi xử lý lock.'); }
    try { process.kill(existing.pid, 0); }
    catch (probe) {
      if (probe.code === 'ESRCH') {
        fs.unlinkSync(file); fs.writeFileSync(file, marker, { flag: 'wx', mode: 0o600 });
        return () => { if (fs.readFileSync(file, 'utf8') === marker) fs.unlinkSync(file); };
      }
    }
    throw new Error('Server hoặc tác vụ bảo trì đang dùng kho dữ liệu. Dừng server trước khi sao lưu/đổi khoá offline.');
  }
  return () => { if (fs.existsSync(file) && fs.readFileSync(file, 'utf8') === marker) fs.unlinkSync(file); };
}
module.exports = { acquireLock };
