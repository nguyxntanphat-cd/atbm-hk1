const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { AppError } = require('./package-format');
function createScanner(env, directory) {
  if (!env.SCANNER_COMMAND) return null;
  if (!path.isAbsolute(env.SCANNER_COMMAND) || !fs.existsSync(env.SCANNER_COMMAND)) throw new Error('SCANNER_COMMAND cần là đường dẫn tuyệt đối tới chương trình quét.');
  const args = JSON.parse(env.SCANNER_ARGS || '[]');
  if (!Array.isArray(args) || !args.every(arg => typeof arg === 'string')) throw new Error('SCANNER_ARGS phải là mảng JSON chuỗi.');
  return async bytes => {
    await fs.promises.mkdir(directory, { recursive: true });
    const filename = path.join(directory, crypto.randomBytes(16).toString('hex') + '.scan');
    await fs.promises.writeFile(filename, bytes, { mode: 0o600, flag: 'wx' });
    try {
      await new Promise((resolve, reject) => execFile(env.SCANNER_COMMAND, [...args, filename],
        { windowsHide: true, timeout: 20000, maxBuffer: 65536 }, error => {
          if (!error) resolve();
          else if (error.code === 1) reject(new AppError(422, 'Phần mềm quét phát hiện file nghi nhiễm mã độc. Không cung cấp bản rõ.'));
          else reject(new AppError(503, 'Dịch vụ quét file không sẵn sàng. Không cung cấp bản rõ.'));
        }));
      return 'clean';
    } finally { await fs.promises.unlink(filename).catch(() => {}); }
  };
}
module.exports = { createScanner };
