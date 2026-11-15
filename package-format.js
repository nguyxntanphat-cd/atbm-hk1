const format = require('./public/package-format');
class AppError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
function check(condition, message) {
  if (!condition) throw new AppError(400, message);
}
function text(value, label, max, optional = false) {
  check(typeof value === 'string' && value.length <= max && (optional || value.trim().length > 0)
    && !/[\u0000-\u001f\u007f]/.test(value), `${label} không hợp lệ (tối đa ${max} ký tự).`);
}
function base64(value, label, min, max) {
  check(typeof value === 'string' && value.length <= Math.ceil(max / 3) * 4
    && value.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(value), `${label} phải là Base64 hợp lệ.`);
  const bytes = Buffer.from(value, 'base64');
  check(bytes.length >= min && bytes.length <= max && bytes.toString('base64') === value, `${label} có độ dài không hợp lệ.`);
  return bytes;
}
function validatePackage(p, { allowLegacy = false } = {}) {
  check(p && typeof p === 'object' && !Array.isArray(p), 'Gói mã hoá phải là một object.');
  const legacy = p.version === undefined;
  check(!legacy || allowLegacy, 'Upload mới yêu cầu gói phiên bản 3.');
  check(legacy || ([2, 3].includes(p.version) && p.algorithm === format.ALGORITHM), 'Phiên bản hoặc thuật toán không được hỗ trợ.');
  text(p.sender, 'Người gửi', 100);
  text(p.title, 'Tiêu đề', 200, true);
  text(p.category, 'Loại tài liệu', 100);
  text(p.filename, 'Tên file', 255);
  check(!/[\\/]/.test(p.filename) && p.filename !== '.' && p.filename !== '..', 'Tên file không được chứa đường dẫn.');
  if (!legacy) {
    text(p.senderUsername, 'Tài khoản người gửi', 64);
    check(typeof p.keyId === 'string' && /^[a-f0-9]{64}$/.test(p.keyId), 'Mã khoá không hợp lệ.');
    check(format.CATEGORIES.includes(p.category), 'Loại tài liệu không được hỗ trợ.');
    check(Number.isSafeInteger(p.fileSize) && p.fileSize >= 0 && p.fileSize <= format.MAX_FILE_BYTES, 'File tối đa 10 MiB.');
  }
  if (p.version === 3) {
    text(p.recipientUsername, 'Tài khoản người nhận', 64);
    check(p.previousId === null || (typeof p.previousId === 'string' && /^\d{13}-[a-f0-9]{6,16}$/.test(p.previousId)), 'Mã phiên bản trước không hợp lệ.');
    check(p.expiresAt === null || (typeof p.expiresAt === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(p.expiresAt)
      && Number.isFinite(Date.parse(p.expiresAt))), 'Thời hạn tài liệu không hợp lệ.');
  }
  const encKey = base64(p.encKey, 'Khoá AES đã bọc', 256, 256);
  const iv = base64(p.iv, 'IV', 12, 12);
  const data = base64(p.data, 'Nội dung mã hoá', 16, format.MAX_FILE_BYTES + 16);
  check(legacy || data.length === p.fileSize + 16, 'Kích thước file không khớp gói mã hoá.');
  return { legacy, encKey, iv, data };
}
module.exports = { ...format, AppError, check, validatePackage };
