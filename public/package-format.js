// Cùng một biểu diễn metadata cho Web Crypto và Node.js.
(function (root) {
  'use strict';
  const VERSION = 3;
  const ALGORITHM = 'RSA-OAEP-SHA256+A256GCM';
  const MAX_FILE_BYTES = 10 * 1024 * 1024;
  const CATEGORIES = ['Báo cáo cấu trúc dự án', 'Tài liệu cần Boss ký', 'Khác'];
  function aadText(p) {
    const fields = [p.version, p.algorithm, p.keyId, p.senderUsername,
      p.sender, p.title, p.category, p.filename, p.fileSize];
    if (p.version >= 3) fields.push(p.recipientUsername, p.previousId, p.expiresAt);
    return JSON.stringify(fields);
  }
  const format = Object.freeze({ VERSION, ALGORITHM, MAX_FILE_BYTES, CATEGORIES, aadText });
  if (typeof module !== 'undefined' && module.exports) module.exports = format;
  else root.PackageFormat = format;
})(typeof globalThis !== 'undefined' ? globalThis : this);
