const { AppError, check, MAX_FILE_BYTES } = require('./package-format');
const MAX_BODY = Math.ceil((MAX_FILE_BYTES + 16) / 3) * 4 + 16 * 1024;
function readBody(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    const chunks = []; let length = 0, failed = false;
    req.on('data', chunk => {
      length += chunk.length;
      if (length > limit) {
        if (!failed) reject(new AppError(413, 'Gói quá lớn. File gốc tối đa 10 MiB.'));
        failed = true; chunks.length = 0;
      } else if (!failed) chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) return;
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        check(value && typeof value === 'object' && !Array.isArray(value), 'Body phải là JSON object.'); resolve(value);
      } catch (error) { reject(error instanceof AppError ? error : new AppError(400, 'JSON không hợp lệ.')); }
    });
    req.on('error', reject); req.on('aborted', () => reject(new AppError(400, 'Request bị ngắt.')));
  });
}
function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function redirect(res, location) { res.writeHead(302, { Location: location }); res.end(); }
module.exports = { readBody, send, redirect };
