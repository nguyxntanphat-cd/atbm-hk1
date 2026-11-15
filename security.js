const crypto = require('crypto');
const scrypt = require('util').promisify(crypto.scrypt);
const { check } = require('./package-format');
async function passwordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = (await scrypt(password, salt, 64)).toString('hex');
  return { salt, hash };
}
async function verifyPassword(password, user) {
  const computed = await scrypt(password, user?.salt || 'missing-user-dummy-salt', 64);
  return !!user && crypto.timingSafeEqual(computed, Buffer.from(user.hash, 'hex'));
}
function validatePassword(value) {
  check(typeof value === 'string' && value.length >= 12 && value.length <= 256, 'Mật khẩu mới cần 12–256 ký tự.');
}
function tokenHash(token) { return crypto.createHash('sha256').update(token || '').digest('hex'); }
module.exports = { passwordRecord, verifyPassword, validatePassword, tokenHash };
