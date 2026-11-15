// Node.js phục vụ web; MySQL/MariaDB của XAMPP lưu tài khoản và metadata.
const { createApp } = require('./app');
if (require.main === module) {
  // Cho phép chạy node server.js sau khi tạo .env, không ghi đè biến môi trường có sẵn.
  const fs = require('fs');
  if (fs.existsSync('.env')) process.loadEnvFile('.env');
  createApp().then(({ server, close }) => {
    const host = process.env.HOST || '127.0.0.1', port = Number(process.env.PORT || 3000);
    server.listen(port, host, () => console.log(`Hệ thống: ${process.env.TLS_KEY ? 'https' : 'http'}://localhost:${port}/login\nDatabase: ${process.env.DB_NAME || 'atbm_internal'} (MySQL/XAMPP)`));
    server.on('error', async error => { console.error('Không khởi động được server:', error.code); await close(); process.exitCode = 1; });
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(async () => { await close(); process.exit(0); }));
  }).catch(error => {
    const connectionErrors = ['ECONNREFUSED','ER_ACCESS_DENIED_ERROR','ER_BAD_DB_ERROR'];
    console.error(connectionErrors.includes(error.code)
      ? `Không kết nối được MySQL (${error.code}). Bật MySQL trong XAMPP, kiểm tra DB_PORT/DB_USER/DB_PASSWORD và chạy npm run db:init.` : error.message);
    process.exitCode = 1;
  });
}
module.exports = { createApp };
