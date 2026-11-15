const fs = require('fs');
const { Store, databaseConfig } = require('../store');
if (fs.existsSync('.env')) process.loadEnvFile('.env');
(async () => {
  const config = databaseConfig();
  const store = await Store.open(config, { createDatabase: true });
  await store.close();
  console.log(`Đã chuẩn bị database ${config.database} trên ${config.host}:${config.port}. Chạy node server.js để khởi tạo tài khoản và nhập chỉ mục tài liệu cũ.`);
})().catch(error => { console.error('Không khởi tạo được MySQL:', error.code || error.message); process.exitCode = 1; });
