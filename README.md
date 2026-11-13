# Đồ án ATBM HTTT: Ứng dụng mã hoá RSA và AES trong truyền tải dữ liệu nội bộ

## Chạy ứng dụng
```bash
node server.js
```
Mặc định chạy tại `http://localhost:3000` (tự động chuyển hướng về `/login`).

## Tài khoản mặc định
- **Nhân viên:** `nhanvien` / `123456` (gửi tài liệu tại `/`)
- **Boss (Admin):** `boss` / `admin123` (hộp thư tại `/admin`, công cụ giải mã tại `/tool`)
- **Passphrase mở Private Key:** `boss123` (có thể đổi bằng biến môi trường `BOSS_PASS`)
