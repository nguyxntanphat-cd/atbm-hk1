# Aether Vault · Hệ thống truyền tải tài liệu an toàn

Ứng dụng Node.js thuần, không cần cài thư viện ngoài. Tệp được mã hóa trong trình duyệt bằng AES-256-GCM; khóa AES được bọc bằng RSA-OAEP/SHA-256 trước khi lưu lên máy chủ. Người gửi ký gói đã mã hóa bằng RSA-PSS/SHA-256; máy chủ xác minh chữ ký bằng khóa công khai đã đăng ký trước khi lưu hoặc giải mã gói.

## Khởi chạy

```bash
node server.js
```

Mở `http://localhost:3000/login`. Không dùng Live Server vì ứng dụng cần backend Node.js.

Sau khi đăng nhập, nhân viên dùng `/` để xem tổng quan, `/send` để gửi tài liệu và `/history` để xem lịch sử. Admin dùng `/admin`, `/activity` và `/tool`.

## Tài khoản demo

- Nhân viên: `nhanvien` / `123456`
- Quản trị viên: `boss` / `admin123`
- Passphrase private key: `boss123` (có thể đặt qua biến môi trường `BOSS_PASS` trước lần sinh khóa đầu tiên)

## Chức năng

- Nhân viên gửi tệp tối đa 18 MB, kéo thả, chọn danh mục và theo dõi các bước mã hóa.
- Lần gửi đầu tiên, trình duyệt tạo cặp khóa RSA-PSS 2048 bit. Khóa bí mật được giữ trong localStorage của trình duyệt; máy chủ chỉ lưu khóa công khai theo tài khoản nhân viên.
- Chữ ký số bao phủ tên tệp, người gửi, tiêu đề, danh mục, khóa AES đã bọc, IV và nội dung mã hóa. Gói có chữ ký sai sẽ bị từ chối; gói cũ chưa ký vẫn có thể giải mã nhưng được đánh dấu chưa xác minh.
- Quản trị viên tìm kiếm/lọc/sắp xếp hộp thư, xem trước tệp văn bản, giải mã và tải tệp.
- Nhật ký hoạt động: admin theo dõi đăng nhập thành công/thất bại, đăng xuất, gửi, giải mã và xóa; nhân viên chỉ xem lịch sử tài liệu và hoạt động của tài khoản mình.
- Xuất nhật ký hệ thống ra CSV để lưu trữ hoặc tổng hợp.
- Tải gói `.enc.json` và giải mã bằng công cụ quản trị riêng.
- Xóa gói mã hóa khỏi hộp thư.

Các gói mã hóa và nhật ký hoạt động được lưu trong `storage/`. Khóa RSA để bọc khóa AES nằm trong `keystore/receiver/` và `keystore/sender/`; private key của người nhận không được gửi tới trình duyệt. Khóa công khai xác minh chữ ký nằm trong `keystore/signers/`. Mỗi tài khoản ký số trên trình duyệt đã đăng ký khóa; xóa dữ liệu trình duyệt đồng nghĩa mất khóa bí mật và cần quy trình cấp lại khóa để gửi tiếp.
