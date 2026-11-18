# Aether Vault · Hệ thống truyền tải tài liệu an toàn

Ứng dụng Node.js thuần, không cần cài thư viện ngoài. Tệp được mã hóa trong trình duyệt bằng AES-256-GCM; khóa AES được bọc bằng RSA-OAEP/SHA-256 trước khi lưu lên máy chủ.

## Khởi chạy

Tạo tài khoản admin đầu tiên bằng CLI trước khi đăng nhập:

```bash
node accounts-cli.js
```

Đặt passphrase riêng cho private key trước lần chạy đầu tiên. PowerShell:

```powershell
$env:BOSS_PASS = 'thay-bang-passphrase-rieng'
node server.js
```

Trên macOS/Linux, dùng `BOSS_PASS='thay-bang-passphrase-rieng' node server.js`. Nếu cặp khóa đã tồn tại, server dùng khóa đó và không cần biến này để khởi động.

Mở `http://localhost:3000/login`. Không dùng Live Server vì ứng dụng cần backend Node.js.

## Tạo tài khoản từ terminal

```bash
node accounts-cli.js
```

Chọn user hoặc admin rồi nhập họ tên, tên tài khoản, số điện thoại, email và mật khẩu. Mật khẩu được băm bằng scrypt trước khi lưu vào `storage/accounts.json`; mật khẩu không hiển thị khi nhập trong terminal tương tác.

Đăng nhập nhanh là tùy chọn và đọc cấu hình local từ `storage/quick-logins.json`. Tệp này nằm trong thư mục bị Git bỏ qua; có thể thêm các mục gồm `id`, `label`, `username` và `password` để hiện nút đăng nhập tương ứng. Không đưa mật khẩu vào mã nguồn hoặc commit tệp này.

Sau khi đăng nhập, nhân viên dùng `/` để xem tổng quan, `/send` để gửi tài liệu và `/history` để xem lịch sử. Admin dùng `/admin`, `/activity`, `/accounts` và `/tool`.

## Chức năng

- Nhân viên gửi tệp tối đa 18 MB, kéo thả, chọn danh mục và theo dõi các bước mã hóa.
- Quản trị viên tìm kiếm/lọc/sắp xếp hộp thư, xem trước tệp văn bản, giải mã và tải tệp.
- Nhật ký hoạt động: admin theo dõi đăng nhập thành công/thất bại, đăng xuất, gửi, giải mã và xóa; nhân viên chỉ xem lịch sử tài liệu và hoạt động của tài khoản mình.
- Quản lý tài khoản ở `/accounts` có hai tab user/admin; admin có thể sửa thông tin liên hệ, khóa/mở khóa hoặc xóa tài khoản.
- Xuất nhật ký hệ thống ra CSV để lưu trữ hoặc tổng hợp.
- Tải gói `.enc.json` và giải mã bằng công cụ quản trị riêng.
- Xóa gói mã hóa khỏi hộp thư.

Các gói mã hóa và nhật ký hoạt động được lưu trong `storage/`. Cặp khóa RSA nằm trong `keystore/`; private key không được gửi tới trình duyệt.
