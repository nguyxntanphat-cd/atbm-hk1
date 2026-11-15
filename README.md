# Hệ thống gửi tài liệu nội bộ — RSA, AES và MySQL

Đồ án minh hoạ gửi tài liệu bảo mật: nhân viên mã hoá file trên trình duyệt bằng
AES-256-GCM, bọc khoá AES bằng RSA-OAEP rồi gửi cho người nhận. Người nhận nhập
passphrase để server giải mã. MySQL lưu tài khoản, metadata, session và nhật ký;
nội dung file được lưu dưới dạng gói mã hoá trong `storage/`.

README hướng dẫn **cài mới sau khi clone Git**, ưu tiên Windows + PowerShell + XAMPP.

## Mục lục

- [1. Chuẩn bị môi trường](#1-chuẩn-bị-môi-trường)
- [2. Clone và cài thư viện](#2-clone-và-cài-thư-viện)
- [3. Bật MySQL trong XAMPP](#3-bật-mysql-trong-xampp)
- [4. Tạo và cấu hình .env](#4-tạo-và-cấu-hình-env)
- [5. Khởi tạo database và chạy server](#5-khởi-tạo-database-và-chạy-server)
- [6. Đăng nhập và thử gửi tài liệu](#6-đăng-nhập-và-thử-gửi-tài-liệu)
- [7. Những lần chạy tiếp theo](#7-những-lần-chạy-tiếp-theo)
- [8. Kiểm thử](#8-kiểm-thử)
- [9. Lỗi thường gặp](#9-lỗi-thường-gặp)
- [10. Khoá RSA, dữ liệu và phục hồi](#10-khoá-rsa-dữ-liệu-và-phục-hồi)
- [11. Cấu trúc và tài liệu chi tiết](#11-cấu-trúc-và-tài-liệu-chi-tiết)

## 1. Chuẩn bị môi trường

| Công cụ | Yêu cầu | Dùng để làm gì? |
| --- | --- | --- |
| Git | Cài và sử dụng được lệnh `git` | Clone/cập nhật mã nguồn |
| Node.js | **22.13 trở lên**, kèm npm | Chạy server và cài thư viện |
| XAMPP | Có dịch vụ MySQL/MariaDB | Chạy database local |
| Trình duyệt | Có Web Crypto API, ví dụ Chrome hoặc Edge | Mã hoá file và sử dụng giao diện |

Có thể tải từ [Git](https://git-scm.com/downloads), [Node.js](https://nodejs.org/en/download)
và [XAMPP](https://www.apachefriends.org/download.html).

Mở **PowerShell** hoặc Terminal trong VS Code, kiểm tra:

```powershell
git --version
node --version
npm --version
```

Nếu báo không tìm thấy lệnh, kiểm tra đã cài và thêm công cụ vào PATH, rồi mở lại Terminal.
Các lệnh dưới đây chạy tại **thư mục gốc project**, nơi có `package.json` và `server.js`.

**Không cần PHP, không cần chép project vào `htdocs`.** Node.js phục vụ website;
XAMPP chỉ cung cấp database. Apache chỉ cần bật nếu muốn mở phpMyAdmin.

## 2. Clone và cài thư viện

```powershell
git clone https://github.com/nguyxntanphat-cd/atbm-hk1.git
cd atbm-hk1
npm ci
```

`npm ci` cài đúng phiên bản trong `package-lock.json`. Sau khi hoàn tất sẽ có
thư mục `node_modules/`. Không cần chạy lệnh build frontend.

Nếu PowerShell báo `npm.ps1 cannot be loaded ... running scripts is disabled`,
dùng `npm.cmd` thay cho `npm` trong các lệnh, ví dụ:

```powershell
npm.cmd ci
```

Không cần thay đổi Execution Policy chỉ để chạy project này.

## 3. Bật MySQL trong XAMPP

1. Mở **XAMPP Control Panel**.
2. Bấm **Start** ở dòng **MySQL**.
3. Chờ trạng thái Running/màu xanh và ghi lại **Port(s)**.

Project kết nối được với MariaDB đi kèm XAMPP thông qua driver `mysql2`.
Tên dịch vụ trên XAMPP vẫn là MySQL.

**Chọn đúng cổng database:**

- Cấu hình mẫu của repo đang để **3307**, theo máy phát triển.
- Nếu XAMPP trên máy bạn dùng **3306**, đổi `DB_PORT=3306` ở bước tiếp theo.
- Có thể xem cổng tại **MySQL → Config → my.ini**, mục `[mysqld]`, dòng `port=...`.
- Không đổi cổng một database khác hoặc dừng dịch vụ khác chỉ để khớp cấu hình mẫu.

## 4. Tạo và cấu hình .env

Sau khi clone mới, tạo file cấu hình:

```powershell
Copy-Item .env.example .env
```

Nếu đã có `.env`, sửa file hiện tại; **không chạy lệnh sao chép để ghi đè cấu hình cũ**.
Mở `.env` và kiểm tra:

```dotenv
NODE_ENV=development
HOST=127.0.0.1
PORT=3000

DB_HOST=127.0.0.1
DB_PORT=3307
DB_USER=root
DB_PASSWORD=
DB_NAME=atbm_internal

EMPLOYEE_PASSWORD=123456
BOSS_PASSWORD=admin123
ADMIN_PASSWORD=quantri123
BOSS_PASS=boss123

STORAGE_QUOTA_MB=1024
```

| Biến | Cách điền khi chạy local |
| --- | --- |
| `DB_PORT` | Cổng MySQL **thực tế trong XAMPP**, thường 3306 hoặc 3307 |
| `DB_USER` | Tài khoản database; XAMPP local có thể dùng `root` |
| `DB_PASSWORD` | Để trống nếu tài khoản DB chưa có mật khẩu; nếu có thì điền đúng |
| `DB_NAME` | Database riêng của project, mặc định `atbm_internal` |
| `PORT` | Cổng website Node.js, mặc định `3000`; khác với cổng database |
| `BOSS_PASS` | Passphrase bảo vệ private key ban đầu, không phải mật khẩu đăng nhập |

Ví dụ XAMPP dùng cổng 3306 thì chỉ cần sửa:

```dotenv
DB_PORT=3306
```

Ứng dụng tự đọc `.env` khi chạy. Nếu trước đó đã đặt cùng biến bằng `$env:...`
trong PowerShell, giá trị đó có ưu tiên; kiểm tra Terminal đang dùng nếu sửa `.env`
nhưng cấu hình không thay đổi. Mở Terminal mới để tránh giữ biến môi trường cũ.

Để chạy demo local, giữ `NODE_ENV=development` và để các dòng `TLS_*`,
`SCANNER_*` được comment như file mẫu. Chưa cần cài HTTPS hoặc phần mềm quét file.
Các mật khẩu mẫu chỉ dành cho học tập, không dùng với dữ liệu nhạy cảm.

## 5. Khởi tạo database và chạy server

Đảm bảo MySQL trong XAMPP vẫn đang chạy, sau đó:

```powershell
npm run db:init
npm start
```

Lệnh đầu tạo database nếu chưa có, chuẩn bị các bảng và trigger. Tài khoản DB cần
có quyền tạo database, bảng và trigger khi cài mới. Không cần import SQL thủ công
nếu đã chạy `npm run db:init` thành công.

Ở lần chạy đầu với database và kho dữ liệu mới, server sẽ:

1. Tạo thư mục dữ liệu/khoá nếu chưa tồn tại.
2. Sinh cặp RSA-2048 cho người nhận ban đầu.
3. Tạo ba tài khoản demo và lưu hash mật khẩu vào MySQL.

Terminal hiển thị tương tự:

```text
Hệ thống: http://localhost:3000/login
Database: atbm_internal (MySQL/XAMPP)
```

Giữ Terminal này chạy và mở **http://localhost:3000/login**.
Nếu đã đổi `PORT`, dùng đúng cổng mới trên trình duyệt.

Có thể kiểm tra kết nối server/database bằng PowerShell ở Terminal khác:

```powershell
Invoke-RestMethod http://localhost:3000/api/health
```

Kết quả có `ok: True` là server truy vấn được database. Chỉ có bảng trong MySQL
chưa có nghĩa ứng dụng đã chạy; vẫn phải giữ tiến trình `npm start` hoạt động.

## 6. Đăng nhập và thử gửi tài liệu

Nếu giữ các mật khẩu mẫu trong `.env` khi khởi tạo lần đầu:

| Vai trò | Tên đăng nhập | Mật khẩu | Trang sau đăng nhập |
| --- | --- | --- | --- |
| Nhân viên | `nhanvien` | `123456` | Gửi tài liệu `/` |
| Người nhận | `boss` | `admin123` | Hộp thư `/admin` |
| Quản trị | `quantri` | `quantri123` | Quản lý `/manage` |

**Passphrase giải mã ban đầu: `boss123`**, nếu chưa thay `BOSS_PASS` lúc sinh khoá.
Đăng nhập chỉ dùng tên tài khoản và mật khẩu; passphrase được nhập riêng khi mở tài liệu.

### Thử luồng gửi và nhận

1. Tạo file `demo.txt` có nội dung ngắn để dễ đối chiếu.
2. Đăng nhập `nhanvien`, chọn người nhận `Boss`, điền tiêu đề và chọn file.
3. Bấm **Mã hoá & gửi tài liệu**, chờ thông báo gửi thành công.
4. Đăng xuất và đăng nhập `boss`.
5. Trong hộp thư, nhập passphrase `boss123`, chọn **Xem** hoặc **Lưu**.
6. Đối chiếu nội dung nhận được với file gốc.

Khi chưa cấu hình scanner, hệ thống thông báo chưa quét mã độc; đây là trạng thái
bình thường của demo, không phải lỗi giải mã. File gốc tối đa **10 MiB**.

### Thử tài khoản mới

Đăng nhập `quantri` → tạo tài khoản tại trang Quản lý. Người nhận mới cần có thêm
passphrase khởi tạo khoá riêng. Mật khẩu tạm và passphrase mới cần tối thiểu 12 ký tự.
Người dùng mới phải đổi mật khẩu tạm tại trang Tài khoản trước khi dùng chức năng khác.
Quản trị quản lý tài khoản/nhật ký nhưng không có quyền gọi API giải mã tài liệu.

Muốn thử nhiều người dùng đồng thời, dùng các hồ sơ trình duyệt riêng hoặc cửa sổ
thường và cửa sổ riêng tư; nhiều tab cùng hồ sơ dùng chung cookie đăng nhập.

**Tài khoản chỉ khởi tạo một lần.** Sau đó đổi `EMPLOYEE_PASSWORD`, `BOSS_PASSWORD`
hoặc `ADMIN_PASSWORD` trong `.env` không đổi mật khẩu đã lưu trong MySQL. Hãy dùng
trang Tài khoản hoặc chức năng đặt lại mật khẩu của quản trị.

## 7. Những lần chạy tiếp theo

1. Bật MySQL trong XAMPP.
2. Mở Terminal tại thư mục project và chạy `npm start`.
3. Mở `http://localhost:3000`.

Không cần clone lại, cài lại thư viện hoặc tạo lại database mỗi lần chạy.
Dừng server bằng **Ctrl + C** trong Terminal của nó. Khi sửa backend hoặc `.env`,
dừng rồi chạy lại; khi sửa giao diện có thể cần **Ctrl + F5** trên trình duyệt.

Khi cập nhật mã nguồn từ Git, dừng server trước, sao lưu nếu có dữ liệu cần giữ, rồi:

```powershell
git pull
npm ci
npm run db:init
npm start
```

Không ghi đè `.env` và không xoá khoá/dữ liệu cũ trong quá trình cập nhật.

## 8. Kiểm thử

Vẫn cần MySQL/XAMPP chạy và `.env` kết nối đúng:

```powershell
npm test
```

Tài khoản DB chạy test cần quyền tạo/xoá database thử nghiệm. Test tạo database riêng
có tên `atbm_test_<random>` và thư mục tạm, sau đó dọn chúng; không dùng database chính
để lưu dữ liệu thử. Không cần bật server trên cổng 3000 vì test tự mở cổng riêng.

## 9. Lỗi thường gặp

| Hiện tượng | Cách xử lý |
| --- | --- |
| Không có lệnh `node`, `npm` hoặc `git` | Kiểm tra cài đặt/PATH, mở lại Terminal |
| Không tìm thấy `package.json` | Chạy `cd atbm-hk1` tới thư mục gốc trước |
| `Cannot find module 'mysql2/promise'` | Chạy `npm ci` tại thư mục project |
| PowerShell chặn `npm.ps1` | Dùng `npm.cmd`, ví dụ `npm.cmd start` |
| `ECONNREFUSED` | Bật MySQL trong XAMPP, kiểm tra `DB_HOST` và `DB_PORT` |
| `ER_ACCESS_DENIED_ERROR` | Kiểm tra `DB_USER`, `DB_PASSWORD` và quyền tài khoản DB |
| `ER_BAD_DB_ERROR` hoặc thiếu bảng | Kiểm tra `DB_NAME`, chạy `npm run db:init` |
| XAMPP không bật được MySQL | Xem log MySQL và cổng đang dùng; không xoá thư mục `data` để sửa nhanh |
| `EADDRINUSE` | Server khác đang giữ cổng; dừng đúng server cũ hoặc đổi `PORT` |
| Trang hiện nhưng nút không hoạt động sau cập nhật | Khởi động lại server đúng thư mục project rồi Ctrl + F5 |
| Có thông báo server/tác vụ bảo trì đang dùng kho dữ liệu | Dừng tiến trình cũ trước; không xoá lock khi server vẫn chạy |
| Quá nhiều yêu cầu đăng nhập | Chờ theo giới hạn; kiểm tra tài khoản/mật khẩu trước khi thử tiếp |
| `crypto.subtle` không có | Dùng `http://localhost:3000`; truy cập IP nội bộ qua HTTP có thể không dùng được Web Crypto |
| Sai passphrase hoặc thiếu private key | Phân biệt mật khẩu đăng nhập với passphrase; xem mục phục hồi bên dưới |

## 10. Khoá RSA, dữ liệu và phục hồi

Git được cấu hình bỏ qua `.env`, `node_modules/`, các khoá PEM và file JSON trong
`storage/`. **Clone mã nguồn không phải là phục hồi dữ liệu của một máy khác.**

| Trường hợp | Cách xử lý |
| --- | --- |
| Cài mới hoàn toàn | Dùng database mới, không chép tài liệu cũ; server tự sinh khoá mới khi chạy lần đầu |
| Dùng tiếp dữ liệu cũ | Phục hồi đồng bộ database, `storage/` và `keystore/`, giữ đúng passphrase |
| Có file mã hoá nhưng mất private key | Khôi phục khoá tương ứng từ backup; sinh khoá mới không mở được file cũ |
| Database cũ còn nhưng khoá trên máy mới không có | Không chạy như cài mới; dùng bản sao lưu đầy đủ hoặc cấu hình một môi trường demo mới tách biệt |

Không xoá `keystore/` để xử lý lỗi đăng nhập/giải mã. Chỉ đổi `BOSS_PASS` trong `.env`
cũng không mã hoá lại private key đã tồn tại; dùng chức năng đổi passphrase tại trang Tài khoản.

Hướng dẫn tạo backup mã hoá và phục hồi vào database mới nằm trong
[tài liệu kỹ thuật — Sao lưu và kiểm tra phục hồi](docs/TECHNICAL.md#sao-lưu-và-kiểm-tra-phục-hồi).

## 11. Cấu trúc và tài liệu chi tiết

```text
atbm-hk1/
├── server.js               Khởi động web và đọc .env
├── app.js                  API, đăng nhập, phân quyền
├── store.js                Kết nối MySQL, transaction, nhật ký
├── database/schema.sql     Cấu trúc bảng
├── documents.js            Quản lý metadata và quyền tài liệu
├── receiver.js             Xử lý khoá và giải mã RSA/AES
├── public/                 HTML, CSS và JavaScript phía trình duyệt
├── scripts/                Khởi tạo DB, sao lưu và phục hồi
├── test/                   Kiểm thử tự động
├── docs/TECHNICAL.md        Chi tiết chức năng, bảo mật, vận hành
├── .env.example            Mẫu cấu hình, được lưu trên Git
└── package.json            Thư viện và lệnh chạy
```

Thư mục `keystore/`, `storage/` và các file cần thiết được tạo khi chạy nếu chưa có.
Mô hình hiện tại tin cậy server để giải mã, chưa phải mã hoá đầu cuối giữa hai thiết bị.
Chạy local với tài khoản mẫu dành cho demo; triển khai thật cần HTTPS, scanner, tài khoản
và quyền database phù hợp. Xem [tài liệu kỹ thuật](docs/TECHNICAL.md) trước khi triển khai.
