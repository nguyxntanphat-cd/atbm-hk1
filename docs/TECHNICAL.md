# Chức năng, bảo mật và vận hành

Hướng dẫn cài mới nằm tại [README](../README.md). Các lệnh bên dưới chạy từ thư mục gốc project.

## Chức năng và phân quyền

- Tài khoản riêng: tạo, khoá/mở, đặt lại mật khẩu tạm, hạn mức lưu trữ.
- Khoá tài khoản hoặc đặt lại mật khẩu thu hồi mọi session của tài khoản đó.
- Session lưu hash token trong MySQL, tồn tại qua restart, hết hạn sau 30 phút.
- Mật khẩu scrypt có salt; cookie `HttpOnly`, `SameSite=Strict`, thêm `Secure` khi HTTPS.
- Chỉ người nhận được đọc/giải mã tài liệu gửi cho mình. Người gửi xem metadata đã gửi
  và tải gói mã hoá của mình; không có API giải mã hộ người nhận.
- Hộp thư và đã gửi có tìm kiếm, phân trang 10 bản ghi/trang; cập nhật hộp thư mỗi 5 giây.
- Trạng thái đã nhận/đã mở; “đã mở” chỉ có nghĩa server đã giải mã và trả file,
  không chứng minh người dùng đã đọc hoặc phê duyệt.
- Phiên bản mới liên kết `previousId`, không ghi đè file cũ. Cùng người gửi và người nhận.
- Thu hồi/hết hạn chặn truy cập tiếp theo trên server. Không xoá được bản rõ/bản mã
  đã tải xuống hoặc nội dung người dùng đã sao chép trước đó.
- Hạn mức tính theo số byte gói lưu thực tế (gồm Base64/metadata), không chỉ file gốc.
  Mặc định 100 MiB/người gửi và 1024 MiB tổng. File gốc tối đa 10 MiB.
- File thu hồi vẫn chiếm hạn mức vì còn được lưu để truy vết; chưa tự động xoá dữ liệu.

## Mã hoá và tương thích dữ liệu cũ

Mỗi file có AES key 256 bit và IV 96 bit riêng. AES-256-GCM dùng tag 128 bit;
RSA-2048 OAEP/SHA-256 bọc AES key. Base64 chỉ là cách biểu diễn, không phải thuật toán bảo mật.

Upload mới dùng **gói phiên bản 3**. AAD là UTF-8 của mảng JSON theo thứ tự cố định:

```text
[version, algorithm, keyId, senderUsername, sender,
 title, category, filename, fileSize, recipientUsername, previousId, expiresAt]
```

`keyId` là SHA-256 của public key SPKI DER. `id` và `time` do server tạo,
không thuộc AAD. Gói được lập chỉ mục kèm SHA-256 để phát hiện thay đổi trên ổ đĩa.
File không được đưa trực tiếp vào HTML; metadata hiển thị bằng `textContent`.
CSP cấm inline script/handler; API ghi dữ liệu kiểm tra JSON, custom header và Origin.

Lần nâng cấp đầu, các file JSON cũ được **lập chỉ mục**, không mã hoá lại, không sửa file
hoặc khoá cũ. Gói v1/v2 thuộc Boss ban đầu và vẫn dùng được; v1 không bảo vệ metadata.
Tài liệu mới chỉ nhận v3. Gói v3 giải mã thủ công cần ID đã có trong DB để áp dụng
quyền, thu hồi và thời hạn. Không tự nhận gói từ một hệ thống khác.

**Server được tin cậy:** server giữ private key mã hoá và xử lý passphrase/bản rõ khi
người nhận yêu cầu. Đây chưa phải mã hoá đầu cuối giữa hai thiết bị. AAD không thay
thế chữ ký số. Quản trị máy chủ/DB vẫn là thành phần có đặc quyền; giới hạn vai trò
trong API không phải cách ly mật mã khỏi người kiểm soát toàn bộ máy chủ.

## Quản lý và luân chuyển khoá

- Boss ban đầu giữ đường dẫn cũ `keystore/receiver/` và `keystore/sender/`.
- Người nhận mới có kho riêng dưới `keystore/users/<username>/<id>/`.
- Trang **Tài khoản → Khoá nhận tài liệu** cho chọn khoá, đổi passphrase hoặc luân chuyển.
- Đổi passphrase mã hoá lại cùng private key; không đổi `keyId` và không làm mất file cũ.
- Luân chuyển tạo cặp mới cho lần gửi tiếp theo; khoá cũ vẫn giữ để mở tài liệu cũ.
  Người nhận cần nhớ passphrase tương ứng. Có thể đổi passphrase từng khoá cũ riêng.
- Không tự sinh đè khi mất khoá. Startup kiểm tra public key/fingerprint và sự tồn tại
  private key; việc mở/xác thực private key bằng passphrase diễn ra khi giải mã.

Giải mã được chuyển sang worker thread, tối đa 2 tác vụ đồng thời; server trả 503 nếu bận.
Một tiến trình phục vụ một kho dữ liệu; file lock chặn chạy hai tiến trình hoặc sao lưu
offline trùng lúc. Windows cần đặt ACL cho khoá; `mode: 0o600` không thay thế ACL.

## File độc hại và chính sách loại file

Mã hoá không làm file trở nên an toàn. Chế độ demo chưa cấu hình scanner sẽ hiện
`not-configured`, không tuyên bố file đã sạch. Production bắt buộc cấu hình scanner.

```dotenv
SCANNER_COMMAND=C:/Program Files/ClamAV/clamscan.exe
SCANNER_ARGS=["--no-summary"]
ALLOWED_EXTENSIONS=.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.png,.jpg,.jpeg
```

Đây là giao diện cho công cụ tương thích ClamAV: exit 0 sạch, 1 phát hiện nguy cơ,
khác là lỗi. Không chạy qua shell, giới hạn 20 giây. Sau khi giải mã, file tạm trong
`storage/.quarantine` được quét trước khi trả bản rõ; lỗi hoặc phát hiện nguy cơ đều
chặn bản rõ. File tạm được xoá trong `finally`; nếu máy sập có thể còn file tạm,
cần kiểm tra/dọn sau khi server đã dừng. Kho tạm cũng cần ACL và ổ đĩa được bảo vệ.

Chưa cài ClamAV hay database nhận diện virus cho bạn; cần tự cấu hình và cập nhật
công cụ trước khi dùng thật. Không gửi tài liệu nội bộ lên dịch vụ quét công khai.
Giới hạn đuôi file không thay thế kiểm tra nội dung; chưa có sandbox/CDR hoặc chống
mọi định dạng archive độc hại. Hệ thống không tự giải nén hoặc chạy tài liệu.

## Nhật ký và kiểm thử

Nhật ký trong MySQL ghi đăng nhập, gửi, tải bản mã, giải mã, thu hồi và thay đổi tài khoản/
khoá. Không ghi mật khẩu, passphrase hoặc nội dung bản rõ. Các bản ghi có chuỗi hash;
trigger chặn UPDATE/DELETE thông thường. Người có quyền DBA vẫn có thể sửa cấu trúc,
nên đây chưa phải nhật ký bất biến độc lập; nên xuất nhật ký ra nơi quản trị tách biệt khi dùng thật.

Giới hạn 10 lần đăng nhập thất bại/IP/15 phút và tổng 60 yêu cầu đăng nhập/IP/phút;
30 yêu cầu giải mã/tài khoản/phút. Rate limit còn trong RAM, phù hợp triển khai một tiến trình.

```powershell
npm test
```

Test cần MySQL/XAMPP đang chạy và tài khoản DB có quyền tạo/xoá database thử nghiệm.
Mỗi fixture dùng tên `atbm_test_<random>` và thư mục tạm riêng, không xoá dữ liệu thật.
Kiểm tra Web Crypto → API → giải mã, dữ liệu sửa đổi, phân quyền từng tài liệu,
session, tài khoản mới, quota, thu hồi, nhiều khoá và phục hồi backup.
Không thay thế việc kiểm thử tải, trình duyệt thật hoặc đánh giá bảo mật độc lập.

## Sao lưu và kiểm tra phục hồi

**Dừng server trước khi sao lưu.** Công cụ không sao chép dữ liệu đang thay đổi.
Backup gồm dữ liệu bảng, gói mã hoá và các khoá cần thiết; toàn bộ archive được mã hoá
AES-GCM với khoá dẫn xuất từ `BACKUP_PASSWORD`. Không lưu mật khẩu backup cùng archive.

```powershell
$env:BACKUP_PASSWORD = 'mat-khau-backup-rieng-tu-16-ky-tu'
npm run backup
node scripts/backup.js verify backups/ten-file.atbm-backup
node scripts/backup.js restore backups/ten-file.atbm-backup atbm_restore_kiemtra
Remove-Item Env:BACKUP_PASSWORD
```

Restore chỉ ghi vào database **mới** có tiền tố `atbm_restore_` và thư mục mới
`runtime/atbm_restore_kiemtra`, không ghi đè database/thư mục đang dùng. Kiểm tra hash file,
fingerprint public key, chuỗi audit và không phục hồi session đăng nhập. Nếu lỗi,
database/thư mục phục hồi được giữ để kiểm tra, chưa được coi là sẵn sàng phục vụ.

Muốn chạy bản phục hồi, tạo cấu hình riêng với `DB_NAME`, `DATA_DIR`, `KEYSTORE_DIR`
trỏ tới bản phục hồi, giữ server gốc dừng. Đăng nhập và thử giải mã một tài liệu bằng
passphrase tương ứng. Không coi việc verify archive thành công là đã kiểm tra toàn bộ phục hồi.
Công cụ dành cho snapshot nhỏ (~128 MiB dữ liệu); hệ thống lớn cần backup streaming,
lịch sao lưu ngoài máy chủ và thử phục hồi định kỳ. Mất cả khoá/passphrase/backup thì
không thể khôi phục bằng cách sinh RSA mới.

## Triển khai có kiểm soát

`NODE_ENV=production` yêu cầu HTTPS, `BOSS_PASS` tối thiểu 12 ký tự và scanner.
Nếu khởi tạo tài khoản lần đầu, đặt thêm `EMPLOYEE_PASSWORD`, `BOSS_PASSWORD`,
`ADMIN_PASSWORD` riêng (12–256 ký tự); không dùng tài khoản demo cho dữ liệu thật.
Nếu DB đã có tài khoản, phải đổi mật khẩu trong ứng dụng trước khi dùng thật.

```dotenv
NODE_ENV=production
HOST=0.0.0.0
PORT=3000
TLS_KEY=certs/server-key.pem
TLS_CERT=certs/server-cert.pem
DB_USER=atbm_app
DB_PASSWORD=mat-khau-rieng
DB_NAME=atbm_internal
```

Chuẩn bị chứng thư tin cậy cho đúng hostname. HTTPS thêm cookie Secure và HSTS.
Production không tự tạo bảng; chạy `npm run db:init` bằng tài khoản migration có quyền
DDL trước. Tài khoản chạy app chỉ cần SELECT/INSERT/UPDATE/DELETE trên database dự án;
không dùng root không mật khẩu khi triển khai thật. Backup/khôi phục dùng tài khoản vận hành
riêng có đủ quyền. Các câu lệnh SQL dữ liệu dùng parameter/prepared statements.

XAMPP là môi trường phát triển; khi đưa lên máy chủ thật cần cấu hình MySQL, firewall,
ACL, backup ngoài máy, cập nhật Node/DB/antivirus, giám sát dung lượng và dịch vụ.
`GET /api/health` kiểm tra kết nối DB, không công khai thông tin chi tiết hoặc mật khẩu.
Chưa cài chứng thư, dịch vụ tự khởi động, lịch backup hay giám sát bên ngoài.

## Mã nguồn và giới hạn

```text
server.js                nạp cấu hình, khởi động/dừng HTTP(S)
app.js                   xác thực, phân quyền và API
store.js                 MySQL connection pool, transaction, audit
database/schema.sql      bảng InnoDB/utf8mb4, tương thích XAMPP MariaDB
documents.js             chỉ mục, quota, quyền đọc và tìm kiếm
security.js              băm mật khẩu và token phiên
receiver.js              khoá RSA và AES-GCM phía nhận
decrypt-worker.js        tác vụ giải mã ngoài event loop chính
scanner.js               adapter quét bản rõ, chặn nếu quét thất bại
public/                  giao diện và Web Crypto phía gửi
scripts/                 khởi tạo DB, backup/restore, đổi passphrase offline
test/                    kiểm thử với database riêng
```

Ứng dụng vẫn là bản dùng thử cho nhóm nhỏ: chưa có chữ ký số người gửi, E2EE,
SSO, nhiều người nhận trong một lần gửi, thông báo email, xoá tự động theo chính sách,
KMS/HSM, hệ thống giám sát hoặc kiểm thử tải quy mô lớn. File/backup còn xử lý trong
RAM; session và metadata đã bền vững nhưng tác vụ nặng vẫn cần kiểm soát tải.
Không thể xoá vật lý mọi bản sao bản rõ trong bộ nhớ trình duyệt/runtime; file đã tải
xuống do người nhận bảo quản. Các giới hạn này cần được đánh giá trước khi dùng tài liệu nhạy cảm.

Tham khảo thiết kế: [MySQL2](https://sidorares.github.io/node-mysql2/docs),
[XAMPP Windows FAQ](https://www.apachefriends.org/faq_windows.html),
[OWASP File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
