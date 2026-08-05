# Giải phẫu Cấu trúc Mã nguồn NasHubs Agent 🧩

NasHubs Agent được thiết kế theo tư duy "Microservice", sử dụng ngôn ngữ Golang để đạt được tốc độ thực thi cao và khả năng cross-compile dễ dàng mà không phụ thuộc vào các thư viện bên ngoài. 

Toàn bộ logic được chia tách thành các module (file `.go`) riêng biệt, mỗi module đảm nhận một trọng trách cụ thể trong hệ sinh thái.

---

## 📂 Danh sách các Module Cốt lõi

### 1. `main.go` (Điểm khởi đầu)
- **Chức năng:** Điểm vào (Entry point) của chương trình. Đọc các tham số dòng lệnh (flags như `--data`, `--port`, `--debug`).
- Khởi tạo thư mục dữ liệu, sinh cấu hình mặc định (nếu chưa có), và kích hoạt bộ đếm thời gian (Scheduler) hoặc máy chủ HTTP (`server.go`).

### 2. `server.go` (Trái tim của HTTP Router)
- **Chức năng:** Định nghĩa và quản lý các Endpoints (API) để Ứng dụng iOS giao tiếp.
- Mọi request đi vào đều bị chặn lại bởi Middleware `s.requireAuth(...)`. Nếu không có chữ ký hợp lệ, request bị từ chối ngay lập tức.
- Điều phối request đến các hàm xử lý cụ thể (như `handleDeploy`, `handleRemove`, `handleLogs`).

### 3. `auth.go` (Kẻ gác đổng Zero-Trust)
- **Chức năng:** Triển khai thuật toán xác thực chữ ký ECDSA P-256.
- **Bảo vệ chống Replay Attack:** Quản lý bộ đệm (Cache) để ghi nhớ các `Nonce` đã dùng, và kiểm tra `Timestamp` của request để đảm bảo nó không trễ quá 30 giây.
- Giải mã Public Key từ file `state.json` và băm nội dung HTTP Body để xác thực tính toàn vẹn (Integrity).

### 4. `cert.go` (Trình quản lý TLS TOFU)
- **Chức năng:** Tự động sinh ra một Chứng chỉ X.509 (TLS/HTTPS Certificate) tự ký cùng Khóa Bí mật ECDSA nội bộ khi Agent lần đầu khởi động.
- Tính toán vân tay (SHA256 Fingerprint) để Ứng dụng iOS ghim (Pin) lại, đảm bảo mã hóa đầu cuối (End-to-End Encryption) mà không cần lệ thuộc vào bên thứ 3 (CA).

### 5. `deploy.go` & `remove.go` (Kỹ sư Quản lý Container)
- **Chức năng:** Đọc các gói lệnh JSON từ iOS App. Nếu là một stack cấu hình mới, nó sẽ lưu thành `docker-compose.yml` vào đúng thư mục dự án.
- Tự động thay thế các biến cấu hình (`{{APP_DIR}}`, `{{PORT}}`).
- Giao tiếp với `/var/run/docker.sock` bằng cách gọi lệnh `docker-compose` dưới dạng process ngầm, trả về log thực thi (stdout/stderr).

### 6. `cloudflare.go` & `proxy.go` (Kỹ sư Mạng)
- **Chức năng:** Can thiệp trực tiếp vào thư mục cài đặt của Nginx và Cloudflared.
- Phân tích và viết đè file `config.yml` (của Cloudflared) hoặc các file `.conf` (của Nginx) để khai báo các Subdomain hoặc Subpath.
- Gọi lệnh Docker khởi động lại các container mạng này để luật định tuyến (Ingress) có hiệu lực ngay lập tức.

### 7. `logs.go` & `health.go` (Mắt thần Giám sát)
- **Chức năng:** Quét hệ thống Docker để kiểm tra trạng thái sức khỏe (Healthcheck) của từng Container.
- Trích xuất log trực tiếp (Stream) qua giao thức Server-Sent Events (SSE) để đẩy liên tục về màn hình iPad của người dùng mà không cần chờ toàn bộ file tải xong.
