# Bài học Thực tiễn: Mê cung Lỗi của Cloudflare Tunnel ☁️

Tích hợp Cloudflare Tunnel để truy cập các dịch vụ nội bộ (như Immich, Nextcloud) ra ngoài Internet bằng tên miền (Domain) mà không cần mở Port rườm rà là một trong những tính năng sát thủ của Nasdeck.

Tuy nhiên, việc triển khai tự động quá trình này (API `route dns`) thông qua Nasdeck Agent đã khiến chúng tôi vấp phải hàng loạt "hố đen" lỗi hệ thống cực kỳ tinh vi. Dưới đây là biên bản hậu phẫu (Post-mortem) của vụ việc.

---

## 1. Ảo ảnh Thành công (False Positive) và Lỗi Phân quyền

### Sự cố:
Khi người dùng Nasdeck App yêu cầu mở tên miền phụ cho ứng dụng Immich (`immich.domain.com`), Ứng dụng báo "Thành công". Tuy nhiên, trên bảng điều khiển DNS của Cloudflare hoàn toàn không có bản ghi nào, và trang web trả về lỗi `NXDOMAIN` (Tên miền không tồn tại).

### Điều tra nguyên nhân:
Khi App gọi API, Agent ngầm thực thi lệnh `docker run cloudflare/cloudflared tunnel route dns ...`. Docker trả về Exit Code 0 (Báo thành công) nhưng lệnh thực chất đã chết từ trong trứng nước!
- Cloudflared CLI chạy bên trong Container dưới quyền người dùng bảo mật là `nonroot` (ID: 65532).
- Khóa bảo mật (File `.json` Credentials) được tạo lúc trước bằng quyền `root` và được lưu vào thư mục Volume trên NAS.
- Vì user `nonroot` không có quyền đọc (Read Permission) file của `root`, lệnh `route dns` bị lỗi văng ra (Silent Fail) mà không bắn vỡ luồng thực thi (Crash) của Agent.

### Giải pháp khắc phục:
Bắt buộc phải ép Container chạy dưới quyền cao nhất để có thể đọc được chứng chỉ từ NAS khi gọi lệnh định tuyến. 
Chúng ta đã thêm cờ `--user root` vào hàm gọi `exec.Command` bên trong module Golang của Agent:
```go
out, err := exec.Command("docker", "run", "--rm", "--user", "root", "-v", "nasdeck-cf-creds:/root/.cloudflared", ...).CombinedOutput()
```
Đồng thời, bổ sung cơ chế kiểm tra (Catch error) bằng cách đọc kỹ chuỗi `CombinedOutput` để vạch trần mọi "Ảo ảnh thành công" nếu lệnh không thực sự sinh ra chuỗi "Added CNAME".

---

## 2. Bóng ma của `--url` và Lỗi 502 Bad Gateway

### Sự cố:
Sau khi đã tạo thành công bản ghi DNS trên Cloudflare, người dùng truy cập `https://immich.domain.com` nhưng lại bị đập vào mặt lỗi **502 Bad Gateway**.

### Điều tra nguyên nhân:
Theo lý thuyết, Agent đã tạo ra file cấu hình `config.yml` chứa các luật định tuyến (Ingress rules) chỉ định rằng `immich.domain.com` sẽ được dẫn tới `http://localhost:2283` (Nơi Immich đang chạy).
Tuy nhiên, Container Cloudflared hoàn toàn phớt lờ file này!
- **Lý do:** Khi người dùng cài đặt Cloudflared lần đầu tiên bằng Nasdeck, file `docker-compose.yml` chứa một cờ khởi động cứng đầu là `--url http://localhost:5000` (để kết nối nhanh giao diện Synology DSM).
- Theo tài liệu của Cloudflare, nếu khởi động Tunnel với tham số `--url` truyền thẳng trên dòng lệnh, nó sẽ **tự động vô hiệu hóa toàn bộ cơ chế Ingress (Đa luồng)** và ép mọi tên miền đi qua Tunnel đó phải dẫn về một đích duy nhất (localhost:5000).
- Bóng ma này được ghi nhớ trong thư mục cài đặt của Agent (Cached `docker-compose.yml`). Dù có khởi động lại Container bao nhiêu lần, nó vẫn tiếp tục bị kẹt với cờ `--url` kia.

### Giải pháp khắc phục:
1. Sửa đổi file cấu hình tĩnh trong Github Repo `nasdeck/templates` (File `index.json`) để xóa vĩnh viễn tham số `--url` khỏi mẫu khởi tạo.
2. Đối với những hệ thống cũ đã bị nhiễm "bóng ma", Agent phải dùng lệnh `sed` can thiệp trực tiếp vào thư mục cài đặt (`/volume1/docker/cloudflared/.../docker-compose.yml`) trên NAS để cắt bỏ cờ `--url`, sau đó ra lệnh:
   ```bash
   docker-compose up -d --force-recreate
   ```
Container mới được tái sinh đã chịu khó đọc lại file `config.yml` và phân luồng chính xác hàng chục ứng dụng khác nhau qua chung một Tunnel duy nhất!

---
*Ghi chú: Lỗi này được phát hiện vào 2026-07-28 nhờ một người dùng đã "phát điên" khi chỉ gõ mỗi chữ `immich` thay vì tên miền đầy đủ.*
