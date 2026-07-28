# Nasdeck Agent 🕵️‍♂️

**Nasdeck Agent** là một ứng dụng siêu nhẹ (Microservice) được viết bằng Golang, đóng vai trò như một "Điệp viên ngầm" được cài đặt trực tiếp trên hệ điều hành của NAS (Network Attached Storage), đặc biệt tối ưu cho Synology DSM.

Nhiệm vụ duy nhất của nó là nhận các lệnh điều khiển mã hóa từ ứng dụng di động **Nasdeck iOS App** và thực thi chúng ở cấp độ hệ thống, giúp bạn quản lý NAS mà không cần phải mở giao diện web DSM rườm rà.

---

## 🛠 Nguyên lý Hoạt động

👉 **[Đọc tài liệu phân tích chuyên sâu tại sao Nasdeck KHÔNG dùng SSH tại đây (Cơ chế Hoạt động).](AGENT_MECHANISM.md)**

Khác với các hệ thống quản lý NAS truyền thống, Nasdeck Agent được thiết kế với tư duy "Cloud-Native" và "Zero-Trust":

### 1. Thao tác hệ thống qua Docker Socket
Agent không chạy các lệnh shell nguy hiểm. Thay vào đó, nó giao tiếp trực tiếp với **Docker Daemon** thông qua file socket nội bộ (`/var/run/docker.sock`).
- Khi bạn bấm "Cài đặt Immich" trên App iOS, Agent sẽ nhận payload JSON, tự động dịch nó thành lệnh `docker-compose up -d`.
- Nó có thể đọc log theo thời gian thực (Server-Sent Events) và trả thẳng về màn hình iPhone của bạn.

### 2. Tự động hóa Mạng (Tailscale & Cloudflare)
Agent tích hợp sẵn logic để điều khiển các đường hầm VPN thế hệ mới:
- **Cloudflare Zero Trust:** Nó có khả năng "luồn" vào container Cloudflared, đọc cấu hình xác thực, và tự động gọi API `route dns` để gán tên miền phụ (VD: `immich.domain.com`) trỏ thẳng về NAS của bạn.
- **Reverse Proxy nội bộ:** Tích hợp Nginx để tự động phân luồng giao thông (Subpath routing), cho phép gom nhiều ứng dụng vào chung một tên miền (VD: `nas.domain.com/apps/hello-world`).

### 3. Giao tiếp siêu bảo mật (TOFU & HMAC)
Mọi kết nối từ App iOS đến Agent đều không dùng mật khẩu.
- **TOFU (Trust On First Use):** Khi kết nối lần đầu, Agent cấp một chứng chỉ tự ký (Self-signed Certificate). App iOS sẽ ghim (Pin) dấu vân tay của chứng chỉ này lại. Nếu ai đó cố gắng thực hiện Man-In-The-Middle attack, App sẽ chặn đứng ngay lập tức!
- **Chữ ký Request (HMAC Signature):** Mọi request gửi đi đều kèm theo Timestamp, Nonce, và được ký bằng khóa ECDSA Private Key ẩn sâu trong phần cứng mã hóa (Secure Enclave) của iPhone. Agent giữ Public Key và sẽ từ chối mọi truy cập giả mạo.

---

## 🚀 Hướng dẫn Biên dịch (Build)

Agent được thiết kế để chạy trên mọi kiến trúc CPU, nhưng phổ biến nhất là `linux/amd64` (Synology NAS).

### 1. Biên dịch chéo (Cross-Compile) trên macOS / Windows
Chỉ cần bạn đã cài đặt Go (phiên bản 1.21 trở lên):

```bash
# Clone repository
git clone https://github.com/nasdeck/agent.git
cd agent

# Biên dịch cho Linux AMD64
GOOS=linux GOARCH=amd64 go build -o nasdeck-agent-linux main.go

# (Tuỳ chọn) Build cho ARM64 (Raspberry Pi)
GOOS=linux GOARCH=arm64 go build -o nasdeck-agent-arm64 main.go
```

### 2. Triển khai (Deploy)
Agent thường được đóng gói thành một Docker Image siêu nhỏ gọn (`ghcr.io/nasdeck/agent`). File `Dockerfile` đã được tối ưu hóa theo mô hình Multi-stage build.

```bash
docker build -t ghcr.io/nasdeck/agent:latest .
```

---

## 📂 Cấu trúc Mã nguồn

- `server.go`: Nơi định nghĩa các API Endpoints (như `/deploy`, `/logs`, `/remove`).
- `deploy.go`: Logic cốt lõi phân tích file Docker-Compose và gọi lệnh thực thi.
- `cloudflare.go`: Module chuyên biệt xử lý cấp phát chứng chỉ và định tuyến Ingress cho Cloudflare Tunnel.
- `auth.go`: Kiểm tra chữ ký bảo mật từ Header của HTTP Requests.
- `proxy.go`: Tương tác với Nginx để nạp cấu hình Reverse Proxy động.

---
*Thuộc Hệ sinh thái Nasdeck. Cảm ơn bạn đã quan tâm đóng góp!*
