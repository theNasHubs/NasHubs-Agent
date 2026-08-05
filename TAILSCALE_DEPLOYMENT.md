# Bài học Thực tiễn: Triển khai Tailscale bằng Docker 🐉

Một trong những thử thách lớn nhất khi thiết lập mạng riêng ảo (VPN) trên NasHubs là tích hợp Tailscale trực tiếp bằng Docker thay vì cài đặt bằng ứng dụng gốc của Synology (SPK). Việc chạy mạng ảo bên trong môi trường cô lập của Container dẫn đến rất nhiều "cái bẫy" nguy hiểm. 

Tài liệu này đúc kết những bài học xương máu (Post-mortem) từ quá trình gỡ lỗi (troubleshooting) thực tế.

---

## 1. Bài học về Quyền truy cập Mạng (Network Capabilities)

### Sự cố:
Khi triển khai Tailscale Docker với file `docker-compose.yml` tiêu chuẩn, container báo lỗi `failed to open /dev/net/tun: Operation not permitted` và tự động tắt (Crash loop). Mạng VPN không thể khởi chạy.

### Phân tích nguyên nhân:
Docker theo mặc định tước đi hầu hết các đặc quyền mạng cấp thấp của container vì lý do an toàn. Tailscale cần tạo một giao diện mạng ảo (TUN interface) để mã hóa/giải mã và định tuyến gói tin VPN. Tuy nhiên, nó bị chặn lại bởi hạt nhân Linux (Kernel).

Mặc dù Tailscale có cơ chế **"Userspace Networking"** (tạo mạng ảo trên không gian người dùng để né tránh việc can thiệp hạt nhân), nhưng hiệu năng của nó thấp hơn rất nhiều, và trên NAS Synology, nó không tương thích tốt để nhận lưu lượng Inbound từ bên ngoài vào.

### Giải pháp khắc phục:
Chúng ta bắt buộc phải cấp cho Tailscale hai đặc quyền năng lực (Capabilities) cao nhất của Linux liên quan đến mạng:
1. `NET_ADMIN`: Cho phép container tạo card mạng ảo (`/dev/net/tun`) và sửa đổi bảng định tuyến (Routing table).
2. `NET_RAW`: Cho phép tạo các socket thô (Raw sockets) để xử lý trực tiếp các gói ICMP (Ping).

**Mã YAML đã được sửa:**
```yaml
services:
  tailscale:
    image: tailscale/tailscale:latest
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun:/dev/net/tun
```

---

## 2. Bài học về Sự mất trí nhớ (Amnesia) sau khi Khởi động lại

### Sự cố:
Mỗi khi NAS mất điện hoặc NasHubs Agent khởi động lại tiến trình cài đặt Tailscale, thiết bị NAS bị gán một IP nội bộ Tailscale hoàn toàn mới. Người dùng bị ngắt kết nối do iPhone vẫn ghi nhớ IP cũ.

### Phân tích nguyên nhân:
Mặc định, Tailscale lưu trữ chứng chỉ đăng nhập (State) và Khóa bí mật (Node Key) vào bên trong hệ thống file ảo của Container (tại `/var/lib/tailscale`). 
Khi container bị xóa (Docker rm) và tạo lại, trạng thái này bị mất. Tailscale tưởng rằng đây là một cỗ máy mới hoàn toàn tham gia vào mạng lưới, do đó nó đăng ký một Node ID mới và cấp một dải IP mới.

### Giải pháp khắc phục:
Bắt buộc phải Ánh xạ (Map) thư mục lưu trạng thái ra một ổ đĩa vật lý (Volume) trên NAS để giữ cố định khóa định danh của thiết bị.

**Mã YAML đã được sửa:**
```yaml
volumes:
  - {{APP_DIR}}/state:/var/lib/tailscale
```
Với cấu hình này, dù bạn có xóa hẳn container Tailscale và cài lại 100 lần, NAS của bạn vẫn giữ nguyên địa chỉ IP `100.x.y.z` duy nhất đó!
