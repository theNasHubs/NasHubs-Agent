# Cơ chế Hoạt động của Nasdeck Agent 🧠

Nasdeck Agent là một chương trình siêu nhỏ gọn (Microservice) được viết bằng ngôn ngữ Golang. Nó đóng vai trò như một "bộ não trung gian" hay "quản gia" nằm vùng sâu bên trong hệ điều hành NAS của bạn (đặc biệt tối ưu cho Synology DSM).

Tài liệu này giải phẫu chi tiết cơ chế hoạt động của Agent và giải thích lý do tại sao kiến trúc này lại vượt trội so với các phương pháp quản lý NAS truyền thống.

---

## 1. Tại sao Nasdeck KHÔNG dùng SSH để điều khiển?

Hầu hết các ứng dụng quản lý máy chủ hiện nay trên thị trường (như Termius, ServerAuditor, hay các app NAS 서드파티) đều yêu cầu bạn cung cấp tài khoản root/admin và kết nối liên tục thông qua SSH để gửi lệnh. Nasdeck **kiên quyết nói KHÔNG** với cách tiếp cận này, bởi vì:

### ❌ Rủi ro Bảo mật (Command Injection)
Khi một ứng dụng gửi lệnh Shell (VD: `docker run ...`) qua SSH, một sai sót nhỏ trong việc lọc chuỗi (escaping) cũng có thể dẫn đến việc hacker tiêm mã độc (Command Injection) và xóa toàn bộ dữ liệu trên NAS của bạn.
### ❌ Tốc độ & Hiệu năng quá chậm
Việc khởi tạo một phiên SSH (SSH Handshake) tốn rất nhiều thời gian và tài nguyên CPU. Đối với một ứng dụng di động cần hiển thị thông số RAM/CPU theo thời gian thực (Real-time), việc liên tục mở kết nối SSH để gõ lệnh `top` hay `docker stats` là một thảm họa về mặt hiệu năng.
### ❌ Trải nghiệm Lỗi (Error Handling) tệ hại
Lệnh Shell trả về dữ liệu dưới dạng chuỗi văn bản (Plain text). Việc dùng Regex để bóc tách thông tin từ các chuỗi này cực kỳ dễ hỏng (Fragile) nếu HĐH NAS thay đổi phiên bản.

**👉 Giải pháp của Nasdeck:** Agent chỉ dùng SSH **đúng 1 lần duy nhất** trong đời để tự động cài đặt chính nó vào NAS. Sau đó, nó đóng vĩnh viễn cửa SSH đối với Ứng dụng iOS và chuyển sang giao tiếp thông qua API HTTP(s) nội bộ tốc độ cao với định dạng dữ liệu JSON có cấu trúc chặt chẽ.

---

## 2. Thao tác hệ thống qua Docker Socket

Đã không dùng lệnh Shell, vậy làm sao Agent điều khiển được Docker?

Thay vì "gõ lệnh", Nasdeck Agent giao tiếp trực tiếp với "Trái tim" của Docker thông qua file socket nội bộ: **`/var/run/docker.sock`**.
- Khi bạn bấm "Cài đặt ứng dụng" trên iOS, App gửi một file cấu hình JSON cho Agent.
- Agent phân tích file này và gọi thẳng **Docker Engine API** qua giao thức HTTP-over-Unix-Socket để yêu cầu tải Image, tạo Container, gắn Volume (ổ cứng) và mở Port. 
- Nó tương đương với việc Agent tự mình "viết code" trực tiếp vào bộ nhớ của hệ thống Docker. Điều này loại bỏ hoàn toàn khả năng bị Command Injection và tăng tốc độ xử lý lên hàng chục lần.

---

## 3. Người gác đổng Ingress (Cloudflare & Nginx)

Bên cạnh việc quản lý ứng dụng, Agent còn đóng vai trò như một kỹ sư mạng (Network Engineer) tự động:
- **Tích hợp Cloudflare Tunnel:** Khi bạn cần mở tên miền phụ (VD: `immich.domain.com`), Agent sẽ luồn sâu vào thư mục chứa file `config.yml` của đường hầm Cloudflared đang chạy. Nó viết thêm luật định tuyến (Ingress Rule), và ra lệnh cho container Cloudflared khởi động lại trong nháy mắt. Bạn không cần phải mở giao diện web hay thiết lập DNS phức tạp.
- **Nginx Reverse Proxy:** Nó cũng tự động điều phối file cấu hình Reverse Proxy, giúp gom nhiều ứng dụng vào chung một tên miền chính thông qua định tuyến Subpath (VD: `nas.domain.com/apps/hello-world`).

---

## 4. Kiến trúc Bảo mật Bất đối xứng (Zero-Trust)

Agent tuyệt đối không lưu trữ, không hỏi, và không biết mật khẩu quản trị trị (Admin) của NAS bạn là gì.

1. Khi cài đặt (Bootstrap), iOS App gửi cho Agent một **Khóa Công Khai (ECDSA Public Key)** và Agent lưu nó vào file `/data/state.json`.
2. Ngay khi vừa thức dậy, Agent tự động sinh ra một Chứng chỉ bảo mật (TLS Certificate) tự ký và báo cáo vân tay (Fingerprint) này về cho iOS App ghim lại (TOFU Pinning).
3. Mọi lệnh sau này từ điện thoại gửi lên đều phải được **ký điện tử (HMAC)** bằng Khóa Bí Mật (Private Key) nằm sâu trong phần cứng Secure Enclave của iPhone.
4. Agent nhận lệnh -> Dùng Khóa Công Khai để kiểm tra chữ ký -> Kẻ gian dù có ăn cắp được gói tin hay mò được IP của NAS cũng không thể ra lệnh cho Agent vì họ không có Khóa Bí Mật trên điện thoại của bạn.

### Tóm lại
**Nasdeck Agent = Trình quản lý Docker API + Máy chủ Xác thực Mật mã + Kỹ sư Mạng tự động.** 
Nhờ sự xuất hiện của Agent, việc quản lý NAS trở nên mượt mà, siêu tốc và an toàn tuyệt đối ngay từ thiết kế (Secure by Design)!
