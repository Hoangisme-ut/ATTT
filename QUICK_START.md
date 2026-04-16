# 🚀 Bắt đầu nhanh — 1 Phút Trải Nghiệm Phần Mềm

> Tài liệu này được thiết kế cực kỳ ngắn gọn, phù hợp cho **Giảng viên** và người dùng không chuyên muốn nghiệm thu sản phẩm ngay lập tức.

---

## Dành cho Người dùng Phổ thông (Cực Nhanh)
Không cần cài đặt bất kì chương trình dòng lệnh nào. 

1. Mở thư mục `dist/`.
2. **Nháy đúp (Double-click)** vào ứng dụng `DigitalSignatureDemo.exe`.
3. Cửa sổ Giao diện đồ họa (GUI) sẽ nổi lên ngay lập tức.
4. Tha hồ thử nghiệm việc sinh khóa, ký tin nhắn và verify tin nhắn ở giữa 2 tab Ký/Xác minh.

---

## Dành cho Developers / Giảng Viên (Test Code)

Yêu cầu môi trường phải có **Python 3.9+** và thư viện `pycryptodome` (bằng cách gõ `pip install pycryptodome`).

### Phân đoạn 1: Auto-Test Chống Bug
Kiểm nghiệm kiến trúc dự án có khả năng hoạt động logic hoàn chỉnh chưa. Khởi chạy bộ giả lập tích hợp:
```bash
python main.py selftest
```
*(Kết quả ra `OK` báo hiệu 100% Core Engine ổn định).*

### Phân đoạn 2: Trải nghiệm CLI Thủ công
**Ký thông điệp** (Khóa tự động sinh nếu chưa có):
```bash
python main.py genkey anh_nam
python main.py sign anh_nam --message "Hello World" --out demo.json
```
**Xác minh thông điệp**:
```bash
python main.py verify --package demo.json --pub keystore/public/anh_nam_public.pem
```

---

## 🏆 Cẩm nang Báo cáo đồ án
Khi trình chiếu sản phẩm, hãy tập trung nhấn mạnh điểm này:  
> *"Ứng dụng không chỉ đóng gói chữ ký mà còn xuất ra rõ nội dung gói tin trên tab (ĐÁNG TIN CẬY). Ngoài ra, khi file JSON bị chọc phá dẫu chỉ một dấu chấm, chữ ký sẽ gãy ngang và app hiển thị cảnh báo đỏ trực quan không bao che lỗi."*
