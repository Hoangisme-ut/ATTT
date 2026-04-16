# 🖋️ Phần mềm Chữ ký số — Bảo vệ Tính toàn vẹn Thông tin (Digital Signature Application)

> Ứng dụng Python minh họa kỹ thuật chữ ký số **RSA-3072 + SHA-256** theo chuẩn hiện đại.  
> Được thiết kế chuyên biệt cho mục đích học thuật, đồ án môn học và demo an toàn thông tin cơ bản.

---

## 1. Mục đích dự án (Project Purpose) 💡

Trong thế giới trao đổi số, làm sao để người nhận chắc chắn rằng:
1. Tin nhắn đến từ đúng người gửi?
2. Tin nhắn không bị thay đổi trên đường truyền?

Phần mềm này giải quyết bài toán trên bằng công nghệ **Chữ ký số**, cung cấp 3 lớp bảo mật thực tế:
- **Xác thực nguồn gốc:** Xác nhận chính danh người ký qua Khóa công khai.
- **Tính toàn vẹn:** Phát hiện mọi sự thay đổi dù là nhỏ nhất (một dấu phẩy) trong văn bản gốc.
- **Tính chống chối bỏ:** Người gửi không thể phủ nhận việc mình đã ký văn bản đó.

---

## 2. Các tính năng nổi bật (Key Features) ✨

- **Giao diện thân thiện (GUI-First):** Giao diện đồ họa đơn giản, trực quan, dễ thao tác cho người dùng cuối mà không cần kiến thức về dòng lệnh.
- **Luồng CLI mạnh mẽ:** Dành cho lập trình viên với bộ lệnh CLI đầy đủ (`genkey`, `sign`, `verify`, `selftest`).
- **An toàn cốt lõi:** Ngăn chặn việc ghi đè khóa cũ một cách vô ý.
- **Tính minh bạch (Honesty in Cryptography):** Hiển thị rõ ràng chuỗi mã băm được tính toán lại từ nội dung nhận được, tuân thủ đúng nguyên lý lập trình của chuẩn PKCS#1 v1.5.
- **Đóng gói chuẩn chỉnh:** Cung cấp định dạng gói `.json` chuyên nghiệp chứa toàn bộ thông điệp, chữ ký mã hóa Base64 dư kèm siêu dữ liệu (Metadata).

---

## 3. Công nghệ sử dụng (Technologies Used) 🛠️

- **Ngôn ngữ:** Python 3.9+
- **Thư viện Mật mã:** `pycryptodome` (Chuẩn RSA-3072 và SHA-256)
- **Giao diện (GUI):** `tkinter` (Native Desktop)
- **Đóng gói ứng dụng:** `PyInstaller` (Cho bản `.exe`)

---

## 4. Hướng dẫn sử dụng cho Người dùng Phổ thông (Normal Users) 🖱️

Cách nhanh chóng nhất để trải nghiệm ứng dụng mà không cần kiến thức lập trình!

1. Tải file **`DigitalSignatureDemo.exe`** (nằm trong thư mục `dist/`) về máy tính của bạn.
2. **Nháy đúp chuột (Double-click)** vào file để mở thẳng Giao diện đồ họa (GUI). *(Lưu ý: Không hề xuất hiện màn hình đen dòng lệnh).*
3. Nếu Windows Defender cảnh báo (vì phần mềm chưa có chứng chỉ thương mại), hãy bấm **More info → Run anyway**.

### Luồng Ký số (Người Gửi)
*![Giao diện Tab Ký tin nhắn](demo_data/placeholder_sign.png)*
1. Tại tab **Ký tin nhắn**, điền tên người dùng (VD: `nguoi_gui`) và bấm **Tạo khóa** (nếu chưa có).
2. Nhập văn bản cần ký vào ô nội dung.
3. Bấm **Sign và lưu JSON** để bảo mật văn bản vào một file `.json`.

### Luồng Xác minh (Người Nhận)
*![Giao diện Tab Xác minh](demo_data/placeholder_verify.png)*
1. Tại tab **Xác minh**, bấm **Chọn file** để mở gói `.json` vừa nhận.
2. Bấm **Chọn key** để chọn khóa công khai (`.pem`) của người gửi.
3. Bấm **Verify**.
   - 🟢 **Xanh:** Tin nhắn nguyên vẹn. Khung nội dung hiển thị: `[ĐÁNG TIN CẬY - TÍNH TOÀN VẸN ĐƯỢC ĐẢM BẢO]`.
   - 🔴 **Đỏ:** Bị sửa đổi/Sai khóa. Khung nội dung hiển thị: `[CẢNH BÁO: KHÔNG ĐÁNG TIN CẬY / BỊ THAY ĐỔI / SAI KHÓA]`.

---

## 5. Hướng dẫn cho Nhà phát triển (Advanced Users) 💻

Dành cho giảng viên, lập trình viên muốn chạy mã nguồn gốc hoặc thao tác CLI.

### Cài đặt môi trường
Mở thư mục gốc của dự án trong Terminal và chạy:
```bash
pip install pycryptodome
```

### Các lệnh CLI (Command-Line Interface)
```bash
# Xem hướng dẫn trợ giúp
python main.py

# Sinh bộ cặp khóa RSA cho người dùng có tên 'user1'
python main.py genkey user1

# Tiến hành ký văn bản (xuất ra file JSON)
python main.py sign user1 --message "Chuyển 500 triệu đồng" --out hop_dong.json

# Xác thực văn bản JSON với Public Key
python main.py verify --package hop_dong.json --pub keystore/public/user1_public.pem

# Mở giao diện lập trình GUI thủ công
python main.py gui

# Khởi chạy chế độ kiểm thử tự động nội bộ (CI/CD)
python main.py selftest
```

---

## 6. Sửa lỗi thường gặp (Troubleshooting) 🔧

| Vấn đề | Cách khắc phục |
|---|---|
| Báo lỗi `No module named 'Crypto'` khi chạy mã nguồn gốc | Bạn cần cài đặt thư viện mật mã: chạy lệnh `pip install pycryptodome` |
| Báo lỗi `Không tìm thấy private key` | Hệ thống không thấy khóa để ký. Bạn cần phải ấn nút **Tạo khóa** (hoặc chạy `genkey`) trước. |
| Màn hình Verify luôn báo Đỏ thất bại dù chưa sửa chữ | Kiểm tra xem bạn đã chọn ĐÚNG file `_public.pem` của người gửi hay chưa. Chọn sai chìa sẽ bó tay. |

---

## 7. Giải đáp kỹ thuật về Mật mã học (Technical FAQ) 🎓

**1. Tại sao dùng RSA-3072?**  
Đây là độ dài khóa tối thiểu được Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST) khuyến cáo để đảm bảo an toàn sau năm 2030. Khóa 2048-bit tuy nhanh nhưng đang dần lỗi thời.

**2. Tại sao trên giao diện không có dòng chữ "Digest bóc tách từ thông điệp ẩn"?**  
Thư viện Cryptography hiện đại (PKCS#1 v1.5 API) không bao giờ bóc tách mã băm (digest) từ chữ ký để hiển thị thô (Raw) cho bạn xem. Nó tự tính toán băm từ thông điệp, sau đó mã hóa nội bộ với chữ ký và rà soát logic Đúng/Sai. Phần mềm này trung thực về mặt kỹ thuật, bằng cách hiển thị chính xác: *"Mã băm (Digest) SHA-256 (Tính từ nội dung gói JSON)"*. 

**3. Tại sao file .exe không mở màn hình CMD/Terminal?**  
Tiện ích được build với cờ `--noconsole` để tạo trải nghiệm thuần Windows Desktop App. Nếu bạn muốn log CLI, vui lòng dùng `python main.py` từ mã nguồn.

---

## 8. Hướng phát triển tương lai (Future Improvements) 🚀

- Cập nhật chuẩn mật mã đường cong elliptic (ECDSA) thay vì nguyên RSA cho tốc độ sinh khóa nhanh.
- Cấp quyền ký số trực tiếp trên các file văn bản nhị phân như `.docx`, `.pdf`, hoặc Hình ảnh.
- Hỗ trợ kiến trúc Đa quản trị (Có CA - Certificate Authority cấp chứng thư).

---

## 9. Cấu trúc thư mục (Folder Hierarchy) 📁

```text
project/
├── main.py                  # Entry point duy nhất
├── requirements.txt         # Khai báo phụ thuộc pycryptodome
├── README.md                # Tài liệu tổng quan (Bạn đang đọc)
├── QUICK_START.md           # Hướng dẫn nhanh dùng 1 phút
├── DEMO_GMAIL.md            # Kịch bản bảo vệ thực tế qua mạng
├── build_exe.bat            # Công cụ đóng gói exe tự động
├── .gitignore               
│
├── app/
│   ├── constants.py         # Quy ước chung toàn dự án
│   ├── exceptions.py        # Module xử lý ngoại lệ tự định nghĩa
│   ├── models/              # Dataclass chứa cấu trúc Package JSON
│   ├── services/            # Chứa các Business logic Mật mã, I/O 
│   ├── core/                # Core Engine vận hành tổng thể
│   ├── cli/                 # Trình điều khiển Console Parser
│   └── gui/                 # Trình điều khiển Giao diện
│
├── tests/
│   └── test_signature_flow.py  # Unit Test Suite cho CI/CD
│
├── keystore/                # Vị trí khóa mã hóa (Giấu Private, lộ Public)
├── demo_data/               # Hình ảnh/Nội dung dùng demo
└── dist/                    # Chứa ứng dụng Desktop Exe sau khi build
```
