# 🎤 Kịch bản Demo Thực tế giữa 2 Máy Tính (Qua Mạng Gmail)

> Tại buổi bảo vệ đồ án/trình diễn, điều hấp dẫn nhất là chứng minh được một "Hợp đồng" gửi qua mạng (có sự hiện diện thực tế) đã hoạt động an toàn ra sao. Gợi ý làm demo giữa Máy A và Máy B thực tiễn.

---

## 🎭 Chuẩn bị Vai trò

- **Máy A (Máy Người Gửi):** Gửi hợp đồng mua bán sang Máy B.
- **Máy B (Máy Người Nhận):** Thẩm định file nhận được trước khi giải ngân.

_(*Lưu ý: Nếu không tiện đem 2 máy tính, toàn bộ kịch bản này làm hoàn toàn trên 1 Máy thông qua thao tác Tab-to-Tab trên App)*_

---

## 📝 Quy trình Đóng vai Demo

### Bước 1 (Gửi) — Khởi tạo & Ký kết (Máy A)

Trên Máy A (mở công cụ `DigitalSignatureDemo.exe`):
1. Chuyển sang Tab **Ký tin nhắn**. Điền Người ký: `Giám Đốc Cty K`. Click *Tạo khóa*.
2. Nhập nội dung: *"Hợp đồng chuyển nhượng kho số 3. Mức giá: 2.0 Tỷ"*
3. Click **Sign và lưu JSON**. Lưu tên `HopDong_Kho3.json`.

---

### Bước 2 (Gửi) — Truyền thông tin qua mạng

Người dùng máy A truy cập **Gmail**:
1. Soạn email mới gửi sang máy B.
2. Đính kèm 2 tệp cần thiết:
   - File chứng từ `HopDong_Kho3.json`.
   - File chìa khóa `keystore/public/Giam_Doc_Cty_K_public.pem`.
*(Có thể đổi qua gửi qua Zalo hay Cắm USB, file public key này là công khai cho bất kì ai muốn verify).*

---

### Bước 3 (Nhận) — Thẩm định & Xác minh thành công (Máy B) ✅

Máy B tải 2 file đó từ email xuống Desktop và tiến hành Check (Mở `.exe` của máy B lên):
1. Qua Tab **Xác minh**.
2. *Chọn file* trỏ đến túi hồ sơ `HopDong_Kho3.json`.
3. *Chọn key* trỏ đến khóa của Giám Đốc `...public.pem`.
4. Ấn **Verify**.

**Màn hình sẽ báo xanh 🟢**: Phần mềm giải nén chữ ký, giải mã logic thuật toán RSA và kết luận toàn vẹn. Khung nội dung bung chữ: `"Hợp đồng chuyển nhượng kho số 3..."` kèm con triện `[ĐÁNG TIN CẬY]`.  
*(Máy B yên tâm giải ngân).*

---

### Bước 4 (Nhận) — Mô phỏng Rủi ro Hacker Tấn công (Máy B) ❌

Máy B thử đóng vai là kẻ Hacker (hoặc Man in the Middle), lén vào sửa trực tiếp hợp đồng JSON:
1. Chuột phải tệp `HopDong_Kho3.json` chọn **Open with Notepad**.
2. Tìm con số `2.0 Tỷ` — lén lút gõ xóa và thêm số 0 thành `20.0 Tỷ`.
3. `Ctrl + S` lưu dòng code đó lại.

Máy B sau đó mở lại chương trình Chữ ký số `.exe`:
1. Vẫn trỏ vào 2 file đó như cũ.
2. Ấn **Verify**.

**Màn hình sẽ báo đỏ 🔴**: Phần mềm chập cảnh báo khẩn cấp `THẤT BẠI - XÁC MINH KHÔNG THÀNH CÔNG`. Đoạn chữ hợp đồng giả mạo trồi lên kèm nhãn cảnh giác cao độ: `[CẢNH BÁO: KHÔNG ĐÁNG TIN CẬY / BỊ THAY ĐỔI]`.

---

## 🎯 Luận điểm ăn điểm trong buổi Thuyết Trình

Khi giảng viên chất vấn công nghệ giải thuật đằng sau, bạn trả lời theo cấu trúc này:

> "Thưa hội đồng, việc tấn công thay đổi nội dung trở nên vô nghĩa bởi *Mã Băm (Hash)* được sinh ra từ câu nói `20.0 Tỷ` hoàn toàn dị biệt với đoạn Hash ban đầu được kẹp bên trong lòng chữ ký số RSA. 
> Cơ chế API verify_package đã mã hóa lại Hash, cự tuyệt khớp kết quả, dẫn tới hệ thống phòng ngự an toàn từ chối thông điệp rác. Khóa bí mật vẫn nằm gọn trong máy A nên kẻ xấu vô phương dựng lên một cặp chữ ký mới cho con số giả dối!"
