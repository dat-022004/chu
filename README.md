# Đề tài: CHỮ KÝ SỐ TRONG FILE PDF  
Sinh viên thực hiện: Đặng Đình Đạt  
MSSV: K225480106003  
Lớp: 58KTPM  
Giảng viên hướng dẫn: Đỗ Duy Cốp   
Thời hạn nộp: 31/10/2025  
=================================
Ảnh 1 – Giai đoạn khởi tạo kiểm tra (verify_pdf.py chạy với bai_tap.pdf)  
File được kiểm tra: bai_tap.pdf (PDF gốc chưa ký).  
Kết quả Terminal hiển thị:  
  - endesive: could not interpret result tuple  
  - Không tìm thấy /ByteRange trong PDF (không có chữ ký hoặc format khác)  
Nhận xét:
File PDF này chưa có chữ ký nên không tồn tại các trường /ByteRange hay /Contents.
Chương trình xác thực (verify_pdf.py) hoạt động đúng khi phát hiện và thông báo rằng “file không có chữ ký”.
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/0417eac9-6b1b-405b-a8bf-f8d4e71b85fb" />

Ảnh 2 – Giai đoạn ký file (ky_bai_tap.py)  
Script ky_bai_tap.py được chạy để ký file.  
Kết quả Terminal hiển thị:  
  -50 trang PDF gốc 6  
  -Ký thành công! File: bai_tap_da_ky.pdf  
  -PDF hợp lệ (6 trang)  
Nhận xét:  
Quá trình ký diễn ra thành công, chương trình tạo file bai_tap_da_ky.pdf.  
Chữ ký hiển thị ở góc phải dưới, được thêm bằng ảnh ky.png và thời gian thực tế hệ thống.  
Không có lỗi font hoặc vị trí; thao tác “dịch lên 10 mm” được thực hiện chính xác.  
Kết quả này tương ứng với file signed.pdf trong phần demo.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/be3abf86-d961-4b0e-98a7-a05ee11b9111" />  

Ảnh 3 – Giai đoạn xác thực chữ ký (verify_pdf.py với bai_tap_da_ky.pdf`)  
File được xác thực: bai_tap_da_ky.pdf.  
Terminal hiển thị log chi tiết:  
  -certvalidator missing or failed...  
  -Found 1 self-signed root candidate(s)  
  -Phát hiện incremental updates hoặc dữ liệu đính kèm sau signature.  
  -TÓM TẮT XÁC THỰC —  
  -chữ ký: ✓ (signature_valid)  
  -messageDigest: ✓  
  -Timestamp: Không có (RFC3161)  
  -KẾT LUẬN TỔNG QUÁT: HỢP LỆ  
Nhận xét:  
Chữ ký trong file hợp lệ, nội dung hash và messageDigest trùng khớp, chứng chỉ tự ký (self-signed) khớp với file cert.pfx.  
Tuy không có timestamp RFC3161, nhưng kết quả xác minh chữ ký hoàn toàn chính xác.  
Phát hiện “incremental update” là bình thường vì PDF được lưu thêm phần chữ ký ở cuối file.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/96d6d324-dd9a-40b1-8533-fe70eba73ab8" />  

Ảnh 4 – Nội dung file nhat_ky_xac_thuc.txt sau xác minh  
File log ghi đầy đủ chi tiết xác thực:  
-ByteRange: (0, 396017, 397929, 882)  
-Computed SHA-256...  
-messageDigest: KHỚP  
-Public key size: RSA 2048 bits  
-Chuỗi chứng chỉ tin cậy
-Timestamp token: không tìm thấy  
-KẾT LUẬN TỔNG QUÁT: HỢP LỆ  
Nhận xét:  
Kết quả xác thực được lưu rõ ràng:  
Thuật toán ký: SHA-256 + RSA 2048 bit  
Chứng chỉ trùng với cert.pfx  
Không có lỗi hash hoặc sai ByteRange  
Kết luận cuối cùng: File hợp lệ – không bị sửa đổi sau khi ký.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/06a92511-a49c-4f42-9f81-70247fca48a3" />  

# Nhận xét tổng thể  
Qua bài thực hành chữ ký số trong PDF, em đã hiểu quy trình tạo, ký và xác minh tài liệu điện tử.  
Hệ thống chạy ổn định, ký đúng chuẩn RSA 2048 + SHA-256, phát hiện được khi file bị chỉnh sửa.  
Kết quả xác thực cho thấy chữ ký hợp lệ, nội dung toàn vẹn, chỉ thiếu timestamp RFC3161 và chứng chỉ tin cậy.  
Nhìn chung, bài làm đạt yêu cầu, thể hiện đúng nguyên lý hoạt động của chữ ký số trong PDF.  




