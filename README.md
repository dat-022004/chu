# Đề tài: CHỮ KÝ SỐ TRONG FILE PDF  
Sinh viên thực hiện: Đặng Đình Đạt  
MSSV: K225480106003  
Lớp: 58KTPM  
Giảng viên hướng dẫn: Đỗ Duy Cốp   
Thời hạn nộp: 31/10/2025  
=================================
Ảnh 1 – Giai đoạn khởi tạo kiểm tra (verify_pdf.py chạy với bai_tap.pdf)  
👉 Kết quả: Xác thực thất bại, chương trình không tìm thấy trường /ByteRange hoặc /Contents.  
📝 Nhận xét: PDF chưa có chữ ký điện tử, hoặc chưa đúng định dạng chứa chữ ký → cần ký lại file gốc trước khi xác thực.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/78848bd9-eb5b-403d-aa62-1cafe4ca83ce" />  

Ảnh 2 – Giai đoạn ký file (ky_bai_tap.py)  
👉 Kết quả: Ký thành công, thêm timestamp, tạo file bai_tap_da_ky.pdf.  
📝 Nhận xét: Hệ thống ký số hoạt động đúng. Thông tin ký (tên, số điện thoại, địa điểm, số trang) hiển thị đầy đủ và rõ ràng.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/0363001d-82c4-4d68-9742-ae9b436f67ed" />  

Ảnh 3 – Giai đoạn xác thực chữ ký (verify_pdf.py với bai_tap_da_ky.pdf`)  
👉 Kết quả: Toàn bộ 8 bước xác thực đều “THÀNH CÔNG”.  
📝 Nhận xét: Chữ ký hợp lệ, nội dung không bị chỉnh sửa, chứng chỉ tin cậy, có timestamp. Hệ thống xác thực hoạt động đúng.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/ffcf495e-1874-4391-bb78-935c64b2176f" />  


Ảnh 4 – Nội dung file nhat_ky_xac_thuc.txt sau xác minh  
👉 Ghi log chi tiết quá trình xác thực, từng bước đều “HỢP LỆ”.  
📝 Nhận xét: Nhật ký rõ ràng, minh chứng được việc kiểm tra toàn diện (PKCS7, hash, signature, chain, OCSP, timestamp).  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/a62f0682-faf4-4f87-843b-2b0b793610e0" />  

# Nhận xét tổng thể  
Quy trình ký và xác thực chữ ký điện tử hoạt động đúng, đảm bảo tính toàn vẹn và xác thực của tài liệu PDF. File sau khi ký có đầy đủ thông tin người ký, thời gian ký và dấu thời gian hợp lệ. Kết quả xác thực cho thấy chữ ký hợp lệ, dữ liệu không bị chỉnh sửa, chứng chỉ và chuỗi xác thực tin cậy. Hệ thống ghi log rõ ràng, minh chứng đầy đủ cho quá trình kiểm tra.



