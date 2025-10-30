 
# Hướng dẫn (huong_dan.md) — cập nhật chính xác theo script

## Mục đích
File này mô tả chính xác cách thiết lập môi trường và cách chạy các script có sẵn trong workspace `BAO_MAT/bt2`. Nội dung đã được cập nhật theo `ky_bai_tap.py` và `verify_pdf.py` (đã kiểm tra mã nguồn kèm theo trong repository).

## Yêu cầu tối thiểu
- Python 3.8+.
- Windows (hướng dẫn sử dụng PowerShell). Điều chỉnh lệnh kích hoạt nếu dùng macOS/Linux.
- Các thư viện chính cần có (có trong `requirements.txt` hoặc cài riêng):
	- PyPDF2
	- endesive
	- cryptography
	- reportlab
	- asn1crypto
	- certvalidator (tùy chọn, chỉ dùng cho bước OCSP/CRL trong `verify_pdf.py`)

## File quan trọng trong repo
- `ky_bai_tap.py`: ký PDF mẫu. Script không yêu cầu tham số — nó đọc `bai_tap.pdf` và `cert.pfx` trong thư mục hiện hành và xuất `bai_tap_da_ky.pdf`.
- `verify_pdf.py`: kiểm tra chữ ký PDF. Hỗ trợ truyền đường dẫn file (tùy chọn) và hai flag: `--trust-local-pfx` và `--quiet`.
- `cert.pfx`: file PFX chứa private key + cert (ky_bai_tap.py mặc định sử dụng mật khẩu b'1234').
- `ky.png`: ảnh chữ ký để chèn lên PDF (nếu có).
- `nhat_ky_xac_thuc.txt`: file log kết quả xác thực do `verify_pdf.py` ghi ra.

## Cài đặt môi trường (PowerShell)
Tạo virtualenv và cài dependencies:

```powershell
python -m venv .\venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

Nếu bạn không có `requirements.txt`, cài tay:

```powershell
pip install PyPDF2 endesive cryptography reportlab asn1crypto
# certvalidator chỉ khi muốn kiểm tra OCSP/CRL
pip install certvalidator
```

## Chạy script — hướng dẫn chính xác

- Ký PDF (script `ky_bai_tap.py`):

	- Hành vi: script đọc `bai_tap.pdf` (trong thư mục hiện hành), chèn overlay (ảnh `ky.png`, tên, ngày, SĐT) lên trang được cấu hình trong mã (biến `dct['page']` có giá trị `5` → tương đương trang thứ 6 vì index bắt đầu từ 0), rồi ký bằng `cert.pfx` (mật khẩu mặc định trong mã `MAT_KHAU_PFX = b'1234'`) và tạo file đầu ra `bai_tap_da_ky.pdf`.
	- Lệnh chạy:

```powershell
python ky_bai_tap.py
```

	- Ghi chú quan trọng:
		- Script hiện không chấp nhận tham số CLI; nếu cần truyền file/mật khẩu, bạn có thể chỉnh mã hoặc yêu cầu tôi thêm argparse.
		- Trang chữ ký được đặt bằng chỉ số 0-based (nếu muốn ký trang 1 hãy đặt `page = 0`). Mặc định trong mã là `page = 5`.
		- Nếu bạn muốn ký mà không chèn ảnh, xóa/không đặt `ky.png` — script sẽ in cảnh báo và tiếp tục.

- Kiểm tra/verify chữ ký (script `verify_pdf.py`):

	- Hành vi: script đọc file PDF (mặc định `bai_tap_da_ky.pdf` nếu không truyền tham số). Nó thực hiện 8 bước kiểm tra (ByteRange, PKCS#7, messageDigest, chữ ký, chuỗi chứng chỉ, OCSP/CRL, timestamp, incremental updates) và ghi ra `nhat_ky_xac_thuc.txt` chi tiết.
	- Tham số và flags:
		- `python verify_pdf.py [pdfpath]` — nếu không truyền `pdfpath` sẽ dùng `bai_tap_da_ky.pdf`.
		- `--trust-local-pfx` — (tùy chọn) nếu bật và có `cert.pfx`, script sẽ thêm PFX làm trust root khi kiểm tra chain.
		- `--quiet` — (tùy chọn) supress console prints (kết quả vẫn ghi vào log file).

	- Ví dụ:

```powershell
python verify_pdf.py               # kiểm tra bai_tap_da_ky.pdf (mặc định)
python verify_pdf.py path\to\file.pdf
python verify_pdf.py --trust-local-pfx path\to\file.pdf
python verify_pdf.py --quiet
```

	- Ghi chú:
		- `verify_pdf.py` có phần kiểm tra OCSP/CRL sử dụng `certvalidator` khi cài đặt; nếu không cài, bước này sẽ bị bỏ qua và script sẽ ghi cảnh báo trong log.
		- Kết luận cuối cùng được đưa vào `nhat_ky_xac_thuc.txt` (ví dụ log đã có trong repo).

## Lưu ý vận hành & khắc phục sự cố
- Nếu gặp lỗi khi load `cert.pfx` trong `ky_bai_tap.py`, kiểm tra mật khẩu (mã hiện đặt `MAT_KHAU_PFX = b'1234'`). Bạn có thể sửa giá trị này trong mã hoặc thay `cert.pfx` bằng file đúng mật khẩu.
- Nếu thiếu module: hãy activate venv và chạy `pip install -r requirements.txt`.
- Quyền truy cập file: đảm bảo PowerShell có quyền đọc các file `.pfx`, `.pem`, và ghi file xuất ra.
- Nếu `verify_pdf.py` báo không tìm thấy `/ByteRange` hoặc `/Contents`, tệp có thể đã bị chỉnh sửa hoặc không phải là PDF được ký theo chuẩn endesive.

## Gợi ý cải tiến (tuỳ chọn)
- Thêm argparse cho `ky_bai_tap.py` để cho phép truyền:
	- đường dẫn PDF nguồn, đường dẫn PFX, mật khẩu PFX, ảnh ký, trang ký, file đầu ra.
- Thêm tests nhỏ (pytest) để kiểm tra luồng: tạo PDF mẫu → ký → verify (đọc `nhat_ky_xac_thuc.txt` để assert kết quả).
- Thêm `examples/` chứa `bai_tap.pdf` mẫu và `ky.png` để thử nhanh.

## Kết luận
Tôi đã cập nhật `huong_dan.md` để phản ánh đúng hành vi hiện tại của `ky_bai_tap.py` và `verify_pdf.py`. Nếu bạn muốn, tôi có thể tiếp tục và:
- Thêm argparse vào `ky_bai_tap.py` để chạy linh hoạt hơn.
- Cập nhật `requirements.txt` với phiên bản đề nghị của các thư viện.
- Tạo một ví dụ end-to-end (một PDF mẫu + script test).

Cho tôi biết bạn muốn tôi làm bước nào tiếp theo.

