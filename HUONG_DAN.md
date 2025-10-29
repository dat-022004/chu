Tổng quan
-------
Thư mục này chứa các script bằng tiếng Việt để:

- Tạo file bài tập `bai_tap.pdf` (script: `tao_bai_tap_pdf.py`).
- Ký file `bai_tap.pdf` bằng file PKCS#12 `cert.pfx` (script: `ky_bai_tap.py`) tạo `bai_tap_da_ky.pdf`.
- Xác thực file đã ký và ghi log (script: `xac_thuc_bai_tap.py`).

Các bước nhanh (PowerShell):
```powershell
& C:/Users/Admin/AppData/Local/Microsoft/WindowsApps/python3.11.exe -m pip install -r yeu_cau.txt
& C:/Users/Admin/AppData/Local/Microsoft/WindowsApps/python3.11.exe tao_bai_tap_pdf.py
& C:/Users/Admin/AppData/Local/Microsoft/WindowsApps/python3.11.exe ky_bai_tap.py
& C:/Users/Admin/AppData/Local/Microsoft/WindowsApps/python3.11.exe xac_thuc_bai_tap.py
```

Lưu ý:
- Đặt `cert.pfx` vào cùng thư mục và đảm bảo mật khẩu PFX trong `ky_bai_tap.py` (hiện là `1234`).
- Script sử dụng `endesive` để ký và xác thực; để đạt PAdES/LTV đầy đủ cần cập nhật DSS, OCSP/CRL và (tùy chọn) token RFC3161 từ TSA.
