"""
Script tạo chứng chỉ số và các file khóa cho Đặng Đình Đạt
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import datetime

print("Đang tạo các file khóa và chứng chỉ...")
print("="*60)

# 1. Tạo private key
print("\n[1/5] Tạo Private Key (RSA 2048-bit)...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# 2. Lưu private key
print("[2/5] Lưu Private Key -> private_key.pem")
with open('private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 3. Lấy public key và lưu
print("[3/5] Lưu Public Key -> public_key.pem")
public_key = private_key.public_key()
with open('public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# 4. Tạo self-signed certificate
print("[4/5] Tạo Certificate (Self-signed)...")
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'VN'),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Thái Nguyên'),
    x509.NameAttribute(NameOID.LOCALITY_NAME, 'Thái Nguyên'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ICTU'),
    x509.NameAttribute(NameOID.COMMON_NAME, 'Đặng Đình Đạt'),
])

certificate = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    public_key
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 năm
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None),
    critical=True,
).sign(private_key, hashes.SHA256())

# Lưu certificate dạng PEM
print("      -> certificate.pem")
with open('certificate.pem', 'wb') as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

# Lưu certificate dạng DER (CER)
print("      -> certificate.cer")
with open('certificate.cer', 'wb') as f:
    f.write(certificate.public_bytes(serialization.Encoding.DER))

# 5. Tạo file PFX (PKCS#12) - chứa private key + certificate
print("[5/5] Tạo file PFX (PKCS#12) -> cert.pfx")
pfx_data = pkcs12.serialize_key_and_certificates(
    name='Đặng Đình Đạt'.encode('utf-8'),
    key=private_key,
    cert=certificate,
    cas=None,
    encryption_algorithm=serialization.BestAvailableEncryption(b'1234')
)

with open('cert.pfx', 'wb') as f:
    f.write(pfx_data)

print("\n" + "="*60)
print("✓ HOÀN TẤT! Đã tạo các file:")
print("="*60)
print("  1. private_key.pem  - Private key (RSA)")
print("  2. public_key.pem   - Public key")
print("  3. certificate.pem  - Certificate (PEM format)")
print("  4. certificate.cer  - Certificate (DER/CER format)")
print("  5. cert.pfx         - PKCS#12 (password: 1234)")
print("="*60)
print("\nThông tin chứng chỉ:")
print(f"  Tên: Đặng Đình Đạt")
print(f"  Tổ chức: ICTU")
print(f"  Địa điểm: Thái Nguyên, VN")
print(f"  Hiệu lực: 10 năm")
print("="*60 + "\n")
