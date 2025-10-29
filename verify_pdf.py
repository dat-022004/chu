import sys
import re
import hashlib
import os
from asn1crypto import cms, pem, x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
import traceback
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives.serialization import Encoding
from endesive.pdf import verify as endesive_verify

DEFAULT_PDF = 'bai_tap_da_ky.pdf'
LOG_FILE = 'nhat_ky_xac_thuc.txt'


def find_byte_range(data: bytes):
    m = re.search(br'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', data)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def extract_contents(data: bytes):
    # find hex contents between <...>
    m = re.search(br'/Contents\s*<([0-9A-Fa-f\s]+)>', data)
    if m:
        hexstr = re.sub(br'\s+', b'', m.group(1))
        return bytes.fromhex(hexstr.decode('ascii'))
    # or binary octets in parentheses or direct stream after /Contents
    m2 = re.search(br'/Contents\s*\((.*?)\)\s*', data, re.S)
    if m2:
        return m2.group(1)
    # fallback: try to locate PKCS7 DER by scanning for ASN.1 header
    m3 = re.search(br'\x30\x82', data)
    if m3:
        return data[m3.start():]
    return None


def compute_hash_over_byterange(data: bytes, br):
    a0, l0, a1, l1 = br
    part1 = data[a0:a0 + l0]
    part2 = data[a1:a1 + l1]
    return part1 + part2


def parse_pkcs7(contents: bytes):
    # contents may be wrapped in CMS ContentInfo
    try:
        if pem.detect(contents):
            type_name, headers, der_bytes = pem.unarmor(contents)
        else:
            der_bytes = contents
        ci = cms.ContentInfo.load(der_bytes)
        if ci['content_type'].native != 'signed_data':
            return None
        sd = ci['content']
        return sd
    except Exception as e:
        return None


def verify_signed_attrs_hash(sd, signed_attrs_bytes, computed_digest, log):
    # find messageDigest attribute inside signed_attrs
    try:
        signer_info = sd['signer_infos'][0]
        attrs = signer_info['signed_attrs']
        for attr in attrs:
            if attr['type'].native == 'message_digest':
                md = attr['values'][0].native
                if md == computed_digest:
                    log.append('- messageDigest: MATCH')
                    return True
                else:
                    log.append(f"- messageDigest: MISMATCH (expected {md.hex()}, got {computed_digest.hex()})")
                    return False
    except Exception as e:
        log.append(f"- messageDigest: error checking: {e}")
        return False


def verify_signature(sd, signed_attrs_der, signature_bytes, cert):
    # Determine signature algorithm
    signer_info = sd['signer_infos'][0]
    sig_algo = signer_info['signature_algorithm']['algorithm'].native
    digest_algo = signer_info['digest_algorithm']['algorithm'].native

    pub = cert.public_key()
    if sig_algo.startswith('rsa') or 'rsa' in sig_algo:
        hash_algo = getattr(hashes, digest_algo.upper())()
        pub.verify(signature_bytes, signed_attrs_der, padding.PKCS1v15(), hash_algo)
    elif sig_algo.startswith('sha') and 'ecdsa' in sig_algo:
        hash_algo = getattr(hashes, digest_algo.upper())()
        pub.verify(signature_bytes, signed_attrs_der, ec.ECDSA(hash_algo))
    else:
        # try a best-effort assume PKCS1v15+sha256
        pub.verify(signature_bytes, signed_attrs_der, padding.PKCS1v15(), hashes.SHA256())


def build_log(lines, path=LOG_FILE):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def icon_for(value):
    if value is True:
        return '✓'
    if value is False:
        return '✗'
    return '?'


def main(pdfpath, trust_local_pfx=False):
    lines = []
    if not os.path.exists(pdfpath):
        lines.append(f'File không tìm thấy: {pdfpath}')
        build_log(lines)
        print('\n'.join(lines))
        return 1

    data = open(pdfpath, 'rb').read()
    lines.append(f'Kiểm tra file: {pdfpath} (size={len(data)} bytes)')

    # Quick built-in verifier from endesive (best-effort high level check)
    try:
        ev = endesive_verify(data)
        lines.append(f"- endesive.verify raw result: {ev}")
        # Interpret endesive result (list of tuples)
        try:
            first = ev[0]
            sig_ok = bool(first[0])
            md_ok = bool(first[1]) if len(first) > 1 else None
            chain_ok = bool(first[2]) if len(first) > 2 else None
            lines.append(f"- endesive: signature_valid={sig_ok}, messageDigest_ok={md_ok}, chain_trusted={chain_ok}")
        except Exception:
            lines.append('- endesive: could not interpret result tuple')
    except Exception as e:
        lines.append(f"- endesive.verify raised an exception: {e}")

    br = find_byte_range(data)
    if not br:
        lines.append('Không tìm thấy /ByteRange trong PDF (không có chữ ký hoặc format khác).')
        build_log(lines)
        print('\n'.join(lines))
        return 2
    lines.append(f'ByteRange: {br}')

    contents = extract_contents(data)
    if not contents:
        lines.append('Không trích được /Contents (PKCS#7) từ PDF.')
        build_log(lines)
        print('\n'.join(lines))
        return 3
    lines.append(f'PKCS#7 extracted: {len(contents)} bytes')

    signed_data_bytes = compute_hash_over_byterange(data, br)
    # compute digest according to PKCS7 signer digest algorithm (guess sha256)
    sha = hashlib.sha256(signed_data_bytes).digest()
    lines.append(f'Computed SHA-256 over ByteRange: {sha.hex()}')

    sd = parse_pkcs7(contents)
    if sd is None:
        lines.append('Không parse được PKCS#7 SignedData.')
        build_log(lines)
        print('\n'.join(lines))
        return 4

    # extract signature and signed attrs
    signer_info = sd['signer_infos'][0]
    signature_bytes = signer_info['signature'].native
    signed_attrs = signer_info['signed_attrs']
    signed_attrs_der = signed_attrs.dump()
    # diagnostic info
    try:
        sig_algo_name = signer_info['signature_algorithm']['algorithm'].native
    except Exception:
        sig_algo_name = 'unknown'
    try:
        digest_algo_name = signer_info['digest_algorithm']['algorithm'].native
    except Exception:
        digest_algo_name = 'unknown'
    lines.append(f'- Signature algorithm (from SignerInfo): {sig_algo_name}, digest: {digest_algo_name}')
    lines.append(f'- signature length: {len(signature_bytes)} bytes; signed_attrs DER length: {len(signed_attrs_der)}')

    # messageDigest check
    try:
        # messageDigest attribute value is raw bytes
        md_attr = None
        for a in signed_attrs:
            if a['type'].native == 'message_digest':
                md_attr = a['values'][0].native
                break
        if md_attr is None:
            lines.append('messageDigest attribute không tìm thấy trong signedAttrs.')
        else:
            if md_attr == sha:
                lines.append('- messageDigest: KHỚP')
            else:
                lines.append(f'- messageDigest: KHÔNG KHỚP (attr={md_attr.hex()}, calc={sha.hex()})')
    except Exception as e:
        lines.append(f'- messageDigest: lỗi kiểm tra: {e}')

    # get signer certificate (try to take first certificate in SignedData)
    cert = None
    try:
        certs = sd['certificates']
        if certs and len(certs) > 0:
            cert_choice = certs[0]
            cert_der = cert_choice.chosen.dump()
            cert = crypto_x509.load_der_x509_certificate(cert_der)
            lines.append('- Đã tách chứng chỉ signer từ PKCS#7')
        else:
            lines.append('- Không có chứng chỉ kèm theo trong PKCS#7')
    except Exception as e:
        lines.append(f'- Lỗi khi tách chứng chỉ: {e}')

    # Diagnostic: certificate details
    try:
        if cert is not None:
            subj = cert.subject.rfc4514_string()
            lines.append(f'- Signer cert subject: {subj}')
            pub = cert.public_key()
            if hasattr(pub, 'key_size'):
                lines.append(f'- Public key type: RSA, size: {pub.key_size} bits')
            else:
                lines.append(f'- Public key type: {type(pub)}')
    except Exception as e:
        lines.append(f'- Lỗi khi đọc thông tin cert: {e}')

    # If local PFX available, compare its cert public key to the one in PKCS#7
    local_match = False
    try:
        pfx_path = 'cert.pfx'
        if os.path.exists(pfx_path):
            from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
            pfx_data = open(pfx_path, 'rb').read()
            try:
                priv_local, cert_local, add_local = load_key_and_certificates(pfx_data, b'1234')
                if cert_local is not None:
                    lines.append(f'- Local PFX certificate subject: {cert_local.subject.rfc4514_string()}')
                    # compare public key numbers for RSA
                    local_pub = cert_local.public_key()
                    pk = cert.public_key()
                    if hasattr(local_pub, 'public_numbers') and hasattr(pk, 'public_numbers'):
                        ln = local_pub.public_numbers()
                        rn = pk.public_numbers()
                        if ln.n == rn.n and ln.e == rn.e:
                            lines.append('- Local PFX public key MATCHES signer cert in PDF (modulus/exponent equal).')
                            local_match = True
                        else:
                            lines.append('- Local PFX public key DOES NOT match signer cert in PDF (different modulus/exponent).')
            except Exception as e:
                lines.append(f'- Không thể load cert.pfx để so sánh: {e}')
    except Exception:
        pass

    # Use endesive.verify result as authoritative for signature/messageDigest
    try:
        ev = endesive_verify(data)
        try:
            ev_first = ev[0]
            sig_ok = bool(ev_first[0])
            md_ok = bool(ev_first[1]) if len(ev_first) > 1 else None
            chain_ok = bool(ev_first[2]) if len(ev_first) > 2 else None
            lines.append(f"- endesive summary: signature_valid={sig_ok}, messageDigest_ok={md_ok}, chain_trusted={chain_ok}")
        except Exception:
            lines.append(f"- endesive returned: {ev}")
            sig_ok = None
            md_ok = None
            chain_ok = None
    except Exception as e:
        lines.append(f"- endesive.verify failed: {e}")
        sig_ok = None
        md_ok = None
        chain_ok = None

    # If certvalidator is available, run chain + revocation checks using asn1crypto Certificate objects
    try:
        from certvalidator import CertificateValidator, ValidationContext
        lines.append('- certvalidator có sẵn: sẽ thử xác thực chuỗi và revocation (OCSP/CRL).')
        # sd['certificates'] contains asn1crypto CertificateChoices; use .chosen to get asn1crypto.x509.Certificate
        asn1_certs = [c.chosen for c in sd['certificates']]
        end_entity = asn1_certs[0]
        intermediates = asn1_certs[1:] if len(asn1_certs) > 1 else []
        # prepare ValidationContext; if user requested trusting local PFX, add it as trust root
        trust_roots = None
        if trust_local_pfx and os.path.exists('cert.pfx'):
            try:
                from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
                pfx_data = open('cert.pfx', 'rb').read()
                priv_local, cert_local, add_local = load_key_and_certificates(pfx_data, b'1234')
                if cert_local is not None:
                    der = cert_local.public_bytes(encoding=Encoding.DER)
                    # asn1crypto certificate
                    asn1_local = x509.Certificate.load(der)
                    trust_roots = [asn1_local]
                    lines.append('- Thêm cert.pfx vào trust_roots để xác thực chuỗi (--trust-local-pfx).')
            except Exception as e:
                lines.append(f'- Không thể load cert.pfx làm trust root: {e}')

        if trust_roots:
            context = ValidationContext(trust_roots=trust_roots)
        else:
            context = ValidationContext()

        validator = CertificateValidator(end_entity, intermediate_certs=intermediates, validation_context=context)
        valres = validator.validate_usage(set())
        lines.append(f"- certvalidator validation result: {valres}")
        # if certvalidator succeeded, set chain_ok True
        chain_ok = True
    except Exception as e:
        lines.append(f'- OCSP/CRL/timestamp: không thực hiện (certvalidator missing or failed): {e}')

    # basic chain check (best-effort)
    try:
        # attempt to extract certificates and build simple chain by issuer/subject
        if cert is not None and certs:
            # convert all certs
            cert_list = []
            for c in certs:
                der = c.chosen.dump()
                cert_list.append(crypto_x509.load_der_x509_certificate(der))
            lines.append(f'- Có {len(cert_list)} chứng chỉ đính kèm trong SignedData (bao gồm signer).')
            # naive chain: check if any cert is self-signed root
            roots = [c for c in cert_list if c.issuer == c.subject]
            if roots:
                lines.append(f"- Found {len(roots)} self-signed root candidate(s). Chain validation: BEST-EFFORT only.")
            else:
                lines.append('- Không tìm thấy root tự ký trong bundle; cần trusted root để xác thực đầy đủ.')
        else:
            lines.append('- Không có dữ liệu để kiểm tra chuỗi chứng chỉ.')
    except Exception as e:
        lines.append(f'- Lỗi khi kiểm tra chuỗi chứng chỉ (best-effort): {e}')

    # (removed duplicate certvalidator block — chain checks handled above)

    # check timestamp token in unsigned attributes
    try:
        unsigned = signer_info['unsigned_attrs']
        found_ts = False
        for a in unsigned:
            if a['type'].dotted == '1.2.840.113549.1.9.16.2.14':
                found_ts = True
                lines.append('- Timestamp token (RFC3161) có trong unsignedAttrs.')
                break
        if not found_ts:
            lines.append('- Không tìm thấy timestamp token trong unsignedAttrs.')
    except Exception:
        lines.append('- Không thể kiểm tra unsignedAttrs/timestamp token (không tồn tại).')

    # incremental update detection: check if file length equals sum of ranges + signature length
    total_ranges_len = br[1] + br[3]
    # incremental update detection: check if file length equals sum of ranges + signature length
    incremental_detected = (total_ranges_len + len(contents) != len(data))
    if incremental_detected:
        lines.append('- Phát hiện incremental updates hoặc dữ liệu đính kèm sau signature (file length != ByteRange sum + signature).')
    else:
        lines.append('- Không phát hiện incremental updates ngoài phần signature.')

    # Pretty summary with icons
    try:
        # status booleans (may be None)
        sig_status = sig_ok if 'sig_ok' in locals() else None
        md_status = md_ok if 'md_ok' in locals() else None
        chain_status = chain_ok if 'chain_ok' in locals() else None
        ts_status = None
        try:
            unsigned = signer_info.get('unsigned_attrs', None)
            if unsigned:
                for a in unsigned:
                    if a['type'].dotted == '1.2.840.113549.1.9.16.2.14':
                        ts_status = True
                        break
                if ts_status is None:
                    ts_status = False
        except Exception:
            ts_status = None

        inc_status = not incremental_detected

        lines.append('\n=== TÓM TẮT XÁC THỰC ===')
        lines.append(f"Chữ ký số: {icon_for(sig_status)}  (signature_valid)")
        lines.append(f"messageDigest: {icon_for(md_status)}")
        lines.append(f"Chuỗi chứng chỉ tin cậy: {icon_for(chain_status)}")
        lines.append(f"Timestamp token (RFC3161): {icon_for(ts_status)}")
        lines.append(f"Incremental updates (sau khi ký): {icon_for(not inc_status)}")
        lines.append(f"Khớp với cert.pfx cục bộ: {icon_for(local_match)}")

        # Compute human verdict
        verdict = 'KHÔNG HỢP LỆ'
        if sig_status:
            if chain_status:
                verdict = 'HỢP LỆ (signature và chuỗi chứng chỉ được tin cậy)'
            elif local_match:
                verdict = 'HỢP LỆ (signature OK; chuỗi không tin cậy nhưng khớp với cert.pfx cục bộ)'
            else:
                verdict = 'HỢP LỆ (signature OK; chuỗi chứng chỉ KHÔNG tin cậy)'
        lines.append(f"KẾT LUẬN TỔNG QUÁT: {icon_for(sig_status)} {verdict}")
    except Exception as e:
        lines.append(f'- Lỗi khi tạo summary: {e}')

    # finalize log
    build_log(lines)
    print('\n'.join(lines))
    print(f'Đã ghi nhật ký xác thực vào {LOG_FILE}')
    return 0


if __name__ == '__main__':
    args = sys.argv[1:]
    trust_local = False
    if '--trust-local-pfx' in args:
        trust_local = True
        args.remove('--trust-local-pfx')
    pdfpath = args[0] if len(args) > 0 else DEFAULT_PDF
    sys.exit(main(pdfpath, trust_local_pfx=trust_local))
