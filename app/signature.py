import hashlib
import json
import os
import time

from core.math_utils import power_mod
from pki.certificate import CertificateAuthority


def hash_file(file_path: str) -> int:
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Không tìm thấy tệp tin: {file_path}")

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return int(sha256.hexdigest(), 16)


def _resolve_certificate(cert_or_path) -> dict:
    if isinstance(cert_or_path, str):
        return CertificateAuthority.load_certificate(cert_or_path)
    if isinstance(cert_or_path, dict):
        return cert_or_path
    raise TypeError("Chứng thư phải là dict hoặc đường dẫn tới file .crt.")


def _resolve_public_key(key_or_cert) -> tuple:
    if isinstance(key_or_cert, (tuple, list)) and len(key_or_cert) == 2:
        return int(key_or_cert[0]), int(key_or_cert[1])
    cert_dict = _resolve_certificate(key_or_cert)
    return CertificateAuthority.extract_public_key(cert_dict)


def sign_document(
    file_path: str,
    private_key: tuple,
    output_sig_path: str,
    signer_name: str = "",
) -> dict:
    doc_hash = hash_file(file_path)
    d, n = int(private_key[0]), int(private_key[1])
    if doc_hash >= n:
        raise ValueError("Modulus n của khóa RSA phải lớn hơn mã băm SHA-256 (cần key_bits >= 256).")

    signature = power_mod(doc_hash, d, n)

    sig_payload = {
        "file_name": os.path.basename(file_path),
        "hash_algorithm": "SHA-256",
        "signed_at": int(time.time()),
        "signer": signer_name,
        "signature": str(signature),
    }

    parent_dir = os.path.dirname(output_sig_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(output_sig_path, "w", encoding="utf-8") as f:
        json.dump(sig_payload, f, indent=4, ensure_ascii=False)

    return sig_payload


def verify_signature_detailed(
    file_path: str,
    sig_path: str,
    signer_cert_or_key,
    ca_cert_or_key=None,
    check_cert_expiry: bool = True,
) -> tuple:
    try:
        if not os.path.isfile(file_path):
            return False, f"Không tìm thấy tài liệu cần xác thực: {file_path}"
        if not os.path.isfile(sig_path):
            return False, f"Không tìm thấy tệp chữ ký: {sig_path}"

        if not isinstance(signer_cert_or_key, (tuple, list)):
            signer_cert = _resolve_certificate(signer_cert_or_key)
            if ca_cert_or_key is not None:
                ca_pub_key = _resolve_public_key(ca_cert_or_key)
                cert_ok, cert_msg = CertificateAuthority.verify_certificate_detailed(
                    signer_cert, ca_pub_key, check_expiry=check_cert_expiry
                )
                if not cert_ok:
                    return False, f"Chứng thư người gửi không hợp lệ: {cert_msg}"
            user_public_key = CertificateAuthority.extract_public_key(signer_cert)
        else:
            user_public_key = _resolve_public_key(signer_cert_or_key)

        with open(sig_path, "r", encoding="utf-8") as f:
            sig_payload = json.load(f)
        signature = int(sig_payload["signature"])

        current_hash = hash_file(file_path)

        e, n = user_public_key
        decrypted_hash = power_mod(signature, e, n)

        if current_hash == decrypted_hash:
            return True, "Chữ ký hợp lệ - Tài liệu toàn vẹn và chính chủ."
        return False, "Chữ ký không hợp lệ - Tài liệu đã bị chỉnh sửa hoặc chữ ký giả mạo."
    except Exception as err:
        return False, f"Lỗi trong quá trình xác thực chữ ký: {err}"


def verify_signature(
    file_path: str,
    sig_path: str,
    signer_cert_or_key,
    ca_cert_or_key=None,
    check_cert_expiry: bool = True,
) -> bool:
    is_valid, _ = verify_signature_detailed(
        file_path,
        sig_path,
        signer_cert_or_key,
        ca_cert_or_key=ca_cert_or_key,
        check_cert_expiry=check_cert_expiry,
    )
    return is_valid
