import hashlib
import json
import os
import secrets
import time

from core.math_utils import power_mod
from core.rsa_core import RSACore


def hash_data(data_str: str) -> int:
    hex_digest = hashlib.sha256(data_str.encode("utf-8")).hexdigest()
    return int(hex_digest, 16)


def _serialize_tbs(tbs_certificate: dict) -> str:
    return json.dumps(tbs_certificate, sort_keys=True)


def _save_json(data: dict, file_path: str):
    parent_dir = os.path.dirname(file_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def _load_json(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


class CertificateAuthority:
    def __init__(self, ca_name: str = "Nhom09_Root_CA", key_bits: int = 256):
        self.ca_name = ca_name
        self.key_bits = key_bits
        self.public_key = None
        self.private_key = None
        self.ca_certificate = None

    def set_keys(self, public_key: tuple, private_key: tuple, ca_certificate: dict = None):
        self.public_key = (int(public_key[0]), int(public_key[1]))
        self.private_key = (int(private_key[0]), int(private_key[1]))
        self.ca_certificate = ca_certificate

    def initialize_ca(self, validity_days: int = 3650) -> dict:
        keys = RSACore.generate_keys(bits=self.key_bits)
        self.public_key = keys["public_key"]
        self.private_key = keys["private_key"]
        self.ca_certificate = self.issue_certificate(
            subject_name=self.ca_name,
            user_public_key=self.public_key,
            validity_days=validity_days,
            is_ca=True,
        )
        return self.ca_certificate

    @staticmethod
    def create_csr(
        subject_name: str,
        user_public_key: tuple,
        email: str = "",
        organization: str = "",
    ) -> dict:
        return {
            "version": 1,
            "subject": subject_name,
            "email": email,
            "organization": organization,
            "public_key": {
                "e": str(user_public_key[0]),
                "n": str(user_public_key[1]),
            },
            "created_at": int(time.time()),
        }

    def issue_certificate(
        self,
        subject_name: str,
        user_public_key: tuple,
        validity_days: int = 365,
        email: str = "",
        organization: str = "",
        is_ca: bool = False,
    ) -> dict:
        if not self.private_key:
            raise ValueError("Root CA chưa có khóa bí mật. Hãy gọi initialize_ca() hoặc set_keys() trước.")

        now = int(time.time())
        tbs_certificate = {
            "version": "X509-Mini-v1",
            "serial_number": secrets.token_hex(8).upper(),
            "issuer": self.ca_name,
            "subject": subject_name,
            "email": email,
            "organization": organization,
            "is_ca": is_ca,
            "public_key": {
                "e": str(user_public_key[0]),
                "n": str(user_public_key[1]),
            },
            "valid_from": now,
            "valid_to": now + (validity_days * 86400),
            "signature_algorithm": "SHA256-RSA",
        }

        cert_hash = hash_data(_serialize_tbs(tbs_certificate))
        d, n = self.private_key
        if cert_hash >= n:
            raise ValueError("Modulus n của CA phải lớn hơn mã băm SHA-256 (hãy dùng key_bits >= 256).")

        signature = power_mod(cert_hash, d, n)

        return {
            "tbs_certificate": tbs_certificate,
            "signature": str(signature),
        }

    def issue_certificate_from_csr(self, csr_dict: dict, validity_days: int = 365) -> dict:
        pk = csr_dict["public_key"]
        user_public_key = (int(pk["e"]), int(pk["n"]))
        return self.issue_certificate(
            subject_name=csr_dict["subject"],
            user_public_key=user_public_key,
            validity_days=validity_days,
            email=csr_dict.get("email", ""),
            organization=csr_dict.get("organization", ""),
            is_ca=False,
        )

    @staticmethod
    def extract_public_key(cert_dict: dict) -> tuple:
        pk = cert_dict["tbs_certificate"]["public_key"]
        return int(pk["e"]), int(pk["n"])

    @staticmethod
    def verify_certificate_detailed(
        cert_dict: dict,
        ca_public_key: tuple,
        check_expiry: bool = True,
    ) -> tuple:
        try:
            tbs = cert_dict["tbs_certificate"]
            signature = int(cert_dict["signature"])

            if check_expiry:
                now = int(time.time())
                if now < int(tbs["valid_from"]):
                    return False, "Chứng thư số chưa đến thời gian có hiệu lực."
                if now > int(tbs["valid_to"]):
                    return False, "Chứng thư số đã hết hạn sử dụng."

            expected_hash = hash_data(_serialize_tbs(tbs))
            e, n = int(ca_public_key[0]), int(ca_public_key[1])
            decrypted_hash = power_mod(signature, e, n)

            if expected_hash != decrypted_hash:
                return False, "Chữ ký CA không khớp - Chứng thư có dấu hiệu bị chỉnh sửa hoặc giả mạo."

            return True, f"Chứng thư của '{tbs['subject']}' hợp lệ và đáng tin cậy."
        except Exception as err:
            return False, f"Lỗi cấu trúc chứng thư số: {err}"

    @staticmethod
    def verify_certificate(
        cert_dict: dict,
        ca_public_key: tuple,
        check_expiry: bool = True,
    ) -> bool:
        is_valid, _ = CertificateAuthority.verify_certificate_detailed(
            cert_dict, ca_public_key, check_expiry=check_expiry
        )
        return is_valid

    @staticmethod
    def save_certificate(cert_dict: dict, file_path: str):
        _save_json(cert_dict, file_path)

    @staticmethod
    def load_certificate(file_path: str) -> dict:
        return _load_json(file_path)

    @staticmethod
    def save_csr(csr_dict: dict, file_path: str):
        _save_json(csr_dict, file_path)

    @staticmethod
    def load_csr(file_path: str) -> dict:
        return _load_json(file_path)

    @staticmethod
    def save_private_key(private_key: tuple, file_path: str):
        payload = {"d": str(private_key[0]), "n": str(private_key[1])}
        _save_json(payload, file_path)

    @staticmethod
    def load_private_key(file_path: str) -> tuple:
        payload = _load_json(file_path)
        return int(payload["d"]), int(payload["n"])
