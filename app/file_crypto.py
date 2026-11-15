import os
import json
from core.rsa_core import RSACore
from pki.certificate import CertificateAuthority


SUPPORTED_EXTENSIONS = ('.txt', '.pdf', '.png')


def _resolve_certificate(cert_or_path) -> dict:
    if isinstance(cert_or_path, str):
        return CertificateAuthority.load_certificate(cert_or_path)
    if isinstance(cert_or_path, dict):
        return cert_or_path
    raise TypeError("Chứng thư phải là dict hoặc đường dẫn tới tệp .crt hợp lệ.")


def _resolve_public_key(key_or_cert) -> tuple:
    if isinstance(key_or_cert, (tuple, list)) and len(key_or_cert) == 2:
        return int(key_or_cert[0]), int(key_or_cert[1])
    cert_dict = _resolve_certificate(key_or_cert)
    return CertificateAuthority.extract_public_key(cert_dict)


def _get_block_size(n: int) -> int:
   
    key_byte_length = (n.bit_length() + 7) // 8
    return max(1, key_byte_length - 1)


def encrypt_file(
    input_filepath: str,
    recipient_cert_or_key,
    output_filepath: str = None,
    ca_cert_or_key=None,
    check_cert_expiry: bool = True
) -> str:
    
    if not os.path.isfile(input_filepath):
        raise FileNotFoundError(f"Không tìm thấy tệp tin đầu vào: {input_filepath}")

    _, ext = os.path.splitext(input_filepath)
    if ext.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Định dạng tệp không được hỗ trợ ({ext}). Chỉ hỗ trợ các định dạng: {SUPPORTED_EXTENSIONS}")

   
    if not isinstance(recipient_cert_or_key, (tuple, list)):
        recipient_cert = _resolve_certificate(recipient_cert_or_key)
        if ca_cert_or_key is not None:
            ca_pub_key = _resolve_public_key(ca_cert_or_key)
            cert_ok, cert_msg = CertificateAuthority.verify_certificate_detailed(
                recipient_cert, ca_pub_key, check_expiry=check_cert_expiry
            )
            if not cert_ok:
                raise ValueError(f"Chứng thư người nhận không hợp lệ: {cert_msg}")
        e, n = CertificateAuthority.extract_public_key(recipient_cert)
        recipient_name = recipient_cert["tbs_certificate"].get("subject", "Unknown")
    else:
        e, n = int(recipient_cert_or_key[0]), int(recipient_cert_or_key[1])
        recipient_name = "Direct_Key"

   
    block_size = _get_block_size(n)

   
    with open(input_filepath, "rb") as f:
        raw_data = f.read()

    
    encrypted_blocks = []
    for i in range(0, len(raw_data), block_size):
        chunk = raw_data[i:i + block_size]
        m_int = int.from_bytes(chunk, byteorder="big")
        
        if m_int >= n:
            raise ValueError("Dữ liệu khối lớn hơn modulo n. Hãy tăng độ dài bit của khóa (key_bits).")
            
        c_int = RSACore.encrypt(m_int, (e, n))
        encrypted_blocks.append(str(c_int))

   
    if output_filepath is None:
        output_filepath = input_filepath + ".enc"

    package = {
        "original_filename": os.path.basename(input_filepath),
        "extension": ext.lower(),
        "original_size": len(raw_data),
        "block_size": block_size,
        "recipient": recipient_name,
        "cipher_blocks": encrypted_blocks
    }

    parent_dir = os.path.dirname(output_filepath)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    with open(output_filepath, "w", encoding="utf-8") as f:
        json.dump(package, f, indent=4, ensure_ascii=False)

    return output_filepath


def decrypt_file(
    enc_filepath: str,
    private_key: tuple,
    output_dir: str = None
) -> str:
    
    if not os.path.isfile(enc_filepath):
        raise FileNotFoundError(f"Không tìm thấy tệp mã hóa: {enc_filepath}")

    with open(enc_filepath, "r", encoding="utf-8") as f:
        package = json.load(f)

    d, n = int(private_key[0]), int(private_key[1])
    block_size = package["block_size"]
    original_size = package["original_size"]
    cipher_blocks = package["cipher_blocks"]

    decrypted_bytes = bytearray()
    total_blocks = len(cipher_blocks)

    for idx, str_block in enumerate(cipher_blocks):
        c_int = int(str_block)
        m_int = RSACore.decrypt(c_int, (d, n))

       
        if idx == total_blocks - 1:
            chunk_len = original_size - len(decrypted_bytes)
        else:
            chunk_len = block_size

        chunk = m_int.to_bytes(chunk_len, byteorder="big")
        decrypted_bytes.extend(chunk)

   
    if output_dir is None:
        output_dir = os.path.dirname(enc_filepath) or "."
    else:
        os.makedirs(output_dir, exist_ok=True)

    restored_name = "decrypted_" + package["original_filename"]
    output_filepath = os.path.join(output_dir, restored_name)

    with open(output_filepath, "wb") as f:
        f.write(decrypted_bytes)

    return output_filepath
