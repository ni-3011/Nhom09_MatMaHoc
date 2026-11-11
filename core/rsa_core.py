from core.math_utils import generate_large_prime, extended_gcd, mod_inverse, power_mod

class RSACore:
    
    # Hàm sinh cặp khóa công khai và khóa bí mật tự động với độ dài bit tùy chọn
    @staticmethod
    def generate_keys(bits=256):
        p = generate_large_prime(bits)
        q = generate_large_prime(bits)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 65537  
        while extended_gcd(e, phi)[0] != 1:
            e += 2
            
        d = mod_inverse(e, phi)
        return {"public_key": (e, n), "private_key": (d, n)}

    # Hàm mã hóa số nguyên đơn lẻ theo công thức c = m^e mod n
    @staticmethod
    def encrypt(message_int, public_key):
        e, n = public_key
        return power_mod(message_int, e, n)

    # Hàm giải mã số nguyên đơn lẻ theo công thức m = c^d mod n
    @staticmethod
    def decrypt(cipher_int, private_key):
        d, n = private_key
        return power_mod(cipher_int, d, n)

    # Hàm phụ trợ: Chuyển đổi chuỗi văn bản string thành một số nguyên lớn dạng bytes
    @staticmethod
    def text_to_int(text):
        byte_data = text.encode('utf-8')
        return int.from_bytes(byte_data, byteorder='big')

    # Hàm phụ trợ: Dịch ngược số nguyên sau khi giải mã trở lại thành chuỗi văn bản
    @staticmethod
    def int_to_text(number):
        try:
            byte_length = (number.bit_length() + 7) // 8
            byte_data = number.to_bytes(byte_length, byteorder='big')
            return byte_data.decode('utf-8')
        except Exception:
            return "[Lỗi: Không thể chuyển đổi dữ liệu giải mã sang văn bản]"
        
    # Hàm tạo khóa thủ công khi người dùng tự nhập p, q và e từ bàn phím
    @staticmethod
    def manual_generate_keys(p, q, e=65537):
        n = p * q
        phi = (p - 1) * (q - 1)
        
        gcd, x, _ = extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError(f"Khóa e={e} không nguyên tố cùng nhau với phi(n)={phi}!")
            
        d = mod_inverse(e, phi)
        return {"public_key": (e, n), "private_key": (d, n)}
    
    # Hàm thủ công thông minh: Chỉ cần nhập p, q, hệ thống tự động tính n, phi và chọn e phù hợp
    @staticmethod
    def manual_generate_from_primes(p, q):
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 65537
        if extended_gcd(e, phi)[0] != 1:
            e = 17
            if extended_gcd(e, phi)[0] != 1:
                e = 3 
                
        d = mod_inverse(e, phi)
        return {"public_key": (e, n), "private_key": (d, n), "phi": phi}