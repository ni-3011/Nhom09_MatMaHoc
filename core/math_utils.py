import random

# Thuật toán lũy thừa nhanh (Square-and-Multiply) để tối ưu tính toán số mũ lớn
def power_mod(base, exp, mod):
    res = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    return res

# Thuật toán kiểm tra số nguyên tố xác suất Miller-Rabin dùng cho sinh số nguyên tố lớn
def miller_rabin(n, k=5):
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = power_mod(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = power_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Hàm sinh số nguyên tố lớn ngẫu nhiên dựa trên số bit cấu hình
def generate_large_prime(bits=256):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if miller_rabin(num):
            return num

# Thuật toán Euclid mở rộng tìm ước chung lớn nhất và hệ số Bezout (gcd, x, y)
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# Hàm tìm nghịch đảo modulo d của e trong trường hợp d * e ≡ 1 (mod phi)
def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Nghịch đảo modulo không tồn tại (e và phi không nguyên tố cùng nhau)")
    else:
        return (x % phi + phi) % phi