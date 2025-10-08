def xor_bits(a: str, b: str) -> str:
    """Побитовое XOR для строк"""
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))

# S-box (прямой)
sbox = {
    "00": "10",
    "01": "00",
    "10": "11",
    "11": "01"
}

# Обратный S-box (для расшифровки)
inv_sbox = {v: k for k, v in sbox.items()}

def substitute(bits: str) -> str:
    """Прямое S-box (по 2 бита)"""
    return ''.join(sbox[bits[i:i+2]] for i in range(0, len(bits), 2))

def inv_substitute(bits: str) -> str:
    """Обратное S-box"""
    return ''.join(inv_sbox[bits[i:i+2]] for i in range(0, len(bits), 2))

def permute(bits: str) -> str:
    """Прямое переставление: (1→3, 2→1, 3→2, 4→4) применяется к каждой половине"""
    mapping = [2, 0, 1, 3]
    left, right = bits[:4], bits[4:]
    left_p = ''.join(left[i] for i in mapping)
    right_p = ''.join(right[i] for i in mapping)
    return left_p + right_p

def inv_permute(bits: str) -> str:
    """Обратное переставление"""
    mapping = [1, 2, 0, 3]
    left, right = bits[:4], bits[4:]
    left_p = ''.join(left[i] for i in mapping)
    right_p = ''.join(right[i] for i in mapping)
    return left_p + right_p

def round_encrypt(pt: str, key: str) -> str:
    """Один раунд шифрования (8 бит)"""
    step1 = xor_bits(pt, key)       # XOR
    step2 = substitute(step1)       # S-box
    step3 = permute(step2)          # Перестановка
    return step3

def round_decrypt(ct: str, key: str) -> str:
    """Один раунд расшифровки (8 бит)"""
    step1 = inv_permute(ct)
    step2 = inv_substitute(step1)
    step3 = xor_bits(step2, key)
    return step3

# --- Данные ---
pt = "01101101"   # 8-битное сообщение
key = "10101100"  # 8-битный ключ

# Ключи по 4 бита
k1 = key[:4] + key[:4]   
k2 = key[4:] + key[4:]

print("Исходное сообщение (pt):", pt)
print("Исходный ключ (key):     ", key)

# --- Шифрование ---
r1 = round_encrypt(pt, k1)
r2 = round_encrypt(r1, k2)
ciphertext = r2
print("Зашифрованное сообщение:", ciphertext)

# --- Расшифровка ---
d1 = round_decrypt(ciphertext, k2)
d2 = round_decrypt(d1, k1)
decrypted = d2
print("Расшифрованное сообщение:", decrypted)