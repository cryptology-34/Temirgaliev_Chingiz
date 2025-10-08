# lfsr_encrypt.py

from typing import List


def lfsr_next(state: List[int], taps: List[int], direction: str = "right") -> int:
    """
    Выполнить один шаг LFSR:
    - state: текущее состояние регистра в виде списка битов
    - taps: список позиций (индексов), участвующих в XOR обратной связи
    - direction: "right" или "left" — направление сдвига
    Возвращает выходной бит и обновляет state.
    """
    xor_sum = 0
    for t in taps:
        xor_sum ^= state[t]

    if direction == "right":
        # выходной бит — правый (последний)
        output_bit = state[-1]
        new_state = [xor_sum] + state[:-1]
    elif direction == "left":
        # выходной бит — левый (первый)
        output_bit = state[0]
        new_state = state[1:] + [xor_sum]
    else:
        raise ValueError("direction должен быть 'right' или 'left'")

    state[:] = new_state
    return output_bit


def generate_keystream(initial_state: List[int], taps: List[int], length: int, direction: str = "right") -> List[int]:
    """Генерирует ключевой поток заданной длины."""
    state = initial_state.copy()
    stream = []
    for _ in range(length):
        out = lfsr_next(state, taps, direction)
        stream.append(out)
    return stream


def xor_bits_lists(a: List[int], b: List[int]) -> List[int]:
    return [x ^ y for x, y in zip(a, b)]


def binstr_to_bits(s: str) -> List[int]:
    if any(c not in '01' for c in s):
        raise ValueError("Строка должна содержать только 0/1")
    return [int(c) for c in s]


def bits_to_binstr(bits: List[int]) -> str:
    return ''.join(str(b) for b in bits)


def encrypt_lfsr(plaintext: str, initial_state_bits: str, taps: List[int], direction: str = "right") -> str:
    """
    Шифрует двоичную строку любой длины с помощью LFSR.
    """
    plaintext_bits = binstr_to_bits(plaintext)
    state = [int(c) for c in initial_state_bits]
    keystream = generate_keystream(state, taps, length=len(plaintext_bits), direction=direction)
    cipher_bits = xor_bits_lists(plaintext_bits, keystream)
    return bits_to_binstr(cipher_bits)


def decrypt_lfsr(ciphertext: str, initial_state_bits: str, taps: List[int], direction: str = "right") -> str:
    """Дешифрование — то же самое (XOR симметричен)."""
    return encrypt_lfsr(ciphertext, initial_state_bits, taps, direction)


if __name__ == "__main__":
    plaintext = input("Введите plaintext (строка из 0 и 1): ").strip()
    init_state = input("Введите начальное состояние LFSR: ").strip()
    taps_input = input("Введите тап-позиции через пробел (например '0 3 5'): ").strip()
    taps = [int(x) for x in taps_input.split()]
    direction = input("Введите направление (right/left): ").strip().lower()

    ciphertext = encrypt_lfsr(plaintext, init_state, taps, direction)
    print("Ciphertext:", ciphertext)
    decrypted = decrypt_lfsr(ciphertext, init_state, taps, direction)
    print("Decrypted :", decrypted)
