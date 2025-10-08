def F(part: int, key: int) -> int:
    """Простая функция F: XOR с ключом и циклический сдвиг влево на 1 бит."""
    x = part ^ key
    # ограничиваем 8 битами для наглядности
    return ((x << 1) & 0xFF) | (x >> 7)


def feistel_round(left: int, right: int, key: int) -> tuple[int, int]:
    """Один раунд сети Фейстеля."""
    new_left = right
    new_right = left ^ F(right, key)
    return new_left, new_right


def feistel_encrypt(block: int, keys: list[int], rounds: int = None) -> int:
    """Шифрование блока (16 бит)."""
    if rounds is None:
        rounds = len(keys)
    # делим блок на левую и правую половины по 8 бит
    left = (block >> 8) & 0xFF
    right = block & 0xFF

    for i in range(rounds):
        left, right = feistel_round(left, right, keys[i])

    # объединяем обратно
    return (left << 8) | right


def feistel_decrypt(block: int, keys: list[int], rounds: int = None) -> int:
    """Дешифрование блока (16 бит)."""
    if rounds is None:
        rounds = len(keys)
    left = (block >> 8) & 0xFF
    right = block & 0xFF

    # ключи идут в обратном порядке
    for i in reversed(range(rounds)):
        left, right = feistel_round(left, right, keys[i])

    return (left << 8) | right


# Пример использования
if __name__ == "__main__":
    keys = [0x0F, 0x36, 0xA7, 0x55]  # список ключей для раундов
    plaintext = 0x1234               # пример блока (16 бит)

    encrypted = feistel_encrypt(plaintext, keys)
    decrypted = feistel_decrypt(encrypted, keys)

    print(f"Открытый текст: {bin(plaintext)}")
    print(f"Зашифрованный: {bin(encrypted)}")
    print(f"Расшифрованный: {bin(decrypted)}")
