#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sha256_no_lib.py
Реализация SHA-256 без использования крипто-библиотек.
Включает:
 - функция pad_message(message_bytes)
 - функция sha256(message_bytes) -> bytes(32)
 - простой tkinter GUI: выбор "Хешировать" / "Дешифровать"
   (дешифрование недоступно — показывается пояснение)
"""

import struct
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext

# ---- Константы SHA-256 (first 32 bits of the fractional parts of the cube roots of the first 64 primes) ----
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# ---- Вспомогательные функции ----
def _rotr(x, n):
    """Right rotate 32-bit value x by n bits."""
    return ((x >> n) | ((x << (32 - n)) & 0xffffffff)) & 0xffffffff

def _shr(x, n):
    """Logical right shift (for positive ints behaves same as >>)."""
    return (x >> n) & 0xffffffff

# ---- Padding: по стандарту SHA-256 ----
def pad_message(message_bytes: bytes) -> bytes:
    """
    Возвращает сообщение, дополненное до кратности 512 бит (64 байта)
    following SHA-256 rules:
      - append 0x80 (one '1' bit then seven '0' bits)
      - append zero bytes until length_in_bits ≡ 448 (mod 512)
      - append 64-bit big-endian original length (in bits)
    """
    original_bit_len = len(message_bytes) * 8
    # Add 0x80
    padded = message_bytes + b'\x80'
    # Add zero bytes until (len(padded) * 8) mod 512 == 448
    # i.e., len(padded) mod 64 == 56
    while (len(padded) % 64) != 56:
        padded += b'\x00'
    # Append 64-bit big-endian length
    padded += struct.pack('>Q', original_bit_len)
    return padded

# ---- Core SHA-256 ----
def sha256(message_bytes: bytes) -> bytes:
    """
    Compute SHA-256 digest of message_bytes (returns 32-byte digest).
    """
    # Initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
    h0 = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ]

    padded = pad_message(message_bytes)
    # Process each 512-bit chunk
    for chunk_start in range(0, len(padded), 64):
        chunk = padded[chunk_start:chunk_start+64]
        # Prepare message schedule w[0..63]
        w = list(struct.unpack('>16I', chunk))  # w0..w15
        # Extend to w16..w63
        for i in range(16, 64):
            s0 = (_rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ _shr(w[i-15], 3)) & 0xffffffff
            s1 = (_rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ _shr(w[i-2], 10)) & 0xffffffff
            new_w = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
            w.append(new_w)

        a, b, c, d, e, f, g, h = h0

        # Main compression
        for i in range(64):
            S1 = (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) & 0xffffffff
            ch = ((e & f) ^ ((~e) & g)) & 0xffffffff
            temp1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffff
            S0 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) & 0xffffffff
            maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xffffffff
            temp2 = (S0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        # Add this chunk's hash to result so far:
        h0 = [
            (h0[0] + a) & 0xffffffff,
            (h0[1] + b) & 0xffffffff,
            (h0[2] + c) & 0xffffffff,
            (h0[3] + d) & 0xffffffff,
            (h0[4] + e) & 0xffffffff,
            (h0[5] + f) & 0xffffffff,
            (h0[6] + g) & 0xffffffff,
            (h0[7] + h) & 0xffffffff,
        ]

    # Produce final digest (big-endian)
    digest = b''.join(struct.pack('>I', part) for part in h0)
    return digest

def hexdigest(message_bytes: bytes) -> str:
    return sha256(message_bytes).hex()

# ---- Простое GUI-диалоговое окно с tkinter ----
def gui_main():
    root = tk.Tk()
    root.title("SHA-256 (без библиотек)")

    # Instruction text
    tk.Label(root, text="Выберите действие:").pack(pady=(8,0))

    action = tk.StringVar(value="hash")

    frame = tk.Frame(root)
    frame.pack(pady=6)

    tk.Radiobutton(frame, text="Хешировать", variable=action, value="hash").pack(side=tk.LEFT, padx=6)
    tk.Radiobutton(frame, text="Дешифровать (недоступно)", variable=action, value="decrypt").pack(side=tk.LEFT, padx=6)

    def do_action():
        if action.get() == "hash":
            # Ask for input string
            s = simpledialog.askstring("Ввод", "Введите строку для хеширования (UTF-8):", parent=root)
            if s is None:
                return
            data = s.encode('utf-8')
            result = hexdigest(data)
            # Show result in scrollable text
            out = scrolledtext.ScrolledText(root, width=70, height=6)
            out.insert(tk.END, f"Вход (UTF-8): {s}\n")
            out.insert(tk.END, f"Длина (байт): {len(data)}\n")
            out.insert(tk.END, f"SHA-256 (hex): {result}\n")
            out.configure(state='disabled')
            out.pack(pady=6)
        else:
            # Decrypt chosen -> show explanation
            messagebox.showinfo("Невозможно", "SHA-256 — это необратимая хэш-функция. Дешифровка исходных данных по хэшу невозможна.")

    btn = tk.Button(root, text="Выполнить", command=do_action)
    btn.pack(pady=(4,10))

    # Minimal usage tip
    tk.Label(root, text="Примечание: хэш — необратим. 'Дешифровать' недоступно.").pack(pady=(0,10))

    root.mainloop()

# ---- Если запущен как скрипт ----
if __name__ == "__main__":
    gui_main()
