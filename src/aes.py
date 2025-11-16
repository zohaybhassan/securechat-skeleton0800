# src/aes.py
import base64
from Crypto.Cipher import AES

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(padded: bytes) -> bytes:
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS#7 padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return padded[:-pad_len]

def aes_encrypt_block(key16: bytes, plaintext: bytes) -> bytes:
    # AES-128 ECB for simplicity (assignment says block only, no modes)
    cipher = AES.new(key16, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(plaintext, 16))

def aes_decrypt_block(key16: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key16, AES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded)
