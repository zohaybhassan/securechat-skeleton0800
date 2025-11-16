# src/dh.py
import secrets
import hashlib

# Safe-ish baseline parameters (for classroom demo)
# Use a large prime 'p' (here 2048-bit could be used; for brevity we use smaller)
# In production, use established groups; here it's basic DH per assignment.
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16
)
DEFAULT_G = 2

def generate_private_exponent(bits: int = 256) -> int:
    return secrets.randbits(bits)

def compute_public(g: int, p: int, a: int) -> int:
    return pow(g, a, p)

def compute_shared(peer_public: int, p: int, a: int) -> int:
    return pow(peer_public, a, p)

def derive_aes_key_from_shared(Ks: int) -> bytes:
    # K = Trunc16(SHA256(big-endian(Ks)))
    Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, byteorder="big")
    h = hashlib.sha256(Ks_bytes).digest()
    return h[:16]
