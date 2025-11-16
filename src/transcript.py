# src/transcript.py
import hashlib
import base64
import os

class Transcript:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write("")

    def append(self, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_fpr: str):
        line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fpr}\n"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)

    def compute_hash_hex(self) -> str:
        h = hashlib.sha256()
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                h.update(line.encode("utf-8"))
        return h.hexdigest()

def cert_fingerprint_sha256(cert_pem: bytes) -> str:
    # Simple fingerprint over DER
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(encoding=x509.Encoding.DER)
    import hashlib
    return hashlib.sha256(der).hexdigest()
