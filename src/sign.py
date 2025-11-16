# src/sign.py
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

def rsa_sign_sha256(private_key_pem: bytes, data: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    sig = key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return sig

def rsa_verify_sha256(cert_pem: bytes, data: bytes, signature: bytes) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem)
    pub = cert.public_key()
    try:
        pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
