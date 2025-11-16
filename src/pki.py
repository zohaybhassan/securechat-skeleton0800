# src/pki.py
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
import datetime

def load_cert(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def verify_cert_chain(peer_cert_pem: bytes, ca_cert_pem: bytes, expected_cn: str) -> bool:
    try:
        peer = x509.load_pem_x509_certificate(peer_cert_pem)
        ca = x509.load_pem_x509_certificate(ca_cert_pem)

        # Check validity period
        now = datetime.datetime.utcnow()
        if not (peer.not_valid_before <= now <= peer.not_valid_after):
            return False

        # Check issuer matches CA subject
        if peer.issuer != ca.subject:
            return False

        # Check CN
        common_names = peer.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not common_names or common_names[0].value != expected_cn:
            return False

        # Signature verification (basic)
        ca_pub = ca.public_key()
        ca_pub.verify(peer.signature, peer.tbs_certificate_bytes, peer.signature_hash_algorithm)
        return True
    except Exception:
        return False
