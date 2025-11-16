# scripts/gen_cert.py
import os
import sys
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = "certs"

def load_ca():
    with open(os.path.join(CERTS_DIR, "root_ca_key.pem"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(CERTS_DIR, "root_ca_cert.pem"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

def issue_cert(common_name: str, out_key_path: str, out_cert_path: str):
    ca_key, ca_cert = load_ca()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    with open(out_key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(out_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Issued key: {out_key_path}")
    print(f"Issued cert: {out_cert_path}")

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("server", "client"):
        print("Usage: python scripts/gen_cert.py [server|client]")
        sys.exit(1)
    role = sys.argv[1]
    os.makedirs(CERTS_DIR, exist_ok=True)
    if role == "server":
        issue_cert("securechat-server", os.path.join(CERTS_DIR, "server_key.pem"), os.path.join(CERTS_DIR, "server_cert.pem"))
    else:
        issue_cert("securechat-client", os.path.join(CERTS_DIR, "client_key.pem"), os.path.join(CERTS_DIR, "client_cert.pem"))

if __name__ == "__main__":
    main()
