# src/protocol.py
import json
import base64
import time

def json_encode(obj: dict) -> bytes:
    return json.dumps(obj).encode("utf-8")

def json_decode(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))

def make_hello(cert_pem_b64: str, nonce_b64: str) -> dict:
    return {"type": "hello", "client_cert": cert_pem_b64, "nonce": nonce_b64}

def make_server_hello(cert_pem_b64: str, nonce_b64: str) -> dict:
    return {"type": "server hello", "server_cert": cert_pem_b64, "nonce": nonce_b64}

def make_dh_client(g: int, p: int, A: int) -> dict:
    return {"type": "dh_client", "g": g, "p": p, "A": A}

def make_dh_server(B: int) -> dict:
    return {"type": "dh_server", "B": B}

def make_register(email: str, username: str, pwd_hash_b64: str, salt_b64: str) -> dict:
    return {"type": "register", "email": email, "username": username, "pwd": pwd_hash_b64, "salt": salt_b64}

def make_login(email: str, pwd_hash_b64: str, nonce_b64: str) -> dict:
    return {"type": "login", "email": email, "pwd": pwd_hash_b64, "nonce": nonce_b64}

def make_msg(seqno: int, ct_b64: str, sig_b64: str) -> dict:
    return {"type": "msg", "seqno": seqno, "ts": int(time.time() * 1000), "ct": ct_b64, "sig": sig_b64}

def make_receipt(peer: str, first_seq: int, last_seq: int, transcript_sha256_hex: str, sig_b64: str) -> dict:
    return {"type": "receipt", "peer": peer, "first_seq": first_seq, "last_seq": last_seq, "transcript_sha256": transcript_sha256_hex, "sig": sig_b64}
