# src/client.py
import socket
import base64
import os
import hashlib
import struct
from dotenv import load_dotenv
from src.pki import load_cert, load_key, verify_cert_chain
from src.protocol import *
from src.dh import DEFAULT_P, DEFAULT_G, generate_private_exponent, compute_public, compute_shared, derive_aes_key_from_shared
from src.aes import aes_encrypt_block, aes_decrypt_block
from src.sign import rsa_sign_sha256, rsa_verify_sha256
from src.transcript import Transcript, cert_fingerprint_sha256

load_dotenv()

HOST = "127.0.0.1"
PORT = 5555

CA_CERT = load_cert(os.getenv("CA_CERT_PATH"))
CLIENT_CERT = load_cert(os.getenv("CLIENT_CERT_PATH"))
CLIENT_KEY = load_key(os.getenv("CLIENT_KEY_PATH"))
SERVER_EXPECTED_CN = "securechat-server"

def recv_json(conn):
    size_b = conn.recv(4)
    if not size_b:
        return None
    size = int.from_bytes(size_b, "big")
    data = conn.recv(size)
    return json_decode(data)

def send_json(conn, obj):
    data = json_encode(obj)
    conn.sendall(len(data).to_bytes(4, "big"))
    conn.sendall(data)

def do_register_login(conn, mode: str, email: str, username: str, password: str):
    # 1) Send hello
    nonce = os.urandom(16)
    send_json(conn, make_hello(base64.b64encode(CLIENT_CERT).decode(), base64.b64encode(nonce).decode()))

    # 2) Receive server hello & verify server cert
    sh = recv_json(conn)
    if not sh or sh.get("type") != "server hello":
        raise RuntimeError("BAD_SERVER_HELLO")
    server_cert_pem = base64.b64decode(sh["server_cert"])
    if not verify_cert_chain(server_cert_pem, CA_CERT, expected_cn=SERVER_EXPECTED_CN):
        raise RuntimeError("BAD_CERT: server untrusted/expired")

    # 3) Temporary DH for auth plane
    # Receive server's acceptance of DH (as client we initiate)
    a = generate_private_exponent()
    A = compute_public(DEFAULT_G, DEFAULT_P, a)
    send_json(conn, make_dh_client(DEFAULT_G, DEFAULT_P, A))
    dh_server = recv_json(conn)
    if not dh_server or dh_server.get("type") != "dh_server":
        raise RuntimeError("DH_FAIL")
    B = dh_server["B"]
    Ks = compute_shared(B, DEFAULT_P, a)
    temp_key = derive_aes_key_from_shared(Ks)

    # 4) Prepare credentials
    # Generate salt for registration; for login, fetch salt from server ideally; assignment keeps salt client-provided on register.
    if mode == "register":
        salt = os.urandom(16)
        pwd_hash_hex = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
        req = make_register(
            email=email,
            username=username,
            pwd_hash_b64=base64.b64encode(bytes.fromhex(pwd_hash_hex)).decode(),
            salt_b64=base64.b64encode(salt).decode(),
        )
    else:
        # For login, user provides email; server will lookup salt and compare hash.
        # The assignment format sends base64(sha256(salt||pwd)); here you must know your salt.
        # For demo, we assume you know salt (e.g., stored locally after register). In a real system, server would send salt.
        # We'll prompt for salt hex if not present.
        salt_hex = input("Enter your salt (hex from registration): ").strip()
        salt = bytes.fromhex(salt_hex)
        pwd_hash_hex = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
        req = make_login(
            email=email,
            pwd_hash_b64=base64.b64encode(bytes.fromhex(pwd_hash_hex)).decode(),
            nonce_b64=base64.b64encode(os.urandom(16)).decode()
        )

    # Send auth request
    send_json(conn, req)
    auth_ok = recv_json(conn)
    if not auth_ok or auth_ok.get("type") != "auth_ok":
        raise RuntimeError(f"AUTH_FAIL: {auth_ok}")

    print(f"[*] Auth OK mode={auth_ok.get('mode')}")

    # 5) Post-auth DH for chat key
    a2 = generate_private_exponent()
    A2 = compute_public(DEFAULT_G, DEFAULT_P, a2)
    send_json(conn, make_dh_client(DEFAULT_G, DEFAULT_P, A2))
    dh2 = recv_json(conn)
    if not dh2 or dh2.get("type") != "dh_server":
        raise RuntimeError("DH_FAIL")
    B2 = dh2["B"]
    Ks2 = compute_shared(B2, DEFAULT_P, a2)
    chat_key = derive_aes_key_from_shared(Ks2)

    # 6) Chat loop
    transcript = Transcript("logs/client_transcript.log")
    peer_fpr = cert_fingerprint_sha256(server_cert_pem)
    seq = 0

    print("[*] Enter messages. Type /bye to finish.")
    while True:
        line = input("> ").strip()
        if line == "/bye":
            send_json(conn, {"type": "bye"})
            break
        ct = aes_encrypt_block(chat_key, line.encode("utf-8"))
        digest = hashlib.sha256(struct.pack(">q", seq) + struct.pack(">q", int(time.time()*1000)) + ct).digest()
        sig = rsa_sign_sha256(CLIENT_KEY, digest)
        msg = make_msg(seq, base64.b64encode(ct).decode(), base64.b64encode(sig).decode())
        # overwrite ts inside digest to match exact msg
        digest = hashlib.sha256(struct.pack(">q", msg["seqno"]) + struct.pack(">q", msg["ts"]) + ct).digest()
        sig = rsa_sign_sha256(CLIENT_KEY, digest)
        msg["sig"] = base64.b64encode(sig).decode()
        send_json(conn, msg)
        transcript.append(msg["seqno"], msg["ts"], msg["ct"], msg["sig"], peer_fpr)
        seq += 1

    # 7) Receive receipt from server
    receipt = recv_json(conn)
    if receipt and receipt.get("type") == "receipt":
        print("[*] Received Server Session Receipt")
        print(receipt)

def main():
    mode = input("Choose mode [register|login]: ").strip()
    email = input("Email: ").strip()
    username = input("Username (for register): ").strip() if mode == "register" else ""
    password = input("Password: ").strip()

    with socket.create_connection((HOST, PORT)) as conn:
        do_register_login(conn, mode, email, username, password)

if __name__ == "__main__":
    main()
