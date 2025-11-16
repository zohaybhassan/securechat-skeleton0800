Secure chat: Console-based CIANR protocol (AES-128, RSA, DH, SHA-256)
This project implements a minimal client–server secure chat that achieves Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR) using application-layer cryptography, without TLS. It follows the assignment’s protocol: mutual certificate validation via a self-built CA, registration/login under an ephemeral DH-derived AES key, a post-auth DH session key, per-message RSA signatures over SHA-256 digests, replay defense, and a signed session transcript.


Project structure
Code
securechat-skeleton/
  certs/                     # local; private keys & certs (do not commit private keys)
  logs/                      # transcripts and receipts
  scripts/
    gen_ca.py                # create root CA (self-signed)
    gen_cert.py              # issue server/client certs signed by your CA
  src/
    db.py                    # MySQL schema and CRUD
    pki.py                   # cert load/verify helpers
    dh.py                    # Diffie-Hellman and key derivation
    aes.py                   # AES-128 (ECB) with PKCS#7 padding
    sign.py                  # RSA sign/verify (SHA-256, PKCS#1 v1.5)
    protocol.py              # JSON message builders/parsers
    transcript.py            # append-only transcript and session receipt
    server.py                # server main
    client.py                # client main
  .env.example               # configuration template (copy to .env and fill)
  .gitignore                 # excludes venv, secrets, logs, etc.
  README.md                  # this file
Prerequisites
Python 3.11+ (add to PATH)

Git

MySQL Server 8.x + MySQL Workbench (or CLI)

Npcap/Wireshark (for evidence captures)

Python dependencies (installed via pip):

cryptography

pycryptodome

mysql-connector-python

python-dotenv

Configuration
Create and fill .env (copy from .env.example). Do not commit .env.

Code
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=changeme
MYSQL_DB=securechat

# Local paths for keys & certs
CA_KEY_PATH=certs/root_ca_key.pem
CA_CERT_PATH=certs/root_ca_cert.pem
SERVER_KEY_PATH=certs/server_key.pem
SERVER_CERT_PATH=certs/server_cert.pem
CLIENT_KEY_PATH=certs/client_key.pem
CLIENT_CERT_PATH=certs/client_cert.pem
.gitignore already excludes:

.env, certs/*.pem (private keys), logs/, .venv/, __pycache__/, *.pyc

Setup and execution steps
1) Clone and create a virtual environment
bash
git clone https://github.com/<your-username>/securechat-skeleton
cd securechat-skeleton

python -m venv .venv
# PowerShell (Windows):
. .\.venv\Scripts\Activate.ps1
# Bash (Linux/macOS):
source .venv/bin/activate

pip install --upgrade pip
pip install cryptography pycryptodome mysql-connector-python python-dotenv
2) Generate your root CA and issue certs
bash
python scripts/gen_ca.py
python scripts/gen_cert.py server
python scripts/gen_cert.py client
Optional certificate inspection (if OpenSSL is installed):

bash
openssl x509 -in certs/server_cert.pem -text -noout
openssl x509 -in certs/client_cert.pem -text -noout
3) Initialize the database
Ensure your MySQL credentials in .env are correct, then:

bash
python -c "from src.db import init_schema; init_schema()"
This creates database securechat and table users(email, username, salt, pwd_hash).

4) Run server and client
Start the server:

bash
python src/server.py
Start the client (new terminal):

bash
python src/client.py
Follow prompts:

Mode: register (first time) or login (subsequent)

Email, Username (register only), Password

For login, provide the salt used at registration (hex). You can later enhance the client to store/retrieve your salt locally to avoid manual entry.

Protocol overview and message formats
All messages are JSON framed with a 4-byte big-endian length prefix.

Hello (mutual cert exchange):

json
{ "type": "hello", "client_cert": "…PEM base64…", "nonce": "…base64…" }
{ "type": "server hello", "server_cert": "…PEM base64…", "nonce": "…base64…" }
Ephemeral DH for auth plane:

json
{ "type": "dh_client", "g": 2, "p": <int>, "A": <int> }
{ "type": "dh_server", "B": <int> }
Registration (fields sent within the authenticated, DH-derived context):

json
{ "type":"register", "email":"", "username":"", "pwd": "base64(sha256(salt||pwd))", "salt":"base64" }
Login:

json
{ "type":"login", "email":"", "pwd":"base64(sha256(salt||pwd))", "nonce":"base64" }
Post-auth DH to derive chat session key K = Trunc16(SHA256(big-endian(Ks))).

Chat message (encrypted and signed):

json
{ "type":"msg", "seqno": n, "ts": unix_ms, "ct": "base64(AES-128-ECB(pkcs7(plaintext)))",
  "sig": "base64(RSA_SIGN( SHA256(seqno || ts || ct) ))" }
Error responses (examples):

json
{ "type":"error", "code":"BAD_CERT", "detail":"untrusted/expired/self-signed" }
{ "type":"error", "code":"REPLAY" }
{ "type":"error", "code":"SIG_FAIL" }
Session receipt (non-repudiation):

json
{ "type":"receipt", "peer":"server|client", "first_seq":0, "last_seq": n,
  "transcript_sha256":"hex", "sig":"base64(RSA_SIGN(transcript_sha256))" }
Sample interaction
Client:

Code
Choose mode [register|login]: register
Email: alice@example.com
Username (for register): alice
Password: S3cr3t!
[*] Auth OK mode=register
[*] Enter messages. Type /bye to finish.
> hello server
> how are you?
> /bye
[*] Received Server Session Receipt
{'type': 'receipt', 'peer': 'server', 'first_seq': 0, 'last_seq': 1, 'transcript_sha256': '...', 'sig': '...'}
Server:

Code
[*] Server listening on 127.0.0.1:5555
[+] Client connected: ('127.0.0.1', 61234)
[0] hello server
[1] how are you?
[*] Session closed; receipt sent.
Transcripts saved:

logs/client_transcript.log

logs/server_transcript_<port>.log

Each line: seqno|timestamp|ct_base64|sig_base64|peer_cert_fingerprint.

Testing and evidence (for the assignment)
Wireshark/Npcap: capture on loopback, filter tcp.port == 5555. Show that only ciphertext (ct) travels—no plaintext messages on the wire.

Invalid certificate: change expected CN or use a forged/self-signed cert; server should emit BAD_CERT.

Tampering: flip a byte in ct and resend; recipient returns SIG_FAIL (signature verification fails).

Replay: resend an old seqno; recipient returns REPLAY.

Non-repudiation: verify that the SessionReceipt’s signature validates over the transcript hash; any edit to the transcript breaks verification.

Notes and limitations
AES-128 used in ECB mode with PKCS#7 padding per the assignment’s “block only” constraint (no stream/modes).

Salted password hashing: pwd_hash = sha256(salt || password) stored as hex; salts are 16 bytes per user.

The login flow expects the client to know their salt (for classroom simplicity). A production flow would have the server provide the salt during login.

All certs are application-layer verified—no TLS used anywhere.

Development hygiene
Do not commit secrets (.env, private keys in certs).

Keep changes in meaningful commits (CA, cert issuance, DB, DH, AES, signatures, replay defense, transcript/receipt, tests).

Cite any external code snippets in comments and your report.

Quick commands
Install deps: pip install cryptography pycryptodome mysql-connector-python python-dotenv

Generate CA: python scripts/gen_ca.py

Issue certs: python scripts/gen_cert.py server && python scripts/gen_cert.py client

Init DB: python -c "from src.db import init_schema; init_schema()"

Run server: python src/server.py

Run client: python src/client.py