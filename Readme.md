 SecureChat — Assignment Submission

## Overview
SecureChat is a small assignment project implementing:
- Certificate-based authentication (self-signed CA)
- Control-plane + session-plane separation
- Ephemeral Diffie–Hellman (DH) for key agreement
- AES-128-CBC encryption with PKCS#7 padding for messages
- RSA signatures for message integrity and SessionReceipt non-repudiation
- Sequence numbers and timestamp freshness to prevent replays
- Tests: invalid-cert, tamper, replay, receipt verification

## Repo structure
securechat-skeleton/
├── app_server_chat.py
├── scripts/
│ ├── app_client_chat.py
│ ├── tamper_replay.py
│ ├── fake_client_badcert_test.py
│ ├── replay_attack.py
│ ├── mysql_schema_and_sample.sql
│ └── securechat_schema_and_data.sql
├── tools/
│ ├── verify_receipt.py
│ └── verify_message.py
├── server/
│ └── db.py
├── certs/ # public certs only (private keys are ignored by .gitignore)
├── transcripts/ # runtime: excluded from git
├── receipts/ # runtime: excluded from git
└── README.md

markdown
Copy code

## Requirements
- Python 3.10+
- `cryptography` Python package
- `pymysql` (if using the DB features)
- MySQL server (for DB tests)
- Wireshark/tcpdump (for packet capture evidence)

Install Python packages:
```bash
python -m pip install cryptography pymysql
Environment / Configuration
You can configure DB using environment variables (defaults provided in server code):

DB_HOST (default 127.0.0.1)

DB_PORT (default 3306)

DB_USER (default chatuser)

DB_PASS (default chatpass)

DB_NAME (default securechat)

If you run MySQL on localhost and used the provided SQL, defaults will work.

Generating CA and Certificates
bash
Copy code
python scripts/gen_ca.py
python scripts/gen_cert.py server --server
python scripts/gen_cert.py client
This produces certs/ca.cert.pem, certs/server.cert.pem, certs/server.key.pem, certs/client.cert.pem, certs/client.key.pem.

Important: Do NOT commit private keys to GitHub. .gitignore already excludes certs/*.key.pem.

Database schema & sample data
To create DB and sample records:

bash
Copy code
mysql -u root -p < scripts/mysql_schema_and_sample.sql
# (creates DB, users table, sample rows, and a DB user 'chatuser' with password 'chatpass')
To export the SQL dump (for submission):

bash
Copy code
mysqldump -u root -p securechat > scripts/securechat_schema_and_data.sql
Run the server & client
Start the server:

bash
Copy code
python app_server_chat.py
In another terminal, run the control-plane-only client (register/login and exit so server waits):

bash
Copy code
python scripts/app_client_chat.py
# choose register or login per prompts (client will exit after control-plane in this repo)
In another terminal, run session-phase client to send messages:

bash
Copy code
# For interactive session (if client is not modified to exit after control-plane)
python scripts/app_client_chat.py
# or use the tamper/replay scripts for automated tests
Tests (commands)
Wireshark capture filter: tcp.port == 9555 — show ciphertext only.

Bad-certificate test:

bash
Copy code
python scripts/fake_client_badcert_test.py
Expected: server replies {"type":"badcert", ...}

Tamper test (flip ciphertext bit from transcript):

bash
Copy code
python scripts/tamper_replay.py --mode tamper --transcript transcripts/client-<ts>.log
Replay test:

bash
Copy code
python scripts/tamper_replay.py --mode replay --transcript transcripts/client-<ts>.log
Receipt verification:

bash
Copy code
python tools/verify_receipt.py receipts/server-<ts>.json transcripts/server-<ts>.log certs/server.cert.pem
Per-message verification:

bash
Copy code
line=$(sed -n '1p' transcripts/server-<ts>.log)
python tools/verify_message.py "$line" certs/client.cert.pem
Sample input/output (examples)
Client register payload (encrypted in control-plane payload):

json
Copy code
{"type":"register","email":"alice@example.com","username":"alice","pwd":"<hex-hash>","salt":"<b64-salt>"}
Server ACK (example encrypted ack JSON sent back in session):

json
Copy code
{
  "type":"ack",
  "seqno":1,
  "ts":1700000000000,
  "ct":"<base64-iv-ct>",
  "sig":"<base64-signature>"
}
Replay rejection:

json
Copy code
{"type":"nack","why":"seq_mismatch","expected":1}
Tamper rejection:

json
Copy code
{"type":"nack","why":"sigfail"}
Receipt verification (verify_receipt.py):

python
Copy code
Recomputed transcript sha256: <hex>
Receipt transcript_sha256: <hex>
Transcript hash matches the receipt value.
Signature verification: OK (receipt signature valid)
What is NOT in the repo
Private keys (certs/*.key.pem), salts, and runtime transcripts/receipts are excluded via .gitignore for security. Include screenshots/pcaps in your report instead.

Link to repo
Replace with your GitHub repo:

bash
Copy code
https://github.com/<your-username>/securechat-assignment
