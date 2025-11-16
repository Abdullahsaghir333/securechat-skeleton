#!/usr/bin/env python3
# A minimal client to test INVALID CERTIFICATE handling (BAD CERT)

import socket, struct, json, base64, os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import datetime

HOST = "127.0.0.1"
PORT = 9555

# ---- Generate a fake (self-signed) client certificate ----

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

subject = issuer = x509.Name([
    x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"FakeClient"),
    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"client"),
])

now = datetime.datetime.now(datetime.timezone.utc)

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)  # Self-signed → invalid for server
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=1))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)

FAKE_CERT_PEM = cert.public_bytes(serialization.Encoding.PEM).decode()


# ---- helpers for sending framed messages ----

def send_block(conn, data: bytes):
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)

def recv_block(conn):
    raw = conn.recv(4)
    if len(raw) < 4:
        raise ConnectionError("short header")
    size = struct.unpack("!I", raw)[0]
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        buf += chunk
    return buf


# ---- MAIN: send hello with fake cert ----

def main():
    print("[fake-client] Connecting to server for BAD CERT test...")
    conn = socket.create_connection((HOST, PORT))

    fake_hello = {
        "type": "hello",
        "client_cert": FAKE_CERT_PEM,
        "nonce": base64.b64encode(os.urandom(16)).decode()
    }

    send_block(conn, json.dumps(fake_hello).encode())

    try:
        resp = recv_block(conn)
        print("\n[fake-client] Server response:")
        print(resp.decode())
    except:
        print("[fake-client] Server closed connection (BAD CERT detected).")

    conn.close()


if __name__ == "__main__":
    main()
