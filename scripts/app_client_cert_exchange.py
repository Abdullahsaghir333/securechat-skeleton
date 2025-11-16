#!/usr/bin/env python3
# scripts/app_client_cert_exchange.py
import socket, struct
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import datetime

HOST = "127.0.0.1"
PORT = 9443

CERT_DIR = "certs"
CLIENT_CERT_PEM = open(f"{CERT_DIR}/client.cert.pem","rb").read()
CA_CERT_PEM = open(f"{CERT_DIR}/ca.cert.pem","rb").read()

def send_block(conn: socket.socket, data: bytes):
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)

def recv_block(conn: socket.socket) -> bytes:
    raw = conn.recv(4)
    if len(raw) < 4:
        raise ConnectionError("peer closed")
    sz = struct.unpack("!I", raw)[0]
    buf = b""
    while len(buf) < sz:
        chunk = conn.recv(sz - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf

def verify_cert(peer_pem: bytes, ca_pem: bytes, expected_cn: str):
    peer = x509.load_pem_x509_certificate(peer_pem)
    ca = x509.load_pem_x509_certificate(ca_pem)

    ca_pub = ca.public_key()
    try:
        ca_pub.verify(
            peer.signature,
            peer.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"BAD SIGNATURE: {e}"

    now = datetime.datetime.now(datetime.timezone.utc)
    if peer.not_valid_before.replace(tzinfo=datetime.timezone.utc) > now or peer.not_valid_after.replace(tzinfo=datetime.timezone.utc) < now:
        return False, "CERT EXPIRED/NOT YET VALID"

    try:
        cn = peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return False, "NO CN"
    if cn != expected_cn:
        return False, f"CN MISMATCH (expected {expected_cn}, got {cn})"

    return True, "OK"

def main():
    with socket.create_connection((HOST, PORT)) as conn:
        # receive server cert first
        server_pem = recv_block(conn)
        print("[app-client] received server cert bytes:", len(server_pem))

        ok, reason = verify_cert(server_pem, CA_CERT_PEM, expected_cn="server")
        if not ok:
            print("[app-client] server cert verification FAILED:", reason)
            return
        print("[app-client] server cert OK")

        # send our cert
        send_block(conn, CLIENT_CERT_PEM)

        # wait server verification response
        resp = recv_block(conn)
        print("[app-client] server response:", resp.decode())

if __name__ == "__main__":
    main()
