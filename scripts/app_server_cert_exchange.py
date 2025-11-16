#!/usr/bin/env python3
# scripts/app_server_cert_exchange.py
import socket, struct
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import datetime

HOST = "127.0.0.1"
PORT = 9443  # plain TCP port (not TLS)

CERT_DIR = "certs"
SERVER_CERT_PEM = open(f"{CERT_DIR}/server.cert.pem","rb").read()
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

    # 1) verify signature (cert signed by CA)
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

    # 2) validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    if peer.not_valid_before.replace(tzinfo=datetime.timezone.utc) > now or peer.not_valid_after.replace(tzinfo=datetime.timezone.utc) < now:
        return False, "CERT EXPIRED/NOT YET VALID"

    # 3) common name match
    try:
        cn = peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return False, "NO CN"
    if cn != expected_cn:
        return False, f"CN MISMATCH (expected {expected_cn}, got {cn})"

    return True, "OK"

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("[app-server] listening on", HOST, PORT)
        conn, addr = s.accept()
        with conn:
            print("[app-server] connection from", addr)
            # server sends its cert first
            send_block(conn, SERVER_CERT_PEM)
            # receive client's cert
            client_pem = recv_block(conn)
            print("[app-server] received client cert (bytes)", len(client_pem))

            ok, reason = verify_cert(client_pem, CA_CERT_PEM, expected_cn="client")
            if ok:
                print("[app-server] client cert verified OK")
                send_block(conn, b"VERIFIED")
            else:
                print("[app-server] client cert verification FAILED:", reason)
                send_block(conn, b"BADCERT:" + reason.encode())

if __name__ == "__main__":
    main()
