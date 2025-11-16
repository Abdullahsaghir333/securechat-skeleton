#!/usr/bin/env python3
# scripts/app_client_dh.py
import socket, struct, json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import hashlib

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

def derive_aes_key_from_shared(shared_bytes: bytes) -> bytes:
    digest = hashlib.sha256(shared_bytes).digest()
    return digest[:16]

def main():
    with socket.create_connection((HOST, PORT)) as conn:
        # 1) receive server cert, verify
        server_pem = recv_block(conn)
        ok, reason = verify_cert(server_pem, CA_CERT_PEM, expected_cn="server")
        if not ok:
            print("[app-client-dh] server cert verification FAILED:", reason)
            return
        print("[app-client-dh] server cert OK")

        # send our cert
        send_block(conn, CLIENT_CERT_PEM)
        # receive verification response
        resp = recv_block(conn)
        print("[app-client-dh] server response:", resp.decode())

        # 2) receive DH params from server (p,g,B)
        raw = recv_block(conn)
        j = json.loads(raw.decode())
        if j.get("type") != "dh_server_params":
            print("[app-client-dh] unexpected message:", j)
            return
        p = int(j["p"]); g = int(j["g"]); B_int = int(j["B"])
        print("[app-client-dh] got server DH params")

        # construct parameters and generate client key
        params_numbers = dh.DHParameterNumbers(p, g)
        parameters = params_numbers.parameters()
        client_priv = parameters.generate_private_key()
        client_pub = client_priv.public_key()
        client_pub_numbers = client_pub.public_numbers().y
        # send client's A
        send_block(conn, json.dumps({"type":"dh_client_pub", "A":str(client_pub_numbers)}).encode())
        print("[app-client-dh] sent client A")

        # compute shared
        peer_numbers = dh.DHPublicNumbers(B_int, params_numbers)
        server_pub = peer_numbers.public_key()
        shared = client_priv.exchange(server_pub)
        K = derive_aes_key_from_shared(shared)
        print("[app-client-dh] derived AES-128 key (hex):", K.hex())

        # wait ack
        resp2 = recv_block(conn)
        print("[app-client-dh] server ack:", resp2.decode())

if __name__ == "__main__":
    main()
