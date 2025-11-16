#!/usr/bin/env python3
# scripts/app_server_dh.py
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
    # shared_bytes is raw secret from private_key.exchange()
    # take SHA256(shared_bytes) and truncate to 16 bytes
    digest = hashlib.sha256(shared_bytes).digest()
    return digest[:16]

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("[app-server-dh] listening on", HOST, PORT)
        conn, addr = s.accept()
        with conn:
            print("[app-server-dh] connection from", addr)

            # 1) certificate exchange (server sends first)
            send_block(conn, SERVER_CERT_PEM)
            client_pem = recv_block(conn)
            ok, reason = verify_cert(client_pem, CA_CERT_PEM, expected_cn="client")
            if not ok:
                print("[app-server-dh] client cert verification FAILED:", reason)
                send_block(conn, b"BADCERT:" + reason.encode())
                return
            print("[app-server-dh] client cert OK")
            send_block(conn, b"VERIFIED")

            # 2) DH: server generates parameters and its key, sends p,g and B
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            params_numbers = parameters.parameter_numbers()
            p = params_numbers.p
            g = params_numbers.g

            server_priv = parameters.generate_private_key()
            server_pub = server_priv.public_key()
            server_pub_numbers = server_pub.public_numbers().y

            # send JSON: p,g,B as decimal strings
            j = {"type":"dh_server_params", "p":str(p), "g":str(g), "B":str(server_pub_numbers)}
            send_block(conn, json.dumps(j).encode())

            # 3) receive client's A
            raw = recv_block(conn)
            obj = json.loads(raw.decode())
            if obj.get("type") != "dh_client_pub":
                print("[app-server-dh] unexpected message:", obj)
                return
            A_int = int(obj["A"])
            print("[app-server-dh] received client A")

            # reconstruct client's public key and perform key exchange
            peer_numbers = dh.DHPublicNumbers(A_int, params_numbers)
            client_pub = peer_numbers.public_key()
            shared = server_priv.exchange(client_pub)  # bytes
            K = derive_aes_key_from_shared(shared)
            print("[app-server-dh] derived AES-128 key (hex):", K.hex())

            # confirm: send acknowledgement (not needed in final protocol)
            send_block(conn, b"DH_OK:" + K.hex().encode())

if __name__ == "__main__":
    main()
