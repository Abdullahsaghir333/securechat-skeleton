#!/usr/bin/env python3
# scripts/app_server_chat.py
import socket, struct, json, os, time, base64, hashlib, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization as ser
import threading

HOST = "127.0.0.1"
PORT = 5000   # change from 3306

CERT_DIR = "certs"
SERVER_CERT_PEM = open(f"{CERT_DIR}/server.cert.pem","rb").read()
SERVER_KEY = open(f"{CERT_DIR}/server.key.pem","rb").read()
CA_CERT_PEM = open(f"{CERT_DIR}/ca.cert.pem","rb").read()

def send_block(conn, data: bytes):
    conn.sendall(struct.pack("!I", len(data))); conn.sendall(data)
def recv_block(conn):
    raw = conn.recv(4)
    if len(raw)<4: raise ConnectionError()
    sz = struct.unpack("!I", raw)[0]; buf=b""
    while len(buf)<sz:
        chunk=conn.recv(sz-len(buf)); 
        if not chunk: raise ConnectionError()
        buf+=chunk
    return buf

def verify_cert(peer_pem, ca_pem, expected_cn):
    peer=x509.load_pem_x509_certificate(peer_pem); ca=x509.load_pem_x509_certificate(ca_pem)
    ca_pub=ca.public_key()
    try:
        ca_pub.verify(peer.signature, peer.tbs_certificate_bytes, padding.PKCS1v15(), peer.signature_hash_algorithm)
    except Exception as e:
        return False, f"BAD SIGN:{e}"
    now=datetime.datetime.now(datetime.timezone.utc)
    if peer.not_valid_before.replace(tzinfo=datetime.timezone.utc)>now or peer.not_valid_after.replace(tzinfo=datetime.timezone.utc)<now:
        return False, "EXPIRED/NOTYET"
    cn=peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn!=expected_cn: return False, f"CN MISMATCH expected {expected_cn} got {cn}"
    # fingerprint hex
    fp = peer.fingerprint(hashes.SHA256()).hex()
    return True, fp

def derive_key(shared_bytes):
    return hashlib.sha256(shared_bytes).digest()[:16]

def pkcs7_pad(b):
    padder=sym_padding.PKCS7(128).padder()
    return padder.update(b)+padder.finalize()
def pkcs7_unpad(b):
    unpadder=sym_padding.PKCS7(128).unpadder()
    return unpadder.update(b)+unpadder.finalize()

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(pkcs7_pad(plaintext)) + enc.finalize()
    return iv + ct
def aes_decrypt(key, iv_ct):
    iv = iv_ct[:16]; ct = iv_ct[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor().update(ct)+cipher.decryptor().finalize()
    return pkcs7_unpad(dec)

def load_rsa_private(pem_bytes):
    return ser.load_pem_private_key(pem_bytes, password=None)

def rsa_sign(priv, data: bytes):
    return priv.sign(data, padding.PKCS1v15(), hashes.SHA256())

def rsa_verify(pub, sig, data: bytes):
    pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())

def log_line(path, line):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(line + "\n")

def main():
    # load server rsa priv
    server_priv = load_rsa_private(SERVER_KEY)
    session_id = str(int(time.time()))
    transcript_path = f"transcripts/server-{session_id}.log"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT)); s.listen(1)
        print("[server] listening", HOST, PORT)
        conn, addr = s.accept()
        with conn:
            print("[server] connection", addr)
            # cert exchange
            send_block(conn, SERVER_CERT_PEM)
            client_pem = recv_block(conn)
            ok, info = verify_cert(client_pem, CA_CERT_PEM, expected_cn="client")
            if not ok:
                print("[server] BAD CLIENT CERT:", info)
                send_block(conn, b"BADCERT:"+info.encode()); return
            client_fp = info
            send_block(conn, b"VERIFIED")
            # DH params
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            nums = parameters.parameter_numbers(); p=nums.p; g=nums.g
            priv = parameters.generate_private_key(); pub = priv.public_key().public_numbers().y
            send_block(conn, json.dumps({"type":"dh_params","p":str(p),"g":str(g),"B":str(pub)}).encode())
            # receive A
            raw = recv_block(conn); obj=json.loads(raw.decode())
            A = int(obj["A"])
            peer_nums = dh.DHPublicNumbers(A, nums); peer_pub = peer_nums.public_key()
            shared = priv.exchange(peer_pub); K = derive_key(shared)
            print("[server] derived K:", K.hex())

            # start state
            expected_seq = 1

            # main receive loop: receive one message, verify, decrypt, log, send signed ACK
            while True:
                raw = recv_block(conn)
                obj = json.loads(raw.decode())
                if obj.get("type")!="msg": 
                    print("[server] unknown type", obj); break
                seq = int(obj["seqno"]); ts = int(obj["ts"]); ct_b64 = obj["ct"]; sig_b64 = obj["sig"]
                ivct = base64.b64decode(ct_b64); sig = base64.b64decode(sig_b64)
                # replay/ordering check
                if seq < expected_seq:
                    print("[server] replay/old seq", seq, "expected", expected_seq)
                    send_block(conn, json.dumps({"type":"nack","why":"replay"}).encode()); continue
                # verify signature (on seq||ts||ct bytes)
                m = str(seq).encode()+b"||"+str(ts).encode()+b"||"+ivct
                try:
                    client_cert = x509.load_pem_x509_certificate(client_pem)
                    rsa_pub = client_cert.public_key()
                    rsa_verify(rsa_pub, sig, hashlib.sha256(m).digest())
                except Exception as e:
                    print("[server] signature FAIL", e)
                    send_block(conn, json.dumps({"type":"nack","why":"sigfail"}).encode()); continue
                # decrypt
                try:
                    pt = aes_decrypt(K, ivct).decode()
                except Exception as e:
                    print("[server] decrypt error", e)
                    send_block(conn, json.dumps({"type":"nack","why":"decrypt"}).encode()); continue
                # accepted
                print(f"[server] msg seq={seq} ts={ts} -> {pt}")
                # log: seq|ts|ct|sig|peer_fp
                line = f"{seq}|{ts}|{ct_b64}|{sig_b64}|{client_fp}"
                log_line(transcript_path, line)
                expected_seq = seq + 1

                # send signed ACK (server uses its own seq for ACKs = seq)
                ack_msg = f"ACK for {seq}".encode()
                ack_ivct = base64.b64encode(aes_encrypt(K, ack_msg)).decode()
                ack_seq = seq
                ack_ts = int(time.time()*1000)
                m2 = str(ack_seq).encode()+b"||"+str(ack_ts).encode()+b"||"+base64.b64decode(ack_ivct)
                sig2 = rsa_sign(server_priv, hashlib.sha256(m2).digest())
                payload = {"type":"ack","seqno":ack_seq,"ts":ack_ts,"ct":ack_ivct,"sig":base64.b64encode(sig2).decode()}
                send_block(conn, json.dumps(payload).encode())
                # log server's ack line (with server's fingerprint)
                server_cert = x509.load_pem_x509_certificate(SERVER_CERT_PEM)
                server_fp = server_cert.fingerprint(hashes.SHA256()).hex()
                log_line(transcript_path, f"{ack_seq}|{ack_ts}|{ack_ivct}|{base64.b64encode(sig2).decode()}|{server_fp}")

if __name__=="__main__":
    main()
