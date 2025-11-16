
#!/usr/bin/env python3
# scripts/app_client_chat.py (client w/ automatic SessionReceipt on Ctrl+C)
import socket, struct, json, os, time, base64, hashlib, datetime, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization as ser

HOST="127.0.0.1"; PORT=9443
CERT_DIR="certs"
CLIENT_CERT_PEM = open(f"{CERT_DIR}/client.cert.pem","rb").read()
CLIENT_KEY = open(f"{CERT_DIR}/client.key.pem","rb").read()
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
    return True, peer.fingerprint(hashes.SHA256()).hex()

def derive_key(shared_bytes):
    return hashlib.sha256(shared_bytes).digest()[:16]

def pkcs7_pad(b):
    padder=sym_padding.PKCS7(128).padder(); return padder.update(b)+padder.finalize()
def pkcs7_unpad(b):
    unpadder=sym_padding.PKCS7(128).unpadder(); return unpadder.update(b)+unpadder.finalize()

def aes_encrypt(key, plaintext):
    iv=os.urandom(16); cipher=Cipher(algorithms.AES(key), modes.CBC(iv)); enc=cipher.encryptor()
    ct = enc.update(pkcs7_pad(plaintext)) + enc.finalize(); return iv + ct
def aes_decrypt(key, iv_ct):
    iv=iv_ct[:16]; ct=iv_ct[16:]; cipher=Cipher(algorithms.AES(key), modes.CBC(iv)); dec=cipher.decryptor().update(ct)+cipher.decryptor().finalize()
    return pkcs7_unpad(dec)

def load_priv(pem): return ser.load_pem_private_key(pem, password=None)
def sign(priv, data): return priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
def verify(pub, sig, data): pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())

def append_line(path, line):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path,"a") as f: f.write(line+"\n")

def make_receipt_from_transcript(transcript_path, role, session_id, privkey_pem):
    if not os.path.exists(transcript_path):
        lines=[]
    else:
        with open(transcript_path,"rb") as f:
            lines = f.read().splitlines()
    concat = b"\n".join(lines)
    digest = hashlib.sha256(concat).digest()
    sig = sign(load_priv(privkey_pem), digest)
    receipt = {
        "type":"receipt",
        "peer": role,
        "session_id": session_id,
        "first_seq": None,
        "last_seq": None,
        "transcript_sha256": digest.hex(),
        "sig": base64.b64encode(sig).decode()
    }
    if lines:
        try:
            first = int(lines[0].decode().split("|",1)[0])
            last = int(lines[-1].decode().split("|",1)[0])
            receipt["first_seq"] = first; receipt["last_seq"] = last
        except Exception:
            pass
    os.makedirs("receipts", exist_ok=True)
    out_path = f"receipts/client-{session_id}.json"
    with open(out_path,"w") as f: json.dump(receipt, f, indent=2)
    return out_path, receipt

def main():
    client_priv = load_priv(CLIENT_KEY)
    session_id = str(int(time.time()))
    transcript_path = f"transcripts/client-{session_id}.log"
    try:
        with socket.create_connection((HOST, PORT)) as conn:
            server_pem = recv_block(conn)
            ok, info = verify_cert(server_pem, CA_CERT_PEM, expected_cn="server")
            if not ok: print("bad server cert", info); return
            send_block(conn, CLIENT_CERT_PEM)
            resp = recv_block(conn).decode(); print("[client] server resp", resp)
            raw = recv_block(conn); j=json.loads(raw.decode()); p=int(j["p"]); g=int(j["g"]); B=int(j["B"])
            nums = dh.DHParameterNumbers(p,g); params = nums.parameters()
            priv = params.generate_private_key(); A = priv.public_key().public_numbers().y
            send_block(conn, json.dumps({"type":"dh_client_pub","A":str(A)}).encode())
            peer_nums = dh.DHPublicNumbers(B, nums); peer_pub = peer_nums.public_key()
            shared = priv.exchange(peer_pub); K = derive_key(shared)
            print("[client] derived K:", K.hex())

            seq = 1
            while True:
                try:
                    msg = input("You: ")
                except EOFError:
                    break
                if not msg: continue
                ts = int(time.time()*1000)
                ivct = aes_encrypt(K, msg.encode())
                ct_b64 = base64.b64encode(ivct).decode()
                m = str(seq).encode()+b"||"+str(ts).encode()+b"||"+ivct
                sig = sign(client_priv, hashlib.sha256(m).digest())
                payload = {"type":"msg","seqno":seq,"ts":ts,"ct":ct_b64,"sig":base64.b64encode(sig).decode()}
                send_block(conn, json.dumps(payload).encode())
                server_fp = x509.load_pem_x509_certificate(server_pem).fingerprint(hashes.SHA256()).hex()
                append_line(transcript_path, f"{seq}|{ts}|{ct_b64}|{base64.b64encode(sig).decode()}|{server_fp}")
                raw = recv_block(conn); obj=json.loads(raw.decode())
                if obj.get("type")=="ack":
                    ack_ct = base64.b64decode(obj["ct"]); ack_sig = base64.b64decode(obj["sig"])
                    server_pub = x509.load_pem_x509_certificate(server_pem).public_key()
                    m2 = str(obj["seqno"]).encode()+b"||"+str(obj["ts"]).encode()+b"||"+ack_ct
                    try:
                        verify(server_pub, ack_sig, hashlib.sha256(m2).digest())
                        ack_plain = aes_decrypt(K, ack_ct).decode()
                        print("[server ACK]:", ack_plain)
                    except Exception as e:
                        print("ACK verify/decrypt fail", e)
                seq += 1
    except KeyboardInterrupt:
        print("\n[client] interrupted, generating SessionReceipt...")
        out_path, receipt = make_receipt_from_transcript(transcript_path, "client", session_id, CLIENT_KEY)
        print("[client] receipt saved:", out_path)
        print("[client] transcript lines:", end=" ")
        try:
            print(len(open(transcript_path,"r").read().splitlines()))
        except Exception:
            print("0")
        sys.exit(0)

if __name__=="__main__":
    main()

