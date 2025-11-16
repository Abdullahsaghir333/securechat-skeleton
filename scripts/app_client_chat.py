#!/usr/bin/env python3
# scripts/app_client_chat.py — corrected client (control-plane + session)
import socket, struct, json, os, time, base64, hashlib, datetime, sys, traceback
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization as ser

# ---- CONFIG ----
HOST = "127.0.0.1"; PORT = 9555
CERT_DIR = "certs"
CLIENT_CERT_PEM = open(f"{CERT_DIR}/client.cert.pem","rb").read()
CLIENT_KEY_PEM  = open(f"{CERT_DIR}/client.key.pem","rb").read()
CA_CERT_PEM     = open(f"{CERT_DIR}/ca.cert.pem","rb").read()
MAX_SKEW_MS = 2 * 60 * 1000

# ---- NET helpers ----
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

# ---- crypto helpers ----
def verify_cert(peer_pem, ca_pem, expected_cn):
    peer = x509.load_pem_x509_certificate(peer_pem)
    ca = x509.load_pem_x509_certificate(ca_pem)
    ca_pub = ca.public_key()
    try:
        ca_pub.verify(peer.signature, peer.tbs_certificate_bytes,
                      padding.PKCS1v15(), peer.signature_hash_algorithm)
    except Exception as e:
        return False, f"BAD SIGN: {e}"
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        nb = peer.not_valid_before_utc
        na = peer.not_valid_after_utc
    except AttributeError:
        nb = peer.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        na = peer.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if nb > now or na < now:
        return False, "EXPIRED/NOTYET"
    cn = peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != expected_cn:
        return False, f"CN MISMATCH expected {expected_cn} got {cn}"
    return True, peer.fingerprint(hashes.SHA256()).hex()

def derive_key(shared_bytes):
    return hashlib.sha256(shared_bytes).digest()[:16]

def pkcs7_pad(b: bytes):
    padder = sym_padding.PKCS7(128).padder()
    return padder.update(b) + padder.finalize()

def pkcs7_unpad(b: bytes):
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(b) + unpadder.finalize()

def aes_encrypt(key, pt):
    if isinstance(pt, str):
        pt = pt.encode()
    padded = pkcs7_pad(pt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = cipher.update(padded) + cipher.finalize()
    return iv + ct

def aes_decrypt(key, ivct):
    iv = ivct[:16]; ct = ivct[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt_padded = cipher.update(ct) + cipher.finalize()
    return pkcs7_unpad(pt_padded)

def load_priv(pem):
    return ser.load_pem_private_key(pem, password=None)

def sign(priv, blob):
    return priv.sign(blob, padding.PKCS1v15(), hashes.SHA256())

def verify(pub, sig, blob):
    pub.verify(sig, blob, padding.PKCS1v15(), hashes.SHA256())

# ---- transcript helpers ----
def append_line(path, line):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(line + "\n")

def make_receipt_from_transcript(transcript_path, role, priv_pem):
    if not os.path.exists(transcript_path):
        lines = []
    else:
        with open(transcript_path, "rb") as f:
            lines = f.read().splitlines()
    concat = b"\n".join(lines)
    digest = hashlib.sha256(concat).digest()
    priv = load_priv(priv_pem)
    sig = sign(priv, digest)
    receipt = {
        "type": "receipt",
        "peer": role,
        "first_seq": None,
        "last_seq": None,
        "transcript_sha256": digest.hex(),
        "sig": base64.b64encode(sig).decode()
    }
    if lines:
        try:
            receipt["first_seq"] = int(lines[0].decode().split("|",1)[0])
            receipt["last_seq"] = int(lines[-1].decode().split("|",1)[0])
        except Exception:
            pass
    os.makedirs("receipts", exist_ok=True)
    out_path = f"receipts/client-{int(time.time())}.json"
    with open(out_path, "w") as f:
        json.dump(receipt, f, indent=2)
    return out_path

# ---- CONTROL PLANE (first TCP connection) ----
def do_control_plane():
    """
    Performs control-plane handshake. Allows register then immediate login
    by reconnecting automatically after a successful registration (server
    closes connection on return).
    Returns: (ok_bool, email_or_None, server_cert_pem_or_None)
    """
    server_cert_pem = None

    # helper to (re)open a connection and perform hello -> receive server_hello -> verify
    def open_and_hello():
        conn = socket.create_connection((HOST, PORT))
        # send hello
        client_nonce = os.urandom(16)
        hello = {"type": "hello",
                 "client_cert": CLIENT_CERT_PEM.decode(),
                 "nonce": base64.b64encode(client_nonce).decode()}
        send_block(conn, json.dumps(hello).encode())

        # receive server_hello
        raw = recv_block(conn)
        srv_hello = json.loads(raw.decode())
        if srv_hello.get("type") != "server_hello":
            conn.close()
            raise RuntimeError("bad server_hello: %r" % (srv_hello,))
        srv_cert = srv_hello["server_cert"].encode()
        ok, info = verify_cert(srv_cert, CA_CERT_PEM, expected_cn="server")
        if not ok:
            conn.close()
            raise RuntimeError("server cert verify failed: %s" % info)
        return conn, srv_cert

    # open initial control connection
    try:
        conn, server_cert_pem = open_and_hello()
    except Exception as e:
        print("[client] control-plane connect/hello failed:", e)
        return False, None, None

    try:
        while True:
            # Wait for server's ctrl_dh params
            raw = recv_block(conn)
            dh_params = json.loads(raw.decode())
            if dh_params.get("type") != "ctrl_dh":
                print("[client] expected ctrl_dh, got", dh_params)
                conn.close()
                return False, None, None

            p = int(dh_params["p"]); g = int(dh_params["g"]); B = int(dh_params["B"])
            nums = dh.DHParameterNumbers(p, g); params = nums.parameters()
            priv = params.generate_private_key(); A = priv.public_key().public_numbers().y

            # derive control key
            peer_pub = dh.DHPublicNumbers(B, nums).public_key()
            shared = priv.exchange(peer_pub); K_control = derive_key(shared)

            # interactive reg/login
            while True:
                choice = input("Choose [r]egister / [l]ogin: ").strip().lower()
                if choice not in ("r","l"): continue

                if choice == "r":
                    email = input("email: ").strip()
                    username = input("username: ").strip()
                    pwd = input("password: ").strip()
                    salt = os.urandom(16)
                    pwd_hash = hashlib.sha256(salt + pwd.encode()).hexdigest()
                    payload = {"type":"register","email":email,"username":username,"pwd":pwd_hash,"salt":base64.b64encode(salt).decode()}
                else:
                    email = input("email: ").strip()
                    pwd = input("password: ").strip()
                    salt_path = f"salts/{email}.bin"
                    if not os.path.exists(salt_path):
                        print("salt not found locally; you must register first.")
                        # break back to allow user to register
                        break
                    salt = open(salt_path,"rb").read()
                    pwd_hash = hashlib.sha256(salt + pwd.encode()).hexdigest()
                    payload = {"type":"login","email":email,"pwd":pwd_hash}

                pt = json.dumps(payload).encode()
                ivct = aes_encrypt(K_control, pt)
                ivct_b64 = base64.b64encode(ivct).decode()

                # Try sending; if server has closed we will get BrokenPipe or ConnectionError
                try:
                    send_block(conn, json.dumps({"type":"ctrl_dh_client","A":str(A),"payload":ivct_b64}).encode())
                except (BrokenPipeError, ConnectionError) as e:
                    # server closed before we could send (common after previous register). Reconnect and redo handshake.
                    print("[client] connection closed while sending control payload; reconnecting...")
                    try:
                        conn.close()
                    except: pass
                    conn, server_cert_pem = open_and_hello()
                    # break out of inner while to re-read ctrl_dh (server will send new ctrl_dh on new connection)
                    break

                # receive response
                try:
                    resp = json.loads(recv_block(conn).decode())
                except Exception as e:
                    print("[client] recv error after send:", e)
                    conn.close()
                    return False, None, None

                if resp.get("type") == "ok":
                    print("[client] OK:", resp.get("msg"))
                    if payload["type"] == "register":
                        # save salt, close connection, then re-open fresh control connection to allow immediate login
                        os.makedirs("salts", exist_ok=True)
                        with open(f"salts/{payload['email']}.bin","wb") as f:
                            f.write(salt)
                        print("[client] registration saved locally; reconnecting for login...")
                        conn.close()
                        # re-open a fresh hello + continue outer loop (which will read new ctrl_dh)
                        conn, server_cert_pem = open_and_hello()
                        break  # break inner loop to re-handle ctrl_dh on new connection
                    else:
                        # login OK -> return success and server cert
                        conn.close()
                        return True, payload["email"], server_cert_pem
                else:
                    print("[client] ERR:", resp)
                    if resp.get("msg") == "email_exists":
                        print("[client] Try login instead.")
                    # continue inner loop so user can try again or switch to register

            # continue outer loop to read the new ctrl_dh from the re-opened connection
    except Exception as e:
        print("[client] control-plane exception:", repr(e))
        traceback.print_exc()
        try: conn.close()
        except: pass
        return False, None, None

# ---- SESSION (second TCP connection) ----
def do_session(email, server_cert_pem):
    """
    Connect again and perform session DH and encrypted messaging.
    Follows server.handle_session:
    - send {"type":"dh_client", "p","g","A"}
    - receive {"type":"dh_server","B"}
    """
    try:
        conn = socket.create_connection((HOST, PORT))
    except Exception as e:
        print("[client] session connect failed:", e); return

    try:
        # pick fresh params (server will build params using client's p/g and respond)
        params = dh.generate_parameters(generator=2, key_size=2048)
        nums = params.parameter_numbers()
        p = nums.p; g = nums.g
        priv = params.generate_private_key(); A = priv.public_key().public_numbers().y

        send_block(conn, json.dumps({"type":"dh_client","p":str(p),"g":str(g),"A":str(A)}).encode())

        resp = json.loads(recv_block(conn).decode())
        if resp.get("type") != "dh_server":
            print("[client] bad dh_server:", resp); conn.close(); return
        B = int(resp["B"])

        peer_nums = dh.DHPublicNumbers(B, dh.DHParameterNumbers(p,g))
        shared = priv.exchange(peer_nums.public_key()); K = derive_key(shared)
        print("[client] session K:", K.hex())

        # messaging loop
        client_priv = load_priv(CLIENT_KEY_PEM)
        server_cert = x509.load_pem_x509_certificate(server_cert_pem)
        server_pub = server_cert.public_key()
        server_fp = server_cert.fingerprint(hashes.SHA256()).hex()

        session_id = str(int(time.time()))
        transcript_path = f"transcripts/client-{session_id}.log"
        os.makedirs("transcripts", exist_ok=True)

        seq = 1
        while True:
            try:
                message = input("You: ")
            except EOFError:
                break
            if not message: continue

            ts = int(time.time()*1000)
            ivct = aes_encrypt(K, message.encode())
            ct_b64 = base64.b64encode(ivct).decode()

            m = str(seq).encode() + b"||" + str(ts).encode() + b"||" + ivct
            digest = hashlib.sha256(m).digest()
            sig = client_priv.sign(digest, padding.PKCS1v15(), hashes.SHA256())

            out = {"type":"msg","seqno":seq,"ts":ts,"ct":ct_b64,"sig":base64.b64encode(sig).decode()}
            send_block(conn, json.dumps(out).encode())

            # log to transcript
            append_line(transcript_path, f"{seq}|{ts}|{ct_b64}|{base64.b64encode(sig).decode()}|{server_fp}")

            # wait for ack/nack
            ack_raw = recv_block(conn)
            ack = json.loads(ack_raw.decode())
            if ack.get("type") == "ack":
                ack_ct = base64.b64decode(ack["ct"]); ack_sig = base64.b64decode(ack["sig"])
                ack_ts = int(ack["ts"])
                m2 = str(ack["seqno"]).encode() + b"||" + str(ack_ts).encode() + b"||" + ack_ct
                digest2 = hashlib.sha256(m2).digest()
                try:
                    server_pub.verify(ack_sig, digest2, padding.PKCS1v15(), hashes.SHA256())
                    # freshness check
                    if abs(int(time.time()*1000) - ack_ts) > MAX_SKEW_MS:
                        print("[client] ACK stale")
                    ack_plain = aes_decrypt(K, ack_ct).decode()
                    print("[server ACK]:", ack_plain)
                except Exception as e:
                    print("[client] ack verify fail:", e)
            elif ack.get("type") == "nack":
                print("[server NACK]:", ack.get("why"))
            else:
                print("[client] unknown response:", ack)
            seq += 1

    except Exception as e:
        print("[client] session error:", repr(e))
        traceback.print_exc()
    finally:
        # generate receipt before exit
        try:
            out_path = make_receipt_from_transcript(transcript_path, "client", CLIENT_KEY_PEM)
        except Exception:
            pass
        try: conn.close()
        except: pass

# ---- main ----
if __name__ == "__main__":
    ok, email, server_cert = do_control_plane()
    if not ok:
        print("[client] control-plane failed, exiting")
        sys.exit(1)
    print("[client] logged in as:", email)
    do_session(email, server_cert)
