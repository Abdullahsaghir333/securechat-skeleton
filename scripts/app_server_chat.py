#!/usr/bin/env python3
# app_server_chat.py — Assignment-Compliant Secure Chat Server

import socket, struct, json, os, time, base64, hashlib, datetime, sys, hmac, traceback
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization as ser
import pymysql

HOST = "127.0.0.1"
PORT = 9555
CERT_DIR = "certs"

SERVER_CERT = open(f"{CERT_DIR}/server.cert.pem","rb").read()
SERVER_KEY = open(f"{CERT_DIR}/server.key.pem","rb").read()
CA_CERT = open(f"{CERT_DIR}/ca.cert.pem","rb").read()

DB_HOST = os.getenv("DB_HOST","127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT","3306"))
DB_USER = os.getenv("DB_USER","chatuser")
DB_PASS = os.getenv("DB_PASS","chatpass")
DB_NAME = os.getenv("DB_NAME","securechat")

MAX_SKEW_MS = 24 * 3600 * 1000   # 24 hours for testing only


def send_block(conn, data: bytes):
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)

def recv_block(conn):
    raw = conn.recv(4)
    if len(raw) < 4: raise ConnectionError()
    size = struct.unpack("!I", raw)[0]
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk: raise ConnectionError()
        buf += chunk
    return buf

def verify_cert(peer_pem, ca_pem, expected_cn):
    peer = x509.load_pem_x509_certificate(peer_pem)
    ca = x509.load_pem_x509_certificate(ca_pem)
    ca_pub = ca.public_key()

    try:
        ca_pub.verify(peer.signature, peer.tbs_certificate_bytes,
                      padding.PKCS1v15(),
                      peer.signature_hash_algorithm)
    except Exception as e:
        return False, f"BAD SIGN:{e}"

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        nb = peer.not_valid_before_utc
        na = peer.not_valid_after_utc
    except:
        nb = peer.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        na = peer.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    if nb > now or na < now:
        return False, "EXPIRED"

    cn = peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != expected_cn:
        return False, f"CN MISMATCH (expected {expected_cn}, got {cn})"

    fp = peer.fingerprint(hashes.SHA256()).hex()
    return True, fp

def derive_key(shared):
    return hashlib.sha256(shared).digest()[:16]

def pad(b):
    p = sym_padding.PKCS7(128).padder()
    return p.update(b) + p.finalize()

def unpad(b):
    p = sym_padding.PKCS7(128).unpadder()
    return p.update(b) + p.finalize()

def aes_encrypt(key, pt):
    """
    AES-128-CBC encrypt with PKCS7 padding.
    Returns iv || ciphertext
    """
    # ensure pt is bytes
    if isinstance(pt, str):
        pt = pt.encode()
    # apply PKCS7 padding
    padded = pad(pt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = cipher.update(padded) + cipher.finalize()
    return iv + ct


def aes_decrypt(key, ivct):
    iv = ivct[:16]
    ct = ivct[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return unpad(cipher.update(ct) + cipher.finalize())

def db_conn():
    return pymysql.connect(host=DB_HOST, port=DB_PORT,
                           user=DB_USER, password=DB_PASS,
                           database=DB_NAME, autocommit=True,
                           cursorclass=pymysql.cursors.DictCursor)

def db_get_user(email):
    with db_conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            return cur.fetchone()
def db_create_user(email, username, salt, pwd_hash):
    with db_conn() as c:
        with c.cursor() as cur:
            cur.execute("INSERT INTO users (email,username,salt,pwd_hash) VALUES (%s,%s,%s,%s)",
                        (email, username, salt, pwd_hash))


# ---- CONTROL PLANE: HELLO, DH, REGISTER/LOGIN ----
def handle_control_plane(conn):
    """
    Implements assignment's control-plane:
    1) hello exchange
    2) ephemeral DH -> AES-128
    3) encrypted register/login
    Closes connection after success.
    """

    # 1) Receive client hello
    raw = recv_block(conn)
    msg = json.loads(raw.decode())
    if msg.get("type") != "hello":
        send_block(conn, b"BADHELLO")
        return False, "badhello", None

    client_cert_str = msg["client_cert"]
    client_cert_str = client_cert_str.replace("\\n", "\n")
    client_cert_pem = client_cert_str.encode()

    client_nonce = base64.b64decode(msg["nonce"])

    ok, info = verify_cert(client_cert_pem, CA_CERT, "client")
    if not ok:
        send_block(conn, json.dumps({"type":"badcert", "msg":info}).encode())
        return False, "certfail", None

    # 2) Send server_hello
    server_nonce = os.urandom(16)
    server_hello = {
        "type": "server_hello",
        "server_cert": SERVER_CERT.decode(),
        "nonce": base64.b64encode(server_nonce).decode()
    }
    send_block(conn, json.dumps(server_hello).encode())
    # 3) Ephemeral DH for control-plane encryption
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    nums = parameters.parameter_numbers()
    p = nums.p
    g = nums.g

    priv = parameters.generate_private_key()
    B = priv.public_key().public_numbers().y

    # send DH params to client
    send_block(conn, json.dumps({
        "type": "ctrl_dh",
        "p": str(p),
        "g": str(g),
        "B": str(B)
    }).encode())

    # receive client's A + encrypted payload
    raw = recv_block(conn)
    msg = json.loads(raw.decode())

    if msg.get("type") != "ctrl_dh_client":
        send_block(conn, json.dumps({"type": "error", "msg": "expected ctrl_dh_client"}).encode())
        return False, "bad_ctrl", None

    A = int(msg["A"])
    enc_payload = base64.b64decode(msg["payload"])

    # derive control-plane AES key
    peer_nums = dh.DHPublicNumbers(A, nums)
    shared = priv.exchange(peer_nums.public_key())
    K_control = derive_key(shared)

    # decrypt the register/login payload
    try:
        pt = aes_decrypt(K_control, enc_payload).decode()
        obj = json.loads(pt)
    except Exception as e:
        send_block(conn, json.dumps({"type":"error","msg":"decryptfail"}).encode())
        return False, "decryptfail", None

    # --------------------------
    # REGISTER
    # --------------------------
    if obj["type"] == "register":
        email = obj["email"]
        username = obj["username"]
        pwd_hash_b64 = obj["pwd"]
        salt_b64 = obj["salt"]

        if db_get_user(email):
            send_block(conn, json.dumps({"type":"error","msg":"email_exists"}).encode())
            return False, "exists", None

        salt = base64.b64decode(salt_b64)
        pwd_hash = pwd_hash_b64  # already hex string per assignment

        db_create_user(email, username, salt, pwd_hash)
        send_block(conn, json.dumps({"type":"ok","msg":"registered"}).encode())
        return True, "registered", client_cert_pem

    # --------------------------
    # LOGIN
    # --------------------------
    elif obj["type"] == "login":
        email = obj["email"]
        pwd_hash_b64 = obj["pwd"]

        row = db_get_user(email)
        if not row:
            send_block(conn, json.dumps({"type":"error","msg":"nouser"}).encode())
            return False, "nouser", None

        stored_hash = row["pwd_hash"]
        if not hmac.compare_digest(stored_hash, pwd_hash_b64):
            send_block(conn, json.dumps({"type":"error","msg":"bad_credentials"}).encode())
            return False, "bad_credentials", None

        send_block(conn, json.dumps({"type":"ok","msg":"login_ok"}).encode())
        return True, "login_ok", client_cert_pem

    else:
        send_block(conn, json.dumps({"type":"error","msg":"bad_op"}).encode())
        return False, "bad_op", None
# ---- SESSION PHASE (SECOND CONNECTION) ----
def handle_session(conn, client_cert_pem):
    """
    Implements assignment's session phase:
    - Client sends DH params {type: dh_client, p,g,A}
    - Server responds {type: dh_server, B}
    - Derive K = Trunc16(SHA256(Ks))
    - Use AES-128 + PKCS7 for encryption
    - RSA signatures over SHA256(seq||ts||ct)
    - Strict seqno and timestamp checks
    - Log transcript
    """

    server_priv = ser.load_pem_private_key(SERVER_KEY, password=None)

    # receive dh_client
    raw = recv_block(conn)
    msg = json.loads(raw.decode())

    if msg.get("type") != "dh_client":
        print("[server] expected dh_client")
        return

    p = int(msg["p"])
    g = int(msg["g"])
    A = int(msg["A"])

    # build parameters
    nums = dh.DHParameterNumbers(p, g)
    params = nums.parameters()

    priv = params.generate_private_key()
    B = priv.public_key().public_numbers().y

    # send B
    send_block(conn, json.dumps({"type":"dh_server","B":str(B)}).encode())

    # derive session key
    peer_nums = dh.DHPublicNumbers(A, nums)
    shared = priv.exchange(peer_nums.public_key())
    K = derive_key(shared)

    print("[server] Session key:", K.hex())

    # transcript setup
    session_id = str(int(time.time()))
    transcript_path = f"transcripts/server-{session_id}.log"
    os.makedirs("transcripts", exist_ok=True)

    expected_seq = 1
    client_cert = x509.load_pem_x509_certificate(client_cert_pem)
    client_pub = client_cert.public_key()
    client_fp = client_cert.fingerprint(hashes.SHA256()).hex()

    # main message loop
    while True:
        try:
            raw = recv_block(conn)
        except:
            break

        obj = json.loads(raw.decode())
        if obj.get("type") != "msg":
            print("[server] unknown message:", obj)
            break

        seq = int(obj["seqno"])
        ts = int(obj["ts"])
        ct_b64 = obj["ct"]
        sig_b64 = obj["sig"]

        ivct = base64.b64decode(ct_b64)
        sig = base64.b64decode(sig_b64)

        # timestamp freshness
        now_ms = int(time.time()*1000)
        if abs(now_ms - ts) > MAX_SKEW_MS:
            send_block(conn, json.dumps({"type":"nack","why":"stale"}).encode())
            continue

        # seqno check
        if seq != expected_seq:
            send_block(conn, json.dumps({"type":"nack","why":"seq_mismatch","expected":expected_seq}).encode())
            continue

        # verify RSA signature
        m = str(seq).encode() + b"||" + str(ts).encode() + b"||" + ivct
        digest = hashlib.sha256(m).digest()

        try:
            client_pub.verify(sig, digest,
                              padding.PKCS1v15(),
                              hashes.SHA256())
        except Exception as e:
            send_block(conn, json.dumps({"type":"nack","why":"sigfail"}).encode())
            continue

        # decrypt
        try:
            pt = aes_decrypt(K, ivct).decode()
        except Exception:
            send_block(conn, json.dumps({"type":"nack","why":"decrypt"}).encode())
            continue

        print(f"[server] msg {seq} -> {pt}")

        # append transcript
        with open(transcript_path, "a") as f:
            f.write(f"{seq}|{ts}|{ct_b64}|{sig_b64}|{client_fp}\n")

        expected_seq += 1

        # send ACK
        ack_msg = f"ACK for {seq}".encode()
        ack_ivct = aes_encrypt(K, ack_msg)
        ack_ivct_b64 = base64.b64encode(ack_ivct).decode()

        ack_ts = int(time.time()*1000)
        m2 = str(seq).encode() + b"||" + str(ack_ts).encode() + b"||" + ack_ivct
        sig2 = server_priv.sign(hashlib.sha256(m2).digest(),
                                padding.PKCS1v15(),
                                hashes.SHA256())

        payload = {
            "type": "ack",
            "seqno": seq,
            "ts": ack_ts,
            "ct": ack_ivct_b64,
            "sig": base64.b64encode(sig2).decode()
        }
        send_block(conn, json.dumps(payload).encode())

        # log server ACK
        server_cert = x509.load_pem_x509_certificate(SERVER_CERT)
        server_fp = server_cert.fingerprint(hashes.SHA256()).hex()

        with open(transcript_path, "a") as f:
            f.write(f"{seq}|{ack_ts}|{ack_ivct_b64}|{base64.b64encode(sig2).decode()}|{server_fp}\n")
    return transcript_path


def make_receipt(transcript_path, role):
    """
    Creates SessionReceipt with transcript hash.
    """
    if not os.path.exists(transcript_path):
        return None

    with open(transcript_path, "rb") as f:
        lines = f.read().splitlines()

    concat = b"\n".join(lines)
    digest = hashlib.sha256(concat).hexdigest()

    if lines:
        first = int(lines[0].decode().split("|",1)[0])
        last = int(lines[-1].decode().split("|",1)[0])
    else:
        first = None
        last = None

    priv = ser.load_pem_private_key(SERVER_KEY, password=None)
    sig = priv.sign(bytes.fromhex(digest), padding.PKCS1v15(), hashes.SHA256())

    receipt = {
        "type": "receipt",
        "peer": role,
        "first_seq": first,
        "last_seq": last,
        "transcript_sha256": digest,
        "sig": base64.b64encode(sig).decode()
    }

    os.makedirs("receipts", exist_ok=True)
    out_path = f"receipts/server-{int(time.time())}.json"
    with open(out_path, "w") as f:
        json.dump(receipt, f, indent=2)

    return out_path


# ---- MAIN SERVER LOOP ----
# ---- MAIN SERVER LOOP ----
def main():
    print(f"[server] listening on {HOST}:{PORT}")

    while True:
        # ------------------------------------
        # CONTROL PLANE (FIRST TCP CONNECTION)
        # ------------------------------------
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(1)

            conn, addr = s.accept()
            print("[server] control-plane connection from", addr)

            with conn:
                ok, status, client_cert = handle_control_plane(conn)

            if not ok:
                print("[server] control-plane failed:", status)
                continue

        # ------------------------------------
        # SESSION PHASE (SECOND TCP CONNECTION)
        # ------------------------------------
        print("[server] waiting for second connection for session…")

        with socket.socket() as s2:
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s2.bind((HOST, PORT))
            s2.listen(1)

            conn2, addr2 = s2.accept()
            print("[server] session connection from", addr2)

            # handle_session now RETURNS transcript_path
            with conn2:
                transcript_path = handle_session(conn2, client_cert)

            # ------------------------------------
            # CREATE SESSION RECEIPT
            # ------------------------------------
            if transcript_path:
                out = make_receipt(transcript_path, role="server")
                if out:
                    print("[server] receipt saved to", out)
                else:
                    print("[server] make_receipt() returned None (no receipt created)")
            else:
                print("[server] No transcript produced — cannot create receipt.")


if __name__ == "__main__":
    main()

