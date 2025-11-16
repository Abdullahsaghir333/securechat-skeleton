#!/usr/bin/env python3
# tools/tamper_replay.py
import argparse, socket, struct, json, base64, os, sys, time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import hashlib, traceback

HOST="127.0.0.1"
PORT=9555

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

def derive_key(shared):
    import hashlib
    return hashlib.sha256(shared).digest()[:16]

def parse_transcript_line(line):
    # expected format: seq|ts|ct_b64|sig_b64|peer_fp
    parts = line.strip().split("|")
    if len(parts) < 4:
        raise ValueError("bad transcript line")
    seq = int(parts[0])
    ts = int(parts[1])
    ct_b64 = parts[2]
    sig_b64 = parts[3]
    return seq, ts, ct_b64, sig_b64

def flip_one_bit(b: bytes):
    if len(b) == 0:
        return b
    arr = bytearray(b)
    arr[0] ^= 1  # flip least-significant bit of first byte
    return bytes(arr)

def do_session_and_send(out_json):
    # perform DH handshake (client side)
    conn = socket.create_connection((HOST, PORT))
    try:
        # send dh_client with fresh params
        params = dh.generate_parameters(generator=2, key_size=2048)
        nums = params.parameter_numbers()
        p = nums.p; g = nums.g
        priv = params.generate_private_key()
        A = priv.public_key().public_numbers().y

        send_block(conn, json.dumps({"type":"dh_client","p":str(p),"g":str(g),"A":str(A)}).encode())

        # receive dh_server
        raw = recv_block(conn)
        resp = json.loads(raw.decode())
        if resp.get("type") != "dh_server":
            print("Bad dh_server:", resp); conn.close(); return
        B = int(resp["B"])

        peer_nums = dh.DHPublicNumbers(B, dh.DHParameterNumbers(p,g))
        shared = priv.exchange(peer_nums.public_key())
        K = derive_key(shared)
        print("[tool] derived session key:", K.hex())

        # send our crafted message JSON
        send_block(conn, json.dumps(out_json).encode())

        # receive server response (ACK or NACK)
        raw2 = recv_block(conn)
        resp2 = json.loads(raw2.decode())
        print("[tool] server response:", json.dumps(resp2, indent=2))
    finally:
        try: conn.close()
        except: pass

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=("tamper","replay"), required=True)
    p.add_argument("--transcript", required=True, help="path to client transcript (e.g. transcripts/client-123.log)")
    p.add_argument("--line", type=int, default=-1, help="line number (1-based) from transcript; default last line")
    args = p.parse_args()

    if not os.path.exists(args.transcript):
        print("Transcript not found:", args.transcript); sys.exit(1)

    with open(args.transcript,"r") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    if not lines:
        print("No lines in transcript"); sys.exit(1)

    idx = args.line-1 if args.line>0 else len(lines)-1
    if idx < 0 or idx >= len(lines):
        print("invalid line index"); sys.exit(1)

    seq, ts, ct_b64, sig_b64 = parse_transcript_line(lines[idx])
    ivct = base64.b64decode(ct_b64)
    sig = base64.b64decode(sig_b64)

    if args.mode == "tamper":
        ivct_tampered = flip_one_bit(ivct)
        ct_tampered_b64 = base64.b64encode(ivct_tampered).decode()
        out = {"type":"msg","seqno":seq,"ts":ts,"ct":ct_tampered_b64,"sig":sig_b64}
        print(f"[tool] sending tampered message (seq={seq})")
        do_session_and_send(out)
    else:
        out = {"type":"msg","seqno":seq,"ts":ts,"ct":ct_b64,"sig":sig_b64}
        print(f"[tool] replaying recorded message (seq={seq})")
        do_session_and_send(out)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
