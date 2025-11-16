#!/usr/bin/env python3
import sys, os, json, base64, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
def usage():
    print("Usage: python scripts/make_receipt.py <transcript_path> <role> <privkey_pem>")
    print("Example: python scripts/make_receipt.py transcripts/server-1763290076.log server certs/server.key.pem")
    sys.exit(1)
if len(sys.argv)!=4:
    usage()
transcript_path = sys.argv[1]
role = sys.argv[2]
privkey_path = sys.argv[3]
if not os.path.exists(transcript_path):
    print("Transcript not found:", transcript_path); sys.exit(2)
with open(transcript_path,"rb") as f:
    lines = f.read().splitlines()
concat = b"\\n".join(lines)
digest = hashlib.sha256(concat).digest()
with open(privkey_path,"rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)
sig = priv.sign(digest, padding.PKCS1v15(), hashes.SHA256())
receipt = {
    "type":"receipt",
    "peer": role,
    "session_id": os.path.basename(transcript_path).split("-",1)[1].split(".")[0],
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
out = f"receipts/{role}-{receipt['session_id']}.json"
with open(out,"w") as f:
    json.dump(receipt, f, indent=2)
print("WROTE:", out)
