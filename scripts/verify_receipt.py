
#!/usr/bin/env python3
# scripts/verify_receipt.py
import sys, json, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def usage():
    print("Usage: python scripts/verify_receipt.py <receipt.json> <signer_cert.pem>")
    sys.exit(1)

if len(sys.argv) != 3:
    usage()

receipt_path = sys.argv[1]; signer_cert_path = sys.argv[2]
r = json.load(open(receipt_path))
sig = base64.b64decode(r["sig"])
digest_hex = r["transcript_sha256"]
digest = bytes.fromhex(digest_hex)

cert = x509.load_pem_x509_certificate(open(signer_cert_path,"rb").read())
pub = cert.public_key()
try:
    pub.verify(sig, digest, padding.PKCS1v15(), hashes.SHA256())
    print("OK: receipt signature valid")
    print("peer:", r.get("peer"))
    print("session_id:", r.get("session_id"))
    print("first_seq:", r.get("first_seq"), "last_seq:", r.get("last_seq"))
    print("transcript_sha256:", digest_hex)
except Exception as e:
    print("INVALID: ", e)
    sys.exit(2)
