#!/usr/bin/env python3
import sys, json, base64, hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

if len(sys.argv) != 4:
    print("Usage: python tools/verify_receipt.py <receipt.json> <transcript.log> <server_cert.pem>")
    sys.exit(1)

receipt_path = sys.argv[1]
transcript_path = sys.argv[2]
server_cert_path = sys.argv[3]

with open(receipt_path, "r") as f:
    receipt = json.load(f)

# recompute transcript digest
with open(transcript_path, "rb") as f:
    lines = f.read().splitlines()

concat = b"\n".join(lines)
digest = hashlib.sha256(concat).hexdigest()

print("Recomputed transcript sha256:", digest)
print("Receipt transcript_sha256:", receipt.get("transcript_sha256"))

if digest != receipt.get("transcript_sha256"):
    print("WARNING: transcript hash does NOT match receipt value!")
else:
    print("Transcript hash matches the receipt value.")

# verify receipt signature
sig = base64.b64decode(receipt["sig"])
digest_bytes = bytes.fromhex(receipt["transcript_sha256"])

with open(server_cert_path, "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())
pub = cert.public_key()

try:
    pub.verify(sig,
               digest_bytes,
               padding.PKCS1v15(),
               hashes.SHA256())
    print("Signature verification: OK (receipt signature valid)")
except Exception as e:
    print("Signature verification: FAILED:", e)
