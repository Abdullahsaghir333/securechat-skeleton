#!/usr/bin/env python3
# Verify a single line of the transcript (message-level non-repudiation)

import sys, base64, hashlib
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

if len(sys.argv) != 3:
    print("Usage: python tools/verify_message.py '<line>' <cert.pem>")
    sys.exit(1)

line = sys.argv[1]
cert_path = sys.argv[2]

parts = line.split("|")
seq = parts[0]
ts  = parts[1]
ct_b64 = parts[2]
sig_b64 = parts[3]

ivct = base64.b64decode(ct_b64)
sig  = base64.b64decode(sig_b64)

# recompute digest exactly as assignment requires
m = seq.encode() + b"||" + ts.encode() + b"||" + ivct
digest = hashlib.sha256(m).digest()

# load cert
cert = x509.load_pem_x509_certificate(open(cert_path,"rb").read())
pub  = cert.public_key()

try:
    pub.verify(sig, digest, padding.PKCS1v15(), hashes.SHA256())
    print("Message signature OK ✔")
except Exception as e:
    print("Message signature FAILED ✗:", e)
