# scripts/gen_cert.py
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import sys
import os
import ipaddress

def generate_cert(common_name, is_server=False):
    with open("certs/ca.key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open("certs/ca.cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    key_path = f"certs/{common_name}.key.pem"
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )

    san_list = [x509.DNSName(common_name)]
    if is_server:
        san_list.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    else:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)

    builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    cert = builder.sign(ca_key, hashes.SHA256())

    cert_path = f"certs/{common_name}.cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificate generated: {common_name}")
    print(f"Private key: {key_path}")
    print(f"Certificate: {cert_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/gen_cert.py <common_name> [--server]")
        sys.exit(1)
    name = sys.argv[1]
    server_flag = ("--server" in sys.argv)
    generate_cert(name, is_server=server_flag)
