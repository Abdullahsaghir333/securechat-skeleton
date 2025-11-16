# scripts/gen_ca.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os

def generate_ca():
    os.makedirs("certs", exist_ok=True)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open("certs/ca.key.pem", "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    ca_cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
    )

    ca_cert = ca_cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    with open("certs/ca.cert.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("CA generated successfully!")
    print("Stored in certs/ca.key.pem and certs/ca.cert.pem")


if __name__ == "__main__":
    generate_ca()
