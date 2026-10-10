"""Self-signed certificate for serving the fake API (needs cryptography)."""

import datetime
import os


def make_cert(directory, name='fakepve'):
    """Write <name>.crt and <name>.key into directory; returns (certfile, keyfile, der)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    certfile = os.path.join(directory, name + '.crt')
    keyfile = os.path.join(directory, name + '.key')
    with open(certfile, 'wb') as out:
        out.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, 'wb') as out:
        out.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    return certfile, keyfile, cert.public_bytes(serialization.Encoding.DER)
