"""Self-signed certificate for serving the fake API (needs cryptography)."""

import datetime
import ipaddress
import os


def make_cert(directory, name='fakepve', hosts=()):
    """Write <name>.crt and <name>.key into directory; returns (certfile, keyfile, der).

    The certificate names localhost, 127.0.0.1 and every address or name in hosts (the host the fake
    listens on), so a client can verify it with the certificate as its CA.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    names = []
    for host in ('localhost', '127.0.0.1') + tuple(hosts):
        if host in ('0.0.0.0', '::', ''):
            continue
        try:
            entry = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            entry = x509.DNSName(host)
        if entry not in names:
            names.append(entry)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    certfile = os.path.join(directory, name + '.crt')
    keyfile = os.path.join(directory, name + '.key')
    with open(certfile, 'wb') as out:
        out.write(cert.public_bytes(serialization.Encoding.PEM))
    # The key is for this process only: owner read/write, whatever the umask.
    with os.fdopen(os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as out:
        os.chmod(keyfile, 0o600)
        out.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    return certfile, keyfile, cert.public_bytes(serialization.Encoding.DER)
