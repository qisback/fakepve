"""The generated certificate verifies when it is the client's CA."""

import asyncio
import os
import socket
import ssl
import stat

import pytest

from fakepve import FakePve, settle
from fakepve.certs import make_cert


def test_certificate_has_sans_and_server_usage(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID
    certfile, keyfile, der = make_cert(str(tmp_path), hosts=('127.0.0.9', 'pve.test', '0.0.0.0'))
    cert = x509.load_der_x509_certificate(der)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sorted(san.get_values_for_type(x509.DNSName)) == ['localhost', 'pve.test']
    assert sorted(str(a) for a in san.get_values_for_type(x509.IPAddress)) == ['127.0.0.1', '127.0.0.9']
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert constraints.critical and constraints.value.ca is False
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and not usage.key_cert_sign
    assert ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == 'secp256r1'
    if os.name == 'posix':
        assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600


def connect(host, port, cafile, server_hostname=None):
    ctx = ssl.create_default_context(cafile=cafile)
    with socket.create_connection((host, port), 5) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_hostname or host) as tls:
            return tls.version()


@pytest.mark.skipif(os.name != 'posix', reason='needs the whole of 127.0.0.0/8')
async def test_client_verifies_by_address_and_by_localhost(tmp_path):
    pve = FakePve(host='127.0.0.7', port=0)
    certfile, keyfile, _ = make_cert(str(tmp_path), hosts=(pve.host,))
    await pve.start(certfile, keyfile)
    try:
        assert pve.port and pve.url == 'https://127.0.0.7:{0}'.format(pve.port)
        loop = asyncio.get_running_loop()
        assert await loop.run_in_executor(None, connect, '127.0.0.7', pve.port, certfile)
        assert await loop.run_in_executor(None, connect, '127.0.0.7', pve.port, certfile, 'localhost')
        with pytest.raises(ssl.SSLCertVerificationError):
            await loop.run_in_executor(None, connect, '127.0.0.7', pve.port, certfile, 'other.example')
    finally:
        await settle()
        await pve.stop()


async def test_verification_by_127_0_0_1(tmp_path):
    pve = FakePve(host='127.0.0.1', port=0)
    certfile, keyfile, _ = make_cert(str(tmp_path), hosts=(pve.host,))
    await pve.start(certfile, keyfile)
    try:
        assert await asyncio.get_running_loop().run_in_executor(None, connect, '127.0.0.1', pve.port, certfile)
    finally:
        await settle()
        await pve.stop()
