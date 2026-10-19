"""The command line and the certificate: private key permissions, temporary files, the exposure warning."""

import asyncio
import os
import stat
import sys

import pytest


# ------------------------------------------------------- F12: key and temp files

@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX permissions')
def test_private_key_is_owner_only(tmp_path):
    from fakepve.certs import make_cert
    old = os.umask(0)
    try:
        _, keyfile, _ = make_cert(str(tmp_path))
        assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600
        os.chmod(keyfile, 0o644)  # an existing, loose file is tightened too
        make_cert(str(tmp_path))
        assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600
    finally:
        os.umask(old)


def test_cli_leaves_no_certificate_files_behind(tmp_path):
    from test_cli import GUESTS, Cli, free_port
    port = free_port('127.0.0.1')
    server = Cli([GUESTS, '--host', '127.0.0.1', '--port', str(port), '--time-scale', '0'], '127.0.0.1', port,
                 TMPDIR=str(tmp_path), TEMP=str(tmp_path), TMP=str(tmp_path))
    try:
        assert server.banner.startswith('fakepve listening')
        assert os.listdir(str(tmp_path)) == []
        assert server.login()[0] == 200
    finally:
        server.stop()
    assert os.listdir(str(tmp_path)) == []


# ------------------------------------------------- F4: public default credentials

def test_exposed_default_credentials_warn(capsys):
    from fakepve.__main__ import warn_if_exposed
    assert warn_if_exposed('0.0.0.0', 'secret') is True
    err = capsys.readouterr().err
    assert 'WARNING' in err and 'default password' in err and '0.0.0.0' in err
    assert warn_if_exposed('192.0.2.7', 'secret') is True
    assert warn_if_exposed('example.org', 'secret') is True


@pytest.mark.parametrize('host,password', [('127.0.0.2', 'secret'), ('127.5.5.5', 'secret'), ('::1', 'secret'),
                                           ('localhost', 'secret'), ('0.0.0.0', 'chosen'), ('::', 'chosen')])
def test_no_warning_when_safe(capsys, host, password):
    from fakepve.__main__ import warn_if_exposed
    assert warn_if_exposed(host, password) is False
    assert capsys.readouterr().err == ''


def test_main_warns_before_serving(monkeypatch, capsys):
    from fakepve import __main__ as cli
    served = []
    monkeypatch.setattr(cli, 'serve', lambda args: served.append(args) or asyncio.sleep(0))
    monkeypatch.delenv('PVE_PASS', raising=False)
    monkeypatch.setattr(sys, 'argv', ['fakepve', 'g.json', '--host', '0.0.0.0'])
    cli.main()
    assert 'WARNING' in capsys.readouterr().err and served
    monkeypatch.setattr(sys, 'argv', ['fakepve', 'g.json', '--host', '0.0.0.0', '--password', 'x'])
    cli.main()
    assert capsys.readouterr().err == ''
    monkeypatch.setenv('PVE_PASS', 'fromenv')
    monkeypatch.setattr(sys, 'argv', ['fakepve', 'g.json', '--host', '0.0.0.0'])
    cli.main()
    assert capsys.readouterr().err == ''
