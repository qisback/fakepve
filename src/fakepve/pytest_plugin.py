"""pytest fixtures that serve a fake PVE: fakepve, fakepve_session, fakepve_url and fakepve_cafile.

The fake runs on its own event loop in a thread, so the fixtures work in plain and async tests alike
and need no pytest-asyncio. It listens on 127.0.0.1 with a port the system picks, so parallel tests
and pytest-xdist workers never collide. Needs the crypto extra (pip install 'fakepve[crypto]').
"""

import asyncio
import threading

import pytest

from .certs import make_cert
from .server import FakePve, settle

HOST = '127.0.0.1'
START_TIMEOUT = 30


class _Serving(object):
    """A FakePve served on a private event loop in a daemon thread."""

    def __init__(self, pve, certfile, keyfile):
        self.pve = pve
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, name='fakepve-' + str(id(pve)), daemon=True)
        self.thread.start()
        try:
            self._call(pve.start(certfile, keyfile))
        except BaseException:
            self._halt()
            raise

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(START_TIMEOUT)

    def _halt(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(START_TIMEOUT)
        if not self.thread.is_alive():
            self.loop.close()

    def stop(self):
        try:
            self._call(settle())
            self._call(self.pve.stop())
        finally:
            self._halt()


def _options(request):
    marker = request.node.get_closest_marker('fakepve')
    options = dict(user='root@pam', password='secret', time_scale=0)
    if marker:
        unknown = set(marker.kwargs) - set(options)
        if unknown or marker.args:
            raise pytest.UsageError('fakepve marker takes user, password and time_scale, not {0}'.format(
                sorted(unknown) or 'positional arguments'))
        options.update(marker.kwargs)
    return options


def _serve(options, pki):
    pve = FakePve(user=options['user'], password=options['password'], host=HOST, port=0)
    pve.time_scale = options['time_scale']
    return _Serving(pve, *pki)


def pytest_configure(config):
    config.addinivalue_line(
        'markers', 'fakepve(user=, password=, time_scale=): options for the fakepve fixture '
                   '(defaults root@pam, secret, 0)')


@pytest.fixture(scope='session')
def _fakepve_pki(tmp_path_factory):
    try:
        return make_cert(str(tmp_path_factory.mktemp('fakepve-pki')), hosts=(HOST,))[:2]
    except ModuleNotFoundError as exc:
        pytest.fail("fakepve's fixtures need the cryptography package: pip install 'fakepve[crypto]' ({0})".format(exc))


@pytest.fixture(scope='session')
def fakepve_cafile(_fakepve_pki):
    """Path of the self-signed certificate every fake serves; use it as the CA to verify the connection."""
    return _fakepve_pki[0]


@pytest.fixture
def fakepve(request, _fakepve_pki):
    """A started FakePve for one test, with time_scale 0; add guests and faults before or while using it."""
    serving = _serve(_options(request), _fakepve_pki)
    try:
        yield serving.pve
    finally:
        serving.stop()


@pytest.fixture(scope='session')
def fakepve_session(_fakepve_pki):
    """One started FakePve for the whole session (root@pam / secret, time_scale 0). State persists between tests."""
    serving = _serve(dict(user='root@pam', password='secret', time_scale=0), _fakepve_pki)
    try:
        yield serving.pve
    finally:
        serving.stop()


@pytest.fixture
def fakepve_url(fakepve):
    """https://host:port of the fakepve fixture."""
    return fakepve.url
