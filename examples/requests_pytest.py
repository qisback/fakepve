"""pytest with a synchronous client (requests): the fake runs in a thread.

    pip install 'fakepve[crypto]' requests pytest
    pytest examples/requests_pytest.py

The fake lives on an asyncio loop in a background thread. Setting plain
attributes (vm.shutdown_secs, pve.tfa, ...) from the test thread is fine;
for the coroutines (pve.backup, pve.migrate, pve.hold_config_lock) use
fake.run(...).
"""

import asyncio
import threading
import time

import pytest
from fakepve import FakePve, settle
from fakepve.certs import make_cert

requests = pytest.importorskip('requests')
pytestmark = pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')  # self-signed


class ThreadedFake(object):
    """A FakePve served from its own thread; `pve` is the object to configure."""

    def __init__(self, certfiles, **attrs):
        self.pve = FakePve(user='root@pam', password='secret')
        for name, value in attrs.items():
            setattr(self.pve, name, value)
        self.certfiles = certfiles
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)

    def run(self, coro):
        """Run a coroutine on the fake's loop and wait for it."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(30)

    def __enter__(self):
        self.thread.start()
        self.run(self.pve.start(*self.certfiles))
        return self

    def __exit__(self, *exc):
        self.run(settle())
        self.run(self.pve.stop())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)
        self.loop.close()


class Pve(object):
    """A small synchronous client."""

    def __init__(self, fake, user='root@pam', password='secret'):
        self.base = 'https://{0}:{1}/api2/json'.format(fake.pve.host, fake.pve.port)
        self.session = requests.Session()
        self.session.verify = False          # self-signed certificate
        data = self.session.post(self.base + '/access/ticket',
                                 data={'username': user, 'password': password}).json()['data']
        self.session.cookies.set('PVEAuthCookie', data['ticket'])
        self.session.headers['CSRFPreventionToken'] = data['CSRFPreventionToken']

    def call(self, method, path, **params):
        rsp = self.session.request(method, self.base + path, data=params or None)
        return rsp.status_code, rsp.json()

    def wait(self, upid, node='pve1'):
        while True:
            task = self.call('GET', '/nodes/{0}/tasks/{1}/status'.format(node, upid))[1]['data']
            if task['status'] == 'stopped':
                return task
            time.sleep(0.01)


@pytest.fixture(scope='session')
def certfiles(tmp_path_factory):
    certfile, keyfile, _ = make_cert(str(tmp_path_factory.mktemp('pki')))
    return certfile, keyfile


def test_start_and_follow_the_task(certfiles):
    with ThreadedFake(certfiles) as fake:
        vm = fake.pve.add_vm(100, 'web1')
        api = Pve(fake)
        status, body = api.call('POST', '/nodes/pve1/qemu/100/status/start')
        assert status == 200
        assert api.wait(body['data'])['exitstatus'] == 'OK'
        assert vm.status == 'running'


def test_locked_by_a_backup(certfiles):
    with ThreadedFake(certfiles, time_scale=0.01) as fake:
        fake.pve.add_vm(100, 'web1', status='running')
        fake.run(fake.pve.backup(100, secs=60))          # a coroutine: run it on the fake's loop
        status, body = Pve(fake).call('POST', '/nodes/pve1/qemu/100/status/shutdown')
        assert status == 500
        assert body['message'] == 'VM is locked (backup)\n'


def test_validation_error(certfiles):
    with ThreadedFake(certfiles) as fake:
        status, body = Pve(fake).call('POST', '/nodes/pve1/lxc/50/status/start')
        assert status == 400
        assert body['errors'] == {'vmid': 'invalid format - value does not look like a valid VM ID\n'}
