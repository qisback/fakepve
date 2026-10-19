"""pytest with an aiohttp client: the fake runs in the test's own event loop.

    pip install 'fakepve[crypto]' aiohttp pytest pytest-asyncio
    pytest examples/aiohttp_pytest.py

Durations are PVE seconds; time_scale=0 (the default) finishes every task
before the request returns, which keeps tests fast and deterministic.
"""

import ssl

import aiohttp
import pytest
import pytest_asyncio
from fakepve import FakePve, settle
from fakepve.certs import make_cert

pytestmark = pytest.mark.asyncio


@pytest.fixture(scope='session')
def cert(tmp_path_factory):
    certfile, keyfile, _ = make_cert(str(tmp_path_factory.mktemp('pki')))
    return certfile, keyfile


@pytest_asyncio.fixture
async def pve(cert):
    fake = FakePve(user='root@pam', password='secret')   # its own loopback address, port 8006
    yield fake
    await settle()
    await fake.stop()


async def connect(fake, cert):
    """Start the fake and return a logged-in session: ticket cookie and CSRF header."""
    await fake.start(*cert)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # the certificate is self-signed
    ctx.verify_mode = ssl.CERT_NONE
    session = aiohttp.ClientSession(base_url='https://{0}:{1}'.format(fake.host, fake.port),
                                    connector=aiohttp.TCPConnector(ssl=ctx))
    async with session.post('/api2/json/access/ticket',
                            data={'username': 'root@pam', 'password': 'secret'}) as rsp:
        data = (await rsp.json())['data']
    session.headers.update({'Cookie': 'PVEAuthCookie=' + data['ticket'],
                            'CSRFPreventionToken': data['CSRFPreventionToken']})
    return session


async def test_start_a_vm(pve, cert):
    vm = pve.add_vm(100, 'web1')
    async with await connect(pve, cert) as session:
        async with session.post('/api2/json/nodes/pve1/qemu/100/status/start') as rsp:
            upid = (await rsp.json())['data']
        async with session.get('/api2/json/nodes/pve1/tasks/{0}/status'.format(upid)) as rsp:
            task = (await rsp.json())['data']
    assert task['status'] == 'stopped' and task['exitstatus'] == 'OK'
    assert vm.status == 'running'


async def test_shutdown_that_outlasts_the_timeout(pve, cert):
    vm = pve.add_vm(100, 'web1', status='running')
    vm.shutdown_secs = pve.shutdown_default_timeout + 30    # slower than PVE waits
    async with await connect(pve, cert) as session:
        async with session.post('/api2/json/nodes/pve1/qemu/100/status/shutdown') as rsp:
            upid = (await rsp.json())['data']
        async with session.get('/api2/json/nodes/pve1/tasks/{0}/status'.format(upid)) as rsp:
            task = (await rsp.json())['data']
    assert task['exitstatus'] == 'VM quit/powerdown failed - got timeout'
    assert vm.status == 'running'


async def test_a_real_pve_error_by_name(pve, cert):
    pve.add_vm(100, 'web1', status='running')
    pve.fail('DELETE', '/nodes/pve1/qemu/100', error='running_destroy_failed')
    async with await connect(pve, cert) as session:
        async with session.delete('/api2/json/nodes/pve1/qemu/100') as rsp:
            assert rsp.status == 500
            assert (await rsp.json())['message'] == 'VM 100 is running - destroy failed\n'
