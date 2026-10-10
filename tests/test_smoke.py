import ssl

import aiohttp
import pytest

from fakepve import FakePve, settle
from fakepve.certs import make_cert


@pytest.fixture
async def pve(tmp_path):
    certfile, keyfile, _ = make_cert(str(tmp_path))
    fake = FakePve(user='root@pam', password='secret')
    await fake.start(certfile, keyfile)
    yield fake
    await settle()
    await fake.stop()


@pytest.fixture
async def session(pve):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession(base_url='https://{0}:{1}'.format(pve.host, pve.port),
                                     connector=aiohttp.TCPConnector(ssl=ctx)) as s:
        yield s


async def login(session):
    async with session.post('/api2/json/access/ticket', data={'username': 'root@pam', 'password': 'secret'}) as r:
        data = (await r.json())['data']
    return {'Cookie': 'PVEAuthCookie=' + data['ticket'], 'CSRFPreventionToken': data['CSRFPreventionToken']}


async def test_bad_login_is_401(pve, session):
    async with session.post('/api2/json/access/ticket', data={'username': 'root@pam', 'password': 'no'}) as r:
        assert r.status == 401


async def test_resources_and_start(pve, session):
    vm = pve.add_vm(100, 'vm1')
    auth = await login(session)
    async with session.get('/api2/json/cluster/resources', headers=auth) as r:
        names = [d.get('name') for d in (await r.json())['data'] if d['type'] == 'qemu']
    assert names == ['vm1']
    async with session.post('/api2/json/nodes/pve1/qemu/100/status/start', headers=auth) as r:
        upid = (await r.json())['data']
    assert vm.status == 'running'
    async with session.get('/api2/json/nodes/pve1/tasks/{0}/status'.format(upid), headers=auth) as r:
        assert (await r.json())['data']['exitstatus'] == 'OK'


async def test_write_needs_csrf(pve, session):
    pve.add_vm(100, 'vm1')
    auth = await login(session)
    del auth['CSRFPreventionToken']
    async with session.put('/api2/json/nodes/pve1/qemu/100/config', headers=auth, json={'onboot': '1'}) as r:
        assert r.status == 401


async def test_running_vm_config_goes_pending(pve, session):
    vm = pve.add_vm(100, 'vm1', status='running', config={'cores': '1'})
    auth = await login(session)
    async with session.put('/api2/json/nodes/pve1/qemu/100/config', headers=auth, json={'cores': '2'}) as r:
        assert r.status == 200
    assert vm.config['cores'] == '1' and vm.pending['cores'] == '2'


async def test_slow_shutdown_fails_on_pves_default_timeout(pve, session):
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.shutdown_secs = pve.shutdown_default_timeout + 1
    auth = await login(session)
    async with session.post('/api2/json/nodes/pve1/qemu/100/status/shutdown', headers=auth) as r:
        upid = (await r.json())['data']
    async with session.get('/api2/json/nodes/pve1/tasks/{0}/status'.format(upid), headers=auth) as r:
        assert 'got timeout' in (await r.json())['data']['exitstatus']
    assert vm.status == 'running'
    # With a long enough timeout the same guest shuts down.
    async with session.post('/api2/json/nodes/pve1/qemu/100/status/shutdown', headers=auth,
                            json={'timeout': vm.shutdown_secs}) as r:
        assert r.status == 200
    assert vm.status == 'stopped'
