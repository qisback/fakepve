"""proxmoxer against the fake. Optional: skipped when proxmoxer is not installed.

    pip install 'fakepve[crypto]' proxmoxer requests pytest
    pytest examples/proxmoxer_pytest.py

proxmoxer is synchronous, so the fake runs in a thread (see requests_pytest.py).
"""

import asyncio
import threading

import pytest
from fakepve import FakePve, settle
from fakepve.certs import make_cert

proxmoxer = pytest.importorskip('proxmoxer')
pytestmark = pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')  # self-signed


@pytest.fixture
def pve(tmp_path):
    fake = FakePve(user='root@pam', password='secret')
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    certfile, keyfile, _ = make_cert(str(tmp_path))

    def run(coro):
        return asyncio.run_coroutine_threadsafe(coro, loop).result(30)
    run(fake.start(certfile, keyfile))
    yield fake
    run(settle())
    run(fake.stop())
    loop.call_soon_threadsafe(loop.stop)
    thread.join(10)
    loop.close()


def connect(pve, user='root@pam', password='secret'):
    return proxmoxer.ProxmoxAPI('{0}:{1}'.format(pve.host, pve.port), user=user, password=password,
                                verify_ssl=False)


def test_read_and_start(pve):
    vm = pve.add_vm(100, 'web1')
    api = connect(pve)
    assert api.version.get()['version'] == pve.version
    assert api.nodes('pve1').qemu(100).status.current.get()['status'] == 'stopped'
    upid = api.nodes('pve1').qemu(100).status.start.post()
    assert upid.startswith('UPID:pve1:')
    assert vm.status == 'running'


def test_errors_are_exceptions(pve):
    pve.add_vm(100, 'web1')
    pve.users['ops@pve'] = 'pw'
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    ops = connect(pve, 'ops@pve', 'pw')
    with pytest.raises(proxmoxer.core.ResourceException) as err:
        ops.nodes('pve1').qemu(100).status.start.post()
    assert err.value.status_code == 403
    assert 'Permission check failed (/vms/100, VM.PowerMgmt)' in str(err.value)
