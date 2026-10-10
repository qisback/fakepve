import asyncio
import time

import aiohttp
import pytest

VM = '/nodes/pve1/qemu/100'
SCALE = 0.01  # 1 PVE second = 10ms


async def wait_task(api, upid, node='pve1'):
    while True:
        task = await api.data('GET', '/nodes/{0}/tasks/{1}/status'.format(node, upid))
        if task['status'] == 'stopped':
            return task
        await asyncio.sleep(0.01)


# ---------------------------------------------------------------- shutdowns

async def test_delayed_shutdown_beats_pves_default_timeout(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.shutdown_secs = pve.shutdown_default_timeout + 30
    task = await wait_task(api, await api.data('POST', VM + '/status/shutdown'))
    assert task['exitstatus'] == 'VM quit/powerdown failed - got timeout'
    assert vm.status == 'running'
    task = await wait_task(api, await api.data('POST', VM + '/status/shutdown', {'timeout': 120}))
    assert task['exitstatus'] == 'OK' and vm.status == 'stopped'


async def test_force_stop_after_timeout(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.acpi = False
    task = await wait_task(api, await api.data('POST', VM + '/status/shutdown', {'forceStop': 1}))
    assert task['exitstatus'] == 'OK' and vm.status == 'stopped'
    log = await api.data('GET', '/nodes/pve1/tasks/{0}/log'.format(task['upid']))
    assert any('SIGTERM' in line['t'] for line in log)


async def test_shutdown_runs_in_real_time(pve, api):
    pve.time_scale = SCALE
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.shutdown_secs = 30
    upid = await api.data('POST', VM + '/status/shutdown')
    assert (await api.data('GET', '/nodes/pve1/tasks/{0}/status'.format(upid)))['status'] == 'running'
    assert vm.status == 'running'
    started = time.monotonic()
    await wait_task(api, upid)
    assert vm.status == 'stopped' and time.monotonic() - started >= 0.25


# -------------------------------------------------------------------- locks

async def test_locked_vm_refuses_reboot_and_config(pve, api):
    pve.add_vm(100, 'vm1', status='running')
    pve.time_scale = SCALE
    await pve.backup(100, secs=60)
    await asyncio.sleep(0.05)
    status, body = await api.call('POST', VM + '/status/reboot')
    assert status == 500 and body['message'] == 'VM is locked (backup)\n'
    status, body = await api.call('PUT', VM + '/config', {'onboot': 1})
    assert status == 500 and 'VM is locked (backup)' in body['message']


async def test_held_config_lock_times_out_writes(pve, api):
    pve.time_scale = SCALE
    pve.add_vm(100, 'vm1')
    await pve.hold_config_lock(100, secs=None)
    started = time.monotonic()
    status, body = await api.call('PUT', VM + '/config', {'onboot': 1})
    assert status == 500 and "can't lock file '/var/lock/qemu-server/lock-100.conf' - got timeout" in body['message']
    assert time.monotonic() - started >= pve.lock_wait * SCALE * 0.9


async def test_config_write_waits_for_a_short_lock(pve, api):
    pve.time_scale = SCALE
    vm = pve.add_vm(100, 'vm1')
    await pve.hold_config_lock(100, secs=3)
    await api.data('PUT', VM + '/config', {'onboot': 1})
    assert vm.config['onboot'] == 1


async def test_power_task_fails_on_held_lock(pve, api):
    pve.time_scale = SCALE
    vm = pve.add_vm(100, 'vm1')
    await pve.hold_config_lock(100, secs=None)
    task = await wait_task(api, await api.data('POST', VM + '/status/start'))
    assert "can't lock file" in task['exitstatus'] and vm.status == 'stopped'


async def test_interrupted_snapshot_leaves_a_lock(pve, api):
    pve.add_vm(100, 'vm1')
    pve.snapshot_lock(100)
    status, body = await api.call('POST', VM + '/status/start')
    assert status == 500 and body['message'] == 'VM is locked (snapshot)\n'
    pve.unlock(100)
    await wait_task(api, await api.data('POST', VM + '/status/start'))


# -------------------------------------------------------------- the cluster

async def test_lost_quorum_blocks_writes_not_reads(pve, api):
    pve.add_vm(100, 'vm1')
    pve.lose_quorum()
    status, body = await api.call('POST', VM + '/status/start')
    assert status == 500 and body['message'] == 'cluster not ready - no quorum?\n'
    status, body = await api.call('PUT', VM + '/config', {'onboot': 1})
    assert status == 500 and 'no quorum' in body['message']
    assert (await api.data('GET', VM + '/status/current'))['status'] == 'stopped'
    cluster = await api.data('GET', '/cluster/status')
    assert cluster[0]['quorate'] == 0
    pve.regain_quorum()
    await api.data('PUT', VM + '/config', {'onboot': 1})


async def test_offline_node(pve, api):
    pve.add_vm(100, 'vm1')
    pve.add_vm(200, 'vm2', node='pve2', status='running')
    pve.set_node_offline('pve2')
    status, body = await api.call('GET', '/nodes/pve2/qemu/200/status/current')
    assert status == 595
    resources = await api.data('GET', '/cluster/resources?type=vm')
    assert {r['name']: r['status'] for r in resources} == {'vm1': 'stopped', 'vm2': 'unknown'}


async def test_migration_moves_the_vm(pve, api):
    pve.time_scale = SCALE
    vm = pve.add_vm(100, 'vm1', status='running')
    upid = await pve.migrate(100, 'pve2', secs=5)
    await asyncio.sleep(0.01)
    status, body = await api.call('POST', VM + '/status/shutdown')
    assert status == 500 and 'locked (migrate)' in body['message']
    await wait_task(api, upid)
    assert vm.node == 'pve2' and vm.lock is None
    status, _ = await api.call('GET', VM + '/status/current')
    assert status == 500
    await api.data('GET', '/nodes/pve2/qemu/100/status/current')


async def test_ha_managed_vm_acts_later(pve, api):
    pve.time_scale = SCALE
    vm = pve.add_vm(100, 'vm1')
    vm.ha_state = 'stopped'
    task = await wait_task(api, await api.data('POST', VM + '/status/start'))
    assert task['type'] == 'hastart' and task['exitstatus'] == 'OK'
    assert vm.status == 'stopped'
    await asyncio.sleep(pve.ha_delay * SCALE * 1.5)
    assert vm.status == 'running'


# ------------------------------------------------------------------ network

async def test_slow_network(pve, api):
    pve.time_scale = SCALE
    pve.add_vm(100, 'vm1')
    pve.slow_network(20)
    started = time.monotonic()
    await api.data('GET', VM + '/status/current')
    assert time.monotonic() - started >= 0.18


async def test_dropped_connections(pve, api):
    pve.add_vm(100, 'vm1')
    pve.flaky_network(drop_rate=1.0)
    with pytest.raises(aiohttp.ClientError):
        await api.call('GET', VM + '/status/current')
    pve.flaky_network(drop_rate=0.0)
    await api.data('GET', VM + '/status/current')


# --------------------------------------------------------------------- ceph

async def test_ceph_down_breaks_rbd_vms_only(pve, api):
    pve.add_ceph_storage('ceph-pool')
    on_ceph = pve.add_vm(100, 'vm1', config={'scsi0': 'ceph-pool:vm-100-disk-0,size=8G'})
    local = pve.add_vm(101, 'vm2', config={'scsi0': 'local-lvm:vm-101-disk-0,size=8G'})
    pve.ceph_down()
    task = await wait_task(api, await api.data('POST', VM + '/status/start'))
    assert task['exitstatus'].startswith('rbd error') and on_ceph.status == 'stopped'
    await wait_task(api, await api.data('POST', '/nodes/pve1/qemu/101/status/start'))
    assert local.status == 'running'
    status, body = await api.call('GET', '/nodes/pve1/storage/ceph-pool/content')
    assert status == 500 and 'rbd' in body['message']
    status, body = await api.call('GET', '/cluster/ceph/status')
    assert status == 500
    pve.ceph_recover()
    await wait_task(api, await api.data('POST', VM + '/status/start'))
    assert on_ceph.status == 'running'


async def test_slow_ceph_stretches_tasks(pve, api):
    pve.time_scale = SCALE
    pve.add_ceph_storage('ceph-pool')
    pve.add_vm(100, 'vm1', config={'scsi0': 'ceph-pool:vm-100-disk-0'})
    pve.ceph_slow(30)
    assert (await api.data('GET', '/cluster/ceph/status'))['health']['status'] == 'HEALTH_WARN'
    started = time.monotonic()
    await wait_task(api, await api.data('POST', VM + '/status/start'))
    assert time.monotonic() - started >= 0.25


# --------------------------------------------------------- auth and access

async def test_ticket_expiry(pve, api):
    pve.add_vm(100, 'vm1')
    for session in pve.tickets.values():
        session['expires'] = 0
    status, body = await api.call('GET', VM + '/status/current')
    assert status == 401 and 'invalid PVE ticket' in body['message']


async def test_permissions(pve, api):
    pve.users['ops@pve'] = 'pw'
    pve.add_vm(100, 'vm1', pool='lab')
    pve.add_vm(101, 'vm2')
    pve.grant('ops@pve', '/pool/lab', 'VM.Audit', 'VM.PowerMgmt')
    await api.login('ops@pve', 'pw')
    resources = await api.data('GET', '/cluster/resources?type=vm')
    assert [r['name'] for r in resources] == ['vm1']
    status, body = await api.call('PUT', VM + '/config', {'cores': 2})
    assert status == 403 and body['message'] == 'Permission check failed (/vms/100, VM.Config.CPU)\n'
    await wait_task(api, await api.data('POST', VM + '/status/start'))


async def test_hookscript_is_root_only(pve, api):
    pve.users['ops@pve'] = 'pw'
    pve.add_vm(100, 'vm1')
    pve.grant('ops@pve', '/', 'VM.Config.Options', 'VM.Config.HWType')
    await api.login('ops@pve', 'pw')
    status, body = await api.call('PUT', VM + '/config', {'hookscript': 'local:snippets/x.pl'})
    assert status == 403 and "only root can set 'hookscript'" in body['message']


# ---------------------------------------------------------- API behaviour

async def test_running_vm_config_goes_pending(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running', config={'cores': '1'})
    await api.data('PUT', VM + '/config', {'cores': '2', 'description': 'note'})
    assert vm.config['cores'] == '1' and vm.pending['cores'] == '2'
    assert vm.config['description'] == 'note'
    await wait_task(api, await api.data('POST', VM + '/status/reboot'))
    assert vm.config['cores'] == '2' and not vm.pending


async def test_reset_does_not_apply_pending(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running', config={'cores': '1'})
    await api.data('PUT', VM + '/config', {'cores': '2'})
    await wait_task(api, await api.data('POST', VM + '/status/reset'))
    assert vm.config['cores'] == '1'


async def test_stale_digest_is_refused(pve, api):
    pve.add_vm(100, 'vm1')
    digest = (await api.data('GET', VM + '/config'))['digest']
    await api.data('PUT', VM + '/config', {'onboot': 1})
    status, body = await api.call('PUT', VM + '/config', {'onboot': 0, 'digest': digest})
    assert status == 500 and 'detected modified configuration' in body['message']


async def test_boot_order_must_name_devices(pve, api):
    pve.add_vm(100, 'vm1', config={'scsi0': 'local-lvm:vm-100-disk-0'})
    status, body = await api.call('PUT', VM + '/config', {'boot': 'order=scsi0;net0'})
    assert status == 400 and 'net0' in body['errors']['boot']


async def test_wrong_state_errors(pve, api):
    pve.add_vm(100, 'vm1', status='running')
    pve.add_vm(9000, 'tmpl', template=True)
    status, body = await api.call('POST', VM + '/status/start')
    assert body['message'] == 'VM 100 already running\n'
    status, body = await api.call('POST', '/nodes/pve1/qemu/9000/status/start')
    assert "can't start a vm if it's a template" in body['message']
    status, body = await api.call('POST', VM + '/status/frobnicate')
    assert status == 501


async def test_hibernate_and_resume(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running')
    await wait_task(api, await api.data('POST', VM + '/status/suspend', {'todisk': 1}))
    assert vm.status == 'stopped' and vm.lock == 'suspended'
    await wait_task(api, await api.data('POST', VM + '/status/start'))
    assert vm.status == 'running' and vm.lock is None


async def test_guest_agent(pve, api):
    pve.time_scale = SCALE
    vm = pve.add_vm(100, 'vm1', status='running')
    status, body = await api.call('GET', VM + '/agent/get-osinfo')
    assert body['message'] == 'QEMU guest agent is not running\n'
    vm.agent = {'os': {'name': 'Debian'}}
    assert (await api.data('GET', VM + '/agent/get-osinfo'))['result']['name'] == 'Debian'
    vm.agent_hangs = True
    status, body = await api.call('GET', VM + '/agent/get-osinfo')
    assert 'got timeout' in body['message']


async def test_storage_full(pve, api):
    pve.storages['local']['avail'] = 1000
    task = await wait_task(api, await api.data('POST', '/nodes/pve1/storage/local/download-url',
                                                 {'content': 'iso', 'filename': 'big.iso', 'url': 'http://x/big.iso',
                                                  'size': 5000}))
    assert 'No space left on device' in task['exitstatus']
