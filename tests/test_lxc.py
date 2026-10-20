"""Containers keep state: what is written can be read back, and PVE's rules and wording apply."""

import asyncio
import time

import pytest

from conftest import Client

from fakepve import FakeCt

CT = '/nodes/pve1/lxc/100'
TEMPLATE = 'local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst'
SCALE = 0.01  # 1 PVE second = 10ms
NET = 'name=eth0,bridge=vmbr0,ip=192.0.2.10/24,gw=192.0.2.1'


async def wait_task(api, upid, node='pve1'):
    while True:
        task = await api.data('GET', '/nodes/{0}/tasks/{1}/status'.format(node, upid))
        if task['status'] == 'stopped':
            return task
        await asyncio.sleep(0.01)


async def done(api, upid, node='pve1'):
    task = await wait_task(api, upid, node)
    assert task['exitstatus'] == 'OK', task
    return task


async def failed(api, call, message, node='pve1'):
    """The task a call starts ends with exactly this message."""
    task = await wait_task(api, await api.data(*call), node)
    assert task['exitstatus'] == message
    return task


async def make(api, vmid=100, **extra):
    body = {'vmid': vmid, 'ostemplate': TEMPLATE, 'hostname': 'web', 'memory': 1024, 'rootfs': 'local-lvm:8',
            'net0': NET, 'cores': 2}
    body.update(extra)
    await done(api, await api.data('POST', '/nodes/pve1/lxc', body))


async def user_client(pve, api, user='ops@pve'):
    pve.users[user] = 'pw'
    client = Client(api.session)
    assert (await client.login(user, 'pw'))[0] == 200
    return client


# ---------------------------------------------------------------- lifecycle

async def test_lifecycle_create_to_destroy(pve, api):
    await make(api)
    config = await api.data('GET', CT + '/config')
    assert config['hostname'] == 'web' and config['memory'] == 1024 and config['cores'] == 2
    assert config['rootfs'] == 'local-lvm:vm-100-disk-0,size=8G'
    assert config['ostype'] == 'debian' and config['arch'] == 'amd64'
    assert config['unprivileged'] == 1 and config['swap'] == 512 and 'lock' not in config
    # The network keeps what was sent, plus the hardware address and type PVE adds.
    net = dict(p.split('=') for p in config['net0'].split(','))
    assert net['name'] == 'eth0' and net['ip'] == '192.0.2.10/24' and net['type'] == 'veth'
    assert net['hwaddr'].startswith('BC:24:11:')
    status = await api.data('GET', CT + '/status/current')
    assert status['status'] == 'stopped' and status['name'] == 'web' and status['type'] == 'lxc'
    assert status['maxmem'] == 1024 * 1048576 and status['maxdisk'] == 8 * 1024 ** 3
    listed = await api.data('GET', '/nodes/pve1/lxc')
    assert [c['vmid'] for c in listed] == [100]

    # Start; memory and cores take effect at once, a search domain waits for the next start.
    await done(api, await api.data('POST', CT + '/status/start'))
    assert (await api.data('GET', CT + '/status/current'))['status'] == 'running'
    await api.data('PUT', CT + '/config', {'memory': 2048, 'cores': 4, 'searchdomain': 'example.test'})
    config = await api.data('GET', CT + '/config', None)
    assert config['memory'] == 2048 and config['cores'] == 4 and config['searchdomain'] == 'example.test'
    current = await api.data('GET', CT + '/config?current=1')
    assert current['memory'] == 2048 and 'searchdomain' not in current
    pending = {p['key']: p for p in await api.data('GET', CT + '/pending')}
    assert pending['searchdomain'] == {'key': 'searchdomain', 'pending': 'example.test'}
    assert pending['memory'] == {'key': 'memory', 'value': 2048}

    await done(api, await api.data('POST', CT + '/status/shutdown'))
    assert (await api.data('GET', CT + '/status/current'))['status'] == 'stopped'
    assert 'searchdomain' in {p['key'] for p in await api.data('GET', CT + '/pending') if 'pending' in p}
    await done(api, await api.data('POST', CT + '/status/start'))
    current = await api.data('GET', CT + '/config?current=1')
    assert current['searchdomain'] == 'example.test'
    assert not [p for p in await api.data('GET', CT + '/pending') if 'pending' in p]
    await done(api, await api.data('POST', CT + '/status/stop'))

    await done(api, await api.data('POST', CT + '/snapshot', {'snapname': 'before', 'description': 'clean'}))
    snaps = await api.data('GET', CT + '/snapshot')
    assert [s['name'] for s in snaps] == ['before', 'current']
    assert snaps[0]['description'] == 'clean' and snaps[1]['parent'] == 'before'
    assert (await api.data('GET', CT + '/config'))['parent'] == 'before'

    await done(api, await api.data('POST', CT + '/clone', {'newid': 101, 'hostname': 'copy', 'snapname': 'before'}))
    clone = await api.data('GET', '/nodes/pve1/lxc/101/config')
    assert clone['hostname'] == 'copy' and clone['rootfs'] == 'local-lvm:vm-101-disk-0,size=8G'
    assert clone['net0'] != (await api.data('GET', CT + '/config'))['net0'], 'a clone gets its own hwaddr'
    assert 'parent' not in clone and 'lock' not in clone
    assert (await api.data('GET', CT + '/config'))['hostname'] == 'web'

    await done(api, await api.data('DELETE', '/nodes/pve1/lxc/101'))
    await done(api, await api.data('DELETE', CT))
    assert await api.data('GET', '/nodes/pve1/lxc') == []
    status, body = await api.call('GET', CT + '/config')
    assert status == 500 and body['message'] == "Configuration file 'nodes/pve1/lxc/100.conf' does not exist\n"


async def test_containers_are_listed_in_cluster_resources(pve, api):
    pve.add_vm(100, 'vm1')
    pve.add_ct(101, 'ct1', status='running', config={'tags': 'a;b'})
    items = await api.data('GET', '/cluster/resources')
    lxc = next(i for i in items if i['type'] == 'lxc')
    assert lxc['id'] == 'lxc/101' and lxc['vmid'] == 101 and lxc['name'] == 'ct1' and lxc['status'] == 'running'
    assert lxc['tags'] == 'a;b' and lxc['node'] == 'pve1'
    assert {i['type'] for i in await api.data('GET', '/cluster/resources?type=vm')} == {'qemu', 'lxc'}
    assert {i['type'] for i in await api.data('GET', '/cluster/resources?type=node')} == {'node'}
    pve.set_node_offline('pve1')
    assert [i['status'] for i in (await api.data('GET', '/cluster/resources?type=vm'))
            if i['type'] == 'lxc'] == ['unknown']


async def test_add_ct_defaults_and_uniqueness(pve):
    ct = pve.add_ct(100, ostemplate='alpine-3.19-default_20240207_amd64.tar.xz', template=True, lock='backup')
    assert isinstance(ct, FakeCt) and ct.name == 'CT100' and ct.guest == 'lxc/100'
    assert ct.config['ostype'] == 'alpine' and ct.template and ct.lock == 'backup'
    assert ct.config['rootfs'] == 'local-lvm:vm-100-disk-0,size=8G'
    with pytest.raises(ValueError, match="CT 100 already exists on node 'pve1'"):
        pve.add_ct(100, 'again')
    pve.add_vm(200, 'vm')
    with pytest.raises(ValueError, match="VM 200 already exists on node 'pve1'"):
        pve.add_ct(200, 'again')


async def test_vmid_is_unique_across_vms_and_containers(pve, api):
    pve.add_vm(100, 'vm1')
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE})
    assert status == 500 and body['message'] == "VM 100 already exists on node 'pve1'\n"
    pve.add_ct(101, 'ct1', node='pve1')
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 101, 'ostemplate': TEMPLATE})
    assert status == 500 and body['message'] == "CT 101 already exists on node 'pve1'\n"
    pve.add_node('pve2')
    status, body = await api.call('POST', '/nodes/pve2/lxc', {'vmid': 101, 'ostemplate': TEMPLATE})
    assert status == 500 and body['message'] == "CT 101 already exists on node 'pve1'\n"


async def test_create_validates_like_the_schema_and_pve(pve, api):
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE,
                                                               'hostname': 'not a hostname'})
    assert status == 400 and 'hostname' in body['errors']
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 100})
    assert status == 400 and body['errors'] == {'ostemplate': 'property is missing and it is not optional'}
    # The default storage 'local' holds no containers.
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE})
    assert status == 400
    assert body['errors'] == {'storage': "storage 'local' does not support container directories"}
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE,
                                                               'rootfs': 'nowhere:8'})
    assert status == 500 and body['message'] == "storage 'nowhere' does not exist\n"
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE,
                                                               'mp0': 'local-lvm:2,mp=/data'})
    assert status == 500 and "mount points configured, but 'rootfs' not set" in body['message']
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': 'local:iso/x.iso',
                                                               'rootfs': 'local-lvm:8'})
    assert status == 500
    assert body['message'] == "unable to use volume local:iso/x.iso - content type needs to be 'vztmpl'\n"
    status, body = await api.call('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE,
                                                               'rootfs': 'local-lvm:8', 'pool': 'nope'})
    assert status == 403 and body['message'] == "Permission check failed (pool 'nope' does not exist)\n"
    assert pve.cts == []


async def test_create_with_mount_points_start_and_pool(pve, api):
    pve.pools['web'] = set()
    await make(api, mp0='local-lvm:2,mp=/data', pool='web', start=1, tags='b,a;B', features='nesting=1')
    config = await api.data('GET', CT + '/config')
    assert config['mp0'] == 'local-lvm:vm-100-disk-1,mp=/data,size=2G'
    assert config['tags'] == 'a;b' and config['features'] == 'nesting=1'
    assert (await api.data('GET', CT + '/status/current'))['status'] == 'running'
    assert pve.pools['web'] == {100}


async def test_created_container_is_locked_while_the_task_runs(pve, api):
    pve.time_scale = SCALE
    pve.ct_secs['create'] = 30
    upid = await api.data('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE, 'rootfs': 'local-lvm:8'})
    config = await api.data('GET', CT + '/config')
    assert config['lock'] == 'create' and 'rootfs' not in config
    # The create worker holds the config file lock throughout, as PVE's does.
    status, body = await api.call('PUT', CT + '/config', {'memory': 256})
    assert status == 500 and "pve-config-100.lock' - got timeout" in body['message']
    assert [i['lock'] for i in await api.data('GET', '/cluster/resources?type=vm')] == ['create']
    await done(api, upid)
    assert 'lock' not in await api.data('GET', CT + '/config')


async def test_failed_create_leaves_nothing_behind(pve, api):
    pve.volume_exists = lambda volid: False
    await failed(api, ('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE, 'rootfs': 'local-lvm:8'}),
                 "unable to create CT 100 - volume '{0}' does not exist".format(TEMPLATE))
    assert pve.cts == []


# ------------------------------------------------------------------- status

async def test_power_state_wording(pve, api):
    pve.add_ct(100, 'ct1', status='running')
    status, body = await api.call('POST', CT + '/status/start')
    assert status == 500 and body['message'] == 'CT 100 already running\n'
    status, body = await api.call('POST', CT + '/status/resume')
    assert status == 500 and body['message'] == 'CT 100 already running\n'
    pve.add_ct(101, 'ct2')
    for action, message in (('stop', 'CT 101 not running'), ('shutdown', 'CT 101 not running'),
                            ('suspend', 'CT 101 not running'), ('reboot', 'VM 101 not running')):
        status, body = await api.call('POST', '/nodes/pve1/lxc/101/status/' + action)
        assert status == 500 and body['message'] == message + '\n', action


async def test_start_of_a_missing_container_fails_in_its_task(pve, api):
    await failed(api, ('POST', CT + '/status/start'), "Configuration file 'nodes/pve1/lxc/100.conf' does not exist")
    status, body = await api.call('POST', '/nodes/pve1/lxc/100/status/stop')
    assert status == 500 and body['message'] == 'CT 100 not running\n'


async def test_task_types_and_ids(pve, api):
    pve.add_ct(100, 'ct1')
    for call, ttype in ((('POST', CT + '/status/start'), 'vzstart'), (('POST', CT + '/status/reboot'), 'vzreboot'),
                        (('POST', CT + '/status/shutdown'), 'vzshutdown'), (('POST', CT + '/status/start'), 'vzstart'),
                        (('POST', CT + '/status/stop'), 'vzstop'), (('POST', CT + '/snapshot', {'snapname': 'snap'}),
                                                                   'vzsnapshot')):
        task = await done(api, await api.data(*call))
        assert task['type'] == ttype and task['id'] == '100', call


async def test_reboot_applies_pending_and_stop_does_not(pve, api):
    pve.add_ct(100, 'ct1', status='running')
    await api.data('PUT', CT + '/config', {'ostype': 'ubuntu'})
    assert (await api.data('GET', CT + '/config?current=1'))['ostype'] == 'debian'
    await done(api, await api.data('POST', CT + '/status/reboot'))
    assert (await api.data('GET', CT + '/config?current=1'))['ostype'] == 'ubuntu'
    await api.data('PUT', CT + '/config', {'ostype': 'alpine'})
    await done(api, await api.data('POST', CT + '/status/stop'))
    assert pve.ct(100).pending == {'ostype': 'alpine'}


async def test_skiplock_is_root_only(pve, api):
    pve.add_ct(100, 'ct1')
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/vms/100', 'VM.PowerMgmt')
    status, body = await ops.call('POST', CT + '/status/start', {'skiplock': 1})
    assert status == 400 and body['errors'] == {'skiplock': 'Only root may use this option.'}


async def test_suspend_and_resume(pve, api):
    pve.add_ct(100, 'ct1', status='running')
    await done(api, await api.data('POST', CT + '/status/suspend'))
    assert pve.ct(100).status == 'stopped'
    await done(api, await api.data('POST', CT + '/status/resume'))
    assert pve.ct(100).status == 'running'
    pve.ct(100).status = 'stopped'
    await failed(api, ('POST', CT + '/status/resume'),
                 "command 'lxc-checkpoint -n 100 -r --foreground -D /var/lib/vz/dump' failed: exit code 1")


# ------------------------------------------------------------------- config

async def test_config_digest_and_no_options(pve, api):
    pve.add_ct(100, 'ct1')
    config = await api.data('GET', CT + '/config')
    status, body = await api.call('PUT', CT + '/config', {'digest': config['digest']})
    assert status == 500 and body['message'] == 'no options specified\n'
    await api.data('PUT', CT + '/config', {'description': 'x', 'digest': config['digest']})
    status, body = await api.call('PUT', CT + '/config', {'description': 'y', 'digest': config['digest']})
    assert status == 500
    assert body['message'] == 'detected modified configuration - file changed by other user? Try again.\n'
    assert pve.ct(100).config['description'] == 'x'


async def test_delete_and_revert(pve, api):
    pve.add_ct(100, 'ct1', config={'description': 'd', 'onboot': 1})
    await api.data('PUT', CT + '/config', {'delete': 'description,onboot'})
    config = await api.data('GET', CT + '/config')
    assert 'description' not in config and 'onboot' not in config
    for opt in ('memory', 'rootfs', 'ostype'):
        status, body = await api.call('PUT', CT + '/config', {'delete': opt})
        assert status == 500 and body['message'] == "unable to delete required option '{0}'\n".format(opt)
    status, body = await api.call('PUT', CT + '/config', {'delete': 'unprivileged'})
    assert body['message'] == "unable to delete read-only option: 'unprivileged'\n"
    status, body = await api.call('PUT', CT + '/config', {'unprivileged': 0})
    assert body['message'] == "unable to modify read-only option: 'unprivileged'\n"
    status, body = await api.call('PUT', CT + '/config', {'delete': 'bogus'})
    assert status == 400 and body['errors'] == {'delete': "unknown option 'bogus'"}
    status, body = await api.call('PUT', CT + '/config', {'cores': 2, 'delete': 'cores'})
    assert status == 400 and 'at the same time' in body['errors']['delete']
    # On a running container a deletion that needs a restart waits, and can be reverted.
    pve.ct(100).status = 'running'
    pve.ct(100).config['nameserver'] = '192.0.2.53'
    await api.data('PUT', CT + '/config', {'delete': 'nameserver'})
    item = next(p for p in await api.data('GET', CT + '/pending') if p['key'] == 'nameserver')
    assert item == {'key': 'nameserver', 'value': '192.0.2.53', 'delete': 1}
    assert 'nameserver' not in await api.data('GET', CT + '/config')
    await api.data('PUT', CT + '/config', {'revert': 'nameserver'})
    assert (await api.data('GET', CT + '/config'))['nameserver'] == '192.0.2.53'


async def test_hotplug_rules_for_a_running_container(pve, api):
    pve.add_ct(100, 'ct1', status='running', config={'nameserver': '192.0.2.53'})
    await api.data('PUT', CT + '/config', {
        'hostname': 'new', 'cores': 3, 'onboot': 1, 'cpulimit': 1, 'cpuunits': 512, 'swap': 256,
        'net1': 'name=eth1,bridge=vmbr1', 'arch': 'arm64', 'console': 0, 'mp0': 'local-lvm:1,mp=/x'})
    config = pve.ct(100).config
    assert config['hostname'] == 'new' and config['cores'] == 3 and config['onboot'] == 1
    assert config['cpulimit'] == 1 and config['cpuunits'] == 512 and config['swap'] == 256
    assert config['net1'].startswith('name=eth1,bridge=vmbr1,hwaddr=') and config['mp0'].startswith('local-lvm:vm-100')
    assert pve.ct(100).pending == {'arch': 'arm64', 'console': 0}
    # An existing mount point is not hotplugged over.
    await api.data('PUT', CT + '/config', {'mp0': 'local-lvm:vm-100-disk-1,mp=/y,size=1G'})
    assert 'mp=/x' in pve.ct(100).config['mp0'] and pve.ct(100).pending['mp0'].endswith('mp=/y,size=1G')
    await api.data('PUT', CT + '/config', {'delete': 'net1,swap'})
    assert 'net1' not in pve.ct(100).config and 'swap' not in pve.ct(100).config


async def test_stopped_container_applies_everything_and_keeps_removed_volumes(pve, api):
    pve.add_ct(100, 'ct1', config={'mp0': 'local-lvm:vm-100-disk-1,mp=/data,size=2G'})
    await api.data('PUT', CT + '/config', {'arch': 'arm64', 'delete': 'mp0'})
    config = pve.ct(100).config
    assert config['arch'] == 'arm64' and 'mp0' not in config and config['unused0'] == 'local-lvm:vm-100-disk-1'
    assert pve.ct(100).pending == {}
    await api.data('PUT', CT + '/config', {'mp1': 'local-lvm:vm-100-disk-1,mp=/data'})
    assert pve.ct(100).config['mp1'] == 'local-lvm:vm-100-disk-1,mp=/data'


async def test_protection_blocks_disk_changes(pve, api):
    pve.add_ct(100, 'ct1', config={'protection': 1, 'mp0': 'local-lvm:vm-100-disk-1,mp=/data'})
    status, body = await api.call('PUT', CT + '/config', {'delete': 'mp0'})
    assert body['message'] == "can't remove CT 100 drive 'mp0' - protection mode enabled\n"
    status, body = await api.call('PUT', CT + '/config', {'mp0': 'local-lvm:vm-100-disk-1,mp=/x'})
    assert body['message'] == "can't update CT 100 drive 'mp0' - protection mode enabled\n"
    status, body = await api.call('DELETE', CT)
    assert body['message'] == "can't remove CT 100 - protection mode enabled\n"


async def test_config_of_a_snapshot(pve, api):
    pve.add_ct(100, 'ct1')
    await done(api, await api.data('POST', CT + '/snapshot', {'snapname': 's1'}))
    await api.data('PUT', CT + '/config', {'memory': 4096})
    snap = await api.data('GET', CT + '/config?snapshot=s1')
    assert snap['memory'] == 512 and 'snapstate' not in snap
    status, body = await api.call('GET', CT + '/config?snapshot=s1&current=1')
    assert status == 400 and set(body['errors']) == {'snapshot', 'current'}
    status, body = await api.call('GET', CT + '/config?snapshot=nope')
    assert body['message'] == "snapshot 'nope' does not exist\n"


# -------------------------------------------------------------------- locks

async def test_locked_container_refuses_changes(pve, api):
    pve.add_ct(100, 'ct1', status='running')
    pve.time_scale = SCALE
    await pve.backup(100, secs=60)
    await asyncio.sleep(0.05)
    assert (await api.data('GET', CT + '/status/current'))['lock'] == 'backup'
    for call in (('PUT', CT + '/config', {'onboot': 1}), ('POST', CT + '/snapshot', {'snapname': 'snap'})):
        status, body = await api.call(*call)
        if call[0] == 'PUT':
            assert status == 500 and body['message'] == 'CT is locked (backup)\n'
        else:
            assert (await wait_task(api, body['data']))['exitstatus'] == 'CT is locked (backup)'
    await failed(api, ('POST', CT + '/status/shutdown'), 'CT is locked (backup)')
    await failed(api, ('POST', CT + '/status/stop'), 'CT is locked (backup)')
    status, body = await api.call('DELETE', CT)
    assert status == 500 and body['message'] == 'CT is locked (backup)\n'
    status, body = await api.call('POST', CT + '/template')
    assert body['message'] == 'CT is locked (backup)\n'
    # skiplock (root) goes past the lock; a reboot ignores it, as PVE does.
    await done(api, await api.data('POST', CT + '/status/stop', {'skiplock': 1}))


async def test_held_config_lock_times_out_writes(pve, api):
    pve.time_scale = SCALE
    pve.add_ct(100, 'ct1')
    await pve.hold_config_lock(100, secs=None)
    started = time.monotonic()
    status, body = await api.call('PUT', CT + '/config', {'onboot': 1})
    assert status == 500
    assert body['message'] == "can't lock file '/run/lock/lxc/pve-config-100.lock' - got timeout\n"
    assert time.monotonic() - started >= pve.lock_wait * SCALE * 0.9
    task = await wait_task(api, await api.data('POST', CT + '/status/start'))
    assert task['exitstatus'] == "can't lock file '/run/lock/lxc/pve-config-100.lock' - got timeout"


async def test_config_write_waits_for_a_short_lock(pve, api):
    pve.time_scale = SCALE
    ct = pve.add_ct(100, 'ct1')
    await pve.hold_config_lock(100, secs=3)
    await api.data('PUT', CT + '/config', {'onboot': 1})
    assert ct.config['onboot'] == 1


async def test_snapshot_locks_the_container_while_it_runs(pve, api):
    pve.time_scale = SCALE
    pve.ct_secs['snapshot'] = 30
    ct = pve.add_ct(100, 'ct1')
    upid = await api.data('POST', CT + '/snapshot', {'snapname': 's1'})
    assert (await api.data('GET', CT + '/config'))['lock'] == 'snapshot'
    assert [s['snapstate'] for s in await api.data('GET', CT + '/snapshot') if s['name'] == 's1'] == ['prepare']
    status, body = await api.call('PUT', CT + '/config', {'onboot': 1})
    assert body['message'] == 'CT is locked (snapshot)\n'
    await done(api, upid)
    assert ct.lock is None and 'snapstate' not in ct.snapshots['s1']


# ---------------------------------------------------------------- snapshots

async def test_snapshot_chain_rollback_and_delete(pve, api):
    pve.add_ct(100, 'ct1', status='running', config={'description': 'keep'})
    status, body = await api.call('POST', CT + '/snapshot', {'snapname': 'current'})
    assert body['message'] == "unable to use snapshot name 'current' (reserved name)\n"
    status, body = await api.call('POST', CT + '/snapshot', {'snapname': 'vzdump'})
    assert body['message'] == "unable to use snapshot name 'vzdump' (reserved name)\n"
    await done(api, await api.data('POST', CT + '/snapshot', {'snapname': 'sa'}))
    await api.data('PUT', CT + '/config', {'memory': 1024, 'description': 'now'})
    await done(api, await api.data('POST', CT + '/snapshot', {'snapname': 'sb'}))
    await failed(api, ('POST', CT + '/snapshot', {'snapname': 'sa'}), "snapshot name 'sa' already used")
    snaps = {s['name']: s for s in await api.data('GET', CT + '/snapshot')}
    assert snaps['sb']['parent'] == 'sa' and 'parent' not in snaps['sa'] and snaps['current']['parent'] == 'sb'
    assert snaps['current']['running'] == 1

    await failed(api, ('POST', CT + '/snapshot/zzz/rollback'), "snapshot 'zzz' does not exist")
    await done(api, await api.data('POST', CT + '/snapshot/sa/rollback'))
    config = pve.ct(100).config
    assert pve.ct(100).status == 'stopped', 'a rollback stops the container'
    assert config['memory'] == 512 and config['parent'] == 'sa' and config['description'] == 'now'
    assert 'lock' not in config and set(pve.ct(100).snapshots) == {'sa', 'sb'}

    await failed(api, ('DELETE', CT + '/snapshot/zzz'), "snapshot 'zzz' does not exist")
    await done(api, await api.data('DELETE', CT + '/snapshot/sa'))
    assert pve.ct(100).snapshots['sb'].get('parent') is None and 'parent' not in pve.ct(100).config
    await done(api, await api.data('DELETE', CT + '/snapshot/sb'))
    assert pve.ct(100).snapshots == {} and 'parent' not in pve.ct(100).config


async def test_rollback_can_start_and_snapshot_description_is_editable(pve, api):
    pve.add_ct(100, 'ct1')
    await done(api, await api.data('POST', CT + '/snapshot', {'snapname': 'sa'}))
    await api.data('PUT', CT + '/snapshot/sa/config', {'description': 'edited'})
    assert (await api.data('GET', CT + '/snapshot/sa/config'))['description'] == 'edited'
    status, body = await api.call('PUT', CT + '/snapshot/zzz/config', {'description': 'x'})
    assert body['message'] == "snapshot 'zzz' does not exist\n"
    await done(api, await api.data('POST', CT + '/snapshot/sa/rollback', {'start': 1}))
    assert pve.ct(100).status == 'running'


async def test_snapshots_need_a_storage_that_has_them(pve, api):
    pve.add_ct(100, 'ct1', config={'rootfs': 'local:100/vm-100-disk-0.raw,size=4G'})
    await failed(api, ('POST', CT + '/snapshot', {'snapname': 'sa'}), 'snapshot feature is not available')
    assert pve.ct(100).snapshots == {} and pve.ct(100).lock is None


# ------------------------------------------------------ template and clone

async def test_template_and_linked_clone(pve, api):
    pve.add_ct(100, 'base', config={'mp0': 'local-lvm:vm-100-disk-1,mp=/data,size=1G'})
    await done(api, await api.data('POST', CT + '/template'))
    config = await api.data('GET', CT + '/config')
    assert config['template'] == 1 and config['rootfs'] == 'local-lvm:base-100-disk-0,size=8G'
    assert config['mp0'] == 'local-lvm:base-100-disk-1,mp=/data,size=1G'
    assert (await api.data('GET', CT + '/status/current'))['template'] == 1
    status, body = await api.call('POST', CT + '/template')
    assert body['message'] == "you can't convert a template to a template\n"
    await failed(api, ('POST', CT + '/status/start'), "you can't start a CT if it's a template")
    await failed(api, ('POST', CT + '/snapshot', {'snapname': 'snap'}), "you can't take a snapshot if it's a template")
    # Templates clone linked by default.
    await done(api, await api.data('POST', CT + '/clone', {'newid': 101}))
    clone = await api.data('GET', '/nodes/pve1/lxc/101/config')
    assert clone['rootfs'] == 'local-lvm:vm-101-disk-0,size=8G' and 'template' not in clone
    status, body = await api.call('POST', CT + '/clone', {'newid': 102, 'storage': 'local-lvm', 'full': 0})
    assert body['message'] == "parameter 'storage' not allowed for linked clones\n"
    assert pve.ct(100).lock is None and pve.ct(102) is None


async def test_template_conversion_rules(pve, api):
    pve.add_ct(100, 'a', status='running')
    status, body = await api.call('POST', CT + '/template')
    assert body['message'] == "you can't convert a CT to template if the CT is running\n"
    pve.ct(100).status = 'stopped'
    await done(api, await api.data('POST', CT + '/snapshot', {'snapname': 'snap'}))
    status, body = await api.call('POST', CT + '/template')
    assert body['message'] == 'unable to create template, because CT contains snapshots\n'


async def test_clone_rules(pve, api):
    pve.add_ct(100, 'a', status='running')
    status, body = await api.call('POST', CT + '/clone', {'newid': 101})
    assert body['message'] == 'Full clone of a running container is only possible from a snapshot\n'
    assert pve.ct(100).lock is None and pve.ct(101) is None, 'a failed clone is cleaned up'
    status, body = await api.call('POST', CT + '/clone', {'newid': 100})
    assert body['message'] == "CT 100 already exists on node 'pve1'\n"
    status, body = await api.call('POST', CT + '/clone', {'newid': 101, 'full': 0})
    assert body['message'] == "Linked clone feature for 'local-lvm:vm-100-disk-0' is not available\n"
    status, body = await api.call('POST', CT + '/clone', {'newid': 101, 'snapname': 'zzz'})
    assert body['message'] == "snapshot 'zzz' does not exist\n"
    status, body = await api.call('POST', CT + '/clone', {'newid': 101, 'target': 'pve9'})
    assert body['message'] == "no such cluster node 'pve9'\n"
    pve.add_node('pve2')
    pve.ct(100).status = 'stopped'
    status, body = await api.call('POST', CT + '/clone', {'newid': 101, 'target': 'pve2'})
    assert body['message'] == "can't clone CT to node 'pve2' (CT uses local storage)\n"
    status, body = await api.call('POST', '/nodes/pve1/lxc/999/clone', {'newid': 101})
    assert body['message'] == "Configuration file 'nodes/pve1/lxc/999.conf' does not exist\n"


async def test_clone_locks_both_containers_while_it_runs(pve, api):
    pve.time_scale = SCALE
    pve.ct_secs['clone'] = 30
    pve.pools['p'] = set()
    pve.add_ct(100, 'a')
    upid = await api.data('POST', CT + '/clone', {'newid': 101, 'pool': 'p', 'storage': 'local-lvm'})
    assert pve.ct(100).lock == 'disk' and pve.ct(101).lock == 'create'
    status, body = await api.call('PUT', CT + '/config', {'onboot': 1})
    assert body['message'] == 'CT is locked (disk)\n'
    task = await done(api, upid)
    assert task['type'] == 'vzclone' and pve.ct(100).lock is None and pve.ct(101).lock is None
    assert pve.pools['p'] == {101}


# ------------------------------------------------------------------ destroy

async def test_destroy_rules(pve, api):
    pve.add_ct(100, 'a', status='running')
    status, body = await api.call('DELETE', CT)
    assert status == 500 and body['message'] == 'unable to destroy CT 100 - container is running\n'
    task = await done(api, await api.data('DELETE', CT + '?force=1&purge=1'))
    assert task['type'] == 'vzdestroy' and pve.ct(100) is None
    assert 'forced to stop CT 100 before destroying!' in pve.tasks[task['upid']]['log']


async def test_destroy_locks_while_it_runs(pve, api):
    pve.time_scale = SCALE
    pve.ct_secs['destroy'] = 30
    pve.add_ct(100, 'a')
    upid = await api.data('DELETE', CT)
    assert pve.ct(100).lock == 'destroyed'
    await done(api, upid)
    assert pve.ct(100) is None


# ------------------------------------------------------------------ migrate

async def test_migrate_rules(pve, api):
    pve.add_node('pve2')
    pve.add_ct(100, 'a', status='running')
    status, body = await api.call('POST', CT + '/migrate', {'target': 'pve1'})
    assert status == 400 and body['errors'] == {'target': 'target is local node.'}
    status, body = await api.call('POST', CT + '/migrate', {'target': 'pve9'})
    assert body['message'] == "no such cluster node 'pve9'\n"
    status, body = await api.call('POST', CT + '/migrate', {'target': 'pve2'})
    assert body['message'] == "can't migrate running container without --online or --restart\n"
    await failed(api, ('POST', CT + '/migrate', {'target': 'pve2', 'online': 1}),
                 'lxc live migration is currently not implemented')
    assert pve.ct(100).node == 'pve1' and pve.ct(100).lock is None
    check = await api.data('GET', CT + '/migrate', {'target': 'pve2'})
    assert check == {'running': 1, 'allowed-nodes': ['pve2'], 'not-allowed-nodes': {}}


async def test_restart_migration_moves_the_container(pve, api):
    pve.add_node('pve2')
    pve.add_ct(100, 'a', status='running')
    task = await done(api, await api.data('POST', CT + '/migrate', {'target': 'pve2', 'restart': 1}))
    assert task['type'] == 'vzmigrate'
    assert pve.ct(100).node == 'pve2' and pve.ct(100).status == 'running'
    status, body = await api.call('GET', CT + '/config')
    assert 'does not exist' in body['message']
    assert (await api.data('GET', '/nodes/pve2/lxc/100/status/current'))['status'] == 'running'
    pve.ct(100).status = 'stopped'
    await done(api, await api.data('POST', '/nodes/pve2/lxc/100/migrate', {'target': 'pve1'}), 'pve2')
    assert pve.ct(100).node == 'pve1' and pve.ct(100).status == 'stopped'


async def test_migration_locks_while_it_runs(pve, api):
    pve.time_scale = SCALE
    pve.ct_secs['migrate'] = 30
    pve.add_node('pve2')
    pve.add_ct(100, 'a')
    upid = await api.data('POST', CT + '/migrate', {'target': 'pve2'})
    assert pve.ct(100).lock == 'migrate'
    await done(api, upid)
    assert pve.ct(100).lock is None


# ------------------------------------------------------------------- resize

async def test_resize(pve, api):
    pve.add_ct(100, 'a', config={'mp0': 'local-lvm:vm-100-disk-1,mp=/data,size=2G'})
    task = await done(api, await api.data('PUT', CT + '/resize', {'disk': 'rootfs', 'size': '+2G'}))
    assert task['type'] == 'resize'
    assert pve.ct(100).config['rootfs'] == 'local-lvm:vm-100-disk-0,size=10G'
    await done(api, await api.data('PUT', CT + '/resize', {'disk': 'mp0', 'size': '4096M'}))
    assert pve.ct(100).config['mp0'] == 'local-lvm:vm-100-disk-1,mp=/data,size=4G'
    for size, message in (('1G', 'unable to shrink disk size'), ('10G', 'disk is already at specified size')):
        status, body = await api.call('PUT', CT + '/resize', {'disk': 'rootfs', 'size': size})
        assert status == 500 and body['message'] == message + '\n'
    status, body = await api.call('PUT', CT + '/resize', {'disk': 'rootfs', 'size': 'huge'})
    assert status == 400 or body['message'] == 'invalid size string\n'
    status, body = await api.call('PUT', CT + '/resize', {'disk': 'mp5', 'size': '1G'})
    assert status == 500 and body['message'].startswith('format error')


# --------------------------------------------------------------- interfaces

async def test_interfaces(pve, api):
    await make(api)
    assert await api.data('GET', CT + '/interfaces') is None
    await done(api, await api.data('POST', CT + '/status/start'))
    eth = {i['name']: i for i in await api.data('GET', CT + '/interfaces')}
    assert set(eth) == {'lo', 'eth0'} and eth['eth0']['inet'] == '192.0.2.10/24'
    assert eth['eth0']['hwaddr'] == eth['eth0']['hardware-address'] and eth['lo']['inet'] == '127.0.0.1/8'
    assert eth['eth0']['ip-addresses'] == [{'ip-address-type': 'inet', 'ip-address': '192.0.2.10', 'prefix': 24}]


# -------------------------------------------------------------- permissions

async def test_permissions_per_operation(pve, api):
    pve.add_ct(100, 'a')
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    assert (await ops.call('GET', CT + '/config'))[0] == 200
    assert (await ops.call('GET', '/nodes/pve1/lxc'))[0] == 200
    for call, priv in ((('POST', CT + '/status/start'), 'VM.PowerMgmt'), (('DELETE', CT), 'VM.Allocate'),
                       (('POST', CT + '/snapshot', {'snapname': 'snap'}), 'VM.Snapshot'),
                       (('POST', CT + '/template'), 'VM.Allocate'),
                       (('POST', CT + '/migrate', {'target': 'pve1'}), 'VM.Migrate'),
                       (('POST', CT + '/clone', {'newid': 101}), 'VM.Clone')):
        status, body = await ops.call(*call)
        assert status == 403, call
        assert body['message'] == 'Permission check failed (/vms/100, {0})\n'.format(priv), call
    pve.grant('ops@pve', '/vms/100', 'VM.PowerMgmt')
    assert (await ops.call('POST', CT + '/status/start'))[0] == 200


async def test_config_changes_need_the_privilege_of_the_option(pve, api):
    pve.add_ct(100, 'a')
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/vms/100', 'VM.Audit', 'VM.Config.CPU')
    assert (await ops.call('PUT', CT + '/config', {'cores': 2}))[0] == 200
    for change, priv in (({'memory': 256}, 'VM.Config.Memory'), ({'hostname': 'x'}, 'VM.Config.Network'),
                         ({'net0': NET}, 'VM.Config.Network'), ({'onboot': 1}, 'VM.Config.Options'),
                         ({'mp0': 'local-lvm:1,mp=/x'}, 'VM.Config.Disk'), ({'delete': 'swap'}, 'VM.Config.Memory')):
        status, body = await ops.call('PUT', CT + '/config', change)
        assert status == 403 and body['message'] == 'Permission check failed (/vms/100, {0})\n'.format(priv), change
    # Any config privilege opens the route; the option decides.
    status, body = await ops.call('PUT', CT + '/config', {'hookscript': 'local:snippets/x.pl', 'cores': 1})
    assert status == 403 and 'only allowed for root@pam' in body['message']
    pve.grant('ops@pve', '/vms/100', 'VM.Config.Disk')
    pve.grant('ops@pve', '/storage/local-lvm', 'Datastore.AllocateSpace')
    assert (await ops.call('PUT', CT + '/config', {'mp0': 'local-lvm:1,mp=/x'}))[0] == 200
    status, body = await ops.call('PUT', CT + '/config', {'mp1': '/host/path,mp=/y'})
    assert status == 403
    assert body['message'] == 'Permission check failed (mount point type bind is only allowed for root@pam)\n'
    status, body = await ops.call('PUT', CT + '/resize', {'disk': 'mp0', 'size': '+1G'})
    assert status == 403 and body['message'].endswith('VM.Config.Options)\n')


async def test_create_permissions(pve, api):
    ops = await user_client(pve, api)
    body = {'vmid': 100, 'ostemplate': TEMPLATE, 'rootfs': 'local-lvm:8'}
    pve.grant('ops@pve', '/storage/local-lvm', 'Datastore.AllocateSpace')
    pve.grant('ops@pve', '/storage/local', 'Datastore.AllocateSpace')
    status, rsp = await ops.call('POST', '/nodes/pve1/lxc', body)
    assert status == 403 and rsp['message'] == 'Permission check failed\n'
    pve.grant('ops@pve', '/vms/100', 'VM.Allocate')
    status, rsp = await ops.call('POST', '/nodes/pve1/lxc', dict(body, unprivileged=0))
    assert status == 403 and rsp['message'] == 'Permission check failed (/, Sys.Modify)\n'
    status, rsp = await ops.call('POST', '/nodes/pve1/lxc', dict(body, start=1))
    assert status == 403 and rsp['message'] == 'Permission check failed (/vms/100, VM.PowerMgmt)\n'
    status, rsp = await ops.call('POST', '/nodes/pve1/lxc', body)
    assert status == 403 and rsp['message'] == 'Permission check failed (/vms/100, VM.Config.Disk)\n'
    pve.grant('ops@pve', '/vms/100', 'VM.Config.Disk')
    status, rsp = await ops.call('POST', '/nodes/pve1/lxc', dict(body, memory=256))
    assert status == 403 and rsp['message'] == 'Permission check failed (/vms/100, VM.Config.Memory)\n'
    status, rsp = await ops.call('POST', '/nodes/pve1/lxc', dict(body, ostemplate='/tmp/x.tar'))
    assert status == 500 and rsp['message'] == 'Only root can pass arbitrary filesystem paths.\n'
    status, rsp = await ops.call('POST', '/nodes/pve1/lxc', body)
    assert status == 200, rsp
    assert (await wait_task(api, rsp['data']))['exitstatus'] == 'OK'


async def test_pool_grants_cover_create(pve, api):
    pve.pools['team'] = set()
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/pool/team', 'VM.Allocate', 'VM.Config.Disk')
    pve.grant('ops@pve', '/storage/local-lvm', 'Datastore.AllocateSpace')
    pve.grant('ops@pve', '/storage/local', 'Datastore.AllocateSpace')
    status, rsp = await ops.call('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE,
                                                              'rootfs': 'local-lvm:8', 'pool': 'team'})
    assert status == 200, rsp


# --------------------------------------------------------------- scenarios

async def test_start_takes_start_secs_and_can_fail(pve, api):
    pve.time_scale = SCALE
    ct = pve.add_ct(100, 'a')
    ct.start_secs = 30
    upid = await api.data('POST', CT + '/status/start')
    assert (await api.data('GET', '/nodes/pve1/tasks/{0}/status'.format(upid)))['status'] == 'running'
    assert ct.status == 'stopped'
    started = time.monotonic()
    await done(api, upid)
    assert ct.status == 'running' and time.monotonic() - started >= 0.2
    await done(api, await api.data('POST', CT + '/status/stop'))
    ct.start_error = 'lxc_init: 845 Failed to initialize container "100"'
    await failed(api, ('POST', CT + '/status/start'), 'lxc_init: 845 Failed to initialize container "100"')
    assert ct.status == 'stopped'


async def test_slow_shutdown_beats_the_timeout_unless_forced(pve, api):
    ct = pve.add_ct(100, 'a', status='running')
    ct.shutdown_secs = 90
    await failed(api, ('POST', CT + '/status/shutdown'), 'container did not stop')
    assert ct.status == 'running'
    await done(api, await api.data('POST', CT + '/status/shutdown', {'timeout': 120}))
    assert ct.status == 'stopped'
    ct.status = 'running'
    await done(api, await api.data('POST', CT + '/status/shutdown', {'forceStop': 1}))
    assert ct.status == 'stopped'
    ct.status = 'running'
    await done(api, await api.data('POST', CT + '/status/reboot'))
    assert ct.status == 'running', 'a reboot kills after the timeout'


async def test_shutdown_runs_in_real_time(pve, api):
    pve.time_scale = SCALE
    ct = pve.add_ct(100, 'a', status='running')
    ct.shutdown_secs = 30
    upid = await api.data('POST', CT + '/status/shutdown')
    assert ct.status == 'running'
    started = time.monotonic()
    await done(api, upid)
    assert ct.status == 'stopped' and time.monotonic() - started >= 0.25


async def test_ha_managed_container_goes_through_the_ha_manager(pve, api):
    ct = pve.add_ct(100, 'a')
    ct.ha_state = 'stopped'
    task = await done(api, await api.data('POST', CT + '/status/start'))
    assert task['type'] == 'hastart' and ct.status == 'running' and ct.ha_state == 'started'
    assert (await api.data('GET', CT + '/status/current'))['ha'] == {'managed': 1, 'state': 'started'}
    task = await done(api, await api.data('POST', CT + '/status/stop'))
    assert task['type'] == 'hastop' and ct.status == 'stopped'
    status, body = await api.call('DELETE', CT)
    assert body['message'] == 'unable to remove CT 100 - used in HA resources and purge parameter not set.\n'


async def test_quorum_loss_and_offline_node(pve, api):
    pve.add_ct(100, 'a')
    pve.lose_quorum()
    for call in (('POST', '/nodes/pve1/lxc', {'vmid': 101, 'ostemplate': TEMPLATE, 'rootfs': 'local-lvm:8'}),
                 ('PUT', CT + '/config', {'onboot': 1}), ('POST', CT + '/status/start')):
        status, body = await api.call(*call)
        assert status == 500 and body['message'] == 'cluster not ready - no quorum?\n', call
    assert (await api.call('GET', CT + '/config'))[0] == 200
    pve.regain_quorum()
    pve.set_node_offline('pve1')
    status, body = await api.call('GET', CT + '/status/current')
    assert status == 595


async def test_catalogued_errors_can_still_be_triggered_by_name(pve, api):
    pve.add_ct(100, 'a')
    pve.fail('POST', CT + '/status/start', error='already_running', times=1)
    status, body = await api.call('POST', CT + '/status/start')
    assert (status, body['message']) == (500, 'CT 100 already running\n')
    pve.fail('POST', CT + '/status/stop', error='not_running', times=1)
    status, body = await api.call('POST', CT + '/status/stop')
    assert (status, body['message']) == (500, 'CT 100 not running\n')
    pve.fail('PUT', CT + '/config', 500, 'boom', times=1)
    assert (await api.call('PUT', CT + '/config', {'onboot': 1}))[0] == 500
    assert (await api.call('PUT', CT + '/config', {'onboot': 1}))[0] == 200


async def test_extjs_format_answers_too(pve, api):
    pve.add_ct(100, 'a')
    async with api.session.get('/api2/extjs' + CT + '/config', headers=api.headers) as rsp:
        body = await rsp.json()
    assert body['success'] == 1 and body['data']['hostname'] == 'a'
