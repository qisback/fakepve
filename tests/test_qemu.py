"""VM create, destroy, snapshots, clone and template keep state, with qemu-server's rules and wording."""

import pytest

from conftest import Client

NODE = '/nodes/pve1'
Q = NODE + '/qemu'
VM = Q + '/100'


@pytest.fixture
def dirs(pve):
    """A directory storage that takes images and an LVM-thin one."""
    pve.storages['vmdir'] = {'type': 'dir', 'active': 1, 'content': 'images,iso', 'files': set(), 'path': '/mnt/vmdir'}
    return pve


async def run(api, pve, method, path, data=None):
    """Send a request that starts a task; return the finished task."""
    return pve.tasks[await api.data(method, path, data)]


async def create(api, pve, vmid=100, **params):
    task = await run(api, pve, 'POST', Q, dict({'vmid': vmid, 'name': 'vm{0}'.format(vmid)}, **params))
    assert task['exitstatus'] == 'OK', task
    return pve.vm(vmid)


async def fails(api, method, path, data=None, status=500):
    got, body = await api.call(method, path, data)
    assert got == status, (got, body)
    return body['errors'] if status == 400 else body['message'].strip()


# ----------------------------------------------------------------- create

async def test_create_makes_a_stateful_vm(dirs, api):
    upid = await api.data('POST', Q, {'vmid': 100, 'name': 'web', 'memory': 256, 'cores': 2, 'kvm': 0,
                                      'ostype': 'l26', 'scsihw': 'virtio-scsi-pci', 'protection': 1,
                                      'scsi0': 'vmdir:2,format=qcow2,discard=on'})
    task = dirs.tasks[upid]
    assert task['type'] == 'qmcreate' and task['id'] == '100' and task['exitstatus'] == 'OK'
    vm = dirs.vm(100)
    assert vm.name == 'web' and vm.status == 'stopped' and vm.lock is None
    config = await api.data('GET', VM + '/config')
    assert config['memory'] == '256' and config['cores'] == 2 and config['kvm'] == 0 and config['protection'] == 1
    # The new disk is a volume of the storage, named as the plugin names it; its format option is consumed.
    assert config['scsi0'] == 'vmdir:100/vm-100-disk-0.qcow2,discard=on,size=2G'
    assert config['boot'] == 'order=scsi0'
    assert config['meta'].startswith('creation-qemu=') and 'ctime=' in config['meta']
    assert config['smbios1'].startswith('uuid=') and len(config['vmgenid']) == 36
    listed = await api.data('GET', NODE + '/storage/vmdir/content', {'vmid': 100})
    assert [(v['volid'], v['size'], v['format']) for v in listed] == [
        ('vmdir:100/vm-100-disk-0.qcow2', 2 * 1024 ** 3, 'qcow2')]
    assert [v['vmid'] for v in await api.data('GET', Q)] == [100]
    # A running VM shows what create wrote.
    await run(api, dirs, 'POST', VM + '/status/start')
    assert (await api.data('GET', VM + '/status/current'))['status'] == 'running'


async def test_create_without_a_name_lists_the_default_name(dirs, api):
    task = await run(api, dirs, 'POST', Q, {'vmid': 100})
    assert task['exitstatus'] == 'OK'
    assert 'name' not in await api.data('GET', VM + '/config')
    assert (await api.data('GET', Q))[0]['name'] == 'VM 100'


async def test_disks_on_block_storage_are_named_vm_id_disk_n(api, pve):
    vm = await create(api, pve, scsi0='local-lvm:4', virtio0='local-lvm:1', net0='virtio,bridge=vmbr0')
    assert vm.config['scsi0'] == 'local-lvm:vm-100-disk-0,size=4G'
    assert vm.config['virtio0'] == 'local-lvm:vm-100-disk-1,size=1G'
    # A MAC is made up; the options after the model are kept.
    assert vm.config['net0'].startswith('virtio=BC:24:11:') and vm.config['net0'].endswith(',bridge=vmbr0')
    assert vm.config['boot'] == 'order=scsi0;net0'
    names = [v['volid'] for v in await api.data('GET', NODE + '/storage/local-lvm/content')]
    assert names == ['local-lvm:vm-100-disk-0', 'local-lvm:vm-100-disk-1']


async def test_pool_and_tags_and_start(dirs, api):
    dirs.pools['web'] = set()
    vm = await create(api, dirs, pool='web', tags='B;a;b', start=1)
    assert dirs.pools['web'] == {100} and vm.pool == 'web'
    assert vm.config['tags'] == 'a;b' and vm.status == 'running'


async def test_create_errors(dirs, api):
    await create(api, dirs, 100)
    used = "unable to create VM {0} - {1} {0} already exists on node 'pve1'"
    assert await fails(api, 'POST', Q, {'vmid': 100}) == used.format(100, 'VM')
    dirs.add_ct(101, 'ct')
    assert await fails(api, 'POST', Q, {'vmid': 101}) == used.format(101, 'CT')
    assert await fails(api, 'POST', Q, {'vmid': 102, 'pool': 'nope'}, 403) == \
        "Permission check failed (pool 'nope' does not exist)"
    assert await fails(api, 'POST', Q, {'vmid': 102, 'scsi0': 'nosuch:1'}) == "storage 'nosuch' does not exist"
    # A bare size is not a volume id, so the schema refuses it before any storage is looked at.
    assert 'scsi0' in await fails(api, 'POST', Q, {'vmid': 102, 'scsi0': '1'}, 400)
    # local takes no images here.
    assert await fails(api, 'POST', Q, {'vmid': 102, 'scsi0': 'local:1'}, 400) == {
        'storage': "storage 'local' does not support vm images"}
    assert (await fails(api, 'POST', Q, {'vmid': 99}, 400))['vmid'].startswith('invalid format')
    assert 'ostype' in await fails(api, 'POST', Q, {'vmid': 102, 'ostype': 'nope'}, 400)
    assert 'net0' in await fails(api, 'POST', Q, {'vmid': 102, 'net0': 'virtio=zz'}, 400)
    assert await fails(api, 'POST', Q, {'vmid': 102, 'bogus': 1}, 400) == {
        'bogus': 'property is not defined in schema and the schema does not allow additional properties'}
    # Nothing was left behind by the refused requests.
    assert sorted(vm.vmid for vm in dirs.vms) == [100]


async def test_a_disk_that_cannot_be_allocated_fails_the_task_and_leaves_nothing(dirs, api):
    dirs.storages['vmdir']['avail'] = 1024 ** 3
    task = await run(api, dirs, 'POST', Q, {'vmid': 100, 'scsi0': 'vmdir:1', 'scsi1': 'vmdir:5'})
    assert task['exitstatus'].startswith('unable to create VM 100 - unable to write to storage')
    assert task['log'][-1].startswith('TASK ERROR: unable to create VM 100 -')
    assert dirs.vm(100) is None
    assert dirs.storages['vmdir'].get('volumes', {}) == {} and dirs.storages['vmdir']['avail'] == 1024 ** 3


async def test_a_missing_volume_fails_the_task(dirs, api):
    task = await run(api, dirs, 'POST', Q, {'vmid': 100, 'scsi0': 'vmdir:100/vm-100-disk-9.raw'})
    assert task['exitstatus'] == 'unable to create VM 100 - volume vmdir:100/vm-100-disk-9.raw does not exist'
    assert dirs.vm(100) is None


async def test_an_iso_needs_media_cdrom(dirs, api):
    dirs.store_file('vmdir', 'a.iso', 1024 ** 2)
    assert await fails(api, 'POST', Q, {'vmid': 100, 'ide2': 'vmdir:iso/a.iso'}, 400) == {
        'ide2': "explicit 'media=cdrom' is required for iso images"}
    vm = await create(api, dirs, ide2='vmdir:iso/a.iso,media=cdrom')
    assert vm.config['ide2'].startswith('vmdir:iso/a.iso,media=cdrom')
    assert vm.config['boot'] == 'order=ide2'


async def test_create_needs_privileges(dirs, api):
    dirs.users['ops@pve'] = 'pw'
    dirs.acl = {}
    ops = Client(api.session)
    await ops.login('ops@pve', 'pw')
    assert (await ops.call('POST', Q, {'vmid': 100}))[0] == 403
    dirs.grant('ops@pve', '/vms/100', 'VM.Allocate', 'VM.Config.Options')
    assert (await ops.call('POST', Q, {'vmid': 100, 'name': 'x'}))[0] == 200
    # A disk needs the disk privilege and room on the storage.
    status, body = await ops.call('POST', Q, {'vmid': 101, 'scsi0': 'vmdir:1'})
    assert status == 403
    dirs.grant('ops@pve', '/vms/101', 'VM.Allocate', 'VM.Config.Disk')
    status, body = await ops.call('POST', Q, {'vmid': 101, 'scsi0': 'vmdir:1'})
    assert status == 403 and '/storage/vmdir, Datastore.AllocateSpace' in body['message']
    dirs.grant('ops@pve', '/storage/vmdir', 'Datastore.AllocateSpace')
    assert (await ops.call('POST', Q, {'vmid': 101, 'scsi0': 'vmdir:1'}))[0] == 200
    status, body = await ops.call('POST', Q, {'vmid': 100})
    assert status == 500 and 'already exists' in body['message']
    assert (await ops.call('POST', Q, {'vmid': 102}))[0] == 403


# ------------------------------------------------------------ config, power

async def test_config_digest_and_hot_or_pending(dirs, api):
    await create(api, dirs, memory=128, cores=1)
    digest = (await api.data('GET', VM + '/config'))['digest']
    await api.data('PUT', VM + '/config', {'memory': 192, 'description': 'd'})
    config = await api.data('GET', VM + '/config')
    assert config['memory'] == '192' and config['description'] == 'd' and config['digest'] != digest
    assert await fails(api, 'PUT', VM + '/config', {'description': 'x', 'digest': digest}) == \
        'checksum mismatch (file change by other user?)'
    # Running: only hot-pluggable keys apply at once.
    await run(api, dirs, 'POST', VM + '/status/start')
    await api.data('PUT', VM + '/config', {'memory': 160, 'tags': 'x'})
    config = await api.data('GET', VM + '/config')
    assert config['memory'] == '192' and config['tags'] == 'x'
    pending = dict((i['key'], i) for i in await api.data('GET', VM + '/pending'))
    assert pending['memory']['pending'] == 160 or str(pending['memory']['pending']) == '160'


async def test_bad_values_are_refused_before_the_vm_is_looked_up(dirs, api):
    assert 'ostype' in await fails(api, 'PUT', VM + '/config', {'ostype': 'nope'}, 400)
    missing = await fails(api, 'PUT', VM + '/config', {'memory': 128})
    assert missing.startswith("Configuration file 'nodes/pve1/qemu-server/100.conf'")
    await create(api, dirs)
    errors = await fails(api, 'PUT', VM + '/config', {'cores': 0}, 400)
    assert errors == {'cores': 'value must have a minimum value of 1'}
    assert 'memory' in await fails(api, 'PUT', VM + '/config', {'memory': 'lots'}, 400)


async def test_start_and_stop_checks_run_in_the_worker(dirs, api):
    await create(api, dirs)
    assert (await run(api, dirs, 'POST', VM + '/status/start'))['exitstatus'] == 'OK'
    again = await run(api, dirs, 'POST', VM + '/status/start')
    assert again['exitstatus'] == 'VM 100 already running' and again['log'][-1] == 'TASK ERROR: VM 100 already running'
    assert (await run(api, dirs, 'POST', VM + '/status/stop'))['exitstatus'] == 'OK'
    # Stopping a stopped VM is not an error.
    assert (await run(api, dirs, 'POST', VM + '/status/stop'))['exitstatus'] == 'OK'


# --------------------------------------------------------------- snapshots

async def test_snapshot_reuse_and_delete_missing_end_the_task(dirs, api):
    await create(api, dirs, scsi0='vmdir:1,format=qcow2')
    first = await run(api, dirs, 'POST', VM + '/snapshot', {'snapname': 's1', 'description': 'd'})
    assert first['exitstatus'] == 'OK'
    again = await run(api, dirs, 'POST', VM + '/snapshot', {'snapname': 's1'})
    assert again['exitstatus'] == "snapshot name 's1' already used"
    assert again['log'][-1] == "TASK ERROR: snapshot name 's1' already used"
    listing = await api.data('GET', VM + '/snapshot')
    assert [s['name'] for s in listing] == ['s1', 'current']
    assert listing[0]['description'] == 'd' and listing[0]['vmstate'] == 0 and listing[1]['parent'] == 's1'
    assert (await run(api, dirs, 'DELETE', VM + '/snapshot/s1'))['exitstatus'] == 'OK'
    gone = await run(api, dirs, 'DELETE', VM + '/snapshot/s1')
    assert gone['exitstatus'] == "snapshot 's1' does not exist"
    assert [s['name'] for s in await api.data('GET', VM + '/snapshot')] == ['current']
    assert 'parent' not in await api.data('GET', VM + '/config')


async def test_snapshot_names_and_features(dirs, api):
    await create(api, dirs, scsi0='vmdir:1')
    assert await fails(api, 'POST', VM + '/snapshot', {'snapname': 'current'}) == \
        "unable to use snapshot name 'current' (reserved name)"
    assert await fails(api, 'POST', VM + '/snapshot', {'snapname': 'Pending'}) == \
        "unable to use snapshot name 'pending' (reserved name)"
    assert 'snapname' in await fails(api, 'POST', VM + '/snapshot', {'snapname': '1 bad'}, 400)
    # A raw image on a directory storage cannot be snapshotted; qcow2 and LVM-thin can.
    task = await run(api, dirs, 'POST', VM + '/snapshot', {'snapname': 'snap-a'})
    assert task['exitstatus'] == 'snapshot feature is not available' and dirs.vm(100).lock is None
    await create(api, dirs, 101, scsi0='local-lvm:1')
    assert (await run(api, dirs, 'POST', Q + '/101/snapshot', {'snapname': 'snap-a'}))['exitstatus'] == 'OK'


async def test_snapshots_chain_and_roll_back(dirs, api):
    vm = await create(api, dirs, scsi0='vmdir:1,format=qcow2', memory=128)
    for name in ('snap-a', 'snap-b', 'snap-c'):
        await run(api, dirs, 'POST', VM + '/snapshot', {'snapname': name})
    assert vm.snapshots['snap-c']['parent'] == 'snap-b' and vm.config['parent'] == 'snap-c'
    await api.data('PUT', VM + '/config', {'memory': 256})
    await run(api, dirs, 'DELETE', VM + '/snapshot/snap-b')
    assert vm.snapshots['snap-c']['parent'] == 'snap-a'
    assert (await run(api, dirs, 'POST', VM + '/snapshot/snap-a/rollback'))['exitstatus'] == 'OK'
    assert vm.config['memory'] == '128' and vm.config['parent'] == 'snap-a' and vm.lock is None
    task = await run(api, dirs, 'POST', VM + '/snapshot/snap-zz/rollback')
    assert task['exitstatus'] == "snapshot 'snap-zz' does not exist"
    # Snapshots change the digest.
    digest = (await api.data('GET', VM + '/config'))['digest']
    await run(api, dirs, 'DELETE', VM + '/snapshot/snap-c')
    assert (await api.data('GET', VM + '/config'))['digest'] != digest


# ----------------------------------------------------- clone, template, destroy

async def test_clone_copies_disks_and_refuses_a_used_id(dirs, api):
    src = await create(api, dirs, scsi0='vmdir:1,format=qcow2', net0='virtio,bridge=vmbr0', name='src')
    task = await run(api, dirs, 'POST', VM + '/clone', {'newid': 101, 'full': 1})
    assert task['type'] == 'qmclone' and task['exitstatus'] == 'OK'
    new = dirs.vm(101)
    assert new.name == 'Copy-of-VM-src' and new.lock is None and 'parent' not in new.config
    assert new.config['scsi0'] == 'vmdir:101/vm-101-disk-0.qcow2,size=1G'
    assert new.config['net0'] != src.config['net0'] and new.config['smbios1'] != src.config['smbios1']
    assert sorted(v['volid'] for v in await api.data('GET', NODE + '/storage/vmdir/content')) == [
        'vmdir:100/vm-100-disk-0.qcow2', 'vmdir:101/vm-101-disk-0.qcow2']
    assert await fails(api, 'POST', VM + '/clone', {'newid': 101}) == \
        'unable to create VM 101: config file already exists'
    assert await fails(api, 'POST', VM + '/clone', {'newid': 102, 'snapname': 'zz'}) == \
        "snapshot 'zz' does not exist"
    assert await fails(api, 'POST', VM + '/clone', {'newid': 102, 'storage': 'nosuch'}) == \
        "storage 'nosuch' does not exist"
    assert await fails(api, 'POST', VM + '/clone', {'newid': 102, 'pool': 'nope'}, 403) == \
        "Permission check failed (pool 'nope' does not exist)"
    # A normal VM is cloned in full: no linked clone of its disks.
    assert await fails(api, 'POST', VM + '/clone', {'newid': 102, 'full': 0}) == \
        "Linked clone feature is not supported for 'vmdir:100/vm-100-disk-0.qcow2' (scsi0)"
    assert dirs.vm(102) is None


async def test_a_failed_clone_leaves_nothing(dirs, api):
    await create(api, dirs, scsi0='vmdir:1')
    dirs.storages['vmdir']['avail'] = 100
    task = await run(api, dirs, 'POST', VM + '/clone', {'newid': 101})
    assert task['exitstatus'].startswith('clone failed: unable to write to storage')
    assert dirs.vm(101) is None and list(dirs.storages['vmdir']['volumes']) == ['100/vm-100-disk-0.raw']


async def test_template_makes_base_volumes_and_linked_clones(dirs, api):
    await create(api, dirs, scsi0='vmdir:1,format=qcow2', ide2='vmdir:iso/a.iso,media=cdrom') \
        if False else await create(api, dirs, scsi0='vmdir:1,format=qcow2')
    task = await run(api, dirs, 'POST', VM + '/template')
    assert task['type'] == 'qmtemplate' and task['exitstatus'] == 'OK'
    vm = dirs.vm(100)
    assert vm.template and vm.config['template'] == 1
    assert vm.config['scsi0'] == 'vmdir:100/base-100-disk-0.qcow2,size=1G'
    assert (await api.data('GET', Q))[0]['template'] == 1
    assert await fails(api, 'POST', VM + '/template') == "you can't convert a template to a template"
    start = await run(api, dirs, 'POST', VM + '/status/start')
    assert start['exitstatus'] == "you can't start a vm if it's a template"
    # Linked by default; the clone's volume sits on the base volume.
    assert (await run(api, dirs, 'POST', VM + '/clone', {'newid': 101}))['exitstatus'] == 'OK'
    assert dirs.vm(101).config['scsi0'] == \
        'vmdir:100/base-100-disk-0.qcow2/101/vm-101-disk-0.qcow2,size=1G'
    assert await fails(api, 'POST', VM + '/clone', {'newid': 102, 'storage': 'vmdir'}) == \
        "parameter 'storage' not allowed for linked clones"
    assert (await run(api, dirs, 'POST', VM + '/clone', {'newid': 103, 'full': 1}))['exitstatus'] == 'OK'
    assert dirs.vm(103).config['scsi0'] == 'vmdir:103/vm-103-disk-0.qcow2,size=1G'


async def test_template_checks(dirs, api):
    await create(api, dirs, scsi0='local-lvm:1')
    await run(api, dirs, 'POST', VM + '/snapshot', {'snapname': 'snap-s'})
    assert await fails(api, 'POST', VM + '/template') == 'unable to create template, because VM contains snapshots'
    await run(api, dirs, 'DELETE', VM + '/snapshot/snap-s')
    await run(api, dirs, 'POST', VM + '/status/start')
    assert await fails(api, 'POST', VM + '/template') == "you can't convert a VM to template if VM is running"
    await run(api, dirs, 'POST', VM + '/status/stop')
    await run(api, dirs, 'POST', VM + '/template')
    assert dirs.vm(100).config['scsi0'] == 'local-lvm:base-100-disk-0,size=1G'
    assert (await run(api, dirs, 'POST', VM + '/snapshot', {'snapname': 'snap-x'}))['exitstatus'] == \
        "you can't take a snapshot if it's a template"


async def test_destroy_checks_then_frees_everything(dirs, api):
    dirs.pools['web'] = set()
    await create(api, dirs, scsi0='vmdir:1,format=qcow2', protection=1, pool='web')
    await api.data('POST', VM + '/firewall/rules', {'type': 'in', 'action': 'ACCEPT'})
    assert await fails(api, 'DELETE', VM) == "can't remove VM 100 - protection mode enabled"
    await api.data('PUT', VM + '/config', {'protection': 0})
    await run(api, dirs, 'POST', VM + '/status/start')
    assert await fails(api, 'DELETE', VM) == 'VM 100 is running - destroy failed'
    await run(api, dirs, 'POST', VM + '/status/stop')
    # A volume that no config references stays unless asked for.
    dirs._qm_alloc('vmdir', 100, 'raw', 1024)
    task = await run(api, dirs, 'DELETE', VM, {'purge': 1})
    assert task['type'] == 'qmdestroy' and task['exitstatus'] == 'OK'
    assert dirs.vm(100) is None and dirs.pools['web'] == set()
    assert list(dirs.storages['vmdir']['volumes']) == ['100/vm-100-disk-1.raw']
    assert await api.data('GET', VM + '/firewall/rules') == []
    assert (await fails(api, 'DELETE', VM)).startswith("Configuration file 'nodes/pve1/qemu-server/100.conf'")
    await create(api, dirs, scsi0='vmdir:1')
    await run(api, dirs, 'DELETE', VM, {'destroy-unreferenced-disks': 1})
    assert dirs.storages['vmdir']['volumes'] == {}


async def test_destroying_a_template_frees_its_base_volumes(dirs, api):
    await create(api, dirs, scsi0='vmdir:1,format=qcow2')
    await run(api, dirs, 'POST', VM + '/template')
    await run(api, dirs, 'DELETE', VM)
    assert dirs.storages['vmdir']['volumes'] == {} and dirs.vm(100) is None


async def test_a_locked_vm_cannot_be_destroyed_or_cloned(dirs, api):
    await create(api, dirs)
    dirs.snapshot_lock(100, 'backup')
    task = await run(api, dirs, 'DELETE', VM)
    assert task['exitstatus'] == 'VM is locked (backup)'
    assert await fails(api, 'POST', VM + '/clone', {'newid': 101}) == 'VM is locked (backup)'


async def test_failed_requests_by_name_still_apply(dirs, api):
    await create(api, dirs)
    dirs.fail('DELETE', VM, error='running_destroy_failed', times=1)
    assert await fails(api, 'DELETE', VM) == 'VM 100 is running - destroy failed'
    assert (await api.call('DELETE', VM))[0] == 200
