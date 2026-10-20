"""Storage that remembers: config, node status and content volumes, with pve-storage's wording."""

from conftest import Client

NODE = '/nodes/pve1'


async def ops_client(pve, api, user='ops@pve'):
    pve.users[user] = 'pw'
    client = Client(api.session)
    assert (await client.login(user, 'pw'))[0] == 200
    return client


async def error(api, method, path, data=None, status=500):
    got, body = await api.call(method, path, data)
    assert got == status, (got, body)
    return body['message'].strip() if status != 400 else body['errors']


# ---------------------------------------------------------------- config

async def test_create_read_list_update_delete(api):
    out = await api.data('POST', '/storage', {'storage': 'backups', 'type': 'dir', 'path': '/srv/backups',
                                              'content': 'backup,iso'})
    assert out == {'storage': 'backups', 'type': 'dir'}
    cfg = await api.data('GET', '/storage/backups')
    assert {k: cfg[k] for k in ('storage', 'type', 'path', 'content')} == {
        'storage': 'backups', 'type': 'dir', 'path': '/srv/backups', 'content': 'backup,iso'}
    assert [s['storage'] for s in await api.data('GET', '/storage')] == ['backups', 'local', 'local-lvm']
    assert [s['storage'] for s in await api.data('GET', '/storage?type=lvmthin')] == ['local-lvm']
    await api.data('PUT', '/storage/backups', {'content': 'backup', 'digest': cfg['digest'], 'shared': 1})
    new = await api.data('GET', '/storage/backups')
    assert new['content'] == 'backup' and new['shared'] == 1 and new['digest'] != cfg['digest']
    await api.data('PUT', '/storage/backups', {'delete': 'shared', 'digest': new['digest']})
    assert 'shared' not in await api.data('GET', '/storage/backups')
    assert await api.data('DELETE', '/storage/backups') is None
    assert await error(api, 'GET', '/storage/backups') == "storage 'backups' does not exist"


async def test_config_errors_in_pves_words(api):
    await api.data('POST', '/storage', {'storage': 'one', 'type': 'dir', 'path': '/srv/one'})
    assert await error(api, 'POST', '/storage', {'storage': 'one', 'type': 'dir', 'path': '/srv/two'}) == \
        "create storage failed: storage ID 'one' already defined"
    assert await error(api, 'POST', '/storage', {'storage': 'two', 'type': 'dir'}) == \
        "missing value for required option 'path'"
    assert await error(api, 'POST', '/storage', {'storage': 'two', 'type': 'dir', 'path': '/a', 'vgname': 'v'}) == \
        "unexpected property 'vgname'"
    assert await error(api, 'POST', '/storage', {'storage': 'two', 'type': 'lvm', 'vgname': 'v',
                                                 'content': 'iso'}) == \
        "storage does not support content type 'none'"
    # Fixed options are not in the update schema at all.
    assert await error(api, 'PUT', '/storage/one', {'path': '/elsewhere'}, status=400) == {
        'path': 'property is not defined in schema and the schema does not allow additional properties'}
    assert await error(api, 'PUT', '/storage/one', {'delete': 'path'}) == \
        "update storage failed: unable to delete required option 'path'"
    assert await error(api, 'PUT', '/storage/one', {'delete': 'bogus'}) == "update storage failed: no such option 'bogus'"
    assert await error(api, 'PUT', '/storage/one', {'shared': 1, 'delete': 'shared'}) == \
        "update storage failed: cannot set and delete property 'shared' at the same time!"
    assert await error(api, 'PUT', '/storage/one', {'shared': 1, 'digest': '0' * 40}) == \
        'update storage failed: detected modified configuration - file changed by other user? Try again.'
    assert await error(api, 'PUT', '/storage/nope', {'shared': 1}) == "update storage failed: storage 'nope' does not exist"
    assert await error(api, 'DELETE', '/storage/nope') == "delete storage failed: storage 'nope' does not exist"


async def test_type_specific_options(api):
    out = await api.data('POST', '/storage', {'storage': 'share', 'type': 'nfs', 'server': '192.0.2.10',
                                              'export': '/export/vm'})
    assert out['type'] == 'nfs'
    cfg = await api.data('GET', '/storage/share')
    assert cfg['path'] == '/mnt/pve/share' and cfg['content'] == 'images'
    assert await error(api, 'POST', '/storage', {'storage': 'bad', 'type': 'nfs', 'server': '192.0.2.10'}) == \
        "missing value for required option 'export'"
    await api.data('POST', '/storage', {'storage': 'smb', 'type': 'cifs', 'server': '192.0.2.11', 'share': 'vm',
                                        'username': 'u', 'password': 'secret'})
    assert 'password' not in await api.data('GET', '/storage/smb')
    assert await error(api, 'POST', '/storage', {'storage': 'ld', 'type': 'dir', 'path': '/a', 'password': 'x'}) == \
        "unexpected property 'password'"


async def test_storage_permissions(pve, api):
    ops = await ops_client(pve, api)
    pve.grant('ops@pve', '/storage/local', 'Datastore.Audit')
    assert [s['storage'] for s in await ops.data('GET', '/storage')] == ['local']
    status, body = await ops.call('GET', '/storage/local')
    assert status == 403 and body['message'].strip() == 'Permission check failed (/storage/local, Datastore.Allocate)'
    status, body = await ops.call('POST', '/storage', {'storage': 'xx', 'type': 'dir', 'path': '/x'})
    assert status == 403 and body['message'].strip() == 'Permission check failed (/storage, Datastore.Allocate)'
    pve.grant('ops@pve', '/storage', 'Datastore.Allocate')
    assert (await ops.call('POST', '/storage', {'storage': 'xx', 'type': 'dir', 'path': '/x'}))[0] == 200


# ----------------------------------------------------------- node status

async def test_node_status_follows_the_config(pve, api):
    pve.add_node('pve2')
    await api.data('POST', '/storage', {'storage': 'only2', 'type': 'dir', 'path': '/srv/only2', 'nodes': 'pve2',
                                        'content': 'images,iso'})
    on1 = dict((s['storage'], s) for s in await api.data('GET', NODE + '/storage'))
    on2 = dict((s['storage'], s) for s in await api.data('GET', '/nodes/pve2/storage'))
    assert (on1['only2']['enabled'], on1['only2']['active']) == (0, 0)
    assert (on2['only2']['enabled'], on2['only2']['active']) == (1, 1)
    assert on2['only2']['content'] == 'images,iso' and on2['only2']['total'] > 0
    assert await error(api, 'GET', NODE + '/storage/only2/content') == "storage 'only2' is not available on node 'pve1'"
    resources = await api.data('GET', '/cluster/resources?type=storage')
    assert sorted(r['id'] for r in resources if r['storage'] == 'only2') == ['storage/pve2/only2']
    await api.data('PUT', '/storage/only2', {'disable': 1})
    assert (await api.data('GET', '/nodes/pve2/storage?storage=only2'))[0]['enabled'] == 0
    assert 'only2' not in [s['storage'] for s in await api.data('GET', '/nodes/pve2/storage?content=iso')]
    assert 'only2' not in [s['storage'] for s in await api.data('GET', '/nodes/pve2/storage?enabled=1')]
    assert await error(api, 'GET', '/nodes/pve2/storage/only2/content') == "storage 'only2' is disabled"
    assert await error(api, 'GET', NODE + '/storage/nope/status', status=400) == {'storage': 'No such storage.'}
    assert await error(api, 'GET', NODE + '/storage?storage=nope', status=400) == {'storage': 'No such storage.'}


async def test_status_shows_space_and_formats(api):
    item = (await api.data('GET', NODE + '/storage?storage=local&format=1'))[0]
    assert item['total'] == item['used'] + item['avail'] == 50 * 1024 ** 3
    assert item['used_fraction'] == 0 and item['formats']['default'] == 'raw'
    assert 'qcow2' in item['formats']['supported']
    status = await api.data('GET', NODE + '/storage/local/status')
    assert status['type'] == 'dir' and status['enabled'] == 1 and 'storage' not in status


# --------------------------------------------------------------- content

async def make_store(api, name='vmstore'):
    await api.data('POST', '/storage', {'storage': name, 'type': 'dir', 'path': '/srv/' + name,
                                        'content': 'images,backup,iso'})


async def test_allocate_list_info_delete(pve, api):
    await make_store(api)
    base = NODE + '/storage/vmstore/content'
    volid = await api.data('POST', base, {'filename': 'vm-100-disk-0.qcow2', 'vmid': 100, 'size': '1G'})
    assert volid == 'vmstore:100/vm-100-disk-0.qcow2'
    item = (await api.data('GET', base))[0]
    assert (item['volid'], item['format'], item['size'], item['vmid'], item['content']) == (
        volid, 'qcow2', 1024 ** 3, 100, 'images')
    assert await api.data('GET', base + '?vmid=101') == []
    info = await api.data('GET', base + '/' + volid)
    assert info['path'] == '/srv/vmstore/images/100/vm-100-disk-0.qcow2' and info['size'] == 1024 ** 3
    assert (await api.data('GET', base + '/vmstore%3A100%2Fvm-100-disk-0.qcow2'))['format'] == 'qcow2'
    assert (await api.data('GET', NODE + '/storage/vmstore/status'))['used'] == 1024 ** 3
    assert await error(api, 'POST', base, {'filename': 'vm-100-disk-0.qcow2', 'vmid': 100, 'size': '1G'}) == \
        "disk image '/srv/vmstore/images/100/vm-100-disk-0.qcow2' already exists"
    upid = await api.data('DELETE', base + '/' + volid)
    task = await api.data('GET', NODE + '/tasks/' + upid + '/status')
    assert task['type'] == 'imgdel' and task['id'] == '100@vmstore' and task['exitstatus'] == 'OK'
    log = await api.data('GET', NODE + '/tasks/' + upid + '/log')
    assert "Removed volume 'vmstore:100/vm-100-disk-0.qcow2'" in [line['t'] for line in log]
    assert await api.data('GET', base) == []
    assert (await api.data('GET', NODE + '/storage/vmstore/status'))['used'] == 0


async def test_allocate_names_and_formats(api):
    await make_store(api)
    base = NODE + '/storage/vmstore/content'
    assert await error(api, 'POST', base, {'filename': 'a.raw', 'vmid': 100, 'size': '4M', 'format': 'qcow2'},
                       status=400) == {'format': 'different storage formats (qcow2 != raw)'}
    assert await error(api, 'POST', base, {'filename': 'disk.iso', 'vmid': 100, 'size': '4M'}) == \
        "unable to parse volume filename 'disk.iso'"
    assert await api.data('POST', base, {'filename': 'data', 'vmid': 100, 'size': '4M', 'format': 'qcow2'}) == \
        'vmstore:100/data.qcow2'
    assert await api.data('POST', base, {'filename': 'plain.raw', 'vmid': 100, 'size': '2048'}) == \
        'vmstore:100/plain.raw'
    assert (await api.data('GET', base + '/vmstore:100/plain.raw'))['size'] == 2048 * 1024
    assert await error(api, 'POST', base, {'filename': 'bad.vmdk', 'vmid': 100, 'size': '1M', 'format': 'raw'},
                       status=400) == {'format': 'different storage formats (raw != vmdk)'}
    assert await error(api, 'POST', base, {'filename': 'x.raw', 'vmid': 100, 'size': 'huge'}, status=400)
    assert await error(api, 'GET', base + '/vmstore:nonsense') == "unable to parse directory volume name 'nonsense'"
    assert await error(api, 'GET', base + '/other:100/a.raw', status=400) == {
        'volume': 'storage ID mismatch (other != vmstore)\n'}
    assert await error(api, 'GET', base + '/vmstore:100/gone.raw') == \
        "volume_size_info on 'vmstore:100/gone.raw' failed - no format"


async def test_block_storage_names(pve, api):
    pve.add_ceph_storage('ceph-pool', pool='rbd')
    base = NODE + '/storage/ceph-pool/content'
    assert await api.data('POST', base, {'filename': 'vm-100-disk-0', 'vmid': 100, 'size': '1G'}) == \
        'ceph-pool:vm-100-disk-0'
    assert await error(api, 'POST', base, {'filename': 'vm-101-disk-0', 'vmid': 100, 'size': '1G'}) == \
        "illegal name 'vm-101-disk-0' - should be 'vm-100-*'"
    assert await error(api, 'POST', base, {'filename': 'vm-100-disk-1', 'vmid': 100, 'size': '1G',
                                           'format': 'qcow2'}) == "unsupported format 'qcow2'"
    assert (await api.data('GET', base + '/ceph-pool:vm-100-disk-0'))['path'] == 'rbd:rbd/vm-100-disk-0'


async def test_volumes_referenced_by_vm_configs(pve, api):
    await make_store(api)
    pve.add_vm(101, 'vm2', config={'scsi0': 'vmstore:101/vm-101-disk-0.raw,size=2G', 'ide2': 'vmstore:iso/x.iso'})
    items = await api.data('GET', NODE + '/storage/vmstore/content?content=images')
    assert [(i['volid'], i['vmid'], i['size']) for i in items] == [('vmstore:101/vm-101-disk-0.raw', 101, 2 * 1024 ** 3)]
    assert (await api.data('GET', NODE + '/storage/vmstore/status'))['used'] == 0
    assert (await api.data('GET', NODE + '/storage/vmstore/content/vmstore:101/vm-101-disk-0.raw'))['size'] == \
        2 * 1024 ** 3


async def test_notes_and_protection_are_for_backups(pve, api):
    await make_store(api)
    name = 'backup/vzdump-qemu-100-2026_10_20-00_00_00.vma.zst'
    pve.storages['vmstore']['volumes'][name] = {'content': 'backup', 'format': 'vma.zst', 'size': 4096, 'vmid': 100}
    base = NODE + '/storage/vmstore/content/vmstore:' + name
    assert (await api.data('GET', base))['protected'] == 0
    await api.data('PUT', base, {'notes': 'before upgrade', 'protected': 1})
    info = await api.data('GET', base)
    assert info['notes'] == 'before upgrade' and info['protected'] == 1
    listed = (await api.data('GET', NODE + '/storage/vmstore/content?content=backup'))[0]
    assert listed['notes'] == 'before upgrade' and listed['protected'] == 1 and listed['vmid'] == 100
    task = await api.data('GET', NODE + '/tasks/' + await api.data('DELETE', base) + '/status')
    assert task['exitstatus'] == "cannot remove protected volume '{0}' on 'vmstore'".format(name)
    await api.data('PUT', base, {'protected': 0})
    task = await api.data('GET', NODE + '/tasks/' + await api.data('DELETE', base) + '/status')
    assert task['id'] == '100@vmstore' and task['exitstatus'] == 'OK'
    await api.data('POST', NODE + '/storage/vmstore/content', {'filename': 'a.raw', 'vmid': 100, 'size': '1M'})
    assert await error(api, 'PUT', NODE + '/storage/vmstore/content/vmstore:100/a.raw', {'notes': 'x'}) == \
        'only backups can have notes'
    assert await error(api, 'PUT', NODE + '/storage/vmstore/content/vmstore:100/a.raw', {'protected': 1}) == \
        "only backups support attribute 'protected'"


async def test_content_needs_the_content_type_and_a_file_storage(api):
    await make_store(api)
    url = {'url': 'https://example.org/t.tar.zst', 'filename': 't.tar.zst', 'content': 'vztmpl'}
    assert await error(api, 'POST', NODE + '/storage/vmstore/download-url', url) == \
        "storage 'vmstore' is not configured for content-type 'vztmpl'"
    assert await error(api, 'POST', NODE + '/storage/local-lvm/download-url', url) == \
        "can't upload to storage type 'lvmthin', not a file based storage!"
    upid = await api.data('POST', NODE + '/storage/local/download-url', url)
    assert (await api.data('GET', NODE + '/tasks/' + upid + '/status'))['exitstatus'] == 'OK'
    items = await api.data('GET', NODE + '/storage/local/content?content=vztmpl')
    assert [(i['volid'], i['content'], i['format']) for i in items] == [('local:vztmpl/t.tar.zst', 'vztmpl', 'zst')]


async def test_isos_keep_working(pve, api):
    pve.storages['local']['files'].add('debian.iso')
    items = await api.data('GET', NODE + '/storage/local/content')
    assert [(i['volid'], i['content'], i['format']) for i in items] == [('local:iso/debian.iso', 'iso', 'iso')]
    upid = await api.data('DELETE', NODE + '/storage/local/content/local:iso/debian.iso')
    assert (await api.data('GET', NODE + '/tasks/' + upid + '/status'))['exitstatus'] == 'OK'
    assert pve.storages['local']['files'] == set()


async def test_content_permissions(pve, api):
    await make_store(api)
    ops = await ops_client(pve, api)
    pve.grant('ops@pve', '/nodes', 'Sys.Audit')  # the first grant turns permission checks on
    base = NODE + '/storage/vmstore/content'
    status, body = await ops.call('POST', base, {'filename': 'a.raw', 'vmid': 100, 'size': '1M'})
    assert status == 403 and body['message'].strip() == 'Permission check failed (/storage/vmstore, Datastore.AllocateSpace)'
    pve.grant('ops@pve', '/storage/vmstore', 'Datastore.AllocateSpace', 'Datastore.Audit')
    volid = await ops.data('POST', base, {'filename': 'a.raw', 'vmid': 100, 'size': '1M'})
    # Owned images need VM.Config.Disk on the owner as well.
    assert await ops.data('GET', base) == []
    status, body = await ops.call('DELETE', base + '/' + volid)
    assert status == 403 and body['message'].strip() == 'Permission check failed (/storage/vmstore, Datastore.Allocate)'
    pve.grant('ops@pve', '/vms/100', 'VM.Config.Disk')
    assert len(await ops.data('GET', base)) == 1
    assert (await ops.data('GET', base + '/' + volid))['size'] == 1024 ** 2
    pve.grant('ops@pve', '/storage/vmstore', 'Datastore.Allocate')
    assert (await ops.call('DELETE', base + '/' + volid))[0] == 200
