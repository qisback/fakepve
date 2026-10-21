"""Pools that remember their members, with pve-manager's wording."""

from conftest import Client


async def ops_client(pve, api, user='ops@pve'):
    pve.users[user] = 'pw'
    client = Client(api.session)
    assert (await client.login(user, 'pw'))[0] == 200
    return client


async def error(api, method, path, data=None, status=500):
    got, body = await api.call(method, path, data)
    assert got == status, (got, body)
    return body['message'].strip()


async def test_pool_lifecycle(pve, api):
    pve.add_vm(100, 'vm1')
    pve.add_vm(101, 'vm2')
    assert await api.data('POST', '/pools', {'poolid': 'dev', 'comment': 'dev guests'}) is None
    assert await api.data('GET', '/pools') == [{'poolid': 'dev', 'comment': 'dev guests'}]
    assert await error(api, 'POST', '/pools', {'poolid': 'dev'}) == "create pool failed: pool 'dev' already exists"
    await api.data('PUT', '/pools/dev', {'vms': '100,101', 'comment': 'both'})
    pool = await api.data('GET', '/pools/dev')
    assert pool['comment'] == 'both' and pool['poolid'] == 'dev'
    assert [(m['id'], m['type'], m['vmid'], m['node'], m['name']) for m in pool['members']] == [
        ('qemu/100', 'qemu', 100, 'pve1', 'vm1'), ('qemu/101', 'qemu', 101, 'pve1', 'vm2')]
    # The same through the form PVE 8 and 9 recommend.
    assert await api.data('GET', '/pools?poolid=dev') == [pool]
    assert (await api.data('GET', '/pools?poolid=dev&type=storage'))[0]['members'] == []
    assert pve.vm(100).pool == 'dev' and pve.pools['dev'] == {100, 101}
    resources = await api.data('GET', '/cluster/resources?type=vm')
    assert [(r['vmid'], r['pool']) for r in resources] == [(100, 'dev'), (101, 'dev')]
    await api.data('PUT', '/pools', {'poolid': 'dev', 'vms': '101', 'delete': 1})
    assert [m['vmid'] for m in (await api.data('GET', '/pools/dev'))['members']] == [100]
    assert 'pool' not in (await api.data('GET', '/cluster/resources?type=vm'))[1]
    assert await error(api, 'DELETE', '/pools/dev') == "delete pool failed: pool 'dev' is not empty (contains VM 100)"
    await api.data('PUT', '/pools/dev', {'vms': '100', 'delete': 1})
    assert await api.data('DELETE', '/pools?poolid=dev') is None
    assert await api.data('GET', '/pools') == []
    assert await error(api, 'GET', '/pools/dev') == "pool 'dev' does not exist"
    assert await error(api, 'DELETE', '/pools/dev') == "delete pool failed: pool 'dev' does not exist"


async def test_member_errors_and_moving(pve, api):
    pve.add_vm(100, 'vm1')
    await api.data('POST', '/pools', {'poolid': 'dev'})
    await api.data('POST', '/pools', {'poolid': 'ops'})
    await api.data('PUT', '/pools/dev', {'vms': '100'})
    assert await error(api, 'PUT', '/pools/dev', {'vms': '100'}) == \
        'update pools failed: VM 100 is already a pool member'
    assert await error(api, 'PUT', '/pools/ops', {'vms': '100'}) == \
        "update pools failed: VM 100 belongs already to pool 'dev' and 'allow-move' is not set"
    assert await error(api, 'PUT', '/pools/ops', {'vms': '101', 'delete': 1}) == \
        'update pools failed: VM 101 is not a pool member'
    assert await error(api, 'PUT', '/pools/nope', {'vms': '100'}) == "update pools failed: pool 'nope' does not exist"
    # A failed update changes nothing, whatever came before the failure.
    assert (await error(api, 'PUT', '/pools/ops', {'comment': 'x', 'vms': '100'})).startswith('update pools failed')
    assert (await api.data('GET', '/pools'))[1] == {'poolid': 'ops'}
    await api.data('PUT', '/pools/ops', {'vms': '100', 'allow-move': 1})
    assert pve.pools == {'dev': set(), 'ops': {100}} and pve.vm(100).pool == 'ops'


async def test_storage_members(pve, api):
    await api.data('POST', '/pools', {'poolid': 'dev'})
    await api.data('PUT', '/pools/dev', {'storage': 'local,local-lvm'})
    members = (await api.data('GET', '/pools/dev'))['members']
    assert [(m['id'], m['storage'], m['type']) for m in members] == [
        ('storage/pve1/local', 'local', 'storage'), ('storage/pve1/local-lvm', 'local-lvm', 'storage')]
    assert [m['storage'] for m in (await api.data('GET', '/pools/dev?type=storage'))['members']] == [
        'local', 'local-lvm']
    resources = await api.data('GET', '/cluster/resources?type=storage')
    assert {r['storage']: r.get('pool') for r in resources} == {'local': 'dev', 'local-lvm': 'dev'}
    assert await error(api, 'PUT', '/pools/dev', {'storage': 'local'}) == \
        "update pools failed: Storage 'local' is already a pool member"
    assert await error(api, 'DELETE', '/pools/dev') == \
        "delete pool failed: pool 'dev' is not empty (contains storage 'local')"
    await api.data('PUT', '/pools/dev', {'storage': 'local', 'delete': 1})
    assert await error(api, 'PUT', '/pools/dev', {'storage': 'local', 'delete': 1}) == \
        "update pools failed: Storage 'local' is not a pool member"
    await api.data('DELETE', '/storage/local-lvm')
    assert await api.data('DELETE', '/pools/dev') is None


async def test_nested_pools(api):
    await api.data('POST', '/pools', {'poolid': 'dev'})
    assert await error(api, 'POST', '/pools', {'poolid': 'qa/team'}) == \
        "create pool failed: parent 'qa' of pool 'qa/team' does not exist"
    await api.data('POST', '/pools', {'poolid': 'dev/web', 'comment': 'sub'})
    assert [p['poolid'] for p in await api.data('GET', '/pools')] == ['dev', 'dev/web']
    assert (await api.data('GET', '/pools?poolid=dev/web'))[0]['comment'] == 'sub'
    assert await error(api, 'DELETE', '/pools?poolid=dev') == \
        "delete pool failed: pool 'dev' is not empty (contains pool 'dev/web')"
    await api.data('DELETE', '/pools?poolid=dev/web')
    await api.data('DELETE', '/pools?poolid=dev')


async def test_pool_permissions(pve, api):
    pve.add_vm(100, 'vm1')
    pve.add_vm(101, 'vm2')
    ops = await ops_client(pve, api)
    pve.grant('ops@pve', '/nodes', 'Sys.Audit')  # the first grant turns permission checks on
    status, body = await ops.call('POST', '/pools', {'poolid': 'dev'})
    assert status == 403 and body['message'].strip() == 'Permission check failed (/pool/dev, Pool.Allocate)'
    pve.grant('ops@pve', '/pool/dev', 'Pool.Allocate', 'Pool.Audit')
    assert (await ops.call('POST', '/pools', {'poolid': 'dev'}))[0] == 200
    assert await api.data('POST', '/pools', {'poolid': 'other'}) is None
    assert [p['poolid'] for p in await ops.data('GET', '/pools')] == ['dev']
    # Adding a guest needs the right to change permissions on it (Permissions.Modify or VM.Allocate).
    assert await error(ops, 'PUT', '/pools/dev', {'vms': '100'}) == \
        'update pools failed: Permission check failed (/vms/100, Permissions.Modify|VM.Allocate)'
    pve.grant('ops@pve', '/vms/100', 'VM.Allocate')
    await ops.data('PUT', '/pools/dev', {'vms': '100'})
    # Membership carries the pool's grants to the guest.
    pve.grant('ops@pve', '/pool/dev', 'VM.Audit')
    assert [r['vmid'] for r in await ops.data('GET', '/cluster/resources?type=vm')] == [100]
    # And a storage in the pool is seen by those with Datastore.Audit on the pool.
    pve.grant('ops@pve', '/pool/dev', 'Datastore.Audit')
    pve.grant('ops@pve', '/storage/local', 'Datastore.Allocate')
    assert await ops.data('GET', '/storage') == []
    await ops.data('PUT', '/pools/dev', {'storage': 'local'})
    assert [s['storage'] for s in await ops.data('GET', '/storage')] == ['local']
    assert (await ops.call('DELETE', '/pools/dev'))[0] == 500
    status, body = await ops.call('GET', '/pools/other')
    assert status == 403 and body['message'].strip() == 'Permission check failed (/pool/other, Pool.Audit)'


async def test_a_name_with_a_space_has_no_acl_path(pve, api):
    # PVE checks permissions first, and a path it cannot normalise gives nobody (but root@pam) a privilege:
    # the 403 shows an empty path. The root login reaches the format check and gets the 400.
    ops = await ops_client(pve, api)
    status, body = await ops.call('POST', '/pools', {'poolid': 'bad name'})
    assert status == 403 and body['message'].strip() == 'Permission check failed (, Pool.Allocate)'
    status, body = await api.call('POST', '/pools', {'poolid': 'bad name'})
    assert status == 400 and 'poolid' in body['errors']
    assert await ops.data('GET', '/pools') == []


async def test_a_pool_of_vms_made_through_the_api(pve, api):
    await api.data('POST', '/pools', {'poolid': 'dev'})
    upid = await api.data('POST', '/nodes/pve1/qemu', {'vmid': 100, 'name': 'vm1', 'pool': 'dev'})
    assert pve.tasks[upid]['exitstatus'] == 'OK'
    assert pve.pools['dev'] == {100}
    assert await error(api, 'DELETE', '/pools/dev') == "delete pool failed: pool 'dev' is not empty (contains VM 100)"
    await api.data('PUT', '/pools/dev', {'vms': '100', 'delete': 1})
    assert await error(api, 'PUT', '/pools/dev', {'vms': '100', 'delete': 1}) == \
        'update pools failed: VM 100 is not a pool member'
    assert await api.data('DELETE', '/pools/dev') is None
    assert pve.vm(100).pool is None
