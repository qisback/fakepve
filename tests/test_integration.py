"""Containers meet the storage, pool and firewall state: one model, whichever module owns it."""

from conftest import Client

from test_lxc import CT, TEMPLATE, done, failed, make


async def ops_client(pve, api, user='ops@pve'):
    pve.users[user] = 'pw'
    client = Client(api.session)
    assert (await client.login(user, 'pw'))[0] == 200
    return client


# -------------------------------------------------------------------- pools

async def test_container_pool_membership(pve, api):
    pve.add_vm(101, 'vm1')
    await api.data('POST', '/pools', {'poolid': 'web'})
    await make(api, pool='web')
    assert pve.pools['web'] == {100} and pve.ct(100).pool == 'web'
    await api.data('PUT', '/pools/web', {'vms': '101'})
    members = (await api.data('GET', '/pools/web'))['members']
    assert [(m['id'], m['type'], m['vmid'], m['name']) for m in members] == [
        ('lxc/100', 'lxc', 100, 'web'), ('qemu/101', 'qemu', 101, 'vm1')]
    assert [m['vmid'] for m in (await api.data('GET', '/pools/web?type=lxc'))['members']] == [100]
    assert [m['vmid'] for m in (await api.data('GET', '/pools?poolid=web&type=qemu'))[0]['members']] == [101]
    resources = await api.data('GET', '/cluster/resources?type=vm')
    assert {(r['type'], r['pool']) for r in resources} == {('lxc', 'web'), ('qemu', 'web')}
    # A pool that has a container is not empty, and a container taken out loses its `pool` field.
    status, body = await api.call('DELETE', '/pools/web')
    assert status == 500 and 'contains VM 100' in body['message']
    await api.data('PUT', '/pools/web', {'vms': '100', 'delete': 1})
    assert pve.ct(100).pool is None
    assert 'pool' not in next(r for r in await api.data('GET', '/cluster/resources') if r['type'] == 'lxc')


async def test_clone_and_destroy_keep_pool_membership(pve, api):
    await api.data('POST', '/pools', {'poolid': 'web'})
    await api.data('POST', '/pools', {'poolid': 'qa'})
    await make(api)
    await done(api, await api.data('POST', CT + '/clone', {'newid': 101, 'pool': 'qa'}))
    assert pve.pools == {'web': set(), 'qa': {101}} and pve.ct(101).pool == 'qa'
    await api.data('PUT', '/pools/qa', {'vms': '100'})
    assert pve.pools['qa'] == {100, 101}
    await done(api, await api.data('DELETE', CT))
    assert pve.pools['qa'] == {101}
    await done(api, await api.data('DELETE', '/nodes/pve1/lxc/101'))
    assert pve.pools['qa'] == set()
    assert (await api.data('GET', '/pools/qa'))['members'] == []
    assert await api.data('DELETE', '/pools/qa') is None


async def test_failed_create_does_not_join_the_pool(pve, api):
    await api.data('POST', '/pools', {'poolid': 'web'})
    pve.volume_exists = lambda volid: False
    await failed(api, ('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE, 'pool': 'web', 'rootfs': 'local-lvm:8'}),
                 "unable to create CT 100 - volume '{0}' does not exist".format(TEMPLATE))
    assert pve.pools['web'] == set()


async def test_pool_permissions_cover_member_containers(pve, api):
    await api.data('POST', '/pools', {'poolid': 'web'})
    ops = await ops_client(pve, api)
    pve.grant('ops@pve', '/nodes', 'Sys.Audit')
    body = {'vmid': 100, 'ostemplate': TEMPLATE, 'pool': 'web', 'rootfs': 'local-lvm:8'}
    status, answer = await ops.call('POST', '/nodes/pve1/lxc', body)
    assert status == 403 and answer['message'] == 'Permission check failed\n'
    pve.grant('ops@pve', '/pool/web', 'VM.Allocate', 'VM.Config.Disk', 'VM.Config.Options')
    pve.grant('ops@pve', '/storage', 'Datastore.AllocateSpace')
    await done(api, await ops.data('POST', '/nodes/pve1/lxc', body))
    assert pve.pools['web'] == {100}
    # The container is under the pool now: the pool's grants reach it, and only those.
    assert await ops.data('GET', '/cluster/resources?type=vm') == []
    status, answer = await ops.call('POST', CT + '/status/start')
    assert status == 403 and answer['message'] == 'Permission check failed (/vms/100, VM.PowerMgmt)\n'
    pve.grant('ops@pve', '/pool/web', 'VM.Audit', 'VM.PowerMgmt')
    assert [(r['vmid'], r['pool']) for r in await ops.data('GET', '/cluster/resources?type=vm')] == [(100, 'web')]
    await done(api, await ops.data('POST', CT + '/status/start'))
    assert pve.ct(100).status == 'running'
    # A container outside the pool is not covered.
    pve.add_ct(200, 'other')
    status, answer = await ops.call('POST', '/nodes/pve1/lxc/200/status/start')
    assert status == 403 and answer['message'] == 'Permission check failed (/vms/200, VM.PowerMgmt)\n'


# ------------------------------------------------------------------ storage

async def test_missing_ostemplate_fails_the_create_task(pve, api):
    # Nothing recorded on the storage: every template is accepted.
    await make(api)
    await done(api, await api.data('DELETE', CT))
    pve.store_file('local', 'other-1.0.tar.zst', 1000, 'vztmpl')
    await failed(api, ('POST', '/nodes/pve1/lxc', {'vmid': 100, 'ostemplate': TEMPLATE, 'rootfs': 'local-lvm:8'}),
                 "unable to create CT 100 - volume '{0}' does not exist".format(TEMPLATE))
    assert pve.cts == []
    await make(api, ostemplate='local:vztmpl/other-1.0.tar.zst')
    assert pve.ct(100) is not None
    assert pve.volume_exists('local:vztmpl/other-1.0.tar.zst') is True
    assert pve.volume_exists(TEMPLATE) is False
    assert pve.volume_exists('nowhere:vztmpl/x.tar.zst') is None
    assert pve.volume_exists('local:backup/none.tar') is None


async def test_container_volumes_are_used_space_in_the_listing(pve, api):
    await make(api, mp0='local-lvm:2,mp=/data')
    items = await api.data('GET', '/nodes/pve1/storage/local-lvm/content')
    got = {i['volid']: (i['content'], i['vmid'], i['size']) for i in items}
    assert got == {'local-lvm:vm-100-disk-0': ('rootdir', 100, 8 * 1024 ** 3),
                   'local-lvm:vm-100-disk-1': ('rootdir', 100, 2 * 1024 ** 3)}
    only = await api.data('GET', '/nodes/pve1/storage/local-lvm/content?vmid=100&content=rootdir')
    assert len(only) == 2
    assert await api.data('GET', '/nodes/pve1/storage/local-lvm/content?vmid=101') == []
    await done(api, await api.data('DELETE', CT))
    assert await api.data('GET', '/nodes/pve1/storage/local-lvm/content') == []


# ------------------------------------------------------------------ cluster

async def test_nextid_skips_vms_and_containers(pve, api):
    assert await api.data('GET', '/cluster/nextid') == 100
    pve.add_vm(100, 'vm1')
    pve.add_ct(101, 'ct1')
    assert await api.data('GET', '/cluster/nextid') == 102
    pve.add_ct(102, 'ct2', node='pve2')
    assert await api.data('GET', '/cluster/nextid') == 103
    assert str(await api.data('GET', '/cluster/nextid?vmid=500')) == '500'
    for taken in (100, 101, 102):
        status, body = await api.call('GET', '/cluster/nextid?vmid={0}'.format(taken))
        assert status == 400 and body['errors'] == {'vmid': 'VM {0} already exists'.format(taken)}
    await make(api, vmid=103)
    assert await api.data('GET', '/cluster/nextid') == 104


# ----------------------------------------------------------------- firewall

async def test_container_firewall_is_served_by_the_firewall_module(pve, api):
    fw = '/nodes/pve1/lxc/100/firewall'
    await make(api)
    rule = {'type': 'in', 'action': 'ACCEPT', 'proto': 'tcp', 'dport': '22', 'source': '192.0.2.0/24'}
    assert await api.data('POST', fw + '/rules', rule) is None
    rules = await api.data('GET', fw + '/rules')
    assert [(r['type'], r['action'], r['dport'], r['source']) for r in rules] == [
        ('in', 'ACCEPT', '22', '192.0.2.0/24')]
    await api.data('PUT', fw + '/options', {'enable': 1, 'policy_in': 'DROP'})
    assert (await api.data('GET', fw + '/options'))['policy_in'] == 'DROP'
    await api.data('POST', fw + '/aliases', {'name': 'lan', 'cidr': '192.0.2.0/24'})
    assert [a['name'] for a in await api.data('GET', fw + '/aliases')] == ['lan']
    await api.data('POST', fw + '/ipset', {'name': 'trusted'})
    await api.data('POST', fw + '/ipset/trusted', {'cidr': '198.51.100.7'})
    assert [e['cidr'] for e in await api.data('GET', fw + '/ipset/trusted')] == ['198.51.100.7']
    # The config is kept by id, so the qemu path of the same id reads the same rules.
    assert len(await api.data('GET', '/nodes/pve1/qemu/100/firewall/rules')) == 1
    status, body = await api.call('POST', fw + '/rules', {'type': 'in', 'action': 'ACCEPT', 'source': 'nonsense'})
    assert status in (400, 500) and 'nonsense' in str(body)
