"""Answers carry the keys a real PVE always sends, with the types it sends (see shapes.py).

The expectations come from PVE's API documentation and what its clients read; nothing here comes from a
recording of a real cluster.
"""

import pytest

from fakepve import schema, shapes


def has(data, keys):
    missing = [k for k in keys if k not in data]
    assert not missing, missing


def types(data, **expected):
    """Every named key has the Python type (or one of the types) given."""
    for key, kind in expected.items():
        assert isinstance(data[key], kind) and not (kind is int and isinstance(data[key], bool)), (key, data[key])


GUEST_USAGE = ('cpu', 'disk', 'maxdisk', 'maxmem', 'mem', 'netin', 'netout', 'uptime')


async def test_qemu_status_current_has_the_usage_and_running_fields(pve, api):
    pve.add_vm(100, 'vm1', status='running', config={'memory': 1024, 'cores': 2, 'tags': 'web',
                                                    'scsi0': 'local:100/vm-100-disk-0.raw,size=32G'})
    data = await api.data('GET', '/nodes/pve1/qemu/100/status/current')
    has(data, GUEST_USAGE + ('balloon', 'clipboard', 'cpus', 'diskread', 'diskwrite', 'memhost', 'name', 'pid',
                             'agent', 'serial', 'qmpstatus', 'running-machine', 'running-qemu', 'status', 'tags',
                             'vmid', 'ha', 'pressurecpufull', 'pressurecpusome', 'pressureiofull', 'pressureiosome',
                             'pressurememoryfull', 'pressurememorysome'))
    types(data, maxdisk=int, maxmem=int, cpus=int, pid=int, agent=int, serial=int, balloon=int, tags=str,
          pressurecpufull=int, uptime=int, memhost=int)
    assert data['maxdisk'] == 32 * 1024 ** 3 and data['maxmem'] == 1024 * 1024 ** 2 and data['cpus'] == 2
    assert data['clipboard'] is None and data['ha'] == {'managed': 0}


async def test_a_stopped_vm_has_no_process_fields(pve, api):
    pve.add_vm(100, 'vm1')
    data = await api.data('GET', '/nodes/pve1/qemu/100/status/current')
    has(data, GUEST_USAGE + ('cpus', 'name', 'status', 'vmid'))
    assert not {'pid', 'running-qemu', 'running-machine', 'pressurecpufull'} & set(data)


async def test_the_qemu_list_shows_the_vms_of_the_node_only(pve, api):
    pve.add_vm(100, 'vm1', status='running', config={'memory': 512})
    pve.add_vm(101, 'vm2', node='pve2', template=True)
    data = await api.data('GET', '/nodes/pve1/qemu')
    assert [d['vmid'] for d in data] == [100]
    has(data[0], GUEST_USAGE + ('cpus', 'memhost', 'name', 'status', 'vmid', 'pid'))
    assert 'diskread' not in data[0]
    other = await api.data('GET', '/nodes/pve2/qemu')
    assert [d['vmid'] for d in other] == [101] and other[0]['template'] == 1


async def test_the_qemu_list_is_filtered_by_audit_rights(pve, api):
    pve.add_vm(100, 'vm1')
    pve.add_vm(101, 'vm2')
    pve.users['bob@pve'] = 'pw'
    pve.grant('bob@pve', '/vms/101', 'VM.Audit')
    bob = type(api)(api.session)
    await bob.login('bob@pve', 'pw')
    assert [d['vmid'] for d in await bob.data('GET', '/nodes/pve1/qemu')] == [101]


async def test_qemu_config_sends_memory_as_a_string(pve, api):
    pve.add_vm(100, 'vm1', config={'memory': 2048})
    data = await api.data('GET', '/nodes/pve1/qemu/100/config')
    assert data['memory'] == '2048'


async def test_cluster_resources_carry_usage_for_guests_and_nodes(pve, api):
    pve.add_vm(100, 'vm1', status='running', config={'tags': 'web'})
    pve.add_ct(200, 'ct1', status='running')
    by_type = dict((r['type'], r) for r in await api.data('GET', '/cluster/resources'))
    for kind in ('qemu', 'lxc', 'node'):
        has(by_type[kind], ('cpu', 'maxcpu', 'maxmem', 'mem', 'uptime', 'disk', 'maxdisk', 'id', 'status'))
        types(by_type[kind], maxcpu=int, maxmem=int, mem=int, uptime=int)
    has(by_type['qemu'], ('netin', 'netout', 'diskread', 'diskwrite', 'memhost', 'tags', 'name', 'vmid', 'template'))
    has(by_type['storage'], ('disk', 'maxdisk', 'storage', 'plugintype'))


async def test_nodes_list_has_usage_and_the_fingerprint(pve, api):
    pve.add_node('pve2', online=False)
    nodes = dict((n['node'], n) for n in await api.data('GET', '/nodes'))
    has(nodes['pve1'], ('cpu', 'disk', 'id', 'level', 'maxcpu', 'maxdisk', 'maxmem', 'mem', 'ssl_fingerprint',
                        'status', 'type', 'uptime'))
    types(nodes['pve1'], maxcpu=int, maxmem=int, uptime=int, id=str)
    assert nodes['pve2']['status'] == 'offline' and 'cpu' not in nodes['pve2']


async def test_cluster_status_nodes_have_an_address(pve, api):
    nodes = [i for i in await api.data('GET', '/cluster/status') if i['type'] == 'node']
    has(nodes[0], ('ip', 'level', 'nodeid', 'online', 'local'))
    assert nodes[0]['ip'].startswith('192.0.2.')


async def test_nextid_is_a_string(pve, api):
    assert await api.data('GET', '/cluster/nextid') == '100'


async def test_ceph_status_has_health_checks_and_quorum(pve, api):
    pve.ceph_slow(1, health='HEALTH_WARN')
    for path in ('/cluster/ceph/status', '/nodes/pve1/ceph/status'):
        data = await api.data('GET', path)
        has(data, ('fsid', 'health', 'quorum', 'quorum_names', 'monmap', 'osdmap', 'pgmap'))
        assert data['health']['checks'] == {} and isinstance(data['quorum'], list)
    assert (await api.data('GET', '/cluster/ceph/status'))['health']['status'] == 'HEALTH_WARN'


async def test_ceph_daemons_osd_tree_pools_and_metadata(pve, api):
    for kind in ('mon', 'mgr', 'mds'):
        item = (await api.data('GET', '/nodes/pve1/ceph/' + kind))[0]
        has(item, ('addr', 'ceph_version', 'ceph_version_short', 'direxists', 'host', 'name', 'service', 'state'))
    mon = (await api.data('GET', '/nodes/pve1/ceph/mon'))[0]
    has(mon, ('quorum', 'rank'))
    tree = await api.data('GET', '/nodes/pve1/ceph/osd')
    has(tree, ('flags', 'root'))
    has(tree['root'], ('children', 'leaf'))
    pool = (await api.data('GET', '/nodes/pve1/ceph/pool'))[0]
    has(pool, ('pool', 'pool_name', 'size', 'min_size', 'pg_num', 'pg_num_final', 'pg_autoscale_mode', 'crush_rule',
               'crush_rule_name', 'bytes_used', 'percent_used', 'application_metadata', 'autoscale_status',
               'target_size', 'target_size_ratio', 'type'))
    meta = await api.data('GET', '/cluster/ceph/metadata')
    has(meta, ('mds', 'mgr', 'mon', 'node', 'osd'))
    has(meta['osd'][0], ('id', 'hostname', 'arch', 'cpu', 'back_addr', 'front_addr', 'hb_back_addr', 'hb_front_addr',
                         'devices', 'device_ids', 'device_paths'))
    types(meta['osd'][0], mem_total_kb=str, mem_swap_kb=str)


async def test_vzdump_defaults_have_the_documented_options_and_no_path_parameters(pve, api):
    data = await api.data('GET', '/nodes/pve1/vzdump/defaults')
    has(data, ('all', 'bwlimit', 'compress', 'dumpdir', 'fleecing', 'ionice', 'lockwait', 'mailnotification', 'mode',
               'notification-mode', 'performance', 'pigz', 'prune-backups', 'quiet', 'remove', 'stdexcludes', 'stop',
               'stopwait', 'storage', 'zstd'))
    assert 'node' not in data and 'vmid' not in data
    assert isinstance(data['fleecing'], dict) and isinstance(data['performance'], dict)


async def test_network_interfaces_have_methods_families_and_priority(pve, api):
    for item in await api.data('GET', '/nodes/pve1/network'):
        has(item, ('iface', 'type', 'method', 'method6', 'families', 'priority', 'active'))
        types(item, priority=int, families=list)
    one = await api.data('GET', '/nodes/pve1/network/vmbr0')
    has(one, ('families', 'method6', 'priority', 'type', 'method'))


async def test_lxc_list_and_status_carry_pressure_as_strings(pve, api):
    pve.add_ct(200, 'ct1', status='running', config={'tags': 'web'})
    listed = (await api.data('GET', '/nodes/pve1/lxc'))[0]
    status = await api.data('GET', '/nodes/pve1/lxc/200/status/current')
    for item in (listed, status):
        has(item, ('pressurecpufull', 'pressurecpusome', 'pressureiofull', 'pressureiosome', 'pressurememoryfull',
                   'pressurememorysome', 'tags', 'diskread', 'diskwrite', 'maxswap', 'swap', 'type'))
        types(item, pressurecpufull=str, tags=str)


async def test_backup_jobs_have_a_type_and_no_guest_selector_keys(pve, api):
    job = await api.data('GET', '/cluster/backup/job1')
    has(job, ('id', 'type', 'schedule', 'storage', 'enabled', 'mode'))
    assert job['mode'] in ('snapshot', 'suspend', 'stop') and job['type'] == 'vzdump'
    assert 'node' not in job and 'vmid' not in job
    listed = (await api.data('GET', '/cluster/backup'))[0]
    has(listed, ('id', 'type', 'schedule', 'enabled', 'mode', 'next-run'))


async def test_notification_endpoints_matchers_and_targets(pve, api):
    sendmail = (await api.data('GET', '/cluster/notifications/endpoints/sendmail'))[0]
    has(sendmail, ('name', 'comment', 'mailto-user', 'origin'))
    one = await api.data('GET', '/cluster/notifications/endpoints/sendmail/' + sendmail['name'])
    has(one, ('name', 'comment', 'digest', 'mailto-user', 'origin'))
    webhook = (await api.data('GET', '/cluster/notifications/endpoints/webhook'))[0]
    has(webhook, ('name', 'url', 'method', 'body', 'header', 'comment', 'origin'))
    matcher = (await api.data('GET', '/cluster/notifications/matchers'))[0]
    has(matcher, ('name', 'comment', 'target', 'origin'))
    has((await api.data('GET', '/cluster/notifications/targets'))[0], ('name', 'type', 'comment', 'origin'))


async def test_disks_apt_and_hardware(pve, api):
    disk = (await api.data('GET', '/nodes/pve1/disks/list'))[0]
    has(disk, ('devpath', 'size', 'type', 'model', 'serial', 'vendor', 'wwn', 'used', 'health', 'gpt'))
    assert 'mounted' not in disk
    version = (await api.data('GET', '/nodes/pve1/apt/versions'))[0]
    has(version, ('Package', 'Version', 'OldVersion', 'CurrentState', 'Priority', 'Section'))
    repos = await api.data('GET', '/nodes/pve1/apt/repositories')
    has(repos['standard-repos'][0], ('handle', 'name', 'description'))
    assert isinstance(repos['infos'][0]['index'], int)
    pci = (await api.data('GET', '/nodes/pve1/hardware/pci'))[0]
    has(pci, ('id', 'class', 'device', 'vendor', 'vendor_name', 'subsystem_device', 'subsystem_vendor',
              'subsystem_vendor_name', 'iommugroup'))
    has((await api.data('GET', '/nodes/pve1/certificates/info'))[0],
        ('filename', 'fingerprint', 'issuer', 'notafter', 'notbefore', 'pem', 'public-key-bits',
         'public-key-type', 'san', 'subject'))
    has(await api.data('GET', '/nodes/pve1/subscription'), ('status', 'message', 'serverid', 'url'))
    has(await api.data('GET', '/nodes/pve1/dns'), ('dns1', 'search'))
    status = await api.data('GET', '/nodes/pve1/status')
    has(status, ('swap', 'uptime', 'cpuinfo', 'memory', 'rootfs', 'boot-info'))
    has(status['cpuinfo'], ('flags', 'vendor', 'model', 'cpus'))
    migration = await api.data('GET', '/nodes/pve1/capabilities/qemu/migration')
    assert migration['has-dbus-vmstate'] in (True, False)


async def test_cluster_config_ha_and_sdn(pve, api):
    pve.add_node('pve2')
    nodes = await api.data('GET', '/cluster/config/nodes')
    has(nodes[0], ('name', 'node', 'nodeid', 'quorum_votes', 'ring0_addr'))
    types(nodes[0], nodeid=str, quorum_votes=str)
    join = await api.data('GET', '/cluster/config/join')
    has(join, ('config_digest', 'nodelist', 'preferred_node', 'totem'))
    has(join['totem'], ('version',))
    assert [n['name'] for n in join['nodelist']] == ['pve1', 'pve2']
    has(await api.data('GET', '/cluster/config/totem'), ('version',))
    assert isinstance(await api.data('GET', '/cluster/config/apiversion'), str)
    has((await api.data('GET', '/cluster/ha/resources'))[0], ('sid', 'digest', 'state', 'type'))
    has(await api.data('GET', '/cluster/ha/status/manager_status'), ('quorum',))
    has((await api.data('GET', '/cluster/sdn/vnets'))[0], ('vnet', 'zone', 'tag', 'vlanaware', 'digest', 'type'))
    has((await api.data('GET', '/cluster/sdn/zones'))[0], ('zone', 'type', 'digest', 'mtu', 'nodes', 'peers'))
    has((await api.data('GET', '/cluster/sdn/ipams'))[0], ('ipam', 'type', 'digest'))
    has((await api.data('GET', '/cluster/tasks'))[0], ('upid', 'node', 'id', 'type', 'user', 'starttime', 'endtime',
                                                       'status', 'tokenid'))


async def test_access_lists(pve, api):
    has((await api.data('GET', '/access/acl'))[0] if await api.data('GET', '/access/acl') else {'propagate': 1},
        ('propagate',))
    roles = dict((r['roleid'], r) for r in await api.data('GET', '/access/roles'))
    has(roles['PVEAuditor'], ('roleid', 'privs', 'special'))
    assert 'VM.Audit' in roles['PVEAuditor']['privs'].split(',')
    assert await api.data('GET', '/access/roles/PVEAuditor') == dict.fromkeys(shapes.ROLES['PVEAuditor'], 1)
    has((await api.data('GET', '/access/users'))[0], ('userid', 'enable', 'expire'))
    has(await api.data('GET', '/access/users/root@pam'), ('enable', 'expire', 'groups', 'tokens'))
    has((await api.data('GET', '/access/groups'))[0], ('groupid', 'users', 'comment'))
    has((await api.data('GET', '/access/domains'))[0], ('realm', 'type', 'comment'))


async def test_permissions_list_what_the_user_holds(pve, api):
    pve.grant('bob@pve', '/', 'VM.Audit', 'Sys.Audit')
    pve.grant('bob@pve', '/vms/100', 'VM.Console')
    pve.users['bob@pve'] = 'pw'
    bob = type(api)(api.session)
    await bob.login('bob@pve', 'pw')
    held = await bob.data('GET', '/access/permissions')
    assert held == {'/': {'Sys.Audit': 1, 'VM.Audit': 1}, '/vms/100': {'VM.Console': 1}}
    root = await api.data('GET', '/access/permissions')
    assert set(root['/']) == set(shapes.PRIVILEGES)


async def test_snapshots_and_their_config(pve, api):
    pve.add_vm(100, 'vm1')
    snaps = await api.data('GET', '/nodes/pve1/qemu/100/snapshot')
    current = [s for s in snaps if s['name'] == 'current'][0]
    has(current, ('description', 'digest', 'running', 'parent'))
    named = [s for s in snaps if s['name'] != 'current'][0]
    has(named, ('description', 'snaptime', 'vmstate'))
    config = await api.data('GET', '/nodes/pve1/qemu/100/snapshot/{0}/config'.format(named['name']))
    has(config, ('snaptime', 'description', 'digest'))


async def test_tasks_carry_the_token_and_the_list_shows_the_exit_status(pve, api):
    pve.apitokens['root@pam!ci'] = 'secret'

    async def body():
        return None
    upid = await pve.task('pve1', 'vzdump', 100, 'root@pam!ci', body)
    for _ in range(100):
        status = await api.data('GET', '/nodes/pve1/tasks/{0}/status'.format(upid))
        if status['status'] == 'stopped':
            break
    has(status, ('tokenid', 'exitstatus', 'upid', 'node', 'pid', 'pstart', 'starttime', 'type', 'id', 'user'))
    assert status['tokenid'] == 'ci' and 'endtime' not in status
    item = [t for t in await api.data('GET', '/nodes/pve1/tasks') if t['upid'] == upid][0]
    has(item, ('tokenid', 'endtime', 'status'))
    assert item['status'] == 'OK' and 'exitstatus' not in item


async def test_services_list_names_services_whose_state_can_be_read(pve, api):
    item = (await api.data('GET', '/nodes/pve1/services'))[0]
    has(item, ('service', 'name', 'desc', 'state', 'active-state', 'unit-state'))
    state = await api.data('GET', '/nodes/pve1/services/{0}/state'.format(item['service']))
    has(state, ('name', 'service', 'desc', 'state', 'active-state', 'unit-state'))


async def test_lxc_interfaces_send_the_prefix_as_a_string(pve, api):
    pve.add_ct(200, 'ct1', status='running', config={'net0': 'name=eth0,bridge=vmbr0,ip=192.0.2.10/24'})
    eth = [i for i in await api.data('GET', '/nodes/pve1/lxc/200/interfaces') if i['name'] == 'eth0'][0]
    assert eth['ip-addresses'][0]['prefix'] == '24'


async def test_a_refusal_by_the_self_or_an_or_rule_names_no_reason(pve, api):
    pve.users['bob@pve'] = 'pw'
    pve.grant('bob@pve', '/vms', 'VM.Audit')
    bob = type(api)(api.session)
    await bob.login('bob@pve', 'pw')
    status, body = await bob.call('GET', '/access/users/root@pam/token')
    assert status == 403 and body['message'].strip() == 'Permission check failed'


async def test_a_rule_naming_a_parameter_the_method_lacks_checks_the_parent_path(pve, api):
    pve.users['bob@pve'] = 'pw'
    pve.grant('bob@pve', '/', 'Sys.Audit')
    bob = type(api)(api.session)
    await bob.login('bob@pve', 'pw')
    status, _ = await bob.call('GET', '/cluster/acme/meta')
    assert status == 200


def test_optional_tables_name_real_properties_and_the_fixups_name_real_methods():
    sch = schema.load()
    for table in (shapes.OPTIONAL, shapes.FIXUPS, shapes.DEVIATIONS):
        for template in table:
            assert 'GET' in sch.paths[template], template
    for template, names in shapes.OPTIONAL.items():
        returns = sch.paths[template]['GET'].get('returns') or {}
        text = repr(returns)
        for name in names.split():
            assert repr(name) in text or name in text, (template, name)


def test_build_leaves_other_methods_alone_and_fills_named_optional_properties():
    sch = schema.load()
    returns = sch.paths['/pools']['GET']['returns']
    assert 'comment' in shapes.build('/pools', returns, {})[0]
    assert shapes.build('/pools', returns, {}, 'POST') == schema.sample(returns, '', {})
    assert 'comment' not in schema.sample(returns, '', {})[0]


@pytest.mark.parametrize('data, base, want', [
    ({'a': 1}, {'a': 2, 'b': 3}, {'a': 1, 'b': 3}),
    ([{'a': 1}, {'a': 2, 'c': 0}], [{'a': 9, 'b': 3}], [{'a': 1, 'b': 3}, {'a': 2, 'c': 0, 'b': 3}]),
])
def test_merge_missing_adds_only_what_is_absent(data, base, want):
    assert shapes.merge_missing(data, base) == want
