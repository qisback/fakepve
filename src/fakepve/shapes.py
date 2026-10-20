"""What the generic answers and the hand-built ones add to the schema's `returns`.

PVE's schema marks many properties optional that a real node returns every time, documents some
answers only loosely and types a few values differently from what it sends (a string where the
schema says an integer). The tables here close those gaps, so a client that reads these keys
finds them with the type a real PVE sends:

- OPTIONAL: per method template, the optional properties to fill.
- HINTS: plausible values for properties by name (invented: example names, RFC 5737 addresses).
- FIXUPS: per method template, functions that add what the schema does not describe and
  correct types.

`build` makes the answer of a generic method; `complete` fills what a hand-built answer lacks.
"""

from . import schema as pve_schema

# Properties of the answer, optional in the schema, that a real PVE returns: filled by name.
OPTIONAL = {
    '/access/acl': (
        'propagate'
    ),
    '/access/domains': (
        'comment'
    ),
    '/access/groups': (
        'comment users'
    ),
    '/access/groups/{groupid}': (
        'comment'
    ),
    '/access/roles': (
        'privs special'
    ),
    '/access/users': (
        'enable expire'
    ),
    '/access/users/{userid}': (
        'enable expire groups tokens'
    ),
    '/cluster/acme/meta': (
        'caaIdentities termsOfService website'
    ),
    '/cluster/backup': (
        'all comment compress enabled exclude mode next-run notes-template pool schedule'
    ),
    '/cluster/backup-info/not-backed-up': (
        'name'
    ),
    '/cluster/backup/{id}': (
        'all compress enabled exclude mode notes-template schedule'
    ),
    '/cluster/backup/{id}/included_volumes': (
        'children name'
    ),
    '/cluster/ceph/metadata': (
        'device_ids device_paths devices'
    ),
    '/cluster/config/join': (
        'nodeid ring0_addr'
    ),
    '/cluster/ha/resources/{sid}': (
        'state'
    ),
    '/cluster/ha/status/current': (
        'armed-state quorate timestamp'
    ),
    '/cluster/notifications/endpoints/sendmail': (
        'comment mailto-user'
    ),
    '/cluster/notifications/endpoints/sendmail/{name}': (
        'comment digest mailto-user'
    ),
    '/cluster/notifications/endpoints/webhook': (
        'body comment header'
    ),
    '/cluster/notifications/endpoints/webhook/{name}': (
        'body comment digest header'
    ),
    '/cluster/notifications/matchers': (
        'comment mode target'
    ),
    '/cluster/notifications/matchers/{name}': (
        'comment digest mode target'
    ),
    '/cluster/notifications/targets': (
        'comment'
    ),
    '/cluster/options': (
        'description keyboard mac_prefix'
    ),
    '/cluster/sdn/vnets': (
        'digest tag vlanaware zone'
    ),
    '/cluster/sdn/vnets/{vnet}': (
        'digest tag vlanaware zone'
    ),
    '/cluster/sdn/zones': (
        'digest mtu nodes peers'
    ),
    '/cluster/status': (
        'ip level'
    ),
    '/nodes': (
        'cpu level maxcpu maxmem mem ssl_fingerprint uptime'
    ),
    '/nodes/{node}/apt/repositories': (
        'Comment Components Options property status'
    ),
    '/nodes/{node}/apt/versions': (
        'ManagerVersion OldVersion RunningKernel'
    ),
    '/nodes/{node}/capabilities/qemu/cpu-flags': (
        'description'
    ),
    '/nodes/{node}/capabilities/qemu/machines': (
        'changes'
    ),
    '/nodes/{node}/ceph/fs': (
        'data_pool_ids data_pools metadata_pool_id'
    ),
    '/nodes/{node}/ceph/mds': (
        'addr ceph_version ceph_version_short direxists fs_name host rank service standby_replay'
    ),
    '/nodes/{node}/ceph/mgr': (
        'addr ceph_version ceph_version_short direxists host service'
    ),
    '/nodes/{node}/ceph/mon': (
        'addr ceph_version ceph_version_short direxists host quorum rank service state'
    ),
    '/nodes/{node}/ceph/osd': (
        'flags'
    ),
    '/nodes/{node}/ceph/pool': (
        'application_metadata autoscale_status bytes_used crush_rule_name percent_used '
        'pg_autoscale_mode pg_num_final pg_num_min target_size target_size_ratio'
    ),
    '/nodes/{node}/certificates/info': (
        'filename fingerprint issuer notafter notbefore pem public-key-bits public-key-type san '
        'subject'
    ),
    '/nodes/{node}/config': (
        'acme description digest'
    ),
    '/nodes/{node}/disks/list': (
        'health model serial used vendor wwn'
    ),
    '/nodes/{node}/disks/lvm': (
        'children'
    ),
    '/nodes/{node}/dns': (
        'dns1 search'
    ),
    '/nodes/{node}/hardware/pci': (
        'device_name subsystem_device subsystem_vendor subsystem_vendor_name vendor_name'
    ),
    '/nodes/{node}/hosts': (
        'digest'
    ),
    '/nodes/{node}/network': (
        'active address autostart bridge_ports cidr exists families gateway method method6 '
        'netmask priority'
    ),
    '/nodes/{node}/qemu': (
        'cpu cpus maxdisk maxmem mem memhost name netin netout uptime'
    ),
    '/nodes/{node}/qemu/{vmid}/cloudinit': (
        'delete value'
    ),
    '/nodes/{node}/qemu/{vmid}/snapshot': (
        'parent snaptime vmstate'
    ),
    '/nodes/{node}/qemu/{vmid}/status/current': (
        'diskread diskwrite maxdisk memhost netin netout'
    ),
    '/nodes/{node}/sdn/zones/{zone}/bridges': (
        'index primary_vlan vlans'
    ),
    '/nodes/{node}/sdn/zones/{zone}/content': (
        'status statusmsg'
    ),
    '/nodes/{node}/status': (
        'secureboot'
    ),
    '/nodes/{node}/subscription': (
        'message serverid url'
    ),
    '/nodes/{node}/vzdump/defaults': (
        'all bwlimit compress dumpdir fleecing ionice lockwait mailnotification mode '
        'notification-mode performance pigz prune-backups quiet remove stdexcludes stop stopwait '
        'zstd'
    ),
    '/pools': (
        'comment'
    ),
    '/pools/{poolid}': (
        'comment'
    ),
}

EPOCH = 1767225600  # 2026-01-01, a fixed time so answers are the same on every run
FINGERPRINT = ':'.join('{0:02X}'.format((n * 17) % 256) for n in range(32))
DIGEST = '0123456789abcdef0123456789abcdef01234567'
MACHINE = 'pc-i440fx-9.2+pve1'
GiB = 1024 ** 3

# Every privilege of PVE 9, and the built-in roles (privilege lists as in PVE::AccessControl).
PRIVILEGES = (
    'Datastore.Allocate Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit Group.Allocate '
    'Mapping.Audit Mapping.Modify Mapping.Use Permissions.Modify Pool.Allocate Pool.Audit Realm.Allocate '
    'Realm.AllocateUser SDN.Allocate SDN.Audit SDN.Use Sys.AccessNetwork Sys.Audit Sys.Console Sys.Incoming '
    'Sys.Modify Sys.PowerMgmt Sys.Syslog User.Modify VM.Allocate VM.Audit VM.Backup VM.Clone VM.Config.CDROM '
    'VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network '
    'VM.Config.Options VM.Console VM.GuestAgent.Audit VM.GuestAgent.FileRead VM.GuestAgent.FileSystemMgmt '
    'VM.GuestAgent.FileWrite VM.GuestAgent.Unrestricted VM.Migrate VM.PowerMgmt VM.Replicate VM.Snapshot '
    'VM.Snapshot.Rollback').split()
ROLES = {
    'Administrator': PRIVILEGES,
    'NoAccess': (),
    'PVEAuditor': ('Datastore.Audit', 'Mapping.Audit', 'Pool.Audit', 'SDN.Audit', 'Sys.Audit', 'VM.Audit',
                   'VM.GuestAgent.Audit'),
}


# Values by property name, for the properties above that have no better default than "fake" or 0.
HINTS = {
    'comment': 'Example comment', 'description': 'Example description', 'digest': DIGEST,
    'enable': 1, 'expire': 0, 'propagate': 1, 'special': 0, 'enabled': 1, 'all': 1, 'schedule': 'sat 02:00',
    'compress': 'zstd', 'exclude': '', 'notes-template': '{{guestname}}', 'next-run': EPOCH + 7200,
    'pool': 'example', 'tags': 'example', 'hastate': 'started', 'ssl_fingerprint': FINGERPRINT, 'level': '',
    'keyboard': 'en-us', 'mac_prefix': 'BC:24:11', 'ip': '192.0.2.10', 'timestamp': EPOCH, 'quorate': 1,
    'armed-state': 'armed', 'termsOfService': 'https://acme.example.org/terms',
    'website': 'https://acme.example.org', 'user': 'root@pam', 'serverid': 'EXAMPLE0123456789',
    'url': 'https://www.proxmox.com/en/proxmox-virtual-environment/pricing', 'message': 'There is no subscription key',
    'dns1': '192.0.2.53', 'search': 'example.org', 'vendor_name': 'Example Corp', 'device_name': 'Example device',
    'subsystem_device': '0x0000', 'subsystem_vendor': '0x0000', 'subsystem_vendor_name': 'Example Corp',
    'model': 'EXAMPLE DISK 1000', 'serial': 'EX0000000001', 'vendor': 'EXAMPLE', 'wwn': '0x5000000000000001',
    'used': 'LVM', 'health': 'PASSED', 'ManagerVersion': '9.0.0', 'OldVersion': '9.0.0-1',
    'RunningKernel': '6.14.8-2-pve', 'target': 'mail-to-root', 'mode': 'all', 'mailto-user': ['root@pam'],
    'header': ['name=X-Example,value=1'], 'body': '{}', 'filename': 'pve-ssl.pem', 'fingerprint': FINGERPRINT,
    'issuer': 'CN=Example CA,O=Example', 'subject': 'CN=pve1.example.org', 'san': ['DNS:pve1.example.org'],
    'notbefore': EPOCH, 'notafter': EPOCH + 31536000, 'public-key-bits': 4096, 'public-key-type': 'rsaEncryption',
    'pem': '-----BEGIN CERTIFICATE-----\nZXhhbXBsZQ==\n-----END CERTIFICATE-----\n',
}


# Where a real PVE sends another type than its schema says (path inside the answer, `[]` for list items).
# The tests do not hold the answers to the schema there.
DEVIATIONS = {
    '/cluster/ceph/metadata': ('osd[].mem_swap_kb', 'osd[].mem_total_kb'),
    '/cluster/config/apiversion': ('',),
    '/cluster/config/join': ('nodelist[].nodeid', 'nodelist[].quorum_votes'),
    '/cluster/config/nodes': ('[].nodeid', '[].quorum_votes'),
    '/nodes/{node}/apt/repositories': ('infos[].index',),
    '/nodes/{node}/ceph/pool': ('[].target_size', '[].target_size_ratio'),
    '/nodes/{node}/disks/list': ('[].mounted',),
    '/nodes/{node}/vzdump/defaults': ('fleecing', 'performance'),
    '/nodes/{node}/sdn/zones/{zone}/bridges': ('[].ports[].vmid', '[].ports[].index'),
}


# ------------------------------------------------------------------ the steps

def reach(data, path):
    """The dicts a dotted path leads to; lists on the way are walked item by item."""
    nodes = [data]
    for seg in [s for s in path.split('.') if s]:
        step = []
        for node in nodes:
            for item in node if isinstance(node, list) else [node]:
                if isinstance(item, dict) and seg in item:
                    step.append(item[seg])
        nodes = step
    out = []
    for node in nodes:
        out.extend(i for i in (node if isinstance(node, list) else [node]) if isinstance(i, dict))
    return out


def add(path='', **keys):
    """Add keys the answer lacks (what is there stays)."""
    def step(data, ctx):
        for item in reach(data, path):
            for key, val in keys.items():
                item.setdefault(key, val)
    return step


def drop(path='', *names):
    """Remove keys PVE does not send, which the schema lists as required."""
    def step(data, ctx):
        for item in reach(data, path):
            for key in names:
                item.pop(key, None)
    return step


def retype(path, key, kind):
    """Give a value the type PVE sends: str, int, bool or float."""
    def step(data, ctx):
        for item in reach(data, path):
            if key in item and item[key] is not None:
                item[key] = kind(item[key]) if kind is not bool else bool(int(item[key] or 0))
    return step


def put(path='', **keys):
    """Set keys, whatever the sample put there."""
    def step(data, ctx):
        for item in reach(data, path):
            item.update(keys)
    return step


def cast(kind):
    """The whole answer given another type (PVE sends some numbers as strings)."""
    def step(data, ctx):
        raise _Replace(kind(data))
    return step


def replace(make):
    """Throw the sample away: the answer is make(ctx)."""
    def step(data, ctx):
        raise _Replace(make(ctx))
    return step


class _Replace(Exception):
    def __init__(self, data):
        super().__init__()
        self.data = data


def refine(template, data, ctx=None):
    """Run the template's steps over an answer; returns the answer."""
    for step in FIXUPS.get(template, ()):
        try:
            step(data, ctx or {})
        except _Replace as new:
            data = new.data
    return data


def build(template, returns, ctx, method='GET'):
    """The answer of a generic method: a sample of `returns`, for a GET with the optional properties PVE sends."""
    if method != 'GET':
        return pve_schema.sample(returns, '', ctx)
    names = OPTIONAL.get(template, '').split()
    known = dict((k, v) for k, v in HINTS.items() if k in names)
    known.update(ctx)
    return refine(template, pve_schema.sample(returns, '', known, names), ctx)


def merge_missing(data, base):
    """Copy into data what base has and data lacks, item by item for lists."""
    if isinstance(data, dict) and isinstance(base, dict):
        for key, val in base.items():
            if key not in data:
                data[key] = val
            elif isinstance(val, (dict, list)):
                merge_missing(data[key], val)
    elif isinstance(data, list) and isinstance(base, list) and base:
        for item in data:
            merge_missing(item, base[0])
    return data


def complete(template, data, returns, ctx):
    """A hand-built answer with the keys it lacks filled as `build` would."""
    return refine(template, merge_missing(data, build(template, returns, ctx)), ctx)


# -------------------------------------------------------------------- answers

def daemon(name, ctx, **extra):
    out = {'name': name, 'hostname': ctx['_nodes'][0], 'arch': 'x86_64', 'ceph_release': 'squid',
           'ceph_version_short': '19.2.1',
           'ceph_version': 'ceph version 19.2.1 (0000000000000000000000000000000000000000) squid (stable)',
           'cpu': 'Example CPU @ 2.00GHz', 'mem_swap_kb': '8388604', 'mem_total_kb': '67108864'}
    out.update(extra)
    return out


def service(name, ctx, **extra):
    """A mds, mgr or mon entry: a daemon with a directory and a unit."""
    return daemon(name, ctx, direxists=1, service=1, **extra)


def osd_metadata(ctx, disk):
    out = daemon('osd.0', ctx, id=0, back_addr='192.0.2.11:6801/1', front_addr='192.0.2.11:6802/1',
                 hb_back_addr='192.0.2.11:6803/1', hb_front_addr='192.0.2.11:6804/1',
                 osd_data='/var/lib/ceph/osd/ceph-0', osd_objectstore='bluestore', **disk)
    del out['name']  # an OSD is known by its id
    return out


def ceph_metadata(ctx):
    node = ctx['_nodes'][0]
    disk = {'devices': 'nvme1n1', 'device_ids': 'nvme1=EXAMPLE', 'device_paths': 'nvme1n1=/dev/disk/by-path/example'}
    return {
        'mds': {node: service(node, ctx, addr='192.0.2.11:6800/1')},
        'mgr': {node: service(node, ctx, addr='192.0.2.11:6800/1', addrs='192.0.2.11:6800/1')},
        'mon': {node: service(node, ctx, addrs='192.0.2.11:6789/0', **disk)},
        'node': {node: {'buildcommit': '0' * 40, 'version': {'parts': ['19', '2', '1'], 'str': '19.2.1'}}},
        'osd': [osd_metadata(ctx, disk)]}


def ceph_status(health='HEALTH_OK', node='pve1'):
    """The `ceph status` document, as PVE passes it on."""
    return {'fsid': '00000000-0000-4000-8000-000000000000', 'election_epoch': 4, 'quorum': [0],
            'quorum_names': [node], 'quorum_age': 3600,
            'health': {'status': health, 'checks': {}, 'mutes': []},
            'monmap': {'epoch': 1, 'min_mon_release_name': 'squid', 'num_mons': 1},
            'osdmap': {'epoch': 10, 'num_osds': 1, 'num_up_osds': 1, 'num_in_osds': 1},
            'pgmap': {'num_pgs': 1, 'num_pools': 1, 'num_objects': 0, 'data_bytes': 0, 'bytes_used': 0,
                      'bytes_avail': 1073741824, 'bytes_total': 1073741824, 'pgs_by_state': []},
            'mgrmap': {'available': True, 'num_standbys': 0, 'modules': ['iostat']},
            'servicemap': {'epoch': 1, 'modified': '2026-01-01T00:00:00.000000+0000', 'services': {}},
            'fsmap': {'epoch': 1, 'by_rank': [], 'up:standby': 0}}


def roles(ctx):
    return [{'roleid': name, 'special': 1, 'privs': ','.join(sorted(privs))} for name, privs in sorted(ROLES.items())]


def role(ctx):
    return dict((priv, 1) for priv in ROLES.get(ctx.get('roleid'), ROLES['PVEAuditor']))


def cluster_nodes(ctx):
    return [{'name': n, 'node': n, 'nodeid': str(i), 'quorum_votes': '1', 'ring0_addr': '192.0.2.{0}'.format(10 + i)}
            for i, n in enumerate(ctx['_nodes'], 1)]


def totem(ctx):
    return {'version': '2', 'cluster_name': 'example', 'config_version': '1', 'ip_version': 'ipv4-6',
            'link_mode': 'passive', 'secauth': 'on', 'interface': {'0': {'linknumber': '0'}}}


def cluster_join(ctx):
    return {'config_digest': DIGEST, 'preferred_node': ctx['_nodes'][0], 'totem': totem(ctx),
            'nodelist': [{'name': n['name'], 'nodeid': n['nodeid'], 'quorum_votes': n['quorum_votes'],
                          'ring0_addr': n['ring0_addr'], 'pve_addr': n['ring0_addr'], 'pve_fp': FINGERPRINT}
                         for n in cluster_nodes(ctx)]}


def ceph_osd_tree(ctx):
    node = ctx['_nodes'][0]
    osd = {'id': '0', 'name': 'osd.0', 'type': 'osd', 'leaf': 1, 'status': 'up', 'host': node,
           'bytes_used': 0, 'percent_used': 0.0, 'ceph_version': 'ceph version 19.2.1 (0) squid (stable)',
           'ceph_version_short': '19.2.1'}
    host = {'id': '-3', 'name': node, 'type': 'host', 'leaf': 0, 'children': [osd], 'version': '19.2.1'}
    root = {'id': '-1', 'name': 'default', 'type': 'root', 'leaf': 0, 'children': [host]}
    return {'flags': '', 'root': {'leaf': 0, 'children': [root]}}


def ceph_pools(ctx):
    return [{'pool': 1, 'pool_name': 'example-pool', 'size': 3, 'min_size': 2, 'pg_num': 32, 'pg_num_min': 1,
             'pg_num_final': 32, 'pg_autoscale_mode': 'on', 'crush_rule': 0, 'crush_rule_name': 'replicated_rule',
             'type': 'replicated', 'bytes_used': 0, 'percent_used': 0.0, 'target_size': None,
             'target_size_ratio': None, 'application_metadata': {'rbd': {}},
             'autoscale_status': {'pool_name': 'example-pool', 'pg_autoscale_mode': 'on', 'pg_num_final': 32,
                                  'pg_num_ideal': 32, 'bias': 1.0, 'crush_root_id': -1, 'would_adjust': False}}]


def networks(ctx):
    return [
        {'iface': 'vmbr0', 'type': 'bridge', 'method': 'static', 'method6': 'manual', 'families': ['inet'],
         'priority': 3, 'active': 1, 'autostart': 1, 'exists': 1, 'address': '192.0.2.11',
         'netmask': '255.255.255.0', 'cidr': '192.0.2.11/24', 'gateway': '192.0.2.1', 'bridge_ports': 'eno1',
         'bridge_stp': 'off', 'bridge_fd': '0'},
        {'iface': 'eno1', 'type': 'eth', 'method': 'manual', 'method6': 'manual', 'families': ['inet'],
         'priority': 2, 'active': 1, 'exists': 1}]


def services(ctx):
    return [{'service': name, 'name': name, 'desc': desc, 'state': 'running', 'active-state': 'active',
             'unit-state': 'enabled'} for name, desc in (
        ('corosync', 'Corosync Cluster Engine'), ('pve-cluster', 'The Proxmox VE cluster filesystem'),
        ('pveproxy', 'PVE API Proxy Server'), ('sshd', 'OpenBSD Secure Shell server'))]


def snapshots(ctx):
    return [{'name': 'example-snap', 'description': 'Example snapshot', 'snaptime': EPOCH, 'vmstate': 0},
            {'name': 'current', 'description': 'You are here!', 'parent': 'example-snap', 'running': 0,
             'digest': DIGEST}]


def included_volumes(ctx):
    disk = {'id': 'scsi0', 'name': 'scsi0', 'included': 1, 'reason': 'included', 'leaf': 1}
    return {'children': [{'id': ctx.get('vmid', 100), 'name': 'example-vm', 'type': 'qemu', 'leaf': 0,
                          'children': [disk]}]}


def tasks(ctx):
    node = ctx['_nodes'][0]
    return [{'upid': 'UPID:{0}:0000ABCD:00001234:{1:08X}:vzdump:100:root@pam:'.format(node, EPOCH), 'node': node,
             'id': '100', 'type': 'vzdump', 'user': 'root@pam', 'tokenid': 'example', 'starttime': EPOCH,
             'endtime': EPOCH + 60, 'status': 'OK'}]


def ceph_status_step(data, ctx):
    raise _Replace(ceph_status(node=ctx['_nodes'][0]))


FIXUPS = {
    '/access/domains': [put('', default=1)],
    '/access/roles': [replace(roles)],
    '/access/roles/{roleid}': [replace(role)],
    '/cluster/backup': [add('', type='vzdump'), drop('', 'node', 'vmid')],
    '/cluster/backup/{id}': [add('', type='vzdump'), drop('', 'node', 'vmid')],
    '/cluster/backup/{id}/included_volumes': [replace(included_volumes)],
    '/cluster/ceph/metadata': [replace(ceph_metadata)],
    '/cluster/ceph/status': [ceph_status_step],
    '/nodes/{node}/ceph/status': [ceph_status_step],
    '/cluster/config/apiversion': [cast(str)],
    '/cluster/config/join': [replace(cluster_join)],
    '/cluster/config/nodes': [replace(cluster_nodes)],
    '/cluster/config/totem': [replace(totem)],
    '/cluster/ha/resources': [add('', digest=DIGEST, state='started', type='vm')],
    '/cluster/ha/status/manager_status': [
        add('', quorum={'node': 'pve1', 'quorate': '1'}, node_status={}, service_status={})],
    '/cluster/nextid': [cast(str)],
    '/cluster/notifications/endpoints/sendmail/{name}': [add('', origin='user-created')],
    '/cluster/notifications/endpoints/webhook/{name}': [add('', origin='user-created')],
    '/cluster/notifications/matchers/{name}': [add('', origin='user-created')],
    '/cluster/sdn/ipams': [add('', digest=DIGEST)],
    '/cluster/sdn/vnets/{vnet}/firewall/options': [add('', digest=DIGEST)],
    '/cluster/tasks': [replace(tasks)],
    '/nodes/{node}/apt/repositories': [
        add('standard-repos', description='Example repository'), put('infos', index=0)],
    '/nodes/{node}/capabilities/qemu/migration': [retype('', 'has-dbus-vmstate', bool)],
    '/nodes/{node}/ceph/osd': [replace(ceph_osd_tree)],
    '/nodes/{node}/ceph/pool': [replace(ceph_pools)],
    '/nodes/{node}/disks/list': [drop('', 'mounted'), put('', type='ssd', **{'osdid-list': ['1']})],
    '/nodes/{node}/disks/lvmthin': [add('', ctime=str(EPOCH))],
    '/nodes/{node}/netstat': [replace(lambda ctx: [{'dev': 'tap100i0', 'vmid': '100', 'in': '0', 'out': '0'}])],
    '/nodes/{node}/network': [replace(networks)],
    '/nodes/{node}/network/{iface}': [add('', families=['inet'], method6='manual', priority=1)],
    '/nodes/{node}/qemu/{vmid}/snapshot': [replace(snapshots)],
    '/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/config': [
        add('', snaptime=EPOCH, description='Example snapshot', digest=DIGEST)],
    '/nodes/{node}/sdn/zones/{zone}/bridges': [
        put('', vlan_filtering=1),
        put('ports', index='0', primary_vlan=1, vlans=['1'], vmid='100')],
    '/nodes/{node}/services': [replace(services)],
    '/nodes/{node}/status': [
        add('', swap={'free': 0, 'total': 0, 'used': 0}, uptime=3600),
        add('cpuinfo', flags='fpu vme', vendor='GenuineIntel')],
    '/nodes/{node}/vzdump/defaults': [
        drop('', 'node', 'vmid'),
        put('', fleecing={'enabled': 0}, performance={'max-workers': 16, 'pbs-entries-max': 1048576})],
}
