"""Stateful LXC containers.

FakeCt is a container; LxcApi is the part of FakePve that keeps them: the
routes under /nodes/{node}/lxc, with the rules and wording of pve-container
(API2/LXC.pm, API2/LXC/Status.pm, API2/LXC/Config.pm, API2/LXC/Snapshot.pm,
LXC/Config.pm) and pve-guest-common (AbstractConfig.pm). Every route is
checked against the schema first, as the generic ones are, so a request
fails the same way whether the container exists or not.

Times are PVE seconds, as in model.py: see FakeCt.start_secs and
FakePve.ct_secs.
"""

import asyncio
import hashlib
import itertools
import json
import re
import secrets
import time

from . import schema as pve_schema
from .model import PveError, TaskError
from .routing import StatefulRoutes, param_error

__all__ = ['FakeCt', 'LxcApi']

SIZE_UNITS = {'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3, 'T': 1024 ** 4}
# A volume still to be allocated: storage:size in GiB.
NEW_DISK = re.compile(r'^([^:\s]+):(\d+(?:\.\d+)?)$')
# Config keys that are mount points or devices, whose names carry a number.
MOUNT_KEY = re.compile(r'^(rootfs|mp\d+|unused\d+)$')
# What a running container takes at once (LXC/Config.pm $LXC_FASTPLUG_OPTIONS).
FASTPLUG = ('description', 'onboot', 'startup', 'protection', 'hostname', 'hookscript', 'cores', 'tags', 'lock')
# Deleting these needs no restart; so do unusedN and netN.
HOT_DELETE = ('swap', 'cpulimit', 'cpuunits')
# Storage types whose container volumes can be snapshotted.
SNAPSHOT_STORAGE = ('lvmthin', 'rbd', 'zfspool', 'btrfs')
# Not part of the config: parameters of the create request.
CREATE_ONLY = ('node', 'vmid', 'ostemplate', 'storage', 'password', 'ssh-public-keys', 'ignore-unpack-errors',
               'bwlimit', 'start', 'ha-managed', 'force', 'restore', 'unique', 'pool', 'unprivileged')
OSTYPES = (('debian', 'debian'), ('devuan', 'devuan'), ('ubuntu', 'ubuntu'), ('centos', 'centos'),
           ('rockylinux', 'centos'), ('almalinux', 'centos'), ('fedora', 'fedora'), ('opensuse', 'opensuse'),
           ('archlinux', 'archlinux'), ('alpine', 'alpine'), ('gentoo', 'gentoo'), ('nixos', 'nixos'))


def _server():
    """The server module, imported late: it imports this one."""
    from . import server
    return server


# ------------------------------------------------------------------ strings

def parse_size(text):
    """Bytes in a size such as 8G or 512M, or None."""
    m = re.fullmatch(r'(\d+(?:\.\d+)?)([KMGT])?', str(text).strip(), re.I)
    if not m:
        return None
    return int(float(m.group(1)) * SIZE_UNITS.get((m.group(2) or '').upper(), 1))


def format_size(size):
    """PVE's spelling of a size in bytes: the largest unit that divides it."""
    for unit in 'TGMK':
        if size and size % SIZE_UNITS[unit] == 0:
            return '{0}{1}'.format(size // SIZE_UNITS[unit], unit)
    return str(size)


def split_props(text):
    """('bare first value' or None, {key: value}) of a comma-separated property string."""
    first, props = None, {}
    for n, part in enumerate(str(text).split(',')):
        key, eq, val = part.partition('=')
        if eq:
            props[key] = val
        elif part and n == 0:
            first = part
    return first, props


def parse_mount(text):
    """A rootfs, mpN or unusedN value as a dict with 'volume' and its options."""
    first, props = split_props(text)
    if first is not None:
        props = dict({'volume': first}, **props)
    return props


def print_mount(mount, rootfs=False):
    """The config value of a mount dict: the volume, then the options in alphabetical order."""
    rest = sorted(k for k in mount if k != 'volume' and not (rootfs and k == 'mp'))
    return ','.join([mount['volume']] + ['{0}={1}'.format(k, mount[k]) for k in rest])


def mount_type(volume):
    """volume, device or bind (LXC/Config.pm classify_mountpoint)."""
    if volume.startswith('/dev/'):
        return 'device'
    return 'bind' if volume.startswith('/') else 'volume'


def volume_owner(volume):
    """The vmid in a volume name such as local-lvm:vm-100-disk-0, or None."""
    m = re.search(r'-(\d+)-disk-\d+', volume)
    return int(m.group(1)) if m else None


def to_base(volume):
    """The volume of a template: vm-100-disk-0 becomes base-100-disk-0."""
    return re.sub(r'\bvm-(\d+)-disk', r'base-\1-disk', volume).replace('subvol-', 'basevol-')


def random_mac():
    return 'BC:24:11:' + ':'.join('{0:02X}'.format(b) for b in secrets.token_bytes(3))


def _boolean(text):
    return pve_schema.parse_boolean(str(text)) or text


def normalise(key, value):
    """A value as PVE writes it back: net with its hwaddr and type, features and tags sorted."""
    if re.fullmatch(r'net\d+', key):
        first, props = split_props(value)
        props.setdefault('hwaddr', random_mac())
        props['type'] = 'veth'
        for flag in ('firewall', 'link_down', 'host-managed'):
            if flag in props:
                props[flag] = _boolean(props[flag])
        order = ['name'] + sorted(k for k in props if k != 'name')
        return ','.join('{0}={1}'.format(k, props[k]) for k in order if k in props)
    if key == 'features':
        _, props = split_props(value)
        return ','.join('{0}={1}'.format(k, _boolean(props[k])) for k in sorted(props))
    if key == 'tags':
        tags = sorted(set(t.lower() for t in re.split(r'[;, ]+', str(value)) if t))
        return ';'.join(tags)
    return value


def ostype_of(template):
    """The ostype PVE detects in a template, from its file name."""
    name = str(template).rsplit('/', 1)[-1].lower()
    return next((kind for prefix, kind in OSTYPES if name.startswith(prefix)), 'unmanaged')


def arch_of(template):
    m = re.search(r'[_-](amd64|arm64|armhf|riscv64|i386)\b', str(template))
    return m.group(1) if m else 'amd64'


def option_exists(opt):
    """True if opt is a container config key."""
    return re.fullmatch(r'(mp|unused|net|dev)\d+', opt) is not None or opt in (
        'arch', 'cmode', 'console', 'cores', 'cpulimit', 'cpuunits', 'debug', 'description', 'entrypoint', 'env',
        'features', 'hookscript', 'hostname', 'lock', 'lxc', 'memory', 'nameserver', 'onboot', 'ostype',
        'protection', 'rootfs', 'searchdomain', 'startup', 'swap', 'tags', 'template', 'timezone', 'tty',
        'unprivileged')


# -------------------------------------------------------------------- model

class FakeCt(object):
    """A container. config holds what /config shows; pending what a running container takes at its next start."""

    def __init__(self, vmid, name=None, node='pve1', status='stopped', config=None, pending=None,
                 template=False, lock=None, pool=None, ostemplate=None, defaults=True):
        self.vmid = vmid
        self.node = node
        self.status = status
        self.config = dict(config or {})
        if defaults:
            self.config.setdefault('hostname', name or 'CT{0}'.format(vmid))
            self.config.setdefault('ostype', ostype_of(ostemplate) if ostemplate else 'debian')
            self.config.setdefault('arch', arch_of(ostemplate or ''))
            self.config.setdefault('memory', 512)
            self.config.setdefault('swap', 512)
            self.config.setdefault('rootfs', 'local-lvm:vm-{0}-disk-0,size=8G'.format(vmid))
            self.config.setdefault('unprivileged', 1)
        if template:
            self.config['template'] = 1
        if lock:
            self.config['lock'] = lock
        # key -> new value, or None for a pending delete
        self.pending = dict(pending or {})
        # name -> a snapshot: the config at the time, with snaptime, description, parent and snapstate
        self.snapshots = {}
        self.pool = pool
        # Extra status/current fields: cpu, mem, uptime, ...
        self.stats = {}
        self.started_at = time.time() if status == 'running' else None
        self.pid = None
        # lxc-checkpoint left a dump, so resume can work.
        self.checkpoint = False
        # PVE seconds the clean shutdown takes; the start and stop tasks' own durations.
        self.shutdown_secs = 0
        self.start_secs = 0
        self.stop_secs = 0
        # The container cannot be started: the task ends with this message.
        self.start_error = None
        # HA resource state when managed: started, stopped, error, ...
        self.ha_state = None
        # Holder of the internal config lock (a task id or 'scenario').
        self.lock_holder = None
        self.lock_released = None

    @property
    def name(self):
        """The hostname, which is the name PVE lists."""
        return self.config.get('hostname') or 'CT{0}'.format(self.vmid)

    @property
    def lock(self):
        """The config lock: backup, migrate, snapshot, create, ..."""
        return self.config.get('lock')

    @lock.setter
    def lock(self, value):
        if value:
            self.config['lock'] = value
        else:
            self.config.pop('lock', None)

    @property
    def template(self):
        """True for a template."""
        return bool(self.config.get('template'))

    @property
    def guest(self):
        """The id as /cluster/resources shows it: lxc/<vmid>."""
        return 'lxc/{0}'.format(self.vmid)

    @property
    def ha_managed(self):
        """True if ha_state is set."""
        return self.ha_state is not None

    @property
    def lock_error(self):
        return "can't lock file '/run/lock/lxc/pve-config-{0}.lock' - got timeout".format(self.vmid)

    def digest(self):
        """The config digest clients pass back to detect concurrent changes."""
        blob = json.dumps([self.config, self.pending, self.snapshots], sort_keys=True)
        return hashlib.sha1(blob.encode()).hexdigest()

    def volumes(self, cfg=None):
        """(key, mount dict) of the config's volumes, not bind or device mounts."""
        cfg = self.config if cfg is None else cfg
        out = []
        for key in sorted(cfg):
            if MOUNT_KEY.match(key):
                mount = parse_mount(cfg[key])
                if mount_type(mount.get('volume', '')) == 'volume':
                    out.append((key, mount))
        return out


class LxcApi(StatefulRoutes):
    """Mixin for FakePve: the containers and their routes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cts = []
        # PVE seconds each container task takes: create, clone, destroy, snapshot, delsnapshot, rollback,
        # template, resize, migrate.
        self.ct_secs = dict.fromkeys(('create', 'clone', 'destroy', 'snapshot', 'delsnapshot', 'rollback',
                                      'template', 'resize', 'migrate'), 0)
        self._ct_pids = itertools.count(2000)

    def _routes_cluster(self):
        return [('GET', '/cluster/nextid', self._nextid)]

    async def _nextid(self, v, user):
        """Cluster.pm nextid: the first free id among VMs and containers, or the asked one if it is free."""
        if v.get('vmid') not in (None, ''):
            if self.guest(int(v['vmid'])):
                raise param_error(vmid='VM {0} already exists'.format(v['vmid']))
            return v['vmid']
        lower, upper = 100, 1000 * 1000
        taken = set(vm.vmid for vm in self.vms) | set(ct.vmid for ct in self.cts)
        for vmid in range(lower, upper):
            if vmid not in taken:
                return vmid
        raise PveError(500, 'unable to get any free VMID in range [{0}, {1}]'.format(lower, upper))

    # ----------------------------------------------------------- lookup

    def add_ct(self, *args, **kwargs):
        """Add a FakeCt (arguments as FakeCt's) and its node; returns the container."""
        ct = FakeCt(*args, **kwargs)
        try:
            self._check_vmid_unused(ct.vmid)
        except PveError as e:
            raise ValueError(e.message) from None
        self.cts.append(ct)
        self.nodes.setdefault(ct.node, {'online': True})
        if ct.pool:
            self._pool_join(ct.pool, ct.vmid)
        if ct.status == 'running':
            ct.pid = next(self._ct_pids)
        return ct

    def ct(self, vmid):
        """The container with this id, or None."""
        for ct in self.cts:
            if ct.vmid == vmid:
                return ct
        return None

    def guest(self, vmid):
        """The VM or container with this id, or None."""
        return self.vm(vmid) or self.ct(vmid)

    def ct_resources(self, user, kind=None):
        """The containers as /cluster/resources lists them."""
        data = []
        if kind not in (None, 'vm'):
            return data
        for ct in self.cts:
            online = self.nodes.get(ct.node, {}).get('online', True)
            if not self.allowed(user, '/vms/{0}'.format(ct.vmid), 'VM.Audit'):
                continue
            item = {'id': ct.guest, 'type': 'lxc', 'node': ct.node, 'name': ct.name, 'vmid': ct.vmid,
                    'status': ct.status if online else 'unknown', 'template': 1 if ct.template else 0,
                    'maxcpu': self._cpus(ct), 'maxmem': self._maxmem(ct), 'maxdisk': self._maxdisk(ct),
                    'cpu': 0, 'mem': 0, 'disk': 0, 'uptime': self._uptime(ct)}
            if ct.lock:
                item['lock'] = ct.lock
            if ct.pool:
                item['pool'] = ct.pool
            if ct.config.get('tags'):
                item['tags'] = ct.config['tags']
            if ct.ha_managed:
                item['hastate'] = ct.ha_state
            data.append(item)
        return data

    def _check_vmid_unused(self, vmid):
        """PVE::Cluster::check_vmid_unused: the id is free among VMs and containers."""
        vm = self.vm(vmid)
        ct = self.ct(vmid)
        owner = ('VM', vm.node) if vm else ('CT', ct.node) if ct else None
        if owner:
            raise PveError(500, "{0} {1} already exists on node '{2}'".format(owner[0], vmid, owner[1]))

    def _find_ct(self, node, vmid):
        """The container on this node, or PVE's 500 for a missing config file."""
        ct = self.ct(int(vmid))
        if ct is None or ct.node != node:
            raise PveError(500, "Configuration file 'nodes/{0}/lxc/{1}.conf' does not exist".format(node, vmid))
        return ct

    def _drop(self, ct):
        if ct in self.cts:
            self.cts.remove(ct)
        self._pool_leave(ct.vmid)

    # ------------------------------------------------------ permissions

    def _vm_perm(self, user, vmid, pool, *privs):
        """Check_vm_perm: every privilege on the guest or on its pool."""
        for priv in privs:
            if not (self.allowed(user, '/vms/{0}'.format(vmid), priv)
                    or (pool and self.allowed(user, '/pool/' + pool, priv))):
                raise PveError(403, 'Permission check failed (/vms/{0}, {1})'.format(vmid, priv))

    def _check_bridge(self, user, net):
        bridge = split_props(net)[1].get('bridge')
        if bridge:
            self.require(user, '/sdn/zones/localnetwork/' + bridge, 'SDN.Use')

    def _check_modify_perm(self, user, vmid, pool, old, new, deletes, unprivileged):
        """PVE::LXC::check_ct_modify_config_perm: the privilege each option needs."""
        if self.acl is None or user == 'root@pam':
            return

        def deny(why):
            raise PveError(403, 'Permission check failed ({0})'.format(why))

        def check(opt, deleting):
            if opt in ('cores', 'cpuunits', 'cpulimit'):
                self._vm_perm(user, vmid, pool, 'VM.Config.CPU')
            elif MOUNT_KEY.match(opt):
                self._vm_perm(user, vmid, pool, 'VM.Config.Disk')
                if deleting:
                    return
                mount = parse_mount(new[opt])
                kind = mount_type(mount.get('volume', ''))
                if kind != 'volume':
                    deny('mount point type {0} is only allowed for root@pam'.format(kind))
                found = NEW_DISK.match(mount['volume'])
                if found:
                    self.require(user, '/storage/' + found.group(1), 'Datastore.AllocateSpace')
                elif volume_owner(mount['volume']) not in (None, vmid):
                    self.require(user, '/storage/' + mount['volume'].split(':')[0], 'Datastore.Audit')
                    self._vm_perm(user, volume_owner(mount['volume']), None, 'VM.Config.Disk')
            elif opt in ('memory', 'swap'):
                self._vm_perm(user, vmid, pool, 'VM.Config.Memory')
            elif re.fullmatch(r'net\d+', opt):
                self._vm_perm(user, vmid, pool, 'VM.Config.Network')
                for cfg in (old or {}, new):
                    if cfg.get(opt):
                        self._check_bridge(user, cfg[opt])
            elif re.fullmatch(r'dev\d+', opt):
                deny('configuring device passthrough is only allowed for root@pam')
            elif opt in ('nameserver', 'searchdomain', 'hostname'):
                self._vm_perm(user, vmid, pool, 'VM.Config.Network')
            elif opt == 'features':
                if not unprivileged:
                    deny('changing feature flags for privileged container is only allowed for root@pam')
                before = split_props((old or {}).get('features', ''))[1]
                after = {} if deleting else split_props(new.get('features', ''))[1]
                changed = set(k for k in set(before) | set(after) if before.get(k) != after.get(k))
                if changed - {'nesting'}:
                    deny('changing feature flags (except nesting) is only allowed for root@pam')
                if changed:
                    self._vm_perm(user, vmid, pool, 'VM.Allocate')
            elif opt == 'hookscript':
                deny('changing the hookscript is only allowed for root@pam')
            else:
                self._vm_perm(user, vmid, pool, 'VM.Config.Options')
        for opt in new:
            check(opt, False)
        for opt in deletes:
            check(opt, True)

    # ------------------------------------------------------------ views

    @staticmethod
    def _cpus(ct):
        return ct.config.get('cores') or ct.config.get('cpulimit') or 1

    @staticmethod
    def _maxmem(ct):
        return int(ct.config.get('memory') or 512) * 1048576

    @staticmethod
    def _maxdisk(ct):
        size = parse_mount(ct.config.get('rootfs', '')).get('size')
        return parse_size(size) if size and parse_size(size) else 4 * 1024 ** 3

    @staticmethod
    def _uptime(ct):
        return int(time.time() - ct.started_at) if ct.status == 'running' and ct.started_at else 0

    def _status(self, ct):
        """The vmstatus fields of a container."""
        data = {'vmid': ct.vmid, 'type': 'lxc', 'name': ct.name, 'status': ct.status, 'cpus': self._cpus(ct),
                'cpu': 0.02 if ct.status == 'running' else 0, 'mem': 67108864 if ct.status == 'running' else 0,
                'maxmem': self._maxmem(ct), 'swap': 0, 'maxswap': int(ct.config.get('swap') or 0) * 1048576,
                'disk': 0, 'maxdisk': self._maxdisk(ct), 'uptime': self._uptime(ct), 'netin': 0, 'netout': 0,
                'diskread': 0, 'diskwrite': 0}
        if ct.pid and ct.status == 'running':
            data['pid'] = ct.pid
        if ct.config.get('tags'):
            data['tags'] = ct.config['tags']
        if ct.template:
            data['template'] = 1
        if ct.lock:
            data['lock'] = ct.lock
        data.update(ct.stats)
        return data

    # ----------------------------------------------------------- routes

    def _lxc_routes(self, router, node):
        """Register the container routes under node (the '/nodes/{node}' path of one API format)."""
        base = node + '/lxc'
        table = (
            ('GET', '', self._lxc_list), ('POST', '', self._lxc_create),
            ('DELETE', '/{vmid}', self._lxc_destroy),
            ('GET', '/{vmid}/status/current', self._lxc_status_current),
            ('POST', '/{vmid}/status/start', self._lxc_start),
            ('POST', '/{vmid}/status/stop', self._lxc_stop),
            ('POST', '/{vmid}/status/shutdown', self._lxc_shutdown),
            ('POST', '/{vmid}/status/reboot', self._lxc_reboot),
            ('POST', '/{vmid}/status/suspend', self._lxc_suspend),
            ('POST', '/{vmid}/status/resume', self._lxc_resume),
            ('GET', '/{vmid}/config', self._lxc_config_get), ('PUT', '/{vmid}/config', self._lxc_config_put),
            ('GET', '/{vmid}/pending', self._lxc_pending),
            ('POST', '/{vmid}/clone', self._lxc_clone), ('POST', '/{vmid}/template', self._lxc_template),
            ('GET', '/{vmid}/migrate', self._lxc_migrate_check), ('POST', '/{vmid}/migrate', self._lxc_migrate),
            ('PUT', '/{vmid}/resize', self._lxc_resize), ('GET', '/{vmid}/interfaces', self._lxc_interfaces),
            ('GET', '/{vmid}/snapshot', self._lxc_snapshot_list),
            ('POST', '/{vmid}/snapshot', self._lxc_snapshot),
            ('DELETE', '/{vmid}/snapshot/{snapname}', self._lxc_snapshot_delete),
            ('POST', '/{vmid}/snapshot/{snapname}/rollback', self._lxc_rollback),
            ('GET', '/{vmid}/snapshot/{snapname}/config', self._lxc_snapshot_config_get),
            ('PUT', '/{vmid}/snapshot/{snapname}/config', self._lxc_snapshot_config_put),
        )
        for method, suffix, fn in table:
            router.add_route(method, base + suffix, self._lxc_handler(fn))

    def _lxc_handler(self, fn):
        """A route: the schema's checks, then fn(user, values)."""
        async def handler(request):
            srv = _server()
            user = request[srv.USER]
            match = self.resolve(request, srv.API)
            data = await self.answer(request, match, await srv.params(request), user,
                                     lambda _match, values: fn(user, values))
            return srv.ok(data)
        return handler

    # ------------------------------------------------------------ locks

    async def _config_lock(self, ct):
        """Take the config lock for a synchronous change (PVE waits 10 s); PVE's 500 on timeout."""
        try:
            await self.acquire(ct, 'config')
        except TaskError as e:
            raise PveError(500, str(e)) from e

    @staticmethod
    def _ct_check_lock(ct):
        if ct.lock:
            raise PveError(500, 'CT is locked ({0})'.format(ct.lock))

    @staticmethod
    def _task_lock(ct, allow=()):
        if ct.lock and ct.lock not in allow:
            raise TaskError('CT is locked ({0})'.format(ct.lock))

    async def _ct_task(self, ct, ttype, user, body, **kwargs):
        return await self.task(ct.node, ttype, ct.vmid, user, body, vm=ct, **kwargs)

    # ------------------------------------------------------- list, status

    async def _lxc_list(self, user, v):
        return [self._status(ct) for ct in self.cts if ct.node == v['node']
                and self.allowed(user, '/vms/{0}'.format(ct.vmid), 'VM.Audit')]

    async def _lxc_status_current(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        data = self._status(ct)
        data['ha'] = {'managed': 1, 'state': ct.ha_state} if ct.ha_managed else {'managed': 0}
        return data

    # ----------------------------------------------------------- volumes

    def _taken_volumes(self):
        out = set()
        for ct in self.cts:
            for cfg in [ct.config] + list(ct.snapshots.values()):
                out.update(mount['volume'] for _, mount in ct.volumes(cfg))
        return out

    def _ct_volume_name(self, vmid, sid, n):
        kind = self.storages.get(sid, {}).get('type', 'dir')
        if kind == 'zfspool':
            return 'subvol-{0}-disk-{1}'.format(vmid, n)
        if kind in ('lvm', 'lvmthin', 'rbd'):
            return 'vm-{0}-disk-{1}'.format(vmid, n)
        return '{0}/vm-{0}-disk-{1}.raw'.format(vmid, n)

    def _allocate(self, vmid, sid, taken):
        """A new volume id for the container on the storage."""
        for n in itertools.count():
            volid = '{0}:{1}'.format(sid, self._ct_volume_name(vmid, sid, n))
            if volid not in taken:
                taken.add(volid)
                return volid

    def _storage_for(self, sid, user=None, vmid=None):
        """The storage config of a rootdir volume: PVE's checks of PVE::Storage and the API."""
        store = self.storages.get(sid)
        if store is None:
            raise PveError(500, "storage '{0}' does not exist".format(sid))
        if 'rootdir' not in str(store.get('content', '')).split(','):
            raise PveError(400, 'Parameter verification failed.',
                           {'storage': "storage '{0}' does not support container directories".format(sid)})
        if user is not None:
            self.require(user, '/storage/' + sid, 'Datastore.AllocateSpace')
        if not store.get('active', 1):
            raise PveError(500, "storage '{0}' is not online".format(sid))
        return store

    def _realise(self, vmid, key, value, taken, default_storage=None):
        """A mount point value with a new volume allocated for 'storage:size' (GiB)."""
        mount = parse_mount(value)
        found = NEW_DISK.match(mount.get('volume', ''))
        if found:
            sid, gib = found.group(1), float(found.group(2))
            mount['volume'] = self._allocate(vmid, sid, taken)
            mount['size'] = format_size(int(gib * SIZE_UNITS['G'])) if gib else '0'
        elif 'size' in mount and parse_size(mount['size']):
            mount['size'] = format_size(parse_size(mount['size']))
        return print_mount(mount, key == 'rootfs')

    @staticmethod
    def _unused_key(cfg):
        for n in range(256):
            if 'unused{0}'.format(n) not in cfg:
                return 'unused{0}'.format(n)
        raise PveError(500, 'Too many unused volumes - please delete them first.')

    # ---------------------------------------------------------- pending

    def _apply(self, ct, selection=None, running=False):
        """Move pending changes into the config: a stopped container takes them all (those selected), a
        running one only what PVE can hotplug (vmconfig_apply_pending, vmconfig_hotplug_pending)."""
        cfg, pend = ct.config, ct.pending
        taken = self._taken_volumes()

        def chosen(opt):
            return selection is None or opt in selection
        deletes = sorted(k for k, x in pend.items() if x is None and chosen(k))
        sets = sorted(k for k, x in pend.items() if x is not None and chosen(k))
        if running:
            for opt in sets:
                if opt in FASTPLUG:
                    cfg[opt] = pend.pop(opt)
            for opt in deletes:
                if opt in FASTPLUG or opt in HOT_DELETE or re.fullmatch(r'(unused|net)\d+', opt):
                    cfg.pop(opt, None)
                    pend.pop(opt)
            for opt in sorted(k for k, x in pend.items() if x is not None and chosen(k)):
                if opt in ('cpulimit', 'cpuunits', 'memory', 'swap') or re.fullmatch(r'net\d+', opt):
                    cfg[opt] = pend.pop(opt)
                elif re.fullmatch(r'(mp|dev)\d+', opt) and opt not in cfg:
                    cfg[opt] = self._realise(ct.vmid, opt, pend.pop(opt), taken) if opt.startswith('mp') \
                        else pend.pop(opt)
            return
        for opt in deletes:
            if re.fullmatch(r'mp\d+', opt) and opt in cfg:
                mount = parse_mount(cfg[opt])
                if mount_type(mount.get('volume', '')) == 'volume':
                    cfg[self._unused_key(cfg)] = mount['volume']
            cfg.pop(opt, None)
            pend.pop(opt)
        for opt in sets:
            value = pend.pop(opt)
            cfg[opt] = self._realise(ct.vmid, opt, value, taken) if MOUNT_KEY.match(opt) else value

    def _cleanup_pending(self, ct):
        """Drop pending entries that change nothing (AbstractConfig cleanup_pending)."""
        for opt, value in list(ct.pending.items()):
            if (value is None and opt not in ct.config) or (value is not None and ct.config.get(opt) == value):
                del ct.pending[opt]

    # ------------------------------------------------------------ config

    async def _lxc_config_get(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        if v.get('snapshot') and v.get('current'):
            text = "cannot use 'snapshot' parameter with 'current'"
            raise PveError(400, 'Parameter verification failed.', {'snapshot': text, 'current': text})
        if v.get('snapshot'):
            snap = ct.snapshots.get(v['snapshot'])
            if snap is None:
                raise PveError(500, "snapshot '{0}' does not exist".format(v['snapshot']))
            data = dict(snap)
            data.pop('snapshots', None)
        else:
            data = dict(ct.config)
            if not v.get('current'):
                for opt, value in ct.pending.items():
                    if value is None:
                        data.pop(opt, None)
                    else:
                        data[opt] = value
        data['digest'] = ct.digest()
        return data

    async def _lxc_pending(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        data = []
        for key in sorted(set(ct.config) | set(ct.pending)):
            item = {'key': key}
            if key in ct.config:
                item['value'] = ct.config[key]
            if key in ct.pending:
                if ct.pending[key] is None:
                    item['delete'] = 1
                else:
                    item['pending'] = ct.pending[key]
            data.append(item)
        return data

    async def _lxc_config_put(self, user, v):
        values = dict((k, x) for k, x in v.items() if k not in ('node', 'vmid'))
        digest = values.pop('digest', None)
        if not values:
            raise PveError(500, 'no options specified')
        deletes = [k for k in str(values.pop('delete', '') or '').split(',') if k]
        reverts = [k for k in str(values.pop('revert', '') or '').split(',') if k]
        self.need_quorum()
        ct = self._find_ct(v['node'], v['vmid'])
        await self._config_lock(ct)
        try:
            self._ct_check_lock(ct)
            if digest and digest != ct.digest():
                raise PveError(500, 'detected modified configuration - file changed by other user? Try again.')
            unprivileged = ct.config.get('unprivileged')
            self._check_modify_perm(user, ct.vmid, None, ct.config, {}, deletes, unprivileged)
            self._check_modify_perm(user, ct.vmid, None, ct.config, {}, reverts, unprivileged)
            for opt in reverts:
                if not option_exists(opt):
                    raise PveError(400, 'Parameter verification failed.',
                                   {'revert': "unknown option '{0}'".format(opt)})
                if opt in values:
                    raise PveError(400, 'Parameter verification failed.', {
                        'revert': "you can't use '-{0}' and '-revert {0}' at the same time".format(opt)})
            for opt in deletes:
                if not option_exists(opt):
                    raise PveError(400, 'Parameter verification failed.',
                                   {'delete': "unknown option '{0}'".format(opt)})
                if opt in values:
                    raise PveError(400, 'Parameter verification failed.', {
                        'delete': "you can't use '-{0}' and -delete {0}' at the same time".format(opt)})
                if opt in reverts:
                    raise PveError(400, 'Parameter verification failed.', {
                        'delete': "you can't use '-delete {0}' and '-revert {0}' at the same time".format(opt)})
            self._check_modify_perm(user, ct.vmid, None, ct.config, values, [], unprivileged)
            await self._update_config(ct, user, values, deletes, reverts)
        finally:
            self.release(ct, 'config')

    async def _update_config(self, ct, user, values, deletes, reverts):
        """PVE::LXC::Config update_pct_config, then the hotplug (running) or the apply (stopped)."""
        running = ct.status == 'running'
        for opt in reverts:
            ct.pending.pop(opt, None)
        modified = set()
        for opt in deletes:
            if opt not in ct.config and ct.pending.get(opt) is None:
                continue
            modified.add(opt)
            if opt in ('memory', 'rootfs', 'ostype'):
                raise PveError(500, "unable to delete required option '{0}'".format(opt))
            if re.fullmatch(r'(unused|mp)\d+', opt):
                self._check_protection(ct, "can't remove CT {0} drive '{1}'".format(ct.vmid, opt))
            elif opt == 'unprivileged':
                raise PveError(500, "unable to delete read-only option: 'unprivileged'")
            ct.pending[opt] = None
        for opt in sorted(values):
            modified.add(opt)
            value = values[opt]
            if MOUNT_KEY.match(opt) and not opt.startswith('unused'):
                self._check_protection(ct, "can't update CT {0} drive '{1}'".format(ct.vmid, opt))
                mount = parse_mount(value)
                if mount_type(mount.get('volume', '')) == 'volume':
                    sid = mount['volume'].split(':')[0]
                    store = self.storages.get(sid)
                    if store is None:
                        raise PveError(500, "storage '{0}' does not exist".format(sid))
                    if 'rootdir' not in str(store.get('content', '')).split(','):
                        raise PveError(500, "storage '{0}' does not allow content type 'rootdir' (Container)"
                                       .format(sid))
            elif opt == 'unprivileged':
                raise PveError(500, "unable to modify read-only option: 'unprivileged'")
            ct.pending[opt] = normalise(opt, value)
        self._cleanup_pending(ct)
        if values or deletes:
            disks = [k for k in list(values) + deletes if MOUNT_KEY.match(k)]
            if disks:
                try:
                    await self.ceph_io(ct, disks)
                except TaskError as e:
                    raise PveError(500, str(e)) from e
        self._apply(ct, modified, running)

    @staticmethod
    def _check_protection(ct, message):
        if ct.config.get('protection'):
            raise PveError(500, '{0} - protection mode enabled'.format(message))

    # ----------------------------------------------------------- create

    async def _lxc_create(self, user, v):
        node, vmid = v['node'], int(v['vmid'])
        self.need_quorum()
        restore, force = bool(v.get('restore')), bool(v.get('force'))
        existing = self.ct(vmid)
        same = existing is not None and existing.node == node
        unprivileged = v.get('unprivileged')
        if not restore:
            unprivileged = 1 if unprivileged is None else unprivileged
            if not unprivileged:
                self.require(user, '/', 'Sys.Modify')
        if v.get('ha-managed'):
            self.require(user, '/', 'Sys.Console')
        if same and restore and force:
            if existing.status == 'running':
                raise PveError(500, "can't overwrite running container")
            self._check_protection(existing, 'unable to restore CT {0}'.format(vmid))
        else:
            self._check_vmid_unused(vmid)
        pool = v.get('pool')
        if pool and pool not in self.pools:
            raise PveError(403, "Permission check failed (pool '{0}' does not exist)".format(pool))
        if v.get('start'):
            self._vm_perm(user, vmid, pool, 'VM.PowerMgmt')
        if not (self.allowed(user, '/vms/{0}'.format(vmid), 'VM.Allocate')
                or (pool and self.allowed(user, '/pool/' + pool, 'VM.Allocate'))
                or (restore and force and same and self.allowed(user, '/vms/{0}'.format(vmid), 'VM.Backup'))):
            raise PveError(403, 'Permission check failed')
        ostemplate = v['ostemplate']
        storage = v.get('storage') or 'local'
        self._check_template(user, ostemplate, restore)
        params = dict((k, x) for k, x in v.items() if k not in CREATE_ONLY)
        self._check_modify_perm(user, vmid, pool, None, params, [], unprivileged)
        mounts, conf = {}, {}
        for opt, value in params.items():
            if opt == 'rootfs' or re.fullmatch(r'mp\d+', opt):
                mounts[opt] = '{0}:{1}'.format(storage, value) if re.fullmatch(r'\d+(\.\d+)?', str(value)) \
                    else str(value)
            elif opt.startswith('unused'):
                continue
            else:
                conf[opt] = normalise(opt, value)
        if mounts and 'rootfs' not in mounts:
            raise PveError(500, "mount points configured, but 'rootfs' not set - aborting")
        for value in mounts.values():
            mount = parse_mount(value)
            kind = mount_type(mount.get('volume', ''))
            if kind != 'volume':
                if user != 'root@pam':
                    raise PveError(500, 'Only root can pass arbitrary filesystem paths.')
            else:
                self._storage_for(mount['volume'].split(':')[0], user, vmid)
        if 'rootfs' not in mounts:
            self._storage_for(storage, user, vmid)
            mounts['rootfs'] = '{0}:4'.format(storage)
        # create_and_lock_config: the container exists, locked, before the task starts.
        if same and restore and force:
            self._drop(existing)
        ct = FakeCt(vmid, node=node, defaults=False, config={'lock': 'create'})
        self.cts.append(ct)
        taken = self._taken_volumes()
        final = dict(conf)
        for opt in sorted(mounts, key=lambda k: (k != 'rootfs', k)):
            final[opt] = self._realise(vmid, opt, mounts[opt], taken)
        if unprivileged:
            final['unprivileged'] = 1
        final.setdefault('hostname', 'CT{0}'.format(vmid))
        final.setdefault('memory', 512)
        final.setdefault('swap', 512)
        final['ostype'] = ostype_of(ostemplate)
        final['arch'] = arch_of(ostemplate)
        emsg = 'unable to {0} CT {1} -'.format('restore' if restore else 'create', vmid)

        async def body():
            try:
                if self.volume_exists(ostemplate) is False:
                    raise TaskError("volume '{0}' does not exist".format(ostemplate))
                await self.pause(self.ct_secs['create'])
                ct.config = dict(final)
                await self.ceph_io(ct, [k for k in final if MOUNT_KEY.match(k)])
            except TaskError as e:
                self._drop(ct)
                raise TaskError('{0} {1}'.format(emsg, e)) from e
            if pool:
                self._pool_join(pool, vmid)
            if v.get('start'):
                await self._start_steps(ct, user)
            if v.get('ha-managed'):
                ct.ha_state = 'started' if v.get('start') else 'stopped'
                return 'Add as HA resource'
            return None
        return await self.task(node, 'vzrestore' if restore else 'vzcreate', vmid, user, body, vm=ct)

    def _check_template(self, user, ostemplate, restore):
        """The checks PVE makes of the OS template or backup volume before it forks the task."""
        sid, colon, name = ostemplate.partition(':')
        if not colon:
            if user != 'root@pam':
                raise PveError(500, 'Only root can pass arbitrary filesystem paths.')
            return
        want = 'backup' if restore else 'vztmpl'
        if sid not in self.storages:
            raise PveError(500, "storage '{0}' does not exist".format(sid))
        kind = name.split('/', 1)[0]
        if kind not in ('iso', 'vztmpl', 'backup', 'snippets', 'import', 'images', 'rootdir'):
            raise PveError(500, "unable to parse directory volume name '{0}'".format(name))
        if kind != want and not (want == 'rootdir' and kind == 'images'):
            raise PveError(500, "unable to use volume {0} - content type needs to be '{1}'".format(
                ostemplate, want))
        if kind in ('iso', 'vztmpl', 'import') and not (
                self.allowed(user, '/storage/' + sid, 'Datastore.Allocate')
                or self.allowed(user, '/storage/' + sid, 'Datastore.AllocateSpace')
                or self.allowed(user, '/storage/' + sid, 'Datastore.Audit')):
            raise PveError(403, 'Permission check failed (/storage/{0}, Datastore.AllocateSpace|Datastore.Audit)'
                           .format(sid))

    # ----------------------------------------------------------- destroy

    async def _lxc_destroy(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        vmid = ct.vmid
        self._check_protection(ct, "can't remove CT {0}".format(vmid))
        self._ct_check_lock(ct)
        if ct.ha_managed and not v.get('purge'):
            raise PveError(500, 'unable to remove CT {0} - used in HA resources and purge parameter not set.'
                           .format(vmid))
        running_msg = 'unable to destroy CT {0} - container is running'.format(vmid)
        if ct.status == 'running' and not v.get('force'):
            raise PveError(500, running_msg)

        async def body():
            self._check_protection(ct, "can't remove CT {0}".format(vmid))
            self._task_lock(ct)
            if ct.status == 'running':
                if not v.get('force'):
                    raise TaskError(running_msg)
                ct.status = 'stopped'
                ct.pid = None
            ct.lock = 'destroyed'
            await self.pause(self.ct_secs['destroy'])
            self._drop(ct)
            if v.get('purge') and ct.ha_managed:
                return 'NOTE: removed CT {0} from HA resource configuration.'.format(vmid)
            return None
        log = ['forced to stop CT {0} before destroying!'.format(vmid)] if ct.status == 'running' else []
        upid = await self._ct_task(ct, 'vzdestroy', user, body, log=log)
        return upid

    # -------------------------------------------------------- power state

    def _skiplock(self, user, v):
        if v.get('skiplock') and user != 'root@pam':
            raise PveError(400, 'Parameter verification failed.', {'skiplock': 'Only root may use this option.'})
        return bool(v.get('skiplock'))

    async def _ct_ha(self, ct, user, state, timeout=None):
        async def body():
            async def later():
                await self.pause(self.ha_delay)
                if state == 'started':
                    self._apply(ct)
                    ct.status = 'running'
                    ct.started_at = time.time()
                    ct.pid = next(self._ct_pids)
                else:
                    ct.status = 'stopped'
                    ct.pid = None
                ct.ha_state = state
            if self.time_scale:
                asyncio.ensure_future(later())
            else:
                await later()
        verb = 'start' if state == 'started' else 'stop'
        return await self._ct_task(ct, 'ha' + verb, user, body, lock=False,
                                   log=['Requesting HA {0} for CT {1}'.format(verb, ct.vmid)])

    async def _start_steps(self, ct, user, skiplock=False):
        """What the vzstart worker does once it holds the config lock."""
        if ct.template:
            raise TaskError("you can't start a CT if it's a template")
        if not skiplock:
            self._task_lock(ct, allow=('mounted',))
        await self.ceph_io(ct, [k for k in ct.config if MOUNT_KEY.match(k)])
        await self.pause(ct.start_secs)
        if ct.start_error:
            raise TaskError(ct.start_error)
        self._apply(ct)
        ct.status = 'running'
        ct.started_at = time.time()
        ct.pid = next(self._ct_pids)

    async def _lxc_start(self, user, v):
        skiplock = self._skiplock(user, v)
        ct = self._here(v)
        if ct is not None and ct.status == 'running':
            raise PveError(500, 'CT {0} already running'.format(v['vmid']))
        self.need_quorum()
        if ct is None:
            # The worker finds out that there is no config file.
            async def missing():
                try:
                    self._find_ct(v['node'], v['vmid'])
                except PveError as e:
                    raise TaskError(e.message) from e
            return await self.task(v['node'], 'vzstart', v['vmid'], user, missing)
        if ct.ha_managed:
            return await self._ct_ha(ct, user, 'started')

        async def body():
            await self._start_steps(ct, user, skiplock)
        return await self._ct_task(ct, 'vzstart', user, body)

    def _here(self, v):
        """The container if it lives on the requested node, else None."""
        ct = self.ct(int(v['vmid']))
        return ct if ct is not None and ct.node == v['node'] else None

    def _ct_running(self, ct, message):
        if ct is None or ct.status != 'running':
            raise PveError(500, message)

    async def _lxc_stop(self, user, v):
        skiplock = self._skiplock(user, v)
        ct = self._here(v)
        self._ct_running(ct, 'CT {0} not running'.format(v['vmid']))
        if ct.ha_managed:
            if v.get('overrule-shutdown'):
                raise PveError(400, 'Parameter verification failed.',
                               {'overrule-shutdown': 'Not applicable for HA resources.'})
            return await self._ct_ha(ct, user, 'stopped')

        async def body():
            if v.get('overrule-shutdown'):
                for task in list(self.tasklog):
                    if task['type'] == 'vzshutdown' and task['id'] == str(ct.vmid) and task['status'] == 'running':
                        task['overruled'] = True
            if not skiplock:
                self._task_lock(ct, allow=('mounted',))
            await self.pause(ct.stop_secs)
            ct.status = 'stopped'
            ct.pid = None
        return await self._ct_task(ct, 'vzstop', user, body)

    async def _ct_powerdown(self, ct, timeout, force):
        """vm_stop with a clean shutdown: the container ends the timeout after lxc-stop, or is killed."""
        if ct.shutdown_secs <= timeout:
            await self.pause(ct.shutdown_secs)
        else:
            await self.pause(timeout)
            if not force:
                raise TaskError('container did not stop')
        ct.status = 'stopped'
        ct.pid = None

    async def _lxc_shutdown(self, user, v):
        ct = self._here(v)
        self._ct_running(ct, 'CT {0} not running'.format(v['vmid']))
        timeout = v['timeout'] if v.get('timeout') is not None else self.shutdown_default_timeout
        if ct.ha_managed:
            return await self._ct_ha(ct, user, 'stopped', timeout)

        async def body():
            self._task_lock(ct)
            await self._ct_powerdown(ct, timeout, bool(v.get('forceStop')))
        return await self._ct_task(ct, 'vzshutdown', user, body)

    async def _lxc_reboot(self, user, v):
        ct = self._here(v)
        # PVE's own wording, which says VM here.
        self._ct_running(ct, 'VM {0} not running'.format(v['vmid']))

        async def body():
            if ct.status != 'running':
                return
            await self._ct_powerdown(
                ct, v['timeout'] if v.get('timeout') is not None else self.shutdown_default_timeout, True)
            await self._start_steps(ct, user, skiplock=True)
        return await self._ct_task(ct, 'vzreboot', user, body)

    async def _lxc_suspend(self, user, v):
        ct = self._here(v)
        self._ct_running(ct, 'CT {0} not running'.format(v['vmid']))

        async def body():
            self._task_lock(ct)
            ct.status = 'stopped'
            ct.pid = None
            ct.checkpoint = True
        return await self._ct_task(ct, 'vzsuspend', user, body)

    async def _lxc_resume(self, user, v):
        ct = self._here(v)
        if ct is not None and ct.status == 'running':
            raise PveError(500, 'CT {0} already running'.format(v['vmid']))
        cmd = "command 'lxc-checkpoint -n {0} -r --foreground -D /var/lib/vz/dump' failed: exit code 1"

        async def body():
            if ct is None or not ct.checkpoint:
                raise TaskError(cmd.format(v['vmid']))
            ct.checkpoint = False
            ct.status = 'running'
            ct.started_at = time.time()
            ct.pid = next(self._ct_pids)
        return await self.task(v['node'], 'vzresume', v['vmid'], user, body)

    # ---------------------------------------------------------- snapshots

    async def _lxc_snapshot_list(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        data = []
        for name, snap in ct.snapshots.items():
            item = {'name': name, 'snaptime': snap.get('snaptime') or 0, 'description': snap.get('description') or ''}
            for key in ('parent', 'snapstate'):
                if snap.get(key):
                    item[key] = snap[key]
            data.append(item)
        current = {'name': 'current', 'digest': ct.digest(), 'running': 1 if ct.status == 'running' else 0,
                   'description': 'You are here!'}
        if ct.config.get('parent'):
            current['parent'] = ct.config['parent']
        data.append(current)
        return data

    async def _lxc_snapshot(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        name = v['snapname']
        for reserved in ('current', 'vzdump'):
            if name == reserved:
                raise PveError(500, "unable to use snapshot name '{0}' (reserved name)".format(name))
        self.need_quorum()

        async def body():
            if ct.template:
                raise TaskError("you can't take a snapshot if it's a template")
            self._task_lock(ct)
            if name in ct.snapshots:
                raise TaskError("snapshot name '{0}' already used".format(name))
            if any(self.storages.get(m['volume'].split(':')[0], {}).get('type') not in SNAPSHOT_STORAGE
                   and m['volume'].split(':')[0] in self.storages for _, m in ct.volumes()):
                raise TaskError('snapshot feature is not available')
            ct.lock = 'snapshot'
            try:
                snap = dict((k, x) for k, x in ct.config.items()
                            if k not in ('lock', 'description') and not k.startswith('unused'))
                snap.update(snapstate='prepare', snaptime=int(time.time()))
                if v.get('description'):
                    snap['description'] = v['description']
                ct.snapshots[name] = snap
                try:
                    await self.ceph_io(ct, [k for k, _ in ct.volumes()])
                    await self.pause(self.ct_secs['snapshot'])
                except TaskError:
                    del ct.snapshots[name]
                    raise
                snap.pop('snapstate')
                ct.config['parent'] = name
            finally:
                ct.lock = None
        return await self._ct_task(ct, 'vzsnapshot', user, body, lock=False)

    async def _lxc_snapshot_delete(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        name = v['snapname']
        self.need_quorum()

        async def body():
            if name not in ct.snapshots:
                raise TaskError("snapshot '{0}' does not exist".format(name))
            self._task_lock(ct)
            ct.lock = 'snapshot-delete'
            try:
                if ct.template:
                    raise TaskError("you can't delete a snapshot if vm is a template")
                ct.snapshots[name]['snapstate'] = 'delete'
                await self.pause(self.ct_secs['delsnapshot'])
                parent = ct.snapshots[name].get('parent')
                del ct.snapshots[name]
                for other in list(ct.snapshots.values()) + [ct.config]:
                    if other.get('parent') == name:
                        if parent:
                            other['parent'] = parent
                        else:
                            other.pop('parent')
            finally:
                ct.lock = None
        return await self._ct_task(ct, 'vzdelsnapshot', user, body, lock=False)

    async def _lxc_rollback(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        name = v['snapname']
        if v.get('start'):
            self.require(user, '/vms/{0}'.format(ct.vmid), 'VM.PowerMgmt')
        self.need_quorum()

        async def body():
            if ct.template:
                raise TaskError("you can't rollback if vm is a template")
            snap = ct.snapshots.get(name)
            if snap is None:
                raise TaskError("snapshot '{0}' does not exist".format(name))
            if snap.get('snapstate'):
                raise TaskError('unable to rollback to incomplete snapshot (snapstate = {0})'.format(
                    snap['snapstate']))
            self._task_lock(ct)
            ct.lock = 'rollback'
            try:
                if ct.status == 'running':
                    ct.status = 'stopped'
                    ct.pid = None
                await self.pause(self.ct_secs['rollback'])
                keep = dict((k, x) for k, x in ct.config.items() if k == 'description' or k.startswith('unused'))
                config = dict((k, x) for k, x in snap.items() if k not in ('snapstate', 'snaptime', 'description'))
                config.update(keep)
                config['parent'] = name
                ct.config = config
                ct.pending = {}
            finally:
                ct.lock = None
            if v.get('start'):
                await self._start_steps(ct, user)
        return await self._ct_task(ct, 'vzrollback', user, body, lock=False)

    async def _lxc_snapshot_config_get(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        snap = ct.snapshots.get(v['snapname'])
        if snap is None:
            raise PveError(500, "snapshot '{0}' does not exist".format(v['snapname']))
        return dict(snap)

    async def _lxc_snapshot_config_put(self, user, v):
        if v.get('description') is None:
            return None
        ct = self._find_ct(v['node'], v['vmid'])
        await self._config_lock(ct)
        try:
            self._ct_check_lock(ct)
            snap = ct.snapshots.get(v['snapname'])
            if snap is None:
                raise PveError(500, "snapshot '{0}' does not exist".format(v['snapname']))
            snap['description'] = v['description']
        finally:
            self.release(ct, 'config')
        return None

    # ------------------------------------------------- clone and template

    async def _lxc_clone(self, user, v):
        node, vmid, newid = v['node'], int(v['vmid']), int(v['newid'])
        pool = v.get('pool')
        if pool and pool not in self.pools:
            raise PveError(403, "Permission check failed (pool '{0}' does not exist)".format(pool))
        target = v.get('target')
        if target == node or target == 'localhost':
            target = None
        if target and target not in self.nodes:
            raise PveError(500, "no such cluster node '{0}'".format(target))
        storage = v.get('storage')
        if storage:
            if storage not in self.storages:
                raise PveError(500, "storage '{0}' does not exist".format(storage))
            if target and not self.storages[storage].get('shared'):
                raise PveError(500, "can't clone to non-shared storage '{0}'".format(storage))
        self.need_quorum()
        src = self._find_ct(node, vmid)
        await self._config_lock(src)
        try:
            self._ct_check_lock(src)
            src.lock = 'disk'
        finally:
            self.release(src, 'config')
        new = None

        def undo():
            if src.lock == 'disk':
                src.lock = None
            if new is not None:
                self._drop(new)
        try:
            self._check_vmid_unused(newid)
            running = src.status == 'running'
            full = v.get('full')
            if full is None:
                full = not src.template
            if storage and not full:
                raise PveError(500, "parameter 'storage' not allowed for linked clones")
            snapname = v.get('snapname')
            if snapname and snapname not in src.snapshots:
                raise PveError(500, "snapshot '{0}' does not exist".format(snapname))
            source = src.snapshots[snapname] if snapname else src.config
            mounts, shared = {}, True
            newconf = {}
            for opt in sorted(source):
                value = source[opt]
                if opt.startswith('unused') or opt in ('snapshots', 'parent', 'snaptime', 'snapstate', 'pending',
                                                       'template', 'lock'):
                    continue
                if opt == 'rootfs' or re.fullmatch(r'mp\d+', opt):
                    mount = parse_mount(value)
                    if mount_type(mount.get('volume', '')) != 'volume':
                        raise PveError(500, "unable to clone mountpoint '{0}' (type {1})".format(
                            opt, mount_type(mount.get('volume', ''))))
                    sid = storage or mount['volume'].split(':')[0]
                    store = self.storages.get(sid)
                    if store is None:
                        raise PveError(500, "storage '{0}' does not exist".format(sid))
                    if not store.get('shared'):
                        shared = False
                    self.require(user, '/storage/' + sid, 'Datastore.AllocateSpace')
                    if full:
                        if running and snapname is None:
                            raise PveError(500, 'Full clone of a running container is only possible from a '
                                                'snapshot')
                    elif not os_base(mount['volume']):
                        raise PveError(500, "Linked clone feature for '{0}' is not available".format(
                            mount['volume']))
                    mounts[opt] = (mount, sid)
                elif re.fullmatch(r'net\d+', opt):
                    props = split_props(value)[1]
                    props['hwaddr'] = random_mac()
                    newconf[opt] = normalise(opt, ','.join('{0}={1}'.format(k, x) for k, x in props.items()))
                    self._check_bridge(user, newconf[opt])
                else:
                    newconf[opt] = value
            if target and not shared:
                raise PveError(500, "can't clone CT to node '{0}' (CT uses local storage)".format(target))
            newconf['lock'] = 'create'
            if v.get('hostname'):
                newconf['hostname'] = v['hostname']
            if v.get('description'):
                newconf['description'] = v['description']
            new = FakeCt(newid, node=node, defaults=False, config=newconf)
            self.cts.append(new)
        except PveError:
            undo()
            raise

        async def body():
            try:
                taken = self._taken_volumes()
                await self.pause(self.ct_secs['clone'])
                for opt in sorted(mounts, key=lambda k: (k != 'rootfs', k)):
                    mount, sid = mounts[opt]
                    mount = dict(mount, volume=self._allocate(newid, sid, taken))
                    new.config[opt] = print_mount(mount, opt == 'rootfs')
                await self.ceph_io(new, list(mounts))
                if pool:
                    self._pool_join(pool, newid)
                new.lock = None
                if target:
                    new.node = target
            except TaskError:
                self._drop(new)
                raise
            finally:
                if src.lock == 'disk':
                    src.lock = None
            return None
        return await self.task(node, 'vzclone', vmid, user, body, vm=new, lock=False, log=[
            'creating a clone of container {0} with ID {1}'.format(vmid, newid)])

    async def _lxc_template(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        await self._config_lock(ct)
        try:
            self._ct_check_lock(ct)
            if ct.snapshots:
                raise PveError(500, 'unable to create template, because CT contains snapshots')
            if ct.template:
                raise PveError(500, "you can't convert a template to a template")
            if ct.status == 'running':
                raise PveError(500, "you can't convert a CT to template if the CT is running")
        finally:
            self.release(ct, 'config')

        async def body():
            await self.pause(self.ct_secs['template'])
            for key, mount in ct.volumes():
                mount['volume'] = to_base(mount['volume'])
                ct.config[key] = print_mount(mount, key == 'rootfs')
            ct.config['template'] = 1
        return await self._ct_task(ct, 'vztemplate', user, body, lock=False)

    # ------------------------------------------------------------ migrate

    async def _lxc_migrate_check(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        self.need_quorum()
        self._ct_check_lock(ct)
        allowed = [n for n in sorted(self.nodes) if n != v['node'] and self.nodes[n].get('online', True)]
        return {'running': 1 if ct.status == 'running' else 0, 'allowed-nodes': allowed, 'not-allowed-nodes': {}}

    async def _lxc_migrate(self, user, v):
        target = v['target']
        if target == v['node']:
            raise PveError(400, 'Parameter verification failed.', {'target': 'target is local node.'})
        self.need_quorum()
        if target not in self.nodes:
            raise PveError(500, "no such cluster node '{0}'".format(target))
        ct = self._find_ct(v['node'], v['vmid'])
        if ct.status == 'running' and not v.get('online') and not v.get('restart'):
            raise PveError(500, "can't migrate running container without --online or --restart")

        async def move():
            running = ct.status == 'running'
            if v.get('online'):
                raise TaskError('lxc live migration is currently not implemented')
            if running and not v.get('restart'):
                raise TaskError('running container can only be migrated in restart mode')
            self._task_lock(ct)
            ct.lock = 'migrate'
            try:
                if running:
                    await self._ct_powerdown(ct, v.get('timeout') or 180, True)
                await self.pause(self.ct_secs['migrate'])
                ct.node = target
                if running:
                    ct.status = 'running'
                    ct.started_at = time.time()
                    ct.pid = next(self._ct_pids)
            finally:
                ct.lock = None
            return 'migration finished successfully'
        if ct.ha_managed:
            async def ha():
                await self.pause(self.ha_delay)
                return await move()
            return await self._ct_task(ct, 'hamigrate', user, ha, lock=False,
                                       log=['Requesting HA migration for CT {0} to node {1}'.format(ct.vmid, target)])
        return await self._ct_task(ct, 'vzmigrate', user, move, lock=False,
                                   log=["starting migration of CT {0} to node '{1}'".format(ct.vmid, target)])

    # ------------------------------------------------------------- resize

    async def _lxc_resize(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        disk = v['disk']
        text = str(v['size'])
        extend = text.startswith('+')
        request = parse_size(text.lstrip('+'))
        if request is None:
            raise PveError(500, 'invalid size string')
        if ct.lock:
            raise PveError(500, 'CT is locked ({0})'.format(ct.lock))
        self._check_modify_perm(user, ct.vmid, None, ct.config, {'disk': disk, 'size': text}, [],
                                ct.config.get('unprivileged'))
        if v.get('digest') and v['digest'] != ct.digest():
            raise PveError(500, 'detected modified configuration - file changed by other user? Try again.')

        def plan():
            value = ct.config.get(disk)
            if value is None:
                raise PveError(500, 'format error\nvolume: property is missing and it is not optional')
            mount = parse_mount(value)
            if mount_type(mount['volume']) != 'volume':
                raise PveError(500, "unable to parse volume ID '{0}'".format(mount['volume']))
            owner = volume_owner(mount['volume'])
            if owner not in (None, ct.vmid):
                raise PveError(500, "can't resize mount point owned by another container ({0})".format(owner))
            sid = mount['volume'].split(':')[0]
            self.require(user, '/storage/' + sid, 'Datastore.AllocateSpace')
            size = parse_size(mount.get('size', '')) or 4 * 1024 ** 3
            new = size + request if extend else request
            if new < size:
                raise PveError(500, 'unable to shrink disk size')
            if new == size:
                raise PveError(500, 'disk is already at specified size')
            return mount, new
        plan()

        async def body():
            try:
                mount, new = plan()
            except PveError as e:
                raise TaskError(e.message) from e
            await self.ceph_io(ct, [disk])
            await self.pause(self.ct_secs['resize'])
            mount['size'] = format_size(new)
            ct.config[disk] = print_mount(mount, disk == 'rootfs')
        return await self._ct_task(ct, 'resize', user, body)

    # --------------------------------------------------------- interfaces

    async def _lxc_interfaces(self, user, v):
        ct = self._find_ct(v['node'], v['vmid'])
        if ct.status != 'running':
            return None
        out = [{'name': 'lo', 'hwaddr': '00:00:00:00:00:00', 'hardware-address': '00:00:00:00:00:00',
                'inet': '127.0.0.1/8', 'inet6': '::1/128',
                'ip-addresses': [{'ip-address-type': 'inet', 'ip-address': '127.0.0.1', 'prefix': 8},
                                 {'ip-address-type': 'inet6', 'ip-address': '::1', 'prefix': 128}]}]
        for key in sorted(k for k in ct.config if re.fullmatch(r'net\d+', k)):
            props = split_props(ct.config[key])[1]
            item = {'name': props.get('name', 'eth0'), 'hwaddr': props.get('hwaddr', ''),
                    'hardware-address': props.get('hwaddr', ''), 'ip-addresses': []}
            for family, field in (('inet', 'ip'), ('inet6', 'ip6')):
                cidr = props.get(field, '')
                if '/' in cidr:
                    address, prefix = cidr.split('/', 1)
                    item[family] = cidr
                    item['ip-addresses'].append({'ip-address-type': family, 'ip-address': address,
                                                 'prefix': int(prefix)})
            out.append(item)
        return out


def os_base(volume):
    """True if the volume is a template's base volume, which linked clones need."""
    return 'base-' in volume or 'basevol-' in volume
