"""QEMU guests: create, destroy, snapshots, clone and template.

Follows qemu-server's PVE/API2/Qemu.pm and pve-guest-common's AbstractConfig.pm. A VM is a FakeVm in
`pve.vms`; its disks are volumes in the storage state (`pve.storages[name]['volumes']`): allocated by create
and clone, renamed to base volumes by template and freed by destroy. Power state, config and pending changes
stay in server.py.
"""

import re
import time
import uuid

from .lxc import SIZE_UNITS, SNAPSHOT_STORAGE, format_size, random_mac, split_props, to_base
from .model import FakeVm, PveError, TaskError
from .routing import StatefulRoutes, die, param_error, split_list
from .storage import _is_file, spec_of

__all__ = ['QemuApi']

# A disk to allocate: [storage:]size in GiB.
NEW_DISK = re.compile(r'^(?:([^/:\s]+):)?(\d+(?:\.\d+)?)$')
DRIVE_KEY = re.compile(r'^(ide[0-3]|sata[0-5]|scsi(?:[0-9]|[12][0-9]|30)|virtio(?:[0-9]|1[0-5])|efidisk0|tpmstate0)$')
# The order PVE picks the boot disk in.
BOOT_PREFIXES = ('ide', 'sata', 'scsi', 'virtio')
# Parameters of the create request that are not config keys.
CREATE_ONLY = ('node', 'vmid', 'archive', 'storage', 'force', 'unique', 'live-restore', 'pool', 'bwlimit', 'start',
               'ha-managed', 'import-working-storage')
# Config keys a snapshot leaves out.
SNAPSHOT_SKIP = ('lock', 'description', 'snapshots', 'snapstate', 'snaptime', 'vmstate', 'digest')
# Config keys a clone does not copy.
CLONE_SKIP = ('snapshots', 'parent', 'snaptime', 'vmstate', 'snapstate', 'runningcpu', 'runningmachine',
              'running-nets-host-mtu', 'lock', 'template')
NET_MODELS = ('e1000', 'e1000-82540em', 'e1000-82544gc', 'e1000-82545em', 'e1000e', 'i82551', 'i82557b', 'i82559er',
              'ne2k_isa', 'ne2k_pci', 'pcnet', 'rtl8139', 'virtio', 'vmxnet3')
# Fixed sizes in KiB: the EFI vars disk (4m) and the TPM state.
FIXED_KIB = {'efidisk0': 528, 'tpmstate0': 4096}
QEMU_VERSION = '10.0.2'


def split_drive(text):
    """(volume, {option: value}) of a drive value."""
    first, props = split_props(text)
    if first is None:
        first = props.pop('file', '')
    return first, props


def join_drive(volume, props):
    """The config value of a drive: the volume, then the options in alphabetical order."""
    return ','.join([volume] + ['{0}={1}'.format(k, props[k]) for k in sorted(props)])


def is_cdrom(volume, props):
    return props.get('media') == 'cdrom' or volume == 'cdrom'


def with_mac(value, fresh=False):
    """A net value as PVE writes it: model=MAC first (a new MAC if none or `fresh`), the rest sorted."""
    model, mac, rest = None, None, []
    for part in str(value).split(','):
        key, _, val = part.partition('=')
        if key in NET_MODELS:
            model, mac = key, val or None
        elif key == 'model':
            model = val
        elif key == 'macaddr':
            mac = val
        elif part:
            rest.append(part)
    if model is None:
        return value
    rest.sort(key=lambda p: p.partition('=')[0])
    return ','.join(['{0}={1}'.format(model, random_mac() if fresh or not mac else mac)] + rest)


def natural(key):
    """Sort key: ide0, ide1, scsi2, scsi10."""
    found = re.fullmatch(r'(\D+)(\d+)', key)
    return (found.group(1), int(found.group(2))) if found else (key, 0)


def drives_of(config, skip_cdrom=False):
    """(key, volume, options) of the drives of a config, in device order."""
    out = []
    for key in sorted(config, key=natural):
        if DRIVE_KEY.match(key):
            volume, props = split_drive(config[key])
            if not (skip_cdrom and is_cdrom(volume, props)):
                out.append((key, volume, props))
    return out


def volume_ref(volume):
    """(storage id, volume name) of a volume id, or (None, volume) for a path or a keyword."""
    if volume.startswith('/') or ':' not in volume:
        return None, volume
    sid, _, name = volume.partition(':')
    return sid, name


def boot_order(config):
    """PVE::QemuServer::get_default_bootdevices: the first disk, the first CD-ROM, the first NIC."""
    found = {}
    for prefix in BOOT_PREFIXES:
        for key, volume, props in drives_of(config):
            if key.startswith(prefix):
                found.setdefault(is_cdrom(volume, props), key)
    order = [found[x] for x in (False, True) if x in found]
    order += sorted((k for k in config if re.fullmatch(r'net\d+', k)), key=natural)[:1]
    return 'order=' + ';'.join(order) if order else None


class QemuApi(StatefulRoutes):
    """Mixin for FakePve: VM create, destroy, snapshots, clone and template."""

    def _routes_qemu(self):
        qemu = '/nodes/{node}/qemu'
        one = qemu + '/{vmid}'
        snap = one + '/snapshot'
        return [('POST', qemu, self._qm_create), ('DELETE', one, self._qm_destroy),
                ('GET', snap, self._qm_snapshot_list), ('POST', snap, self._qm_snapshot),
                ('DELETE', snap + '/{snapname}', self._qm_snapshot_delete),
                ('POST', snap + '/{snapname}/rollback', self._qm_rollback),
                ('GET', snap + '/{snapname}/config', self._qm_snapshot_config_get),
                ('PUT', snap + '/{snapname}/config', self._qm_snapshot_config_put),
                ('POST', one + '/clone', self._qm_clone), ('POST', one + '/template', self._qm_template)]

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _qm_lock(vm, lock):
        vm.lock = lock
        if lock:
            vm.config['lock'] = lock
        else:
            vm.config.pop('lock', None)

    def _qm_taken(self, vmid):
        """True if a guest of either kind holds the id."""
        return self.vm(vmid) is not None or self.guest(vmid) is not None

    def _qm_perm(self, user, vmid, pool, *privs):
        for priv in privs:
            if not (self.allowed(user, '/vms/{0}'.format(vmid), priv)
                    or (pool and self.allowed(user, '/pool/' + pool, priv))):
                raise PveError(403, 'Permission check failed (/vms/{0}, {1})'.format(vmid, priv))

    def _qm_check_pool(self, pool):
        if pool and pool not in self.pools:
            raise PveError(403, "Permission check failed (pool '{0}' does not exist)".format(pool))

    def _qm_image_store(self, sid, user):
        """The storage a disk is allocated on: it exists, the user may allocate there and it takes VM images."""
        self.require(user, '/storage/' + sid, 'Datastore.AllocateSpace')
        store = self._store(sid)
        if 'images' not in split_list(store.get('content')):
            raise param_error(storage="storage '{0}' does not support vm images".format(sid))
        return store

    def _qm_free_name(self, sid, vmid, fmt):
        """The next free vm-<vmid>-disk-<n> of the storage, as find_free_diskname picks it."""
        taken = set()
        for volname in list(self._volumes(sid)):
            found = re.search(r'(?:^|/)(?:vm|base|subvol|basevol)-{0}-disk-(\d+)'.format(vmid), volname)
            if found:
                taken.add(int(found.group(1)))
        n = 0
        while n in taken:
            n += 1
        name = 'vm-{0}-disk-{1}'.format(vmid, n)
        return name if not _is_file(self.storages[sid]) else '{0}.{1}'.format(name, fmt)

    def _qm_alloc(self, sid, vmid, fmt, size, linked_from=None):
        """Allocate a volume of `size` bytes: PVE::Storage::vdisk_alloc. Returns (volume id, format)."""
        store = self.storages[sid]
        if not store.get('active', 1):
            raise die("storage '{0}' is not online".format(sid))
        spec = spec_of(store) or {'format': 'raw'}
        fmt = fmt or store.get('format') or spec['format']
        volname, fmt = self._volume_name(store, vmid, fmt, self._qm_free_name(sid, vmid, fmt))
        if linked_from and _is_file(store):
            volname = '{0}/{1}'.format(linked_from, volname)
        if 'avail' in store:
            if size > store['avail']:
                raise die("unable to write to storage '{0}': No space left on device".format(sid))
            store['avail'] -= size
        store.setdefault('volumes', {})[volname] = {'content': 'images', 'format': fmt, 'size': size, 'vmid': vmid,
                                                    'ctime': int(time.time())}
        return '{0}:{1}'.format(sid, volname), fmt

    def _qm_free(self, volid):
        """PVE::Storage::vdisk_free: forget the volume and give its space back."""
        sid, name = volume_ref(volid)
        store = self.storages.get(sid)
        if store is None:
            return
        vol = store.get('volumes', {}).pop(name, None)
        if vol and 'avail' in store:
            store['avail'] += int(vol.get('size') or 0)

    def _qm_volume(self, volid):
        sid, name = volume_ref(volid)
        return self.storages.get(sid, {}).get('volumes', {}).get(name) if sid else None

    def _qm_rename_volume(self, volid):
        """vdisk_create_base: vm-<id>-disk-<n> becomes base-<id>-disk-<n>; returns the new volume id."""
        sid, name = volume_ref(volid)
        store = self.storages.get(sid)
        new = to_base(name)
        if store is None or new == name:
            return volid
        volumes = store.setdefault('volumes', {})
        if name in volumes:
            volumes[new] = volumes.pop(name)
        return '{0}:{1}'.format(sid, new)

    def _qm_can_snapshot(self, config):
        """has_feature('snapshot'): every disk is on a storage or in a format that snapshots."""
        for _key, volume, _props in drives_of(config, skip_cdrom=True):
            sid, name = volume_ref(volume)
            store = self.storages.get(sid)
            if store is None:
                continue
            if store.get('type') in SNAPSHOT_STORAGE:
                continue
            if not (_is_file(store) and name.endswith('.qcow2')):
                return False
        return True

    # --------------------------------------------------------------- create

    def _qm_check_drive(self, user, vmid, pool, key, value, default):
        """Checks PVE makes of one drive before it forks the create task (check_storage_access and
        check_drive_param)."""
        volume, props = split_drive(value)
        cdrom = is_cdrom(volume, props)
        if not volume or volume in ('none', 'cdrom') or volume.endswith(':cloudinit'):
            return
        found = NEW_DISK.match(volume)
        if found and not cdrom:
            sid = found.group(1) or default
            if not sid:
                raise die('no storage ID specified (and no default storage)')
            self._qm_image_store(sid, user)
            return
        sid, name = volume_ref(volume)
        if sid is None:
            return
        store = self._store(sid)
        vtype, owner, _fmt = self._parse_volname(store, name)
        self._check_access(user, sid, vtype, owner, volume)
        if vtype not in ('images', 'iso'):
            raise param_error(**{key: "content type needs to be 'images' or 'iso'"})
        if vtype == 'iso' and not cdrom:
            raise param_error(**{key: "explicit 'media=cdrom' is required for iso images"})

    def _qm_new_drive(self, vmid, key, value, default):
        """The config value of a drive once its disk is allocated or looked up: (value, volume ids made)."""
        volume, props = split_drive(value)
        props = dict(props)
        found = NEW_DISK.match(volume)
        if not volume or volume in ('none', 'cdrom'):
            props.pop('size', None)
            return join_drive(volume, props), []
        if volume.endswith(':cloudinit'):
            sid = volume_ref(volume)[0] or default
            volid, _ = self._qm_alloc(sid, vmid, props.pop('format', None), 4 * 1024 ** 2)
            props.update(media='cdrom')
            return join_drive(volid, props), [volid]
        if found:
            sid = found.group(1) or default
            kib = FIXED_KIB.get(key)
            size = kib * 1024 if kib else int(float(found.group(2)) * SIZE_UNITS['G'])
            volid, _fmt = self._qm_alloc(sid, vmid, props.pop('format', None), size)
            props['size'] = format_size(size)
            return join_drive(volid, props), [volid]
        sid, name = volume_ref(volume)
        if sid is not None:
            vol = self._volumes(sid).get(name)
            if vol is None:
                raise die('volume {0} does not exist'.format(volume))
            want = props.pop('format', None)
            if want and want != vol.get('format'):
                raise die("drive '{0}' - volume '{1}' - 'format={2}' option different from storage format '{3}'"
                          .format(key, volume, want, vol.get('format')))
            if vol.get('size'):
                props['size'] = format_size(int(vol['size']))
        return join_drive(volume, props), []

    async def _qm_create(self, v, user):
        node, vmid = v['node'], int(v['vmid'])
        self.need_quorum()
        pool, default = v.get('pool'), v.get('storage')
        self._qm_check_pool(pool)
        if default:
            self.require(user, '/storage/' + default, 'Datastore.AllocateSpace')
        if v.get('ha-managed'):
            self.require(user, '/', 'Sys.Console')
        if v.get('start'):
            self._qm_perm(user, vmid, pool, 'VM.PowerMgmt')
        if not (self.allowed(user, '/vms/{0}'.format(vmid), 'VM.Allocate')
                or (pool and self.allowed(user, '/pool/' + pool, 'VM.Allocate'))):
            raise PveError(403, 'Permission check failed')
        if v.get('archive'):
            raise die('unable to restore VM {0} - restoring an archive is not supported'.format(vmid))
        params = dict((k, x) for k, x in v.items() if k not in CREATE_ONLY)
        for key in sorted(params):
            priv = self._config_priv(key)
            if priv == 'root':
                if user != 'root@pam':
                    raise PveError(403, "only root can set '{0}' config".format(key))
            elif key.startswith('ide') and 'media=cdrom' in str(params[key]):
                self._qm_perm(user, vmid, pool, 'VM.Config.CDROM')
            else:
                self._qm_perm(user, vmid, pool, priv)
        for key in sorted(params):
            if DRIVE_KEY.match(key):
                self._qm_check_drive(user, vmid, pool, key, params[key], default)
        for key in params:
            if re.fullmatch(r'net\d+', key):
                params[key] = with_mac(params[key])
        emsg = 'unable to create VM {0} -'.format(vmid)
        if self._qm_taken(vmid):
            other = self.vm(vmid)
            kind, where = ('VM', other) if other else ('CT', self.guest(vmid))
            raise PveError(500, "{0} {1} {2} already exists on node '{3}'".format(emsg, kind, vmid, where.node))
        vm = FakeVm(vmid, params.get('name') or 'VM {0}'.format(vmid), node=node)
        vm.config.pop('name', None)
        self._qm_lock(vm, 'create')
        self.vms.append(vm)
        self.nodes.setdefault(node, {'online': True})
        made = []

        async def body():
            conf = dict((k, x) for k, x in params.items() if not DRIVE_KEY.match(k))
            try:
                for key in sorted(k for k in params if DRIVE_KEY.match(k)):
                    conf[key], volids = self._qm_new_drive(vmid, key, params[key], default)
                    made.extend(volids)
                conf['meta'] = 'creation-qemu={0},ctime={1}'.format(QEMU_VERSION, int(time.time()))
                if not conf.get('boot'):
                    order = boot_order(conf)
                    if order:
                        conf['boot'] = order
                conf.setdefault('smbios1', 'uuid=' + str(uuid.uuid4()))
                if str(conf.get('vmgenid', '1')) == '1':
                    conf['vmgenid'] = str(uuid.uuid4())
                if conf.get('tags'):
                    conf['tags'] = ';'.join(sorted(set(t.lower() for t in re.split(r'[;, ]+', str(conf['tags'])) if t)))
                vm.config = conf
                await self.ceph_io(vm)
            except (PveError, TaskError) as e:
                for volid in made:
                    self._qm_free(volid)
                if vm in self.vms:
                    self.vms.remove(vm)
                raise TaskError('{0} {1}'.format(emsg, getattr(e, 'message', None) or str(e))) from e
            vm.name = conf.get('name') or 'VM {0}'.format(vmid)
            self._qm_lock(vm, None)
            if pool:
                self._pool_join(pool, vmid)
            if v.get('ha-managed'):
                vm.ha_state = 'started' if v.get('start') else 'stopped'
            if v.get('start'):
                vm.status = vm.qmpstatus = 'running'
                vm.started_at = time.time()
            return None
        return await self.task(node, 'qmcreate', vmid, user, body, vm=vm)

    # -------------------------------------------------------------- destroy

    def _qm_check_protection(self, vm, message):
        if vm.config.get('protection') in (1, '1', True):
            raise PveError(500, '{0} - protection mode enabled'.format(message))

    async def _qm_destroy(self, v, user):
        vm = self.find(v['node'], v['vmid'])
        vmid = vm.vmid
        if v.get('skiplock') and user != 'root@pam':
            raise param_error(skiplock='Only root may use this option.')
        self._qm_check_protection(vm, "can't remove VM {0}".format(vmid))
        if not v.get('purge') and vm.ha_managed:
            raise PveError(500, 'unable to remove VM {0} - used in HA resources and purge parameter not set.'
                           .format(vmid))
        if vm.status == 'running':
            raise PveError(500, 'VM {0} is running - destroy failed'.format(vmid))

        async def body():
            if vm.lock and not v.get('skiplock'):
                raise TaskError('VM is locked ({0})'.format(vm.lock))
            self._qm_lock(vm, 'destroyed')
            for _key, volume, _props in drives_of(vm.config):
                self._qm_free(volume)
            for key in sorted(k for k in vm.config if re.fullmatch(r'unused\d+', k)):
                self._qm_free(split_drive(vm.config[key])[0])
            for snap in vm.snapshots.values():
                for _key, volume, _props in drives_of(snap):
                    self._qm_free(volume)
            if v.get('destroy-unreferenced-disks'):
                for sid, store in self.storages.items():
                    for name, vol in list(store.get('volumes', {}).items()):
                        if vol.get('vmid') == vmid and vol.get('content') == 'images':
                            self._qm_free('{0}:{1}'.format(sid, name))
            if vm in self.vms:
                self.vms.remove(vm)
            self._pool_leave(vmid)
            self._fw()['guests'].pop(vmid, None)
            if self.acl:
                for user_id, entries in self.acl.items():
                    self.acl[user_id] = [e for e in entries if e[0] != '/vms/{0}'.format(vmid)]
            if v.get('purge'):
                lines = ['purging VM {0} from related configurations..'.format(vmid)]
                if vm.ha_managed:
                    lines.append('NOTE: removed VM {0} from HA resource configuration.'.format(vmid))
                return '\n'.join(lines)
            return None
        return await self.task(vm.node, 'qmdestroy', vmid, user, body, vm=vm)

    # ------------------------------------------------------------ snapshots

    async def _qm_snapshot_list(self, v, user):
        vm = self.find(v['node'], v['vmid'])
        data = []
        for name, snap in vm.snapshots.items():
            item = {'name': name, 'snaptime': snap.get('snaptime') or 0, 'vmstate': 1 if snap.get('vmstate') else 0,
                    'description': snap.get('description') or ''}
            for key in ('parent', 'snapstate'):
                if snap.get(key):
                    item[key] = snap[key]
            data.append(item)
        current = {'name': 'current', 'digest': vm.digest(), 'running': 1 if vm.status == 'running' else 0,
                   'description': 'You are here!'}
        if vm.config.get('parent'):
            current['parent'] = vm.config['parent']
        data.append(current)
        return data

    async def _qm_snapshot(self, v, user):
        vm = self.find(v['node'], v['vmid'])
        name = v['snapname']
        if name == 'current':
            raise die("unable to use snapshot name 'current' (reserved name)")
        if name.lower() == 'pending':
            raise die("unable to use snapshot name 'pending' (reserved name)")
        self.need_quorum()

        async def body():
            if vm.template:
                raise TaskError("you can't take a snapshot if it's a template")
            if vm.lock:
                raise TaskError('VM is locked ({0})'.format(vm.lock))
            if name in vm.snapshots:
                raise TaskError("snapshot name '{0}' already used".format(name))
            if not self._qm_can_snapshot(vm.config):
                raise TaskError('snapshot feature is not available')
            self._qm_lock(vm, 'snapshot')
            try:
                snap = dict((k, x) for k, x in vm.config.items()
                            if k not in SNAPSHOT_SKIP and not k.startswith('unused'))
                snap.update(snapstate='prepare', snaptime=int(time.time()))
                if v.get('description'):
                    snap['description'] = v['description']
                if v.get('vmstate') and vm.status == 'running':
                    snap['vmstate'] = 'local:vm-{0}-state-{1}'.format(vm.vmid, name)
                vm.snapshots[name] = snap
                try:
                    await self.ceph_io(vm, [k for k, _, _ in drives_of(vm.config)])
                except TaskError:
                    del vm.snapshots[name]
                    raise
                snap.pop('snapstate')
                vm.config['parent'] = name
            finally:
                self._qm_lock(vm, None)
        return await self.task(vm.node, 'qmsnapshot', vm.vmid, user, body, vm=vm, lock=False)

    async def _qm_snapshot_delete(self, v, user):
        vm = self.find(v['node'], v['vmid'])
        name = v['snapname']
        self.need_quorum()

        async def body():
            if name not in vm.snapshots:
                raise TaskError("snapshot '{0}' does not exist".format(name))
            if vm.lock:
                raise TaskError('VM is locked ({0})'.format(vm.lock))
            self._qm_lock(vm, 'snapshot-delete')
            try:
                if vm.template:
                    raise TaskError("you can't delete a snapshot if vm is a template")
                vm.snapshots[name]['snapstate'] = 'delete'
                parent = vm.snapshots[name].get('parent')
                del vm.snapshots[name]
                for other in list(vm.snapshots.values()) + [vm.config]:
                    if other.get('parent') == name:
                        if parent:
                            other['parent'] = parent
                        else:
                            other.pop('parent')
            finally:
                self._qm_lock(vm, None)
        return await self.task(vm.node, 'qmdelsnapshot', vm.vmid, user, body, vm=vm, lock=False)

    async def _qm_rollback(self, v, user):
        vm = self.find(v['node'], v['vmid'])
        name = v['snapname']
        if v.get('start'):
            self.require(user, '/vms/{0}'.format(vm.vmid), 'VM.PowerMgmt')
        self.need_quorum()

        async def body():
            if vm.template:
                raise TaskError("you can't rollback if vm is a template")
            snap = vm.snapshots.get(name)
            if snap is None:
                raise TaskError("snapshot '{0}' does not exist".format(name))
            if snap.get('snapstate'):
                raise TaskError('unable to rollback to incomplete snapshot (snapstate = {0})'.format(
                    snap['snapstate']))
            if vm.lock:
                raise TaskError('VM is locked ({0})'.format(vm.lock))
            self._qm_lock(vm, 'rollback')
            try:
                vm.status = vm.qmpstatus = 'stopped'
                keep = dict((k, x) for k, x in vm.config.items() if k == 'description' or k.startswith('unused'))
                config = dict((k, x) for k, x in snap.items() if k not in ('snapstate', 'snaptime', 'description'))
                config.update(keep)
                config['parent'] = name
                vm.config = config
                vm.pending = {}
            finally:
                self._qm_lock(vm, None)
            if v.get('start'):
                vm.status = vm.qmpstatus = 'running'
                vm.started_at = time.time()
        return await self.task(vm.node, 'qmrollback', vm.vmid, user, body, vm=vm, lock=False)

    async def _qm_snapshot_config_get(self, v, user):
        vm = self.find(v['node'], v['vmid'])
        snap = vm.snapshots.get(v['snapname'])
        if snap is None:
            raise die("snapshot '{0}' does not exist".format(v['snapname']))
        return dict(snap, digest=vm.digest())

    async def _qm_snapshot_config_put(self, v, user):
        vm = self.find(v['node'], v['vmid'])
        snap = vm.snapshots.get(v['snapname'])
        if snap is None:
            raise die("snapshot '{0}' does not exist".format(v['snapname']))
        if v.get('description') is not None:
            snap['description'] = v['description']
        return None

    # ------------------------------------------------------ clone, template

    async def _qm_clone(self, v, user):
        node, vmid, newid = v['node'], int(v['vmid']), int(v['newid'])
        pool, storage, fmt, target = v.get('pool'), v.get('storage'), v.get('format'), v.get('target')
        self._qm_check_pool(pool)
        self._qm_perm(user, newid, pool, 'VM.Allocate')
        if target in (node, 'localhost'):
            target = None
        if target and target not in self.nodes:
            raise die("no such cluster node '{0}'".format(target))
        if storage:
            store = self._store(storage)
            if 'images' not in split_list(store.get('content')):
                raise param_error(storage="storage '{0}' does not support vm images".format(storage))
            if target and not store.get('shared'):
                raise die("can't clone to non-shared storage '{0}'".format(storage))
        self.need_quorum()
        src = self.find(node, vmid)
        self._check_lock(src)
        snapname = v.get('snapname')
        if snapname and snapname not in src.snapshots:
            raise die("snapshot '{0}' does not exist".format(snapname))
        full = v.get('full')
        if full is None:
            full = not src.template
        if storage and not full:
            raise die("parameter 'storage' not allowed for linked clones")
        if fmt and not full:
            raise die("parameter 'format' not allowed for linked clones")
        old = src.snapshots[snapname] if snapname else src.config
        if self._qm_taken(newid):
            raise die('unable to create VM {0}: config file already exists'.format(newid))
        newconf, plan = {}, {}
        for opt in sorted(old):
            value = old[opt]
            if opt in CLONE_SKIP or re.fullmatch(r'unused\d+', opt):
                continue
            if re.fullmatch(r'net\d+', opt):
                newconf[opt] = with_mac(value, fresh=True)
            elif DRIVE_KEY.match(opt):
                volume, props = split_drive(value)
                if is_cdrom(volume, props) or volume_ref(volume)[0] is None:
                    newconf[opt] = value
                    continue
                if volume_ref(volume)[0] not in self.storages:
                    raise die("storage '{0}' does not exist".format(volume_ref(volume)[0]))
                if not full and 'base-' not in volume:
                    raise die("Linked clone feature is not supported for {0}'{1}' ({2})".format(
                        'a snapshot of ' if snapname else '', volume, opt))
                plan[opt] = (volume, props)
            else:
                newconf[opt] = value
        for volume, _props in plan.values():
            self.require(user, '/storage/' + (storage or volume_ref(volume)[0]), 'Datastore.AllocateSpace')
        new = FakeVm(newid, v.get('name') or 'Copy-of-VM-{0}'.format(src.config.get('name') or vmid), node=node)
        new.config = dict(newconf, name=new.name)
        if v.get('description'):
            new.config['description'] = v['description']
        self._qm_lock(new, 'clone')
        self.vms.append(new)
        made = []

        async def body():
            try:
                for opt in sorted(plan):
                    volume, props = plan[opt]
                    sid, name = volume_ref(volume)
                    vol = self._volumes(sid).get(name) or {}
                    size = int(vol.get('size') or 0)
                    dest = storage or sid
                    kind = fmt or (vol.get('format') if dest == sid else None)
                    if full:
                        volid, _ = self._qm_alloc(dest, newid, kind, size)
                    else:
                        base = name.split('/')[-1]
                        volid, _ = self._qm_alloc(dest, newid, vol.get('format'), size,
                                                  linked_from='{0}/{1}'.format(vol.get('vmid', vmid), base))
                    made.append(volid)
                    new.config[opt] = join_drive(volid, dict(props, **({'size': format_size(size)} if size else {})))
                smbios = split_props('x,' + str(new.config.get('smbios1', '')))[1]
                smbios['uuid'] = str(uuid.uuid4())
                new.config['smbios1'] = ','.join('{0}={1}'.format(k, smbios[k]) for k in sorted(smbios))
                if new.config.get('vmgenid'):
                    new.config['vmgenid'] = str(uuid.uuid4())
                await self.ceph_io(new)
            except (PveError, TaskError) as e:
                for volid in made:
                    self._qm_free(volid)
                if new in self.vms:
                    self.vms.remove(new)
                raise TaskError('clone failed: {0}'.format(getattr(e, 'message', None) or str(e))) from e
            self._qm_lock(new, None)
            if pool:
                self._pool_join(pool, newid)
            if target:
                new.node = target
            return None
        return await self.task(node, 'qmclone', vmid, user, body, vm=new, lock=False, log=[
            'creating a clone of VM {0} with ID {1}'.format(vmid, newid)])

    async def _qm_template(self, v, user):
        vm = self.find(v['node'], v['vmid'])
        disk = v.get('disk')
        self._check_lock(vm)
        if vm.snapshots:
            raise die('unable to create template, because VM contains snapshots')
        if vm.template and not disk:
            raise die("you can't convert a template to a template")
        if vm.status == 'running':
            raise die("you can't convert a VM to template if VM is running")

        async def body():
            vm.template = True
            vm.config['template'] = 1
            for key, volume, props in drives_of(vm.config, skip_cdrom=True):
                if disk and key != disk:
                    continue
                vm.config[key] = join_drive(self._qm_rename_volume(volume), props)
        return await self.task(vm.node, 'qmtemplate', vm.vmid, user, body, vm=vm, lock=False)
