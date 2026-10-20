"""Storage: the configuration, the per-node status and the volumes.

Follows pve-storage (PVE/API2/Storage/Config.pm, Status.pm, Content.pm and the
plugins' option tables). `pve.storages` holds one dict per storage: the keys
that are not in INTERNAL are the storage.cfg options, as PVE returns them.
"""

import re
import time

from .model import PveError, TaskError
from .routing import StatefulRoutes, check_digest, die, param_error, sha1, split_list

GIB = 1024 ** 3
# Keys of a pve.storages entry that are the fake's state, not storage.cfg options.
INTERNAL = ('files', 'avail', 'active', 'volumes', 'total')
# Kept apart from storage.cfg by PVE (extract_sensitive_params), so never read back.
SENSITIVE = ('password', 'keyring', 'encryption-key', 'master-pubkey')
FORMAT_EXT = ('raw', 'qcow2', 'vmdk', 'subvol')
STORAGE_ID = re.compile(r'^([a-z][a-z0-9\-\_\.]*[a-z0-9]):(.+)$', re.I)
NAME_DIR = re.compile(r'^((vm-|base-|subvol-)(\d+)-[^/\s]+\.(raw|qcow2|vmdk|subvol))$')
NAME_ANY = re.compile(r'^((base-)?[^/\s]+\.(raw|qcow2|vmdk|subvol))$')


def _plugin(options, content, default, formats=None, default_format='raw', files=False):
    """A storage type: options ('name' optional, 'name!' required and fixed, 'name^' optional and fixed)."""
    opts = {}
    for token in options.split():
        opts[token.rstrip('!^')] = (not token.endswith('!'), token[-1] in '!^')
    return {'options': opts, 'content': content.split(), 'default': default, 'formats': formats.split() if formats
            else None, 'format': default_format, 'files': files}


_FILE_COMMON = ('content-dirs nodes disable prune-backups max-protected-backups content format mkdir '
                'create-base-path create-subdirs bwlimit preallocation snapshot-as-volume-chain^')
_FILE_CONTENT = 'images rootdir vztmpl iso backup snippets import'

# From the plugins' options() and plugindata() in pve-storage/src/PVE/Storage/*.pm.
TYPES = {
    'dir': _plugin('path! shared is_mountpoint ' + _FILE_COMMON, _FILE_CONTENT + ' none', 'images,rootdir',
                   'raw qcow2 vmdk subvol', files=True),
    'nfs': _plugin('path! server! export! options ' + _FILE_COMMON, _FILE_CONTENT, 'images',
                   'raw qcow2 vmdk', files=True),
    'cifs': _plugin('path! server! share! subdir username password domain smbversion options ' + _FILE_COMMON,
                    _FILE_CONTENT, 'images', 'raw qcow2 vmdk', files=True),
    'cephfs': _plugin('path! monhost subdir options username fuse keyring fs-name content-dirs nodes disable '
                      'content format mkdir create-base-path create-subdirs bwlimit prune-backups '
                      'max-protected-backups', 'vztmpl iso backup snippets import', 'backup', files=True),
    'btrfs': _plugin('path! nodes shared disable prune-backups max-protected-backups content format is_mountpoint '
                     'nocow mkdir create-base-path create-subdirs preallocation',
                     _FILE_CONTENT + ' none', 'images,rootdir', 'raw subvol', files=True),
    'lvm': _plugin('vgname! nodes shared disable saferemove on-volume-remove saferemove-stepsize '
                   'saferemove_throughput content base^ tagged_only bwlimit snapshot-as-volume-chain',
                   'images rootdir', 'images', 'raw qcow2'),
    'lvmthin': _plugin('thinpool! vgname! nodes disable content bwlimit', 'images rootdir', 'images,rootdir'),
    'zfspool': _plugin('pool! blocksize sparse nodes disable content bwlimit mountpoint', 'images rootdir',
                       'images,rootdir', 'raw subvol'),
    'rbd': _plugin('nodes disable monhost pool data-pool namespace username content krbd keyring bwlimit',
                   'images rootdir', 'images'),
    'iscsi': _plugin('portal! target! nodes disable content bwlimit', 'images none', 'images'),
    'iscsidirect': _plugin('portal! target! nodes disable content bwlimit', 'images none', 'images'),
    'zfs': _plugin('nodes disable portal! target! pool! blocksize! iscsiprovider! nowritecache sparse comstar_hg '
                   'comstar_tg lio_tpg content bwlimit zfs-base-path', 'images', 'images'),
    'pbs': _plugin('server! datastore! namespace port nodes disable content username password encryption-key '
                   'master-pubkey prune-backups max-protected-backups fingerprint', 'backup none', 'backup'),
}
for _name, _spec in TYPES.items():
    _spec['name'] = _name
# Block storages name their volumes vm-<vmid>-...; one group captures the vmid.
BLOCK_NAME = {
    'lvm': (r'^(?:vm|base)-(\d+)-\S+$', 'lvm'), 'lvmthin': (r'^(?:vm|base)-(\d+)-\S+$', 'lvm'),
    'rbd': (r'^(?:base|vm|subvol)-(\d+)-\S+$', 'rbd'), 'zfspool': (r'^(?:base|basevol|vm|subvol)-(\d+)-\S+$', 'zfs'),
    'zfs': (r'^(?:vm|base)-(\d+)-\S+$', 'zfs'),
}
ISO_EXT = r'\.(?:iso|img)'
TEMPLATE_EXT = r'\.tar\.(?:gz|xz|zst|bz2)'
BACKUP_EXT = r'\.(?:vma|tar)(?:\.(?:gz|lzo|zst))?'


def spec_of(store):
    return TYPES.get(store.get('type'))


def _is_file(store):
    spec = spec_of(store)
    return bool(spec and spec['files'])


def parse_size(text):
    """A content POST size ('10G', '512M', '1048576' kilobytes) in KiB."""
    match = re.match(r'^(\d+)([MG]?)$', str(text))
    if not match:
        raise param_error(size="unable to parse size '{0}'".format(text))
    return int(match.group(1)) * {'': 1, 'M': 1024, 'G': 1024 * 1024}[match.group(2)]


def parse_name_dir(name):
    """PVE::Storage::Plugin::parse_name_dir: (name, format) or die."""
    found = NAME_DIR.match(name)
    if found:
        return found.group(1), found.group(4)
    if re.match(r'^snap-.*\.qcow2$', name):
        raise die("'{0}' is a snapshot filename, not a volume!".format(name))
    found = NAME_ANY.match(name)
    if found:
        return found.group(1), found.group(3)
    raise die("unable to parse volume filename '{0}'".format(name))


class StorageApi(StatefulRoutes):
    """Mixin of FakePve: storage.cfg, node storage status and content."""

    def _routes_storage(self):
        node = '/nodes/{node}/storage'
        content = node + '/{storage}/content'
        return [('GET', '/storage', self._sc_list), ('POST', '/storage', self._sc_create),
                ('GET', '/storage/{storage}', self._sc_read), ('PUT', '/storage/{storage}', self._sc_update),
                ('DELETE', '/storage/{storage}', self._sc_delete),
                ('GET', node, self._ns_list), ('GET', node + '/{storage}/status', self._ns_status),
                ('GET', content, self._content_list), ('POST', content, self._content_create),
                ('GET', content + '/{volume}', self._content_info), ('PUT', content + '/{volume}', self._content_put),
                ('DELETE', content + '/{volume}', self._content_delete)]

    # ---------------------------------------------------------------- config

    def _storage_digest(self):
        """The digest of storage.cfg: it changes with any storage option."""
        view = dict((name, self._options_of(store)) for name, store in sorted(self.storages.items()))
        return sha1(repr(sorted((n, sorted((k, str(v)) for k, v in o.items())) for n, o in view.items())))

    @staticmethod
    def _options_of(store):
        return dict((k, v) for k, v in store.items() if k not in INTERNAL)

    def storage_config(self, name):
        """The storage as GET /storage/{storage} shows it."""
        cfg = self._options_of(self.storages[name])
        cfg.setdefault('content', '')
        cfg['storage'] = name
        cfg['digest'] = self._storage_digest()
        return cfg

    def _store(self, name):
        store = self.storages.get(name)
        if store is None:
            raise die("storage '{0}' does not exist".format(name))
        return store

    def _can_audit(self, user, name):
        return self.allowed(user, '/storage/' + name, 'Datastore.Audit') or \
            self.allowed(user, '/storage/' + name, 'Datastore.AllocateSpace')

    async def _sc_list(self, v, user):
        return [self.storage_config(name) for name in sorted(self.storages)
                if self._can_audit(user, name) and v.get('type') in (None, self.storages[name].get('type', 'dir'))]

    async def _sc_read(self, v, user):
        self._store(v['storage'])
        return self.storage_config(v['storage'])

    @staticmethod
    def _decode_content(spec, value):
        """Plugin::decode_value for `content`: unknown types are dropped (PVE warns), none stands alone."""
        valid = spec['content']
        items = [c for c in split_list(value) if c in valid]
        if 'none' in items and len(items) > 1:
            raise die("unable to combine 'none' with other content types")
        if not items and 'none' not in valid:
            raise die("storage does not support content type 'none'")
        return ','.join(items) if items else 'none'

    def _check_options(self, sid, spec, params, create):
        """SectionConfig::check_config for the type; returns the cleaned options."""
        opts = dict(params)
        if create and spec['name'] in ('nfs', 'cifs', 'cephfs') and not opts.get('path'):
            opts['path'] = '/mnt/pve/' + sid
        for key in sorted(opts):
            if key not in spec['options']:
                raise die("unexpected property '{0}'".format(key))
            if not create and spec['options'][key][1]:
                raise die("can't change value of fixed parameter '{0}'".format(key))
        if create:
            for key, (optional, _fixed) in sorted(spec['options'].items()):
                if not optional and opts.get(key) is None:
                    raise die("missing value for required option '{0}'".format(key))
        if 'content' in opts:
            opts['content'] = self._decode_content(spec, opts['content'])
        return opts

    async def _sc_create(self, v, user):
        kind, sid = v['type'], v['storage']
        params = dict((k, x) for k, x in v.items() if k not in ('type', 'storage', 'node'))
        if not params.get('nodes'):
            params.pop('nodes', None)
        spec = TYPES.get(kind)
        for key in SENSITIVE:
            if spec is None or key in spec['options']:
                params.pop(key, None)
        if spec:
            params = self._check_options(sid, spec, params, True)
            if kind == 'dir' and not re.match(r'^/[-/a-zA-Z0-9_.@]+$', params['path']):
                raise die('illegal path for directory storage: {0}'.format(params['path']))
        if sid in self.storages:
            raise die("create storage failed: storage ID '{0}' already defined".format(sid))
        store = {'type': kind, 'active': 1, 'files': set(), 'volumes': {}}
        if spec:
            store['content'] = spec['default']
        store.update(params)
        if kind == 'rbd' and self.ceph['down']:
            store['active'] = 0
        self.storages[sid] = store
        return {'storage': sid, 'type': kind}

    async def _sc_update(self, v, user):
        sid = v['storage']
        fail = 'update storage failed: '
        try:
            check_digest(self._storage_digest(), v.get('digest'))
        except PveError as e:
            raise die(fail + e.message) from e
        store = self.storages.get(sid)
        if store is None:
            raise die(fail + "storage '{0}' does not exist".format(sid))
        deletes = split_list(v.get('delete'))
        params = dict((k, x) for k, x in v.items() if k not in ('storage', 'digest', 'delete', 'node'))
        spec = spec_of(store)
        for key in SENSITIVE:
            if spec is None or key in spec['options']:
                params.pop(key, None)
        try:
            if spec:
                params = self._check_options(sid, spec, params, False)
            for key in deletes:
                if spec:
                    if key not in spec['options']:
                        raise die("no such option '{0}'".format(key))
                    if not spec['options'][key][0]:
                        raise die("unable to delete required option '{0}'".format(key))
                    if spec['options'][key][1]:
                        raise die("unable to delete fixed option '{0}'".format(key))
                if key in params:
                    raise die("cannot set and delete property '{0}' at the same time!".format(key))
        except PveError as e:
            raise die(fail + e.message) from e
        for key in deletes:
            store.pop(key, None)
        store.update(params)
        if spec and 'content' not in store:
            store['content'] = spec['default']
        return {'storage': sid, 'type': store.get('type', 'dir')}

    async def _sc_delete(self, v, user):
        sid = v['storage']
        if sid not in self.storages:
            raise die("delete storage failed: storage '{0}' does not exist".format(sid))
        for other in self.storages.values():
            if str(other.get('base', '')).split(':')[0] == sid:
                raise die("delete storage failed: can't remove storage - storage is used as base of another storage")
        del self.storages[sid]
        for meta in getattr(self, 'pool_info', {}).values():
            meta['storage'].discard(sid)
        if self.acl:
            for user_id, entries in self.acl.items():
                self.acl[user_id] = [e for e in entries if e[0] != '/storage/' + sid]

    # ------------------------------------------------------------ node status

    def _storage_enabled(self, name, node):
        """PVE::Storage::storage_check_enabled: not disabled, and configured for the node."""
        store = self.storages[name]
        nodes = split_list(store.get('nodes'))
        return not store.get('disable') and (not nodes or node in nodes)

    def _storage_nodes(self, name):
        """The nodes the storage is enabled on."""
        return [n for n in sorted(self.nodes) if self._storage_enabled(name, n)]

    def _check_enabled(self, name, node):
        store = self._store(name)
        if store.get('disable'):
            raise die("storage '{0}' is disabled".format(name))
        nodes = split_list(store.get('nodes'))
        if nodes and node not in nodes:
            raise die("storage '{0}' is not available on node '{1}'".format(name, node))
        return store

    def _active_store(self, name, node):
        """The store, once PVE could activate it: exists, enabled here, reachable, online."""
        store = self._check_enabled(name, node)
        if store.get('type') == 'rbd' and self.ceph['down']:
            raise die('rbd error: rbd: listing images failed: (110) Connection timed out')
        if not store.get('active', 1):
            raise die("storage '{0}' is not online".format(name))
        return store

    def _space(self, store):
        """(total, used, avail) in bytes; `used` is what the stored volumes add up to."""
        used = sum(int(vol.get('size') or 0) for vol in store.get('volumes', {}).values())
        if 'avail' in store:
            return store.get('total', store['avail'] + used), used, store['avail']
        total = store.get('total', 100 * GIB)
        return total, used, max(total - used, 0)

    def _status_item(self, name, node, formats=False):
        store = self.storages[name]
        enabled = self._storage_enabled(name, node)
        active = 1 if enabled and store.get('active', 1) else 0
        total, used, avail = self._space(store) if active else (0, 0, 0)
        item = {'type': store.get('type', 'dir'), 'content': store.get('content', ''), 'enabled': 1 if enabled else 0,
                'active': active, 'shared': 1 if store.get('shared') else 0, 'total': total, 'used': used,
                'avail': avail}
        if formats:
            spec = spec_of(store)
            supported = sorted(spec['formats']) if spec and spec['formats'] else ['raw']
            item['formats'] = {'supported': supported, 'default': store.get('format') or (spec or {}).get(
                'format', 'raw')}
        return item

    async def _ns_list(self, v, user):
        node = v['node']
        wanted = split_list(v.get('content'))
        info = {}
        for name, store in self.storages.items():
            enabled = self._storage_enabled(name, node)
            if wanted and (not enabled or not any(c in split_list(store.get('content')) for c in wanted)):
                continue
            info[name] = self._status_item(name, node, v.get('format'))
        if v.get('storage') and v['storage'] not in info:
            raise param_error(storage='No such storage.')
        out = []
        for name in sorted(info):
            data = info[name]
            if not self._can_audit(user, name) or v.get('storage', name) != name:
                continue
            if v.get('enabled') and self.storages[name].get('disable'):
                continue
            target = v.get('target')
            if target and target != node:
                if not (self.storages[name].get('shared') and self._storage_enabled(name, node)
                        and self._storage_enabled(name, target)):
                    continue
            data = dict(data, storage=name)
            if data['total']:
                data['used_fraction'] = data['used'] / data['total']
            out.append(data)
        return out

    async def _ns_status(self, v, user):
        if v['storage'] not in self.storages:
            raise param_error(storage='No such storage.')
        return self._status_item(v['storage'], v['node'])

    def _storage_resource(self, node, name):
        """The /cluster/resources entry of a storage on a node, or None if it is not enabled there."""
        store = self.storages[name]
        if not self._storage_enabled(name, node):
            return None
        item = {'id': 'storage/{0}/{1}'.format(node, name), 'type': 'storage', 'node': node, 'storage': name,
                'status': 'available' if store.get('active') else 'unknown', 'plugintype': store.get('type', 'dir'),
                'content': store.get('content', ''), 'shared': 1 if store.get('shared') else 0,
                'disk': 0, 'maxdisk': 100 * 1024 ** 3}
        pool = self._pool_of_storage(name) if hasattr(self, '_pool_of_storage') else None
        if pool:
            item['pool'] = pool
        return item

    # --------------------------------------------------------------- volumes

    def _base_path(self, name):
        store = self.storages[name]
        return store.get('path') or ('/var/lib/vz' if name == 'local' else '/mnt/pve/' + name)

    @staticmethod
    def _guest_volumes(guests, name):
        """Volumes the guests' configs reference on this storage: {volname: (vmid, content, size)}."""
        out = {}
        for guest in guests:
            cfg = getattr(guest, 'config', {})
            for key, value in cfg.items():
                base = key.rstrip('0123456789')
                if base not in ('ide', 'sata', 'scsi', 'virtio', 'efidisk', 'tpmstate', 'unused', 'rootfs', 'mp'):
                    continue
                parts = str(value).split(',')
                if not parts[0].startswith(name + ':'):
                    continue
                volname = parts[0][len(name) + 1:]
                if volname.startswith(('iso/', 'vztmpl/', 'snippets/')) or not volname:
                    continue
                size = 0
                for part in parts[1:]:
                    if part.startswith('size='):
                        size = _bytes(part[5:])
                out[volname] = (guest.vmid, 'rootdir' if base in ('rootfs', 'mp') else 'images', size)
        return out

    def _guests(self):
        return list(self.vms) + list(getattr(self, 'cts', []))

    def _volumes(self, name):
        """Everything on the storage: allocated volumes, uploaded files and what guest configs reference."""
        store = self.storages[name]
        out = {}
        for fname in sorted(store['files']):
            out['iso/' + fname] = {'content': 'iso', 'format': 'iso', 'size': 0, 'ctime': 0}
        for volname, vol in store.get('volumes', {}).items():
            out[volname] = vol
        for volname, (vmid, content, size) in self._guest_volumes(self._guests(), name).items():
            if volname not in out:
                out[volname] = {'content': content, 'format': self._ext_format(volname), 'size': size, 'vmid': vmid,
                                'ctime': 0}
        return out

    @staticmethod
    def _ext_format(volname):
        ext = volname.rsplit('.', 1)[-1] if '.' in volname else ''
        return ext if ext in FORMAT_EXT else 'raw'

    def _parse_volname(self, store, volname):
        """(vtype, vmid or None, format) of a volume name, or PVE's die."""
        kind = store.get('type', 'dir')
        if kind in BLOCK_NAME:
            pattern, label = BLOCK_NAME[kind]
            found = re.match(pattern, volname)
            if not found:
                raise die("unable to parse {0} volume name '{1}'".format(label, volname))
            return 'images', int(found.group(1)), 'raw'
        if not _is_file(store):
            raise die("unable to parse volume name '{0}'".format(volname))
        found = re.match(r'^(\d+)/(\S+)$', volname)
        if found:
            _name, fmt = parse_name_dir(found.group(2))
            return 'images', int(found.group(1)), fmt
        for prefix, pattern, vtype in (('iso/', r'^iso/[^/]+' + ISO_EXT + '$', 'iso'),
                                       ('vztmpl/', r'^vztmpl/[^/]+' + TEMPLATE_EXT + '$', 'vztmpl'),
                                       ('backup/', r'^backup/[^/]+' + BACKUP_EXT + '$', 'backup'),
                                       ('snippets/', r'^snippets/[^/]+$', 'snippets'),
                                       ('import/', r'^import/\S+$', 'import')):
            if volname.startswith(prefix) and re.match(pattern, volname):
                owner = None
                if vtype == 'backup':
                    owned = re.match(r'^backup/vzdump-(?:openvz|lxc|qemu)-(\d+)-', volname)
                    owner = int(owned.group(1)) if owned else None
                return vtype, owner, 'raw'
        raise die("unable to parse directory volume name '{0}'".format(volname))

    def _check_access(self, user, sid, vtype, owner, volid):
        """PVE::Storage::check_volume_access."""
        path = '/storage/' + sid
        if self.allowed(user, path, 'Datastore.Allocate'):
            return
        if vtype in ('iso', 'vztmpl', 'import'):
            if not (self.allowed(user, path, 'Datastore.AllocateSpace') or self.allowed(user, path, 'Datastore.Audit')):
                raise PveError(403, 'Permission check failed ({0}, Datastore.AllocateSpace|Datastore.Audit)'.format(
                    path))
        elif vtype == 'backup' and owner:
            self.require(user, path, 'Datastore.AllocateSpace')
            self.require(user, '/vms/{0}'.format(owner), 'VM.Backup')
        elif vtype in ('images', 'rootdir') and owner:
            self.require(user, path, 'Datastore.Audit')
            self.require(user, '/vms/{0}'.format(owner), 'VM.Config.Disk')
        else:
            raise die('missing privileges to access {0}'.format(volid))

    def _volume_path(self, name, volname, vtype):
        store = self.storages[name]
        kind = store.get('type', 'dir')
        if kind == 'rbd':
            return 'rbd:{0}/{1}'.format(store.get('pool', 'rbd'), volname)
        if kind in ('lvm', 'lvmthin'):
            return '/dev/{0}/{1}'.format(store.get('vgname', 'pve'), volname)
        if kind == 'zfspool':
            return '/dev/zvol/{0}/{1}'.format(store.get('pool', 'rpool'), volname)
        base = self._base_path(name)
        subdir = {'images': 'images', 'iso': 'template/iso', 'vztmpl': 'template/cache', 'backup': 'dump',
                  'snippets': 'snippets', 'rootdir': 'private'}.get(vtype, vtype)
        if vtype in ('iso', 'vztmpl', 'backup', 'snippets', 'import'):
            return '{0}/{1}/{2}'.format(base, subdir, volname.split('/', 1)[1])
        return '{0}/{1}/{2}'.format(base, subdir, volname)

    def _item(self, name, volname, vol):
        fmt = vol.get('format')
        item = {'volid': '{0}:{1}'.format(name, volname), 'content': vol['content'], 'format': fmt or 'raw',
                'size': int(vol.get('size') or 0), 'ctime': int(vol.get('ctime') or 0)}
        for key in ('vmid', 'notes', 'used'):
            if vol.get(key) is not None:
                item[key] = vol[key]
        if vol.get('protected') is not None:
            item['protected'] = 1 if vol['protected'] else 0
        return item

    async def _content_list(self, v, user):
        name, node = v['storage'], v['node']
        store = self._active_store(name, node)
        wanted = [v['content']] if v.get('content') else None
        allowed = split_list(store.get('content'))
        out = []
        for volname, vol in self._volumes(name).items():
            if vol['content'] not in allowed or (wanted and vol['content'] not in wanted):
                continue
            if v.get('vmid') is not None and vol.get('vmid') != v['vmid']:
                continue
            try:
                self._check_access(user, name, vol['content'], vol.get('vmid'), '{0}:{1}'.format(name, volname))
            except PveError:
                continue
            out.append(self._item(name, volname, vol))
        return sorted(out, key=lambda item: item['volid'].lower())

    def _volume_name(self, store, vmid, fmt, name):
        """The volume name Plugin::alloc_image gives (and checks): returns (volname, format)."""
        kind = store.get('type', 'dir')
        spec = spec_of(store)
        if kind in BLOCK_NAME:
            if name and not re.match(r'^vm-{0}-'.format(vmid), name):
                raise die("illegal name '{0}' - should be 'vm-{1}-*'".format(name, vmid))
            valid = spec['formats'] or ['raw']
            fmt = fmt or 'raw'
            if fmt not in valid and not (fmt == 'raw'):
                raise die("unsupported format '{0}'".format(fmt))
            return name, fmt
        if fmt not in FORMAT_EXT:
            raise die("unsupported format '{0}'".format(fmt))
        parsed = None
        if re.search(r'\.[^.]+$', name):
            parsed = parse_name_dir(name)[1]
        if parsed == fmt:
            return '{0}/{1}'.format(vmid, name), fmt
        suggestion = re.sub(r'\.[^.]+$', '', name) + '.' + fmt
        if re.search(r'\.[^.]+$', name):
            raise die("illegal name {0} - volume name does not match requested format '{1}' "
                      "(did you mean '{2}'?)".format(name, fmt, suggestion))
        parse_name_dir(suggestion)
        return '{0}/{1}'.format(vmid, suggestion), fmt

    async def _content_create(self, v, user):
        name, node, vmid = v['storage'], v['node'], v['vmid']
        store = self._active_store(name, node)
        filename = v['filename']
        kib = parse_size(v['size'])
        fmt = v.get('format')
        found = re.search(r'\.(raw|qcow2|vmdk)$', filename)
        if found:
            if fmt and fmt != found.group(1):
                raise param_error(format='different storage formats ({0} != {1})'.format(fmt, found.group(1)))
            fmt = found.group(1)
        spec = spec_of(store) or {'format': 'raw', 'formats': None}
        fmt = fmt or store.get('format') or spec['format']
        volname, fmt = self._volume_name(store, vmid, fmt, filename)
        if fmt == 'subvol' and kib != 0:
            raise die('storage does not support subvol quotas')
        volumes = store.setdefault('volumes', {})
        if volname in volumes or volname in self._volumes(name):
            kind = store.get('type', 'dir')
            if kind in BLOCK_NAME:
                raise die(_exists_message(store, volname))
            raise die("disk image '{0}' already exists".format(self._volume_path(name, volname, 'images')))
        size = kib * 1024
        if 'avail' in store:
            if size > store['avail']:
                raise die("unable to write to storage '{0}': No space left on device".format(name))
            store['avail'] -= size
        volumes[volname] = {'content': 'rootdir' if fmt == 'subvol' else 'images', 'format': fmt, 'size': size,
                            'vmid': vmid, 'ctime': int(time.time())}
        return '{0}:{1}'.format(name, volname)

    def _volume_target(self, v):
        """PVE's real_volume_id, then the parsed volume: (storage id, volname, volid, store, vtype, owner, fmt)."""
        volume, sid = v['volume'], v.get('storage')
        if ':' in volume:
            found = STORAGE_ID.match(volume)
            if not found:
                raise param_error(volume="unable to parse volume ID '{0}'\n".format(volume))
            if sid and found.group(1) != sid:
                raise param_error(volume='storage ID mismatch ({0} != {1})\n'.format(found.group(1), sid))
            sid, volname = found.group(1), found.group(2)
        else:
            if not sid:
                raise param_error(volume='no storage specified - incomplete volume ID')
            volname = volume
        volid = '{0}:{1}'.format(sid, volname)
        store = self._store(sid)
        vtype, owner, fmt = self._parse_volname(store, volname)
        return sid, volname, volid, store, vtype, owner, fmt

    def volume_exists(self, volid):
        """True or False if the fake knows whether a volume (an OS template) is on its storage, else None.

        A container create task fails for a False. Known: the storage exists and lists volumes of that
        content type (uploaded, downloaded or set in its `volumes`); a volume missing from such a list is
        missing. A storage with none of that content, or an unknown storage, answers None (accepted).
        """
        sid, colon, volname = str(volid).partition(':')
        if not colon or sid not in self.storages:
            return None
        volumes = self._volumes(sid)
        if volname in volumes:
            return True
        kind = volname.split('/', 1)[0]
        return False if any(name.split('/', 1)[0] == kind and '/' in name for name in volumes) else None

    def _find_volume(self, sid, volname):
        return self._volumes(sid).get(volname)

    async def _content_info(self, v, user):
        sid, volname, volid, store, vtype, owner, _fmt = self._volume_target(v)
        self._check_access(user, sid, vtype, owner, volid)
        vol = self._find_volume(sid, volname)
        if vol is None:
            raise die("volume_size_info on '{0}' failed - no format".format(volid))
        data = {'path': self._volume_path(sid, volname, vtype), 'size': int(vol.get('size') or 0),
                'used': int(vol.get('used') or 0), 'format': vol.get('format') or 'raw'}
        if vol.get('notes') is not None:
            data['notes'] = vol['notes']
        if vtype == 'backup' and _is_file(store):
            data['protected'] = 1 if vol.get('protected') else 0
        return data

    async def _content_put(self, v, user):
        sid, volname, volid, store, vtype, owner, _fmt = self._volume_target(v)
        self._check_access(user, sid, vtype, owner, volid)
        vol = self.storages[sid].setdefault('volumes', {}).get(volname)
        for attr in ('notes', 'protected'):
            if attr not in v:
                continue
            if _is_file(store):
                if attr == 'notes' and vtype != 'backup':
                    raise die('only backups can have notes')
                if attr == 'protected' and vtype != 'backup':
                    raise die("only backups support attribute 'protected'")
            else:
                raise die("attribute '{0}' is not supported for storage type '{1}'".format(attr, store.get('type')))
            if vol is None:
                vol = self._find_volume(sid, volname)
                if vol is None:
                    raise die("volume_size_info on '{0}' failed - no format".format(volid))
                self.storages[sid]['volumes'][volname] = vol
            vol[attr] = v[attr] if attr == 'notes' else bool(v[attr])
            if attr == 'notes' and v[attr] == '':
                vol.pop('notes', None)

    async def _content_delete(self, v, user):
        sid, volname, volid, store, vtype, owner, _fmt = self._volume_target(v)
        if vtype == 'backup' and owner:
            self.require(user, '/storage/' + sid, 'Datastore.AllocateSpace')
            self.require(user, '/vms/{0}'.format(owner), 'VM.Backup')
        else:
            self.require(user, '/storage/' + sid, 'Datastore.Allocate')

        async def body():
            vol = self.storages[sid].get('volumes', {}).get(volname)
            if vol is None and volname.startswith('iso/') and volname[4:] in self.storages[sid]['files']:
                vol = {}
            if vol is not None and vol.get('protected'):
                raise TaskError("cannot remove protected volume '{0}' on '{1}'".format(volname, sid))
            if vol is None:
                if self._find_volume(sid, volname) is None:
                    return "Removed volume '{0}'".format(volid)
                vol = {}
            self.storages[sid].get('volumes', {}).pop(volname, None)
            if volname.startswith('iso/'):
                self.storages[sid]['files'].discard(volname[4:])
            if 'avail' in self.storages[sid]:
                self.storages[sid]['avail'] += int(vol.get('size') or 0)
            return "Removed volume '{0}'".format(volid)
        ident = '{0}@{1}'.format(owner, sid) if owner is not None else sid
        upid = await self.task(v['node'], 'imgdel', ident, user, body, lock=False)
        record = self.tasks[upid]
        if v.get('delay') and record['status'] == 'stopped':
            if record['exitstatus'] == 'OK':
                return None
            raise die(record['exitstatus'])
        return upid


def _bytes(text):
    """A drive size ('32G', '512M', '1T', '4096K', bytes) in bytes."""
    found = re.match(r'^(\d+(?:\.\d+)?)([KMGT]?)$', text)
    if not found:
        return 0
    return int(float(found.group(1)) * {'': 1, 'K': 1024, 'M': 1024 ** 2, 'G': GIB, 'T': 1024 ** 4}[found.group(2)])


def _exists_message(store, volname):
    kind = store.get('type')
    if kind == 'rbd':
        return "rbd create {0} failed: (17) File exists".format(volname)
    if kind in ('lvm', 'lvmthin'):
        return 'lvcreate \'{0}/{1}\' error:   Logical Volume "{1}" already exists in volume group "{0}"'.format(
            store.get('vgname', 'pve'), volname)
    return "zfs error: cannot create '{0}/{1}': dataset already exists".format(store.get('pool', 'rpool'), volname)


# ------------------------------------------------------- download and upload

class StorageTransfer(object):
    """Mixin of FakePve: download-url and upload, the hand-written routes that put files on a storage."""

    def _file_storage(self, request, verb):
        name = request.match_info['storage']
        store = self._active_store(name, request.match_info['node'])
        return name, store

    @staticmethod
    def _need_file_storage(store, text):
        if not _is_file(store):
            raise die(text.format(store.get('type')))

    async def _download_url(self, request):
        from .server import USER, int_param, ok, params
        name, store = self._file_storage(request, 'download')
        user = request[USER]
        self.require(user, '/storage/' + name, 'Datastore.AllocateTemplate')
        self.require(user, '/', 'Sys.Audit')
        self.require(user, '/', 'Sys.Modify')
        p = await params(request)
        # size is the fake's own parameter: how large the download pretends to be.
        size = int_param(p, 'size', 1024 ** 2, minimum=0)
        p = self._verify(request, p, drop=('size',))
        self._need_file_storage(store, "can't upload to storage type '{0}', not a file based storage!")
        content = p['content']
        if content not in split_list(store.get('content')):
            raise die("storage '{0}' is not configured for content-type '{1}'".format(name, content))

        async def body():
            await self.pause(5)
            self.store_file(name, p['filename'], size, content)
        return ok(await self.task(request.match_info['node'], 'download', name, user, body,
                                  log=['downloading {0} to {1}'.format(p.get('url'), p.get('filename'))]))

    async def _upload(self, request):
        from .server import USER, ok
        name, store = self._file_storage(request, 'upload')
        user = request[USER]
        self.require(user, '/storage/' + name, 'Datastore.AllocateTemplate')
        body = await request.read()
        try:
            boundary = request.content_type == 'multipart/form-data' and \
                request.headers['Content-Type'].split('boundary=', 1)[1]
            if not boundary or int(request.headers.get('Content-Length', -1)) != len(body):
                raise ValueError('not a complete multipart body')
            fields = {}
            for part in body.split(b'--' + boundary.encode())[1:-1]:
                head, _, data = part[2:-2].partition(b'\r\n\r\n')
                disposition = head.decode().split('\r\n')[0]
                field = disposition.split('name="', 1)[1].split('"', 1)[0]
                if 'filename="' in disposition:
                    fields['filename'] = disposition.split('filename="', 1)[1].split('"', 1)[0]
                    fields['data'] = data
                else:
                    fields[field] = data.decode()
        except (IndexError, ValueError):  # UnicodeDecodeError is one
            raise PveError(400, 'bad upload request') from None
        content = fields.get('content')
        if content not in ('iso', 'vztmpl'):
            raise PveError(400, 'Parameter verification failed.', {'content': 'value not allowed'})
        self._need_file_storage(store, "can't upload to storage type '{0}'")
        if content not in split_list(store.get('content')):
            raise die("storage '{0}' does not support '{1}' content".format(name, content))
        self.uploaded = fields

        async def body_():
            self.store_file(name, fields['filename'], len(fields.get('data', b'')), content)
        return ok(await self.task(request.match_info['node'], 'imgcopy', '', user, body_))
