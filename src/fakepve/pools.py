"""Resource pools: members (guests, storages), nesting and the permission paths they carry.

Follows pve-manager's PVE/API2/Pool.pm. `pve.pools` maps a pool id to the set of
guest ids in it (a guest is in one pool); `pve.pool_info` holds the comment and
the storage members. Guests are the VMs in `pve.vms` and the containers in
`pve.cts`; lxc.py joins and leaves through `_pool_join` and `_pool_leave`.
"""

import copy

from .model import PveError
from .routing import StatefulRoutes, die, split_list


class PoolsApi(StatefulRoutes):
    """Mixin of FakePve: /pools."""

    def _routes_pools(self):
        pools = '/pools'
        one = '/pools/{poolid}'
        return [('GET', pools, self._pool_index), ('POST', pools, self._pool_create),
                ('PUT', pools, self._pool_update), ('DELETE', pools, self._pool_delete),
                ('GET', one, self._pool_read), ('PUT', one, self._pool_update), ('DELETE', one, self._pool_delete)]

    # ---------------------------------------------------------------- state

    def _pool_meta(self, name):
        meta = self.pool_info.setdefault(name, {'comment': None, 'storage': set()})
        return meta

    def _pool_of_vm(self, vmid):
        """The pool a guest id is a member of, or None."""
        for name, ids in self.pools.items():
            if vmid in ids:
                return name
        return None

    def _pool_join(self, name, vmid):
        """Add a guest (VM or container) to a pool, creating the pool record if only the id exists."""
        self.pools.setdefault(name, set()).add(vmid)
        self._pool_meta(name)
        self._sync_pools()

    def _pool_leave(self, vmid):
        """Remove a guest id from every pool (a guest is destroyed)."""
        for ids in self.pools.values():
            ids.discard(vmid)
        self._sync_pools()

    def _pool_of_storage(self, sid):
        """The pool a storage id is a member of, or None."""
        for name, meta in sorted(self.pool_info.items()):
            if sid in meta['storage'] and name in self.pools:
                return name
        return None

    def _sync_pools(self):
        """Keep each guest's `pool` attribute (shown in /cluster/resources) in step with membership."""
        for guest in list(self.vms) + self.cts:
            guest.pool = self._pool_of_vm(guest.vmid)

    def _guest_of(self, vmid):
        for guest in list(self.vms) + self.cts:
            if guest.vmid == vmid:
                return guest
        return None

    def _members(self, name, kind):
        members = []
        for vmid in sorted(self.pools.get(name, ())):
            guest = self._guest_of(vmid)
            if guest is None or kind not in (None, guest.guest.split('/')[0]):
                continue
            entry = {'id': guest.guest, 'type': guest.guest.split('/')[0], 'vmid': vmid, 'node': guest.node,
                     'name': guest.name, 'status': guest.status}
            if getattr(guest, 'template', False):
                entry['template'] = 1
            members.append(entry)
        if kind in (None, 'storage'):
            for sid in sorted(self._pool_meta(name)['storage']):
                store = self.storages.get(sid)
                if store is None:
                    continue
                node = (self._storage_nodes(sid) or sorted(self.nodes))[0]
                members.append({'id': 'storage/{0}/{1}'.format(node, sid), 'type': 'storage', 'node': node,
                                'storage': sid, 'status': 'available' if store.get('active', 1) else 'unknown',
                                'plugintype': store.get('type', 'dir'), 'content': store.get('content', ''),
                                'shared': 1 if store.get('shared') else 0})
        return members

    # ------------------------------------------------------------- handlers

    async def _pool_index(self, v, user):
        poolid = v.get('poolid')
        if poolid:
            # PVE calls check() with noerr here, which only answers: nothing is refused.
            if poolid not in self.pools:
                raise die("pool '{0}' does not exist".format(poolid))
            data = {'members': self._members(poolid, v.get('type')), 'poolid': poolid}
            if self._pool_meta(poolid)['comment'] is not None:
                data['comment'] = self._pool_meta(poolid)['comment']
            return [data]
        out = []
        for name in sorted(self.pools):
            if not self.allowed(user, '/pool/' + name, 'Pool.Audit'):
                continue
            entry = {'poolid': name}
            if self._pool_meta(name)['comment'] is not None:
                entry['comment'] = self._pool_meta(name)['comment']
            out.append(entry)
        return out

    async def _pool_read(self, v, user):
        # The deprecated /pools/{poolid} answers the object /pools?poolid= has as its only item.
        return (await self._pool_index(v, user))[0]

    async def _pool_create(self, v, user):
        fail = 'create pool failed: '
        name = v['poolid']
        if name in self.pools:
            raise die(fail + "pool '{0}' already exists".format(name))
        if '/' in name:
            parent, leaf = name.rsplit('/', 1)
            if parent not in self.pools:
                raise die(fail + "parent '{0}' of pool '{1}' does not exist".format(parent, name))
            if not leaf[:1].isalpha():
                raise die(fail + 'pool name must start with a letter')
        elif not name[:1].isalpha():
            raise die(fail + 'pool name must start with a letter')
        self.pools[name] = set()
        self.pool_info[name] = {'comment': v['comment'] if v.get('comment') else None, 'storage': set()}

    def _check_perm_modify(self, user, path, extra):
        """RPCEnvironment::check_perm_modify: Permissions.Modify or the object's own allocate privilege."""
        privs = ['Permissions.Modify', extra]
        if not any(self.allowed(user, path, p) for p in privs):
            raise PveError(403, 'Permission check failed ({0}, {1})'.format(path, '|'.join(privs)))

    async def _pool_update(self, v, user):
        fail = 'update pools failed: '
        name = v['poolid']
        if name not in self.pools:
            raise die(fail + "pool '{0}' does not exist".format(name))
        # PVE edits its parsed user.cfg and writes it at the end: a failure changes nothing.
        pools = copy.deepcopy(self.pools)
        info = copy.deepcopy(self.pool_info)
        meta = info.setdefault(name, {'comment': None, 'storage': set()})
        try:
            if v.get('comment') is not None:
                meta['comment'] = v['comment']
            if v.get('vms') is not None:
                for item in split_list(v['vms']):
                    vmid = int(item)
                    self._check_perm_modify(user, '/vms/{0}'.format(vmid), 'VM.Allocate')
                    if v.get('delete'):
                        if vmid not in pools[name]:
                            raise die('VM {0} is not a pool member'.format(vmid))
                        pools[name].discard(vmid)
                    else:
                        if vmid in pools[name]:
                            raise die('VM {0} is already a pool member'.format(vmid))
                        existing = next((p for p, ids in pools.items() if vmid in ids), None)
                        if existing is not None:
                            if not v.get('allow-move'):
                                raise die("VM {0} belongs already to pool '{1}' and 'allow-move' is not set".format(
                                    vmid, existing))
                            if not self.allowed(user, '/pool/' + existing, 'Pool.Allocate'):
                                raise PveError(403, 'Permission check failed (/pool/{0}, Pool.Allocate)'.format(
                                    existing))
                            pools[existing].discard(vmid)
                        pools[name].add(vmid)
            if v.get('storage') is not None:
                for sid in split_list(v['storage']):
                    self._check_perm_modify(user, '/storage/' + sid, 'Datastore.Allocate')
                    if v.get('delete'):
                        if sid not in meta['storage']:
                            raise die("Storage '{0}' is not a pool member".format(sid))
                        meta['storage'].discard(sid)
                    else:
                        if sid in meta['storage']:
                            raise die("Storage '{0}' is already a pool member".format(sid))
                        meta['storage'].add(sid)
        except PveError as e:
            raise PveError(500, fail + e.message) from e
        self.pools, self.pool_info = pools, info
        self._sync_pools()

    async def _pool_delete(self, v, user):
        fail = 'delete pool failed: '
        name = v['poolid']
        if name not in self.pools:
            raise die(fail + "pool '{0}' does not exist".format(name))
        for other in sorted(self.pools):
            if other.startswith(name + '/'):
                raise die(fail + "pool '{0}' is not empty (contains pool '{1}')".format(name, other))
        for vmid in sorted(self.pools[name]):
            if self._guest_of(vmid) is not None:
                raise die(fail + "pool '{0}' is not empty (contains VM {1})".format(name, vmid))
        for sid in sorted(self._pool_meta(name)['storage']):
            if sid in self.storages:
                raise die(fail + "pool '{0}' is not empty (contains storage '{1}')".format(name, sid))
        del self.pools[name]
        self.pool_info.pop(name, None)
        if self.acl:
            for user_id, entries in self.acl.items():
                self.acl[user_id] = [e for e in entries if e[0] != '/pool/' + name]
        self._sync_pools()
