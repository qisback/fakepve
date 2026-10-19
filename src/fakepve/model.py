"""State of the fake cluster: nodes, VMs, tasks, config locks, tickets and permissions.

Times are in PVE seconds. FakePve.time_scale turns them into real ones:
0 runs every task to completion before the request returns; 0.01 makes a
60 second shutdown take 0.6s of wall time.
"""

import asyncio
import hashlib
import itertools
import json
import os
import secrets
import time

from . import errors


class PveError(Exception):
    """An API error as PVE reports it: status, message and per-field errors."""

    def __init__(self, status, message, errors=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.errors = errors


class TaskError(Exception):
    """A task ending with this exit status instead of OK."""


def lock_timeout(vmid):
    return "can't lock file '/var/lock/qemu-server/lock-{0}.conf' - got timeout".format(vmid)


# Keys PVE applies to a running VM at once; anything else goes to pending.
HOTPLUG = ('name', 'description', 'onboot', 'tags', 'protection', 'hookscript', 'startup', 'agent', 'lock')
DRIVE_PREFIXES = ('ide', 'sata', 'scsi', 'virtio', 'efidisk', 'tpmstate', 'unused')


class FakeVm(object):
    def __init__(self, vmid, name, node='pve1', status='stopped', qmpstatus=None, config=None,
                 pending=None, template=False, lock=None, pool=None):
        self.vmid = vmid
        self.name = name
        self.node = node
        self.status = status
        self.qmpstatus = qmpstatus or status
        self.config = dict(config or {})
        self.config.setdefault('name', name)
        # key -> new value, or None for a pending delete
        self.pending = dict(pending or {})
        self.template = template
        # PVE's config lock value: backup, migrate, snapshot, clone, suspended, ...
        self.lock = lock
        self.pool = pool
        # Extra status/current fields: cpu, mem, maxmem, uptime, ha, ...
        self.stats = {}
        self.started_at = time.time() if status == 'running' else None
        self.nmis = 0
        # Guest agent answers ({'os': ..., 'interfaces': ...}); None: no agent running.
        self.agent = None
        # The agent is running but does not answer.
        self.agent_hangs = False
        # A guest OS without ACPI handling ignores shutdown and reboot.
        self.acpi = True
        # PVE seconds the guest takes to power off after ACPI; the start and
        # stop tasks' own durations.
        self.shutdown_secs = 0
        self.start_secs = 0
        self.stop_secs = 0
        # The QEMU process cannot be started (e.g. a missing disk).
        self.start_error = None
        # HA resource state when managed: started, stopped, error, ...
        self.ha_state = None
        # Holder of the internal config lock (a task id or 'scenario').
        self.lock_holder = None
        self.lock_released = None

    @property
    def guest(self):
        """The id as /cluster/resources shows it: qemu/<vmid>."""
        return 'qemu/{0}'.format(self.vmid)

    @property
    def ha_managed(self):
        """True if ha_state is set."""
        return self.ha_state is not None

    def apply_pending(self):
        """Move the pending config into the config (a start or reboot does this)."""
        for key, val in self.pending.items():
            if val is None:
                self.config.pop(key, None)
            else:
                self.config[key] = val
        self.pending = {}

    def digest(self):
        """The config digest PVE's clients pass back to detect concurrent changes."""
        return hashlib.sha1(json.dumps(self.config, sort_keys=True).encode()).hexdigest()

    def devices(self, cfg=None):
        """Keys of the config that are devices (disks, nics, usb, pci)."""
        cfg = self.config if cfg is None else cfg
        return [k for k in cfg if k.startswith(DRIVE_PREFIXES + ('net', 'usb', 'hostpci')) and k[-1].isdigit()]


class Model(object):
    def __init__(self, user='root@pam', password='secret'):
        self.user = user
        self.password = password
        # Other password logins: userid -> password.
        self.users = {}
        self.vms = []
        self.nodes = {'pve1': {'online': True}}
        self.cluster_name = 'fakecluster'
        self.version = '9.0.10'
        self.release_version = '9.0'
        # PVE seconds -> real seconds; 0: tasks finish before the request returns.
        self.time_scale = 0.0
        # PVE seconds added to every response.
        self.latency = 0.0
        # Ticket lifetime; PVE's is 2 hours.
        self.ticket_ttl = 7200
        # PVE seconds a write or task waits for a held VM config lock.
        self.lock_wait = 10
        # PVE ends a shutdown task after this unless the request gives a timeout.
        self.shutdown_default_timeout = 60
        # PVE seconds before the HA manager acts on a request.
        self.ha_delay = 10
        self.quorate = True
        self.tfa = False
        self.refuse_terminal = False
        # 'user@realm!tokenid' -> secret
        self.apitokens = {}
        # None: every user may do anything. Otherwise userid -> [(path, {privs})].
        self.acl = None
        # Pools: name -> {vmids}.
        self.pools = {}
        self.storages = {'local': {'type': 'dir', 'active': 1, 'content': 'iso,vztmpl,backup', 'files': set(),
                                   'avail': 50 * 1024 ** 3},
                         'local-lvm': {'type': 'lvmthin', 'active': 1, 'content': 'images,rootdir', 'files': set()}}
        # Network conditions: latency and jitter (PVE seconds), per node
        # latency, and the share of requests dropped (connection reset) or
        # hung (no answer for hang_secs). seed makes the randomness repeatable.
        self.network = {'latency': 0.0, 'jitter': 0.0, 'node_latency': {}, 'drop_rate': 0.0,
                        'hang_rate': 0.0, 'hang_secs': 120, 'seed': None}
        # Ceph: health, extra PVE seconds on every RBD-backed operation, and
        # whether the cluster is reachable at all.
        self.ceph = {'health': 'HEALTH_OK', 'slow': 0.0, 'down': False}
        self.tickets = {}
        self.tasks = {}
        self.tasklog = []
        self.requests = []
        self.failures = {}
        self._pids = itertools.count(1000)

    # ---------------------------------------------------------------- lookup

    def add_vm(self, *args, **kwargs):
        """Add a FakeVm (arguments as FakeVm's) and its node; returns the VM."""
        vm = FakeVm(*args, **kwargs)
        self.vms.append(vm)
        self.nodes.setdefault(vm.node, {'online': True})
        if vm.pool:
            self.pools.setdefault(vm.pool, set()).add(vm.vmid)
        return vm

    def add_node(self, name, online=True):
        """Add a node to the cluster."""
        self.nodes[name] = {'online': online}

    def vm(self, vmid):
        """The VM with this id, or None."""
        for vm in self.vms:
            if vm.vmid == vmid:
                return vm
        return None

    def find(self, node, vmid):
        """The VM on this node, or a PveError (500, as PVE: no config file)."""
        vm = self.vm(int(vmid))
        if vm is None or vm.node != node:
            raise PveError(500, "Configuration file 'nodes/{0}/qemu-server/{1}.conf' does not exist".format(
                node, vmid))
        return vm

    # ------------------------------------------------------------------ time

    async def pause(self, secs):
        """Sleep secs PVE seconds (scaled by time_scale; nothing at 0)."""
        if secs and self.time_scale:
            await asyncio.sleep(secs * self.time_scale)

    # ----------------------------------------------------------------- locks

    async def acquire(self, vm, holder, wait=None):
        """Take the VM config lock, waiting up to lock_wait PVE seconds."""
        wait = self.lock_wait if wait is None else wait
        if vm.lock_holder is not None and self.time_scale and wait:
            deadline = asyncio.get_running_loop().time() + wait * self.time_scale
            while vm.lock_holder is not None:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                vm.lock_released = vm.lock_released or asyncio.Event()
                try:
                    await asyncio.wait_for(vm.lock_released.wait(), remaining)
                except asyncio.TimeoutError:
                    break
        if vm.lock_holder is not None:
            raise TaskError(lock_timeout(vm.vmid))
        vm.lock_holder = holder

    def release(self, vm, holder):
        """Release the VM config lock if holder has it."""
        if vm.lock_holder == holder:
            vm.lock_holder = None
            if vm.lock_released:
                vm.lock_released.set()
                vm.lock_released = None

    # ----------------------------------------------------------------- tasks

    def _upid(self, node, ttype, tid, user):
        pid = next(self._pids)
        start = int(time.time())
        return 'UPID:{0}:{1:08X}:{2:08X}:{3:08X}:{4}:{5}:{6}:'.format(
            node, pid, pid * 7, start, ttype, tid, user), pid, start

    async def task(self, node, ttype, tid, user, body, vm=None, lock=True, log=()):
        """Start a task; returns its UPID. body() may pause, and raises TaskError to fail."""
        upid, pid, start = self._upid(node, ttype, tid, user)
        record = {'upid': upid, 'node': node, 'pid': pid, 'pstart': pid * 7, 'starttime': start,
                  'type': ttype, 'id': str(tid), 'user': user, 'status': 'running', 'log': list(log)}
        self.tasks[upid] = record
        self.tasklog.append(record)

        async def run():
            status = 'OK'
            try:
                if vm is not None and lock:
                    await self.acquire(vm, upid)
                try:
                    note = await body()
                    if note:
                        record['log'].append(note)
                finally:
                    if vm is not None and lock:
                        self.release(vm, upid)
            except TaskError as e:
                status = str(e)
                record['log'].append(status)
            record['status'] = 'stopped'
            record['exitstatus'] = status
            record['endtime'] = int(time.time())
            record['log'].append('TASK OK' if status == 'OK' else 'TASK ERROR: ' + status)

        if self.time_scale:
            asyncio.ensure_future(run())
        else:
            await run()
        return upid

    # ---------------------------------------------------------------- tickets

    def issue_ticket(self, user):
        """Make a login ticket; returns (ticket, csrf token)."""
        ticket = 'PVE:{0}:{1:08X}::{2}'.format(user, int(time.time()), secrets.token_hex(24))
        csrf = '{0:08X}:{1}'.format(int(time.time()), secrets.token_urlsafe(32))
        self.tickets[ticket] = {'user': user, 'csrf': csrf, 'expires': time.time() + self.ticket_ttl}
        return ticket, csrf

    def check_password(self, user, password):
        """True if the password is right for user (pve.user, or an entry of pve.users)."""
        if user == self.user:
            return password == self.password
        return self.users.get(user) == password

    # ------------------------------------------------------------ permissions

    def grant(self, user, path, *privs):
        """Give user the privileges on path ('/', '/vms', '/vms/100', '/pool/name', '/storage/x', ...)."""
        if self.acl is None:
            self.acl = {}
        self.acl.setdefault(user, []).append((path.rstrip('/') or '/', set(privs)))

    def allowed(self, user, path, priv):
        """True if user holds priv on path. Everyone does until the first grant(); root@pam always does."""
        if self.acl is None or user.split('!')[0] == 'root@pam':
            return True
        paths = [path]
        if path.startswith('/vms/'):
            vmid = int(path.split('/')[2])
            paths += ['/vms'] + ['/pool/' + name for name, ids in self.pools.items() if vmid in ids]
        for user_id in (user, user.split('!')[0]):
            for granted, privs in self.acl.get(user_id, []):
                if priv in privs and (granted == '/' or any(p == granted or p.startswith(granted + '/')
                                                            for p in paths)):
                    return True
        return False

    def require(self, user, path, priv):
        """Like allowed(), but raises a 403 PveError in PVE's wording."""
        if not self.allowed(user, path, priv):
            raise PveError(403, 'Permission check failed ({0}, {1})'.format(path, priv))

    # -------------------------------------------------------------- scenarios

    def lose_quorum(self):
        """/etc/pve goes read-only: config writes and VM actions fail, reads work."""
        self.quorate = False

    def regain_quorum(self):
        """Undo lose_quorum()."""
        self.quorate = True

    def need_quorum(self):
        """Raise PVE's no-quorum error (500) if quorum is lost."""
        if not self.quorate:
            raise PveError(500, 'cluster not ready - no quorum?')

    def set_node_offline(self, node, offline=True):
        """Take a node offline (requests for it get 595), or bring it back with offline=False."""
        self.nodes.setdefault(node, {})['online'] = not offline

    async def hold_config_lock(self, vmid, secs):
        """Another task holds the VM config lock for secs PVE seconds (or until release_config_lock)."""
        vm = self.vm(vmid)
        await self.acquire(vm, 'scenario', wait=0)
        if secs is not None:
            async def later():
                await self.pause(secs)
                self.release(vm, 'scenario')
            asyncio.ensure_future(later())

    def release_config_lock(self, vmid):
        """Release a lock taken by hold_config_lock()."""
        self.release(self.vm(vmid), 'scenario')

    async def backup(self, vmid, secs=30, user='root@pam'):
        """A vzdump of the VM: lock 'backup' for secs PVE seconds."""
        vm = self.vm(vmid)

        async def body():
            vm.lock = 'backup'
            vm.config['lock'] = 'backup'
            try:
                await self.pause(secs)
            finally:
                vm.lock = None
                vm.config.pop('lock', None)
            return 'INFO: Finished Backup of VM {0}'.format(vmid)
        return await self.task(vm.node, 'vzdump', vmid, user, body, vm=vm, lock=False,
                               log=['INFO: starting new backup job: vzdump {0}'.format(vmid)])

    async def migrate(self, vmid, target, secs=20, user='root@pam'):
        """Migrate the VM to target: lock 'migrate' for secs PVE seconds, then it lives there."""
        vm = self.vm(vmid)
        self.nodes.setdefault(target, {'online': True})

        async def body():
            vm.lock = 'migrate'
            try:
                await self.pause(secs)
                vm.node = target
            finally:
                vm.lock = None
            return 'migration finished successfully'
        return await self.task(vm.node, 'qmigrate', vmid, user, body, vm=vm,
                               log=['starting migration of VM {0} to node {1!r}'.format(vmid, target)])

    def snapshot_lock(self, vmid, lock='snapshot'):
        """Leave the VM locked, as an interrupted snapshot, clone or rollback does."""
        vm = self.vm(vmid)
        vm.lock = lock
        vm.config['lock'] = lock

    def unlock(self, vmid):
        """Clear the VM's lock."""
        vm = self.vm(vmid)
        vm.lock = None
        vm.config.pop('lock', None)

    def add_ceph_storage(self, name='ceph-pool', pool='rbd'):
        """An RBD storage; VMs with disks on it feel the Ceph scenarios."""
        self.storages[name] = {'type': 'rbd', 'pool': pool, 'active': 1, 'content': 'images,rootdir',
                               'files': set(), 'shared': 1}

    def ceph_slow(self, secs, health='HEALTH_WARN'):
        """Every RBD-backed operation takes secs PVE seconds longer (slow OSDs, recovery)."""
        self.ceph.update(slow=secs, health=health)

    def ceph_down(self):
        """Ceph unreachable: RBD storages inactive, RBD-backed starts and disk changes fail."""
        self.ceph.update(down=True, health='HEALTH_ERR')
        for store in self.storages.values():
            if store.get('type') == 'rbd':
                store['active'] = 0

    def ceph_recover(self):
        """Undo ceph_down() and ceph_slow()."""
        self.ceph.update(down=False, slow=0.0, health='HEALTH_OK')
        for store in self.storages.values():
            if store.get('type') == 'rbd':
                store['active'] = 1

    def ceph_storages(self):
        """Names of the RBD storages."""
        return {name for name, store in self.storages.items() if store.get('type') == 'rbd'}

    def on_ceph(self, vm, keys=None):
        """True if any of the VM's disks (or of keys) live on RBD."""
        rbd = self.ceph_storages()
        cfg = vm.config
        for key in keys if keys is not None else vm.devices():
            volume = str(cfg.get(key) or '').split(',')[0]
            if volume.split(':')[0] in rbd:
                return True
        return False

    async def ceph_io(self, vm, keys=None):
        """Apply the Ceph scenarios to an operation on the VM's disks."""
        if not self.on_ceph(vm, keys):
            return
        if self.ceph['down']:
            raise TaskError('rbd error: rbd: couldn\'t connect to the cluster! (Connection timed out)')
        await self.pause(self.ceph['slow'])

    def slow_network(self, latency, jitter=0.0, node=None):
        """Add latency (and random jitter) to every response, or to one node's."""
        if node:
            self.network['node_latency'][node] = latency
        else:
            self.network.update(latency=latency, jitter=jitter)

    def flaky_network(self, drop_rate=0.0, hang_rate=0.0, hang_secs=120, seed=None):
        """Drop (connection reset) or hang (no answer) a share of requests."""
        self.network.update(drop_rate=drop_rate, hang_rate=hang_rate, hang_secs=hang_secs, seed=seed)

    def fail(self, method, suffix, status=None, message=None, html=False, error=None, times=None):
        """Answer requests whose path ends with suffix with an error.

        pve.fail('POST', '/nodes/pve1/qemu/100/status/start', 500, 'boom')   # your own status and message
        pve.fail('POST', '/nodes/pve1/qemu/100/status/start', error='already_running')   # PVE's own error

        error is a name from pve.errors_for(method, path) (the catalogue of PVE's real errors, and the
        cross-cutting ones such as no_quorum). Its {placeholders} are filled from the request. An error
        raised inside a PVE worker (in_task) answers with a UPID and ends the task with `TASK ERROR: message`.
        html: a proxy's page instead of JSON. times: fail that many requests, then stop (default: every one).
        """
        if error is not None:
            if status is not None or message is not None:
                raise ValueError('give either error= or status and message')
            known = errors.listing(method, suffix) if suffix.startswith('/') and '{' not in suffix else []
            if known and errors.find(method, suffix, error) is None:
                names = ', '.join(e['name'] for e in known)
                raise ValueError('no error {0!r} for {1} {2}; known: {3}'.format(error, method, suffix, names))
        elif status is None or message is None:
            raise TypeError('fail() needs status and message, or error=')
        self.failures[(method, suffix)] = {'status': status, 'message': message, 'html': html,
                                           'error': error, 'times': times}

    def errors_for(self, method, path, params=None):
        """The errors a method can return at a concrete path: dicts with name, status, message, errors,
        in_task and source. Any of the names can be given to fail(error=...)."""
        return errors.errors_for(method, path, params)

    def revoke_tickets(self):
        """Forget every login ticket: the next request gets 401."""
        self.tickets = {}

    def store_file(self, storage, name, size):
        """Add a file to a storage, or raise TaskError if it does not fit in 'avail'."""
        store = self.storages[storage]
        if size > store.get('avail', float('inf')):
            raise TaskError('unable to write to storage {0!r}: No space left on device'.format(storage))
        store['files'].add(name)
        if 'avail' in store:
            store['avail'] -= size

    def file_size(self, path):
        """Size of a local file in bytes."""
        return os.path.getsize(path)
