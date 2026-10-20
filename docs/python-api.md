# Python API

Everything in fakepve is plain Python state you can read and set. This page explains every public attribute and method of `FakePve`, `FakeVm` and `FakeCt`, and the helper modules. The [signature index](#signature-index) at the end is generated from the code, so it is always complete; the explanations are written by hand, and a test checks that every public name in the index is explained here.

Contents: [the fake](#the-fake) | [building the cluster](#building-the-cluster) | [VMs](#vms) | [containers](#containers) | [time and tasks](#time-and-tasks) | [scenarios](#scenario-methods) | [access](#access) | [failures and errors](#failures-and-errors) | [what the fake records](#what-the-fake-records) | [limits](#limits) | [storages](#storages) | [pools and firewall](#pools-and-the-firewall) | [internals](#internals) | [helper modules](#helper-modules) | [signature index](#signature-index)

All durations are PVE seconds. The examples on this page run as they stand.

## The fake

`FakePve(user='root@pam', password='secret', host=None, port=8006)` is one fake cluster behind one listening socket.

- `host` is the address it listens on. By default each instance takes the next loopback address (`127.0.0.2`, `127.0.0.3`, ...; see `next_loopback()`), so any number of fakes can all use port 8006. Pass your own to choose.
- `port` is the TCP port, 8006 (`PORT`) by default. Port 0 asks the system for a free one; `pve.port` holds the real port once the fake has started, and `pve.url` is `https://host:port`.
- `user` and `password` are the login; this user can do everything. `check_password(user, password)` is what the login uses.

`await pve.start(certfile, keyfile)` listens, with the PEM certificate and key you give it (`fakepve.certs.make_cert` makes a self-signed pair). `await pve.stop()` closes everything. `pve.runner` is the aiohttp runner while it is running, and `None` before and after. `settle()` lets spawned tasks run; call it before `stop()` in a test so background tasks do not outlive the loop.

<!-- run -->
```python
import tempfile

from fakepve import FakePve, next_loopback, settle
from fakepve.certs import make_cert

certfile, keyfile, der = make_cert(tempfile.mkdtemp())
pve = FakePve(host='127.0.0.1', port=18006)
print(pve.host, pve.port, pve.runner)
await pve.start(certfile, keyfile)
print(pve.runner is not None)
await settle()
await pve.stop()
print(pve.runner)
print(next_loopback() != next_loopback())
```

<!-- output -->
```text
127.0.0.1 18006 None
True
None
True
```

`make_cert(directory, name='fakepve')` writes `<name>.crt` and `<name>.key` into the directory and returns `(certfile, keyfile, der)`, the last being the certificate in DER form (for clients that pin it). It needs `cryptography`.

## Building the cluster

A new `FakePve` has one node, `pve1`, and two storages, `local` and `local-lvm`.

`pve.add_vm(vmid, name, node='pve1', status='stopped', ...)` adds a VM and returns it. It takes the arguments of `FakeVm` (below) and creates the node if it is new. `pve.add_node(name, online=True)` adds a node without VMs. `pve.vm(vmid)` returns the VM with that id or `None`; `pve.find(node, vmid)` returns the VM on that node or raises the `PveError` PVE gives for a missing guest (500, `Configuration file 'nodes/pve1/qemu-server/100.conf' does not exist`).

`pve.vms` is the list of VMs and `pve.nodes` a dict of node name to `{'online': bool}`. `pve.pools` maps a pool name to the set of VM ids in it; `add_vm(..., pool='web')` fills it, and grants on `/pool/web` then apply to the VM. `pve.cluster_name` is what `/cluster/status` reports (`fakecluster`), and `pve.version` and `pve.release_version` are what `/version` reports (`9.0.10` and `9.0`).

<!-- run -->
```python
from fakepve import FakePve

pve = FakePve()
web = pve.add_vm(100, 'web1', status='running', pool='web', config={'memory': 2048})
pve.add_vm(101, 'db1', node='pve2')
pve.add_node('pve3', online=False)
print(sorted(pve.nodes), pve.pools)
print(pve.vm(100) is web, pve.vm(999))
print(pve.find('pve2', 101).name)
try:
    pve.find('pve1', 101)
except Exception as exc:
    print(type(exc).__name__, exc.status, exc.message)
print(pve.cluster_name, pve.version, pve.release_version)
```

<!-- output -->
```text
['pve1', 'pve2', 'pve3'] {'web': {100}}
True None
db1
PveError 500 Configuration file 'nodes/pve1/qemu-server/101.conf' does not exist
fakecluster 9.0.10 9.0
```

## VMs

`FakeVm(vmid, name, node='pve1', status='stopped', qmpstatus=None, config=None, pending=None, template=False, lock=None, pool=None)`. You normally get one from `add_vm`. Its attributes are all read and write:

| Attribute | Meaning |
|---|---|
| `vm.vmid`, `vm.name`, `vm.node` | Identity and place. Assigning `vm.node` moves the VM (the old path then 500s, as on PVE). |
| `vm.status` | `running` or `stopped`: what `status/current` shows. |
| `vm.qmpstatus` | The QEMU state: `running`, `stopped`, `paused`. Defaults to `status`. |
| `vm.config` | The config as a dict of strings or numbers. `name` is always present. |
| `vm.pending` | Changes waiting for the next start: key to new value, or `None` for a pending delete. |
| `vm.template` | `True` for a template, which cannot be started. |
| `vm.lock` | PVE's config lock (`backup`, `migrate`, `snapshot`, `clone`, `suspended`, ...): start, shutdown, reboot and config writes fail with `VM is locked (name)`. Use `pve.snapshot_lock` to set it and `pve.unlock` to clear it. |
| `vm.pool` | The pool name, if any. |
| `vm.stats` | Extra fields merged into `status/current`, overriding the defaults: `vm.stats['cpu'] = 0.95`. |
| `vm.started_at` | When it started (`time.time()`), from which uptime is computed; `None` when stopped. |
| `vm.nmis` | How many NMIs the `monitor` endpoint has sent it. |
| `vm.agent` | What the guest agent answers, a dict; `None` means the agent is not running. `os` and `interfaces` answer `get-osinfo` and `network-get-interfaces`; any other command's name (`get-host-name`, `get-timezone`, ...) replaces that command's default result. `files` maps a path to what `file-read` returns, and `exec` maps a command line (`'echo hi'`) to the fields `exec-status` answers with. |
| `vm.agent_hangs` | `True`: the agent is running but never answers (the call fails with PVE's timeout message). |
| `vm.agent_requests` | `(command, parameters)` for every agent request answered, oldest first. `exec` and the file commands only land here: nothing is run and no file is read or written. A `password` is recorded as `***`. |
| `vm.agent_frozen` | `True` between an agent `fsfreeze-freeze` and `fsfreeze-thaw`; `fsfreeze-status` reads it. |
| `vm.agent_pid`, `vm.agent_execs` | The last pid `agent/exec` handed out, and each pid's command line, which `exec-status` looks up. |
| `vm.acpi` | `False`: the guest ignores ACPI shutdown and reboot, so they run into the timeout. |
| `vm.shutdown_secs` | How long the guest takes to power off after a shutdown. A shutdown task fails with `VM quit/powerdown failed - got timeout` if this exceeds its `timeout` parameter (else `pve.shutdown_default_timeout`). |
| `vm.start_secs`, `vm.stop_secs` | How long the start and stop tasks run. |
| `vm.start_error` | The start task fails with this message. |
| `vm.ha_state` | `None`, or the HA resource state, which makes the VM HA managed. |
| `vm.lock_holder`, `vm.lock_released` | Internal bookkeeping of the config lock. Leave them alone; see `pve.acquire`. |

Properties and methods: `vm.guest` is the id `/cluster/resources` shows (`qemu/100`); `vm.ha_managed` is true when `ha_state` is set; `vm.apply_pending()` merges `pending` into `config` (a start does it); `vm.digest()` is the config digest a client passes back to detect concurrent edits; `vm.devices(cfg=None)` lists the config keys that are devices (disks, nics, usb, pci).

One extra, read by the VNC websocket and not set by the constructor: `vm.screen = (width, height, rgb_bytes)` sets what a screenshot over the VNC console shows. It defaults to a 4x2 test pattern.

<!-- run -->
```python
from fakepve import FakePve

pve = FakePve()
vm = pve.add_vm(100, 'web1', status='running', config={'memory': 1024, 'scsi0': 'local-lvm:vm-100-disk-0'})
vm.pending['memory'] = 2048
vm.pending['scsi0'] = None            # a pending delete
vm.stats['cpu'] = 0.95
print(vm.guest, vm.ha_managed, vm.devices())
before = vm.digest()
vm.apply_pending()
print(vm.config, vm.pending)
print(before != vm.digest())
vm.ha_state = 'started'
print(vm.ha_managed)
```

<!-- output -->
```text
qemu/100 False ['scsi0']
{'memory': 2048, 'name': 'web1'} {}
True
True
```

## Containers

`pve.add_ct(vmid, name=None, node='pve1', status='stopped', ...)` adds an LXC container and returns it. It takes the arguments of `FakeCt` and creates the node if it is new, and raises `ValueError` with PVE's message (`CT 100 already exists on node 'pve1'`, or `VM 100 ...`) for an id that a VM or a container already has. `pve.cts` is the list, `pve.ct(vmid)` finds one (or `None`), and `pve.guest(vmid)` finds a VM or a container. Containers show in `/cluster/resources` (type `lxc`; `pve.ct_resources(user, kind)` builds those items) and in `/nodes/{node}/lxc`, and every container route keeps state: see [Containers in the scenarios](scenarios.md#containers).

`FakeCt(vmid, name=None, node='pve1', status='stopped', config=None, pending=None, template=False, lock=None, pool=None, ostemplate=None, defaults=True)`. Unless `defaults` is false the config gets what a created container has: `hostname` (the `name`, else `CT<vmid>`), `ostype` and `arch` (worked out from `ostemplate`, else `debian` and `amd64`), `memory` 512, `swap` 512, a `rootfs` of 8G on `local-lvm`, and `unprivileged` 1.

| Attribute | Meaning |
|---|---|
| `ct.vmid`, `ct.node` | Identity and place. Assigning `ct.node` moves the container (the old path then 500s). |
| `ct.name` | The hostname: `config['hostname']`, which is also what `status/current` shows as `name`. |
| `ct.status` | `running` or `stopped`. |
| `ct.config` | The config as a dict: `rootfs`, `mp0`, `net0`, `memory`, `cores`, `lock`, `parent`, `template`, ... Values are numbers where PVE's are, else strings. |
| `ct.pending` | Changes a running container waits to apply: key to new value, or `None` for a pending delete. A start, a reboot and a rollback apply them; a stop does not. |
| `ct.snapshots` | Snapshot name to a dict: the config at the time plus `snaptime`, `description` and `snapstate`. |
| `ct.template` | `True` for a template (a property over `config['template']`); it cannot be started. |
| `ct.lock` | PVE's config lock (`backup`, `snapshot`, `migrate`, `create`, ...), a property over `config['lock']`: config writes fail with `CT is locked (name)`. |
| `ct.pool` | The pool name, if any. |
| `ct.stats` | Extra fields merged into `status/current`, overriding the defaults. |
| `ct.started_at`, `ct.pid` | When it started, from which uptime is computed, and its fake init pid; `None` when stopped. |
| `ct.checkpoint` | `True` after `suspend`: a `resume` needs it, as PVE needs the dump `lxc-checkpoint` leaves. |
| `ct.shutdown_secs` | How long the container takes to stop after a shutdown. A shutdown task fails with `container did not stop` if this exceeds its `timeout` parameter (else `pve.shutdown_default_timeout`), unless `forceStop` is set; a reboot kills it after the timeout. |
| `ct.start_secs`, `ct.stop_secs` | How long the start and stop tasks run. |
| `ct.start_error` | The start task fails with this message. |
| `ct.ha_state` | `None`, or the HA resource state, which makes the container HA managed. |
| `ct.lock_holder`, `ct.lock_released` | Internal bookkeeping of the config lock. |

Properties and methods: `ct.guest` is the id `/cluster/resources` shows (`lxc/100`); `ct.ha_managed` is true when `ha_state` is set; `ct.digest()` is the config digest (it covers pending changes and snapshots); `ct.volumes()` lists the config's volumes as `(key, mount dict)`; `ct.lock_error` is the message of a lock timeout.

`pve.ct_secs` is a dict of PVE seconds each container task takes, all `0`: `create`, `clone`, `destroy`, `snapshot`, `delsnapshot`, `rollback`, `template`, `resize` and `migrate`. With a non-zero `time_scale` the task shows as running for that long, and the container's lock (`create`, `snapshot`, `disk` on a clone's source, `migrate`, `destroyed`) stays visible meanwhile.

`pve.volume_exists(volid)` answers whether a volume (an OS template) is on its storage: `True` if it is, `False` if the storage lists other volumes of that kind (a template uploaded with `store_file(..., 'vztmpl')` or downloaded) but not this one, and `None` if the fake cannot tell (an unknown storage, or no template of the kind on it). A `False` makes the create task fail with `unable to create CT 100 - volume '...' does not exist`, as PVE's `activate_volume` does; replace the method to decide yourself.

<!-- run -->
```python
from fakepve import FakePve

pve = FakePve()
ct = pve.add_ct(100, 'web1', status='running', ostemplate='debian-12-standard_12.2-1_amd64.tar.zst')
ct.pending['memory'] = 1024
print(ct.guest, ct.name, ct.config['ostype'], ct.config['rootfs'])
print(pve.ct(100) is ct, pve.guest(100) is ct, pve.ct(999))
try:
    pve.add_ct(100, 'again')
except ValueError as exc:
    print(exc)
ct.lock = 'backup'
print(ct.config['lock'], ct.template, ct.digest() == ct.digest())
```

<!-- output -->
```text
lxc/100 web1 debian local-lvm:vm-100-disk-0,size=8G
True True None
CT 100 already exists on node 'pve1'
backup False True
```

## Time and tasks

`pve.time_scale` converts PVE seconds to real ones (default `0`; the command line defaults to `1`). At `0` every task finishes before its request returns. At any other value tasks run in the background, show `running` and hold the VM's config lock. `await pve.pause(secs)` sleeps `secs * time_scale` real seconds, and does nothing at `0`.

`await pve.task(node, ttype, tid, user, body, vm=None, lock=True, log=())` starts a task and returns its UPID. `body` is an async function; it may `pause`, can return a string to add to the log, and raises `TaskError('message')` to end the task with that exit status instead of `OK`. With a `vm` (and `lock=True`) the task holds the VM's config lock while it runs. The task record has `upid`, `node`, `pid`, `pstart`, `starttime`, `type`, `id`, `user`, `status` (`running`, then `stopped`), `exitstatus`, `endtime` and a `log` list that ends with `TASK OK` or `TASK ERROR: message`. It is stored in `pve.tasks` (by UPID) and `pve.tasklog` (in order), and served by `tasks`, `tasks/{upid}/status` and `tasks/{upid}/log`.

<!-- run -->
```python
from fakepve import FakePve, TaskError

pve = FakePve()
vm = pve.add_vm(100, 'web1')

async def good():
    return 'all done'

async def bad():
    raise TaskError('disk on fire')

ok = await pve.task('pve1', 'qmstart', 100, 'root@pam', good, vm=vm)
failed = await pve.task('pve1', 'qmstart', 100, 'root@pam', bad, vm=vm, log=['starting'])
print(pve.tasks[ok]['exitstatus'], pve.tasks[ok]['log'])
print(pve.tasks[failed]['exitstatus'], pve.tasks[failed]['log'])
print(len(pve.tasklog), ok.split(':')[1], ok.split(':')[5:8])
```

<!-- output -->
```text
OK ['all done', 'TASK OK']
disk on fire ['starting', 'disk on fire', 'TASK ERROR: disk on fire']
2 pve1 ['qmstart', '100', 'root@pam']
```

The VM config lock, which is not the `vm.lock` field: PVE serialises writes to a guest with a lock file. `await pve.acquire(vm, holder, wait=None)` takes it, waiting up to `wait` PVE seconds (default `pve.lock_wait`, 10) if someone else has it, and raises `TaskError("can't lock file '/var/lock/qemu-server/lock-100.conf' - got timeout")` if that runs out; `pve.release(vm, holder)` gives it back. `pve.lock_wait` is how long writes and tasks wait. You rarely call these directly; `hold_config_lock` is the scenario that uses them.

Two timeouts: `pve.shutdown_default_timeout` (60) is how long a shutdown task waits for the guest when the request has no `timeout`, and `pve.ha_delay` (10) is how long the HA manager takes to act on a request. `pve.ticket_ttl` and `pve.lock_wait` are covered below and above.

## Scenario methods

Each of these has a recipe in [Scenarios](scenarios.md).

| Call | Effect |
|---|---|
| `pve.backup(vmid, secs=30, user='root@pam')` | async. A `vzdump` task holds lock `backup` for `secs`. Returns the UPID. |
| `pve.migrate(vmid, target, secs=20, user='root@pam')` | async. Lock `migrate` for `secs`, then the VM lives on `target` (created if new). Returns the UPID. |
| `pve.snapshot_lock(vmid, lock='snapshot')` | Leaves the VM locked, as an interrupted snapshot, clone or rollback does. |
| `pve.unlock(vmid)` | Clears the lock. |
| `pve.hold_config_lock(vmid, secs)` | async. Another worker holds the config lock for `secs`, or until `release_config_lock(vmid)` when `secs` is `None`. Needs a non-zero `time_scale` to mean anything. |
| `pve.release_config_lock(vmid)` | Releases it. |
| `pve.lose_quorum()`, `pve.regain_quorum()` | `/etc/pve` goes read-only: VM actions and config writes fail with `cluster not ready - no quorum?`. `pve.quorate` holds the state. `pve.need_quorum()` is the check itself: it raises that error when quorum is lost. |
| `pve.set_node_offline(node, offline=True)` | Requests for the node get 595 `No route to host`. |
| `pve.slow_network(latency, jitter=0.0, node=None)` | Delays responses by `latency` plus up to `jitter` seconds, for one node or for all. |
| `pve.flaky_network(drop_rate=0.0, hang_rate=0.0, hang_secs=120, seed=None)` | Resets the connection for a share of requests, or leaves a share unanswered for `hang_secs`. `seed` makes it repeatable. |
| `pve.add_ceph_storage(name='ceph-pool', pool='rbd')` | Adds an RBD storage. |
| `pve.ceph_slow(secs, health='HEALTH_WARN')` | RBD-backed operations take `secs` longer. |
| `pve.ceph_down()`, `pve.ceph_recover()` | Ceph unreachable, then back. |
| `pve.tfa = True` | Logins answer `NeedTFA`. |
| `pve.refuse_terminal = True` | The termproxy websocket refuses the handshake and closes. |
| `pve.monitor_allowed = False` | Every `monitor` command is refused with 403 `Permission check failed (/, Sys.Modify)`. |

State behind them: `pve.network` is the dict `slow_network` and `flaky_network` fill (`latency`, `jitter`, `node_latency`, `drop_rate`, `hang_rate`, `hang_secs`, `seed`), and `pve.ceph` is `{'health', 'slow', 'down'}`. Ceph's internals are `pve.ceph_storages()` (the names of the RBD storages), `pve.on_ceph(vm, keys=None)` (does any of the VM's disks, or the given config keys, live on RBD?) and `await pve.ceph_io(vm, keys=None)`, which the start, reboot, suspend and config handlers call: it raises `TaskError` when Ceph is down and pauses when it is slow. `pve.latency` exists but nothing reads it; set the delay with `slow_network()`.

<!-- run -->
```python
from fakepve import FakePve

pve = FakePve()
pve.add_vm(100, 'web1', status='running')
pve.add_node('pve2')
pve.add_ceph_storage('ceph-pool')
pve.set_node_offline('pve2')
pve.slow_network(2, jitter=1)
pve.slow_network(10, node='pve2')
pve.flaky_network(drop_rate=0.1, seed=42)
pve.lose_quorum()
print(pve.quorate, pve.nodes['pve2'])
print(pve.network)
try:
    pve.need_quorum()
except Exception as exc:
    print(exc.status, exc.message)
pve.regain_quorum()
pve.ceph_slow(30)
print(pve.ceph, pve.ceph_storages())
pve.ceph_down()
print(pve.ceph, pve.storages['ceph-pool']['active'])
pve.ceph_recover()
print(pve.ceph, pve.storages['ceph-pool']['active'])
pve.snapshot_lock(100, 'clone')
print(pve.vm(100).lock, pve.vm(100).config['lock'])
pve.unlock(100)
print(pve.vm(100).lock)
upid = await pve.backup(100, secs=30)
print(pve.tasks[upid]['type'], pve.tasks[upid]['log'])
upid = await pve.migrate(100, 'pve3')
print(pve.vm(100).node, pve.tasks[upid]['log'])
```

<!-- output -->
```text
False {'online': False}
{'latency': 2, 'jitter': 1, 'node_latency': {'pve2': 10}, 'drop_rate': 0.1, 'hang_rate': 0.0, 'hang_secs': 120, 'seed': 42}
500 cluster not ready - no quorum?
{'health': 'HEALTH_WARN', 'slow': 30, 'down': False} {'ceph-pool'}
{'health': 'HEALTH_ERR', 'slow': 30, 'down': True} 0
{'health': 'HEALTH_OK', 'slow': 0.0, 'down': False} 1
clone clone
None
vzdump ['INFO: starting new backup job: vzdump 100', 'INFO: Finished Backup of VM 100', 'TASK OK']
pve3 ["starting migration of VM 100 to node 'pve3'", 'migration finished successfully', 'TASK OK']
```

## Access

By default there is one login and everyone who has it can do everything. These attributes and methods add users and restrict them.

- `pve.users['name@realm'] = 'password'` adds another password login. `pve.check_password(user, password)` checks one (the main `pve.user` or an entry of `users`).
- `pve.apitokens['user@realm!tokenid'] = 'secret'` registers an API token, sent as `Authorization: PVEAPIToken=user@realm!tokenid=secret`.
- `pve.grant(user, path, *privs)` gives a user privileges on a path (`/`, `/vms`, `/vms/100`, `/pool/web`, `/storage/local`, `/nodes/pve1`, ...). Grants apply to the path and everything below it; a grant on `/vms` covers every VM, and one on `/pool/web` covers the VMs in that pool. `pve.acl` holds them: `None` until the first grant, afterwards `{user: [(path, {privileges})]}`.
- `pve.allowed(user, path, priv)` answers whether a user holds a privilege on a path; `pve.require(user, path, priv)` raises the 403 `PveError` instead, in PVE's words: `Permission check failed (/vms/100, VM.PowerMgmt)`.
- While `acl` is `None` everyone is allowed everything. Once there is a grant, `root@pam` still is, and every other user needs a grant for each privilege. A token is checked as its user and as the token itself, so grants to either apply.
- `pve.issue_ticket(user)` makes a login ticket and returns `(ticket, csrf)`, valid for `pve.ticket_ttl` seconds (7200). `pve.tickets` holds them: ticket to `{'user', 'csrf', 'expires'}`. `pve.revoke_tickets()` forgets them all, so the next request is a 401.
- Task status and log (`tasks/{upid}/status` and `/log`) are readable by the task's owner (a user also sees its tokens' tasks, a token only its own) and by anyone with `Sys.Audit` on `/nodes/<node>`; others get 403, and the task list shows the same set. This is PVE's rule (`PVE/API2/Tasks.pm`).
- `PUT /access/password` follows PVE (`PVE/API2/AccessControl.pm`): API tokens are refused, the `password` must be 8 to 64 characters, `root@pam` may set any user's password, and any other user may only change their own and must give the current one as `confirmation-password` (400 without it, 500 `authentication failure` if it is wrong).

<!-- run -->
```python
from fakepve import FakePve

pve = FakePve()
pve.add_vm(100, 'web1', pool='web')
pve.add_vm(101, 'db1')
pve.users['ops@pve'] = 'pw'
print(pve.check_password('ops@pve', 'pw'), pve.check_password('ops@pve', 'no'), pve.acl)
print(pve.allowed('ops@pve', '/vms/100', 'VM.PowerMgmt'))          # nothing granted yet: allowed
pve.grant('ops@pve', '/pool/web', 'VM.PowerMgmt')
print(pve.acl)
print(pve.allowed('ops@pve', '/vms/100', 'VM.PowerMgmt'), pve.allowed('ops@pve', '/vms/101', 'VM.PowerMgmt'))
print(pve.allowed('root@pam', '/vms/101', 'VM.PowerMgmt'))
try:
    pve.require('ops@pve', '/vms/101', 'VM.PowerMgmt')
except Exception as exc:
    print(exc.status, exc.message)
pve.apitokens['ops@pve!ci'] = 'tok'
print(pve.allowed('ops@pve!ci', '/vms/100', 'VM.PowerMgmt'))
ticket, csrf = pve.issue_ticket('ops@pve')
print(ticket.startswith('PVE:ops@pve:'), pve.tickets[ticket]['user'], len(pve.tickets))
pve.revoke_tickets()
print(pve.tickets)
```

<!-- output -->
```text
True False None
True
{'ops@pve': [('/pool/web', {'VM.PowerMgmt'})]}
True False
True
403 Permission check failed (/vms/101, VM.PowerMgmt)
True
True ops@pve 1
{}
```

## Failures and errors

`pve.fail(method, suffix, status=None, message=None, html=False, error=None, times=None)` makes matching requests fail. Either give your own `status` and `message`, or `error='name'` for one of PVE's own errors (see [Errors](errors.md)). `suffix` is matched against the end of the request path, or, if it contains `{`, against a schema path such as `/nodes/{node}/qemu/{vmid}/status/stop`. `html=True` answers with a proxy's HTML page instead of JSON. `times=n` fails `n` requests and then stops; without it the failure stays until you remove it from `pve.failures`, the dict of `(method, suffix)` to rule. Giving both `error` and `status`/`message` is a `ValueError`; so is a name the method does not have, when the path is complete.

`pve.errors_for(method, path, params=None)` returns the errors a method can produce at a concrete path, as dicts with `name`, `status`, `message`, `in_task`, `source` and (for 400s) `errors`. `params` fills placeholders in the messages.

<!-- run -->
```python
from fakepve import FakePve

pve = FakePve()
pve.fail('GET', '/version', 503, 'Service Unavailable', times=2)
pve.fail('POST', '/nodes/{node}/qemu/{vmid}/status/stop', error='no_quorum')
print(list(pve.failures))
print(pve.failures[('GET', '/version')])
entries = pve.errors_for('POST', '/nodes/pve1/qemu/100/status/stop')
print(entries[0].keys())
print([e['name'] for e in entries if e['status'] == 403])
try:
    pve.fail('POST', '/nodes/pve1/qemu/100/status/stop', error='no_such_error')
except ValueError as exc:
    print(str(exc)[:80])
try:
    pve.fail('GET', '/version', 500, 'x', error='no_quorum')
except ValueError as exc:
    print(exc)
```

<!-- output -->
```text
[('GET', '/version'), ('POST', '/nodes/{node}/qemu/{vmid}/status/stop')]
{'status': 503, 'message': 'Service Unavailable', 'html': False, 'error': None, 'times': 2}
dict_keys(['name', 'status', 'message', 'errors', 'in_task', 'source'])
['permission_denied']
no error 'no_such_error' for POST /nodes/pve1/qemu/100/status/stop; known: param
give either error= or status and message
```

## What the fake records

| Attribute | Contents |
|---|---|
| `pve.requests` | The requests seen, as `(method, path, body)` with the path without its query string and the body as bytes. Assert on it to check what your client sent. It is a plain list holding the last `pve.max_requests` entries. Values of `password`, `new-password`, `confirmation-password`, `ticket`, `vncticket`, `otp` and `tfa-challenge` are recorded as `***`, bodies are cut at 64 KiB, and a request that failed to log in is recorded with an empty body, because the fake does not read the body of a request it will not serve. |
| `pve.tasks`, `pve.tasklog` | Tasks, as above. |
| `pve.tickets` | Live login tickets. |
| `pve.termdata` | The text frames the terminal websocket (termproxy) received. |
| `pve.uploaded` | The fields of the last ISO upload (`content`, `filename`, `data`, ...) as a dict. |

## Limits

The fake is a test tool, not a hardened server, but a few limits keep a misbehaving client (or a stray port scan) from using up the machine. All can be changed; set them before `start()` for the ones that shape the web application.

| Attribute | Default | Effect |
|---|---|---|
| `pve.client_max_size` | 64 MiB | Largest request body in bytes. A bigger one is answered 413 and the connection closed. Raise it before `start()` to upload bigger files. |
| `pve.body_timeout` | 30 | Real seconds a client may take to send its request body. A slower one is answered 408 and the connection closed. `0` waits for ever. |
| `pve.max_requests` | 10000 | Entries kept in `pve.requests`; the oldest are dropped. |
| `pve.vnc_ticket_ttl` | 40 | Real seconds a termproxy or VNC console ticket can open its websocket, as in PVE. A ticket opens one connection, only for the user that asked for it and only with `VM.Console`. |

A request that is not logged in is answered 401 before anything else happens: its body is not read, and `pve.fail` rules do not apply to it (see [Failures](scenarios.md#arbitrary-failures)). Network scenarios (latency, drops, hangs) still apply to everyone. An exception inside a handler is logged by the `fakepve` logger and answered as `500 internal error` without a traceback.

## Storages

`pve.storages` is a dict of storage name to a dict: the storage.cfg options as PVE returns them (`type`, `content`, `path`, `nodes`, `disable`, `shared`, `pool` for RBD, ...) plus the fake's own keys `active` (1 or 0), `files` (a set of ISO names), `volumes` (volume name to a dict with `content`, `format`, `size`, `vmid`, `notes`, `protected`) and `avail` (bytes left; without it the storage has 100 GiB). `local` (type `dir`, 50 GiB available) and `local-lvm` (type `lvmthin`) exist at the start. The storage API reads and writes this dict (see [Scenarios](scenarios.md#storage-pools-and-the-firewall)), so a test can also set it up directly. `pve.storage_config(name)` is the answer of `GET /storage/{name}`. `pve.store_file(storage, name, size, content='iso')` adds a file to a storage and reduces `avail`, or raises `TaskError` with `No space left on device` if it does not fit. `pve.file_size(path)` is `os.path.getsize`, handy for sizing an upload from a real file.

<!-- run -->
```python
from fakepve import FakePve, TaskError

pve = FakePve()
pve.storages['local']['avail'] = 100
pve.store_file('local', 'small.iso', 60)
print(pve.storages['local']['files'], pve.storages['local']['avail'])
try:
    pve.store_file('local', 'big.iso', 60)
except TaskError as exc:
    print(exc)
print(sorted(pve.storages), pve.storages['local-lvm']['type'])
```

<!-- output -->
```text
{'small.iso'} 40
unable to write to storage 'local': No space left on device
['local', 'local-lvm'] lvmthin
```

## Pools and the firewall

`pve.pools` maps a pool id to the set of guest ids in it (a guest is in one pool, and `vm.pool` follows), and `pve.pool_info` maps it to `{'comment': ..., 'storage': {ids}}`. `add_vm(..., pool='lab')` creates the pool. The firewall config is kept inside the fake; `pve.firewall_config('cluster')`, `pve.firewall_config('host', node='pve1')` and `pve.firewall_config('vm', vmid=100)` return the stored dict (`options`, `rules`, `aliases`, `ipset`, `ipset_comments`, and for the cluster `groups` and `group_comments`) for a test that wants to set it up or inspect it. The rules in it are the dicts the API shows, without `pos` and `digest`.

## Internals

These are public because the pieces call each other, but a test rarely needs them: `pve.resolve(request, prefix)` matches a request path against the schema; `pve.is_world(match, method)` says whether a method needs no login; `await pve.answer(request, match, params, user)` is the generic handler (validation, permissions, then an answer); `pve.check_permissions(user, perms, values)` evaluates a schema permission rule; `await pve.synthesise(match, method, info, user, values)` builds the answer from the schema's `returns`. [How it works](how-it-works.md) describes the flow.

## Helper modules

`fakepve.PveError(status, message, errors=None)` is an API error: the status, PVE's message and the per-field `errors` of a 400. Handlers raise it and the middleware turns it into the response. `fakepve.TaskError(message)` ends a task with that exit status.

`fakepve.schema` is the PVE API schema. `schema.load()` returns the vendored schema as a `Schema`; `Schema.match(path)` resolves a path such as `/nodes/pve1/qemu` to a `Match` with `template`, `params` and `methods`, or `None`; `Schema.children(template)` lists the literal child segments of a path template. `schema.validate(spec, values)` checks request values against a parameter schema and returns `(coerced, errors)` with PVE's wording. `schema.sample(sch, name='', ctx=None)` builds a value that satisfies a schema. `schema.is_task(method, info)` says whether a method starts a worker task.

`fakepve.errors` is the error catalogue: `catalogue()` is the raw data keyed by `'METHOD /schema/path'`; `meta()` says which PVE sources it came from; `listing(method, path)` is every error for a method as templates; `find(method, path, name)` gets one by name; `errors_for(method, path, params=None)` is the filled version `pve.errors_for` returns; `fill(template, ctx)` replaces `{placeholders}`.

<!-- run -->
```python
from fakepve import schema, errors

match = schema.load().match('/nodes/pve1/qemu/100/status/start')
print(match.template, match.params, sorted(match.methods))
print(schema.load().children('/nodes/{node}/qemu/{vmid}/status'))
spec = match.methods['POST']['parameters']
print(schema.validate(spec, {'node': 'pve1', 'vmid': 'abc'}))
print(schema.validate({'properties': {'n': {'type': 'integer', 'minimum': 5}}}, {'n': 3}))
print(schema.sample({'type': 'integer', 'minimum': 100}), schema.is_task('POST', match.methods['POST']))
print(sorted(errors.meta()), errors.meta()['errors'] > 2000)
print(errors.find('DELETE', '/nodes/pve1/qemu/100', 'running_destroy_failed')['message'])
print(errors.fill('VM {vmid} on {node} is {adjective}', {'vmid': 100}))
print(len(errors.catalogue()) > 400, errors.listing('GET', '/nodes/nope/none'))
```

<!-- output -->
```text
/nodes/{node}/qemu/{vmid}/status/start {'node': 'pve1', 'vmid': '100'} ['POST']
['current', 'reboot', 'reset', 'resume', 'shutdown', 'start', 'stop', 'suspend']
({'node': 'pve1', 'vmid': 'abc'}, {'vmid': "type check ('integer') failed - got 'abc'"})
({'n': 3}, {'n': 'value must have a minimum value of 5'})
100 True
['date', 'errors', 'in_task', 'methods_with_errors', 'registered_methods', 'repos', 'unmapped'] True
VM {vmid} is running - destroy failed
VM 100 on pve1 is fake
True []
```

<!-- BEGIN GENERATED: signatures (tools/gen_docs.py) -->

## Signature index

Generated by `tools/gen_docs.py` from the code. Do not edit between the markers; the explanations above and below are written by hand.

Names exported by `fakepve`: `PORT`, `FakeCt`, `FakePve`, `FakeVm`, `PveError`, `TaskError`, `next_loopback`, `settle`.

### FakePve

Constructor: `FakePve(user='root@pam', password='secret', host=None, port=8006)`

| Method | What it does |
|---|---|
| `add_vm(*args, **kwargs)` | Add a FakeVm (arguments as FakeVm's) and its node; returns the VM. |
| `add_node(name, online=True)` | Add a node to the cluster. |
| `vm(vmid)` | The VM with this id, or None. |
| `find(node, vmid)` | The VM on this node, or a PveError (500, as PVE: no config file). |
| `async pause(secs)` | Sleep secs PVE seconds (scaled by time_scale; nothing at 0). |
| `async acquire(vm, holder, wait=None)` | Take the VM config lock, waiting up to lock_wait PVE seconds. |
| `release(vm, holder)` | Release the VM config lock if holder has it. |
| `async task(node, ttype, tid, user, body, vm=None, lock=True, log=())` | Start a task; returns its UPID. body() may pause, and raises TaskError to fail. |
| `issue_ticket(user)` | Make a login ticket; returns (ticket, csrf token). |
| `check_password(user, password)` | True if the password is right for user (pve.user, or an entry of pve.users). |
| `grant(user, path, *privs)` | Give user the privileges on path ('/', '/vms', '/vms/100', '/pool/name', '/storage/x', ...). |
| `allowed(user, path, priv)` | True if user holds priv on path. Everyone does until the first grant(); root@pam always does. |
| `require(user, path, priv)` | Like allowed(), but raises a 403 PveError in PVE's wording. |
| `lose_quorum()` | /etc/pve goes read-only: config writes and VM actions fail, reads work. |
| `regain_quorum()` | Undo lose_quorum(). |
| `need_quorum()` | Raise PVE's no-quorum error (500) if quorum is lost. |
| `set_node_offline(node, offline=True)` | Take a node offline (requests for it get 595), or bring it back with offline=False. |
| `async hold_config_lock(vmid, secs)` | Another task holds the VM config lock for secs PVE seconds (or until release_config_lock). |
| `release_config_lock(vmid)` | Release a lock taken by hold_config_lock(). |
| `async backup(vmid, secs=30, user='root@pam')` | A vzdump of the VM: lock 'backup' for secs PVE seconds. |
| `async migrate(vmid, target, secs=20, user='root@pam')` | Migrate the VM to target: lock 'migrate' for secs PVE seconds, then it lives there. |
| `snapshot_lock(vmid, lock='snapshot')` | Leave the VM locked, as an interrupted snapshot, clone or rollback does. |
| `unlock(vmid)` | Clear the VM's lock. |
| `add_ceph_storage(name='ceph-pool', pool='rbd')` | An RBD storage; VMs with disks on it feel the Ceph scenarios. |
| `ceph_slow(secs, health='HEALTH_WARN')` | Every RBD-backed operation takes secs PVE seconds longer (slow OSDs, recovery). |
| `ceph_down()` | Ceph unreachable: RBD storages inactive, RBD-backed starts and disk changes fail. |
| `ceph_recover()` | Undo ceph_down() and ceph_slow(). |
| `ceph_storages()` | Names of the RBD storages. |
| `on_ceph(vm, keys=None)` | True if any of the VM's disks (or of keys) live on RBD. |
| `async ceph_io(vm, keys=None)` | Apply the Ceph scenarios to an operation on the VM's disks. |
| `slow_network(latency, jitter=0.0, node=None)` | Add latency (and random jitter) to every response, or to one node's. |
| `flaky_network(drop_rate=0.0, hang_rate=0.0, hang_secs=120, seed=None)` | Drop (connection reset) or hang (no answer) a share of requests. |
| `fail(method, suffix, status=None, message=None, html=False, error=None, times=None)` | Answer requests whose path ends with suffix with an error. |
| `errors_for(method, path, params=None)` | The errors a method can return at a concrete path: dicts with name, status, message, errors, in_task and source. Any of the names can be given to fail(error=...). |
| `revoke_tickets()` | Forget every login ticket: the next request gets 401. |
| `store_file(storage, name, size, content='iso')` | Add a file (an ISO, by default) to a storage, or raise TaskError if it does not fit in 'avail'. |
| `file_size(path)` | Size of a local file in bytes. |
| `add_ct(*args, **kwargs)` | Add a FakeCt (arguments as FakeCt's) and its node; returns the container. |
| `ct(vmid)` | The container with this id, or None. |
| `guest(vmid)` | The VM or container with this id, or None. |
| `ct_resources(user, kind=None)` | The containers as /cluster/resources lists them. |
| `resolve(request, prefix)` | The schema match of a request path, or None. |
| `is_world(match, method)` | True if the method needs no login. |
| `async answer(request, match, params, user, call=None)` | The data for a request: checked against the schema, then call(match, values) or a value from `returns`. |
| `check_permissions(user, perms, values, declared=None)` | Raise a 403 PveError unless user satisfies the schema's permission rule. |
| `async synthesise(match, method, info, user, values)` | The answer for a generic method: a task UPID, or a value built from its `returns`. |
| `firewall_config(scope, node=None, vmid=None)` | The stored firewall config of 'cluster', a node ('host') or a guest ('vm' or 'ct'). |
| `storage_config(name)` | The storage as GET /storage/{storage} shows it. |
| `volume_exists(volid)` | True or False if the fake knows whether a volume (an OS template) is on its storage, else None. |
| `url` (property) | The address the fake listens on, https://host:port (the real port once started with port 0). |
| `async start(certfile, keyfile)` | Listen on https://host:port with this certificate and key (PEM files). |
| `async stop()` | Stop listening. |

Attributes after construction:

| Attribute | Initial value |
|---|---|
| `user` | `'root@pam'` |
| `password` | `'secret'` |
| `users` | `{}` |
| `vms` | `[]` |
| `nodes` | `{'pve1': {'online': True}}` |
| `cluster_name` | `'fakecluster'` |
| `version` | `'9.0.10'` |
| `release_version` | `'9.0'` |
| `time_scale` | `0.0` |
| `latency` | `0.0` |
| `ticket_ttl` | `7200` |
| `vnc_ticket_ttl` | `40` |
| `lock_wait` | `10` |
| `shutdown_default_timeout` | `60` |
| `ha_delay` | `10` |
| `quorate` | `True` |
| `tfa` | `False` |
| `refuse_terminal` | `False` |
| `apitokens` | `{}` |
| `acl` | `None` |
| `pools` | `{}` |
| `pool_info` | `{}` |
| `storages` | `{'local': {'type': 'dir', 'active': 1, 'content': 'iso,vztmpl,backup', 'files': set(), ...` |
| `network` | `{'latency': 0.0, 'jitter': 0.0, 'node_latency': {}, 'drop_rate': 0.0, 'hang_rate': 0.0,...` |
| `ceph` | `{'health': 'HEALTH_OK', 'slow': 0.0, 'down': False}` |
| `tickets` | `{}` |
| `tasks` | `{}` |
| `tasklog` | `[]` |
| `requests` | `[]` |
| `max_requests` | `10000` |
| `failures` | `{}` |
| `cts` | `[]` |
| `ct_secs` | `{'create': 0, 'clone': 0, 'destroy': 0, 'snapshot': 0, 'delsnapshot': 0, 'rollback': 0,...` |
| `host` | `'127.0.0.2'` |
| `port` | `8006` |
| `runner` | `None` |
| `termdata` | `[]` |
| `monitor_allowed` | `True` |
| `uploaded` | `None` |
| `client_max_size` | `67108864` |
| `body_timeout` | `30.0` |

### FakeVm

Constructor: `FakeVm(vmid, name, node='pve1', status='stopped', qmpstatus=None, config=None, pending=None, template=False, lock=None, pool=None)`

| Method | What it does |
|---|---|
| `guest` (property) | The id as /cluster/resources shows it: qemu/<vmid>. |
| `ha_managed` (property) | True if ha_state is set. |
| `apply_pending()` | Move the pending config into the config (a start or reboot does this). |
| `digest()` | The config digest PVE's clients pass back to detect concurrent changes. |
| `devices(cfg=None)` | Keys of the config that are devices (disks, nics, usb, pci). |

Attributes after construction:

| Attribute | Initial value |
|---|---|
| `vmid` | `100` |
| `name` | `'vm'` |
| `node` | `'pve1'` |
| `status` | `'stopped'` |
| `qmpstatus` | `'stopped'` |
| `config` | `{'name': 'vm'}` |
| `pending` | `{}` |
| `template` | `False` |
| `lock` | `None` |
| `pool` | `None` |
| `stats` | `{}` |
| `started_at` | `None` |
| `nmis` | `0` |
| `agent` | `None` |
| `agent_hangs` | `False` |
| `agent_requests` | `[]` |
| `agent_frozen` | `False` |
| `agent_pid` | `1000` |
| `agent_execs` | `{}` |
| `acpi` | `True` |
| `shutdown_secs` | `0` |
| `start_secs` | `0` |
| `stop_secs` | `0` |
| `start_error` | `None` |
| `ha_state` | `None` |
| `lock_holder` | `None` |
| `lock_released` | `None` |

### FakeCt

Constructor: `FakeCt(vmid, name=None, node='pve1', status='stopped', config=None, pending=None, template=False, lock=None, pool=None, ostemplate=None, defaults=True)`

| Method | What it does |
|---|---|
| `name` (property) | The hostname, which is the name PVE lists. |
| `lock` (property) | The config lock: backup, migrate, snapshot, create, ... |
| `template` (property) | True for a template. |
| `guest` (property) | The id as /cluster/resources shows it: lxc/<vmid>. |
| `ha_managed` (property) | True if ha_state is set. |
| `lock_error` (property) |  |
| `digest()` | The config digest clients pass back to detect concurrent changes. |
| `volumes(cfg=None)` | (key, mount dict) of the config's volumes, not bind or device mounts. |

Attributes after construction:

| Attribute | Initial value |
|---|---|
| `vmid` | `100` |
| `node` | `'pve1'` |
| `status` | `'stopped'` |
| `config` | `{'hostname': 'ct', 'ostype': 'debian', 'arch': 'amd64', 'memory': 512, 'swap': 512, 'ro...` |
| `pending` | `{}` |
| `snapshots` | `{}` |
| `pool` | `None` |
| `stats` | `{}` |
| `started_at` | `None` |
| `pid` | `None` |
| `checkpoint` | `False` |
| `shutdown_secs` | `0` |
| `start_secs` | `0` |
| `stop_secs` | `0` |
| `start_error` | `None` |
| `ha_state` | `None` |
| `lock_holder` | `None` |
| `lock_released` | `None` |

### Exceptions

| Class | Meaning |
|---|---|
| `PveError(status, message, errors=None)` | An API error as PVE reports it: status, message and per-field errors. |
| `TaskError(message)` | A task ending with this exit status instead of OK. |

### fakepve (module functions)

| Function | What it does |
|---|---|
| `next_loopback()` | The next unused loopback address, so each instance can use port 8006. |
| `async settle()` | Let spawned tasks run. |

### fakepve.certs

| Function | What it does |
|---|---|
| `make_cert(directory, name='fakepve', hosts=())` | Write <name>.crt and <name>.key into directory; returns (certfile, keyfile, der). |

### fakepve.errors

| Function | What it does |
|---|---|
| `catalogue()` | {'<METHOD> <schema path>': [error, ...]} as extracted from the PVE sources. |
| `errors_for(method, path, params=None)` | The errors a method can return at a concrete path, as filled entries. |
| `find(method, path, name)` | The error called name for a method and path, or None. |
| `fill(template, ctx)` | Replace {name} in a message template from ctx, else a plausible value. |
| `listing(method, path)` | Every error a method can return as templates: the catalogue's, then the cross-cutting ones. |
| `meta()` | Where the catalogue came from: repositories with commits, date, counts. |

### fakepve.schema

| Function | What it does |
|---|---|
| `load()` | The vendored PVE schema, as a Schema. |
| `validate(spec, values)` | Check request values against a method's parameter schema. |
| `sample(sch, name='', ctx=None, optional=())` | A value that satisfies a schema. ctx maps property names to preferred values. |
| `is_task(method, info)` | True if the method starts a worker task and so answers with a UPID. |

### fakepve.schema.Schema

| Method | What it does |
|---|---|
| `match(path)` | Resolve '/nodes/pve1/qemu' to a Match, or None. |
| `children(template)` | Literal child segments of a path template. |

<!-- END GENERATED: signatures -->
