# fakepve

A lightweight fake of the Proxmox VE API, for testing code that drives Proxmox without needing a cluster, and for putting that code through the things a real cluster does to it: slow shutdowns, locked VMs, lost quorum, flaky networks, Ceph trouble.

It answers like PVE 8/9 does: tickets with CSRF tokens and expiry, API tokens, optional per-path permissions, tasks with real UPIDs that run, hold the VM config lock and keep a log, pending config on running VMs, config digests, and the termproxy and VNC websockets. Errors carry PVE's status codes and its own wording, so a client's error handling is tested against what it will really see.

Depends only on aiohttp. `cryptography` is optional, for a self-signed certificate and VNC authentication.

## Install

```console
pip install .            # aiohttp only
pip install '.[crypto]'  # plus cryptography
```

## Run it

```console
python -m fakepve examples/guests.json --host 127.0.0.2
fakepve listening on https://127.0.0.2:8006
```

Log in as `root@pam` / `secret` (`--user`, `--password`, or `PVE_USER` / `PVE_PASS`). Without `--cert`/`--key` a self-signed certificate is made. Each instance gets its own loopback address by default, so several fakes can all use port 8006 at once.

## Time

Durations are in PVE seconds. `time_scale` turns them into real ones:

- `0` (the default in code): every task finishes before the request returns. Fast, deterministic unit tests.
- `0.01`: a 60s shutdown takes 0.6s; tasks show as running, hold the config lock, and other requests queue behind them as they would on PVE.
- `1` (the CLI default): real time.

## Use it from tests

```python
from fakepve import FakePve
from fakepve.certs import make_cert

async def test_shutdown(tmp_path):
    certfile, keyfile, _ = make_cert(str(tmp_path))
    pve = FakePve(user='root@pam', password='secret')
    vm = pve.add_vm(100, 'vm1', status='running', config={'scsi0': 'local-lvm:vm-100-disk-0'})
    vm.shutdown_secs = 90           # slower than PVE's default shutdown timeout
    await pve.start(certfile, keyfile)
    try:
        ...  # drive https://{pve.host}:8006 with your client
    finally:
        await pve.stop()
```

All state is plain and inspectable: `vm.config`, `vm.pending`, `vm.status` / `vm.qmpstatus`, `vm.lock`, `vm.node`, `pve.tasklog`, `pve.storages`, `pve.requests` (every request seen).

## Scenarios

### VMs and tasks

| Call / setting | What happens |
|---|---|
| `vm.shutdown_secs = s` | the guest takes s seconds to power off; a shutdown task fails with `VM quit/powerdown failed - got timeout` if that's longer than its timeout (`timeout` parameter, else `pve.shutdown_default_timeout`); `forceStop=1` stops it instead |
| `vm.acpi = False` | the guest ignores shutdown and reboot |
| `vm.start_secs`, `vm.stop_secs` | how long the start and stop tasks run |
| `vm.start_error = 'msg'` | the start task fails with msg (a missing disk, a bad device) |
| `pve.backup(vmid, secs)` | a vzdump holds lock `backup`: start, shutdown, reboot and config writes get `VM is locked (backup)` |
| `pve.snapshot_lock(vmid, lock)` / `pve.unlock(vmid)` | a lock left behind by an interrupted snapshot, clone or rollback |
| `pve.hold_config_lock(vmid, secs)` | another task holds the config lock: writes and tasks wait `pve.lock_wait` seconds, then fail with `can't lock file '/var/lock/qemu-server/lock-N.conf' - got timeout` |
| `pve.migrate(vmid, node, secs)` | lock `migrate` while it runs, then the VM lives on the other node |
| `vm.ha_state = 'stopped'` | HA-managed: start and stop file a request (`hastart` / `hastop`) and the VM changes `pve.ha_delay` seconds later |
| `suspend` with `todisk=1` | hibernation: stopped with lock `suspended`; start resumes it |
| `vm.agent = {...}`, `vm.agent_hangs = True` | guest agent answers, is absent (`QEMU guest agent is not running`), or times out |

### The cluster

| Call / setting | What happens |
|---|---|
| `pve.lose_quorum()` / `pve.regain_quorum()` | VM actions and config writes fail with `cluster not ready - no quorum?`; reads still work; `/cluster/status` shows `quorate: 0` |
| `pve.set_node_offline(node)` | requests for that node get 595 `No route to host`; its VMs show as `unknown` in `/cluster/resources` |
| `pve.storages[name]['avail'] = bytes` | downloads and uploads beyond it fail with `No space left on device` |

### Network

| Call | What happens |
|---|---|
| `pve.slow_network(latency, jitter)` | every response is delayed (PVE seconds, scaled) |
| `pve.slow_network(latency, node='pve2')` | only requests for that node are slow |
| `pve.flaky_network(drop_rate, hang_rate, hang_secs, seed)` | a share of requests have their connection reset, or get no answer for hang_secs |

### Ceph

| Call | What happens |
|---|---|
| `pve.add_ceph_storage('ceph-pool')` | an RBD storage; VMs with disks on it feel the Ceph scenarios |
| `pve.ceph_slow(secs)` | every RBD-backed start, reboot and disk change takes secs longer; health `HEALTH_WARN` |
| `pve.ceph_down()` / `pve.ceph_recover()` | RBD storages go inactive, RBD-backed starts and disk changes fail with `rbd error: ... couldn't connect to the cluster`, content listings fail, `/cluster/ceph/status` errors |

### Access

| Call / setting | What happens |
|---|---|
| `pve.users['ops@pve'] = 'pw'`, `pve.grant(user, path, *privs)` | per-path permissions on `/`, `/vms`, `/vms/N`, `/pool/X`, `/storage/X`; missing rights get 403 `Permission check failed (/vms/100, VM.Config.CPU)` |
| `pve.apitokens['user@pve!id'] = secret` | API token logins |
| `pve.ticket_ttl` | ticket lifetime (PVE: 2 hours); expired tickets get 401 |
| `pve.tfa = True` | logins need two-factor authentication |
| `pve.fail(method, path_suffix, status, message, html=False)` | any request answered with an error, or a non-JSON proxy page |

## API behaviour

- Config writes on a running VM go to pending unless the key is hot-pluggable; a CD-ROM media change applies at once; `reboot` and a cold start apply pending, `reset` doesn't.
- `PUT config` checks the `digest`, validates the boot order against the VM's devices (400 with per-field `errors`), and checks the right privilege per key; `hookscript` is root-only.
- Starting a running VM, or acting on a stopped one, gets PVE's messages (`VM 100 already running`, `VM 100 not running`); templates can't be started; unknown actions get 501.
- Task status shows `running` until the task ends, then `stopped` with `exitstatus`; the task log ends with `TASK OK` or `TASK ERROR: ...`. Without Sys.Audit a user only sees their own tasks.

## Endpoints

Every endpoint in the PVE 9 API schema answers: 680 methods on 449 paths, under `/api2/json`. The `/api2/extjs` prefix is not served.

Some areas are stateful, modelled by hand: `access/ticket`, `access/password`, `version`, `nodes`, `cluster/resources`, `cluster/status`, `cluster/ceph/status`; per node: `tasks`, `tasks/{upid}/status`, `tasks/{upid}/log`, `storage`, `storage/{s}/content`, `storage/{s}/download-url`, `storage/{s}/upload`; per VM: `status/current`, `status/{start,stop,shutdown,reboot,reset,suspend,resume}`, `config` (GET, PUT, and POST as a task), `pending`, `termproxy`, `vncproxy`, `vncwebsocket`, `agent/{get-osinfo,network-get-interfaces,ping}`, `monitor`.

Everything else is answered from the schema and keeps no state: a write succeeds but changes nothing, and a read returns a value of the right shape (outcomes and errors, not behaviour). The generic answers:

- check parameters, path parameters included, with PVE's own wording: HTTP 400 and `{"data": null, "errors": {"vmid": "value must have a minimum value of 100"}}`. Missing and undefined properties, enums, types (booleans take 0/1, true/false, yes/no, on/off), minimum and maximum, length and pattern are checked.
- check permissions as the schema states them (`perm` with `any`, `and`, `or`, `userid-param`, `userid-group`, `perm-modify`, and `user: all` or `world`) against `pve.grant`, with `{param}` filled in. 403 reads `Permission check failed (/vms/100, VM.PowerMgmt)`. A method with no permissions in the schema, or a form not known here, is root only.
- build the result from the schema's `returns`: required properties are filled, lists have one item, numbers are their minimum. Values come from the request path and the model where they can (node, vmid, storage).
- start a real task for methods that return a UPID, so `tasks/{upid}/status` and `/log` work (they finish at once with `OK`).
- record the request in `pve.requests`.

Paths not in the schema get 404, and a method the schema does not have on a known path gets 501. A node name the model does not know gets 500 `hostname lookup ... failed`.

### Refreshing the schema

The schema is the PVE API viewer's `apidoc.js`, trimmed of prose and stored in `src/fakepve/data/pve-api.json.gz`; `pve-api.meta.json` beside it records the source, date and hash.

```console
python tools/fetch_schema.py [URL_OR_FILE]
```

Run it, commit the two files, and run the tests: the coverage test sends a valid request to every method in the schema and checks the answer against `returns`.

## Licence

Apache 2.0.
