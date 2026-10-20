# Scenarios

A cookbook of the things a real cluster does to a client, and how to make the fake do them. Each recipe is a runnable snippet followed by exactly what the client sees. The snippets and their output are run by the test suite, so they cannot drift from the code.

Contents: [setup](#setup) | [shutdowns](#shutdowns-and-slow-guests) | [start and stop](#start-stop-and-task-failures) | [locks](#locks) | [backup](#backup) | [migration](#migration) | [HA](#high-availability) | [quorum](#lost-quorum) | [node offline](#node-offline) | [network](#slow-and-flaky-networks) | [Ceph](#ceph) | [storage](#storage-full) | [storage, pools, firewall](#storage-pools-and-the-firewall) | [permissions](#permissions) | [tickets](#expired-tickets-and-tokens) | [TFA](#two-factor-authentication) | [fail](#arbitrary-failures) | [catalogue](#errors-by-catalogue-name) | [guest agent](#guest-agent) | [pending](#pending-changes) | [containers](#containers)

## Setup

All recipes use this small harness: a started fake, and a bare client that logs in, sends the CSRF header on writes and returns `(status, body)`. It is plain aiohttp; use whatever client you like (see [Getting started](getting-started.md) for curl and [CI](ci.md) for pytest).

Two things to know about times. Every duration is in PVE seconds, and `pve.time_scale` converts them to real ones: `0` (the default for the class) finishes every task before the request returns, `0.01` makes 60 PVE seconds take 0.6 real ones and lets tasks show as `running`. The recipes use `0.01` where the wait matters.

<!-- run -->
```python
import asyncio
import contextlib
import json
import ssl
import tempfile

import aiohttp

from fakepve import FakePve, settle
from fakepve.certs import make_cert

CERT = make_cert(tempfile.mkdtemp())


class Api:
    """A bare PVE client: ticket login, CSRF on writes, (status, body) back."""

    def __init__(self, session):
        self.session = session
        self.headers = {}

    async def login(self, user='root@pam', password='secret'):
        status, body = await self.call('POST', '/access/ticket', {'username': user, 'password': password})
        data = (body or {}).get('data') or {}
        if status == 200 and not data.get('NeedTFA'):
            self.headers = {'Cookie': 'PVEAuthCookie=' + data['ticket'],
                            'CSRFPreventionToken': data['CSRFPreventionToken']}
        return status, body

    async def call(self, method, path, data=None):
        kwargs = {'headers': self.headers}
        if data is not None:
            kwargs['params' if method in ('GET', 'DELETE') else 'data'] = data
        async with self.session.request(method, '/api2/json' + path, **kwargs) as rsp:
            return rsp.status, await rsp.json(content_type=None)

    async def wait(self, upid, node='pve1'):
        """Poll a task until it has stopped; returns its status."""
        while True:
            status, body = await self.call('GET', '/nodes/{0}/tasks/{1}/status'.format(node, upid))
            if body['data']['status'] == 'stopped':
                return body['data']
            await asyncio.sleep(0.01)

    async def log(self, upid, node='pve1'):
        status, body = await self.call('GET', '/nodes/{0}/tasks/{1}/log'.format(node, upid))
        return [line['t'] for line in body['data']]


@contextlib.asynccontextmanager
async def fake(login=True, **attrs):
    """A started FakePve with attributes set from keywords, and a logged-in client."""
    pve = FakePve(user='root@pam', password='secret')
    for name, value in attrs.items():
        setattr(pve, name, value)
    await pve.start(CERT[0], CERT[1])
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        async with aiohttp.ClientSession(base_url='https://{0}:{1}'.format(pve.host, pve.port),
                                         connector=aiohttp.TCPConnector(ssl=ctx)) as session:
            api = Api(session)
            if login:
                await api.login()
            yield pve, api
    finally:
        await settle()
        await pve.stop()


def show(result):
    status, body = result
    print(status, json.dumps(body))

```

## Shutdowns and slow guests

PVE gives up on a shutdown after its timeout (the `timeout` parameter, else 60 seconds in the fake: `pve.shutdown_default_timeout`). A guest that needs longer than that is a classic source of broken automation. `vm.shutdown_secs` is how long the guest takes to power off after the ACPI request.

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    vm = pve.add_vm(100, 'web1', status='running')
    vm.shutdown_secs = 90
    status, upid = await api.call('POST', '/nodes/pve1/qemu/100/status/shutdown')
    print(status, 'task started')
    task = await api.wait(upid['data'])
    print(task['exitstatus'], '| VM is', vm.status)
    print(await api.log(upid['data']))
```

<!-- output -->
```text
200 task started
VM quit/powerdown failed - got timeout | VM is running
['VM quit/powerdown failed - got timeout', 'TASK ERROR: VM quit/powerdown failed - got timeout']
```

The client has to raise the timeout, or ask for a forced stop. With a longer `timeout` the same guest shuts down cleanly; with `forceStop=1` PVE terminates it once the timeout passes and the task still ends `OK`:

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    vm = pve.add_vm(100, 'web1', status='running')
    vm.shutdown_secs = 90
    _, upid = await api.call('POST', '/nodes/pve1/qemu/100/status/shutdown', {'timeout': 120})
    print((await api.wait(upid['data']))['exitstatus'], vm.status)

    vm2 = pve.add_vm(101, 'web2', status='running')
    vm2.acpi = False                      # the guest ignores ACPI altogether
    _, upid = await api.call('POST', '/nodes/pve1/qemu/101/status/shutdown', {'forceStop': 1})
    print((await api.wait(upid['data']))['exitstatus'], vm2.status)
    print(await api.log(upid['data']))
```

<!-- output -->
```text
OK stopped
OK stopped
['VM still running - terminating now with SIGTERM', 'TASK OK']
```

`vm.acpi = False` alone (no `forceStop`) makes `shutdown` and `reboot` wait the whole timeout and fail with `VM quit/powerdown failed - got timeout`.

## Start, stop and task failures

A task that fails still starts: the request succeeds with a UPID, and the failure appears in the task's `exitstatus` and log, which is where real clients get caught out. `vm.start_error` makes the start task fail (a missing disk, a bad device); `vm.start_secs` and `vm.stop_secs` set how long the tasks run.

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    vm = pve.add_vm(100, 'web1')
    vm.start_error = "volume 'local-lvm:vm-100-disk-0' does not exist"
    vm.start_secs = 3
    status, body = await api.call('POST', '/nodes/pve1/qemu/100/status/start')
    print(status, 'request accepted')
    task = await api.wait(body['data'])
    print(task['status'], task['exitstatus'])
    print(await api.log(body['data']))
    _, current = await api.call('GET', '/nodes/pve1/qemu/100/status/current')
    print(current['data']['status'])
```

<!-- output -->
```text
200 request accepted
stopped volume 'local-lvm:vm-100-disk-0' does not exist
["volume 'local-lvm:vm-100-disk-0' does not exist", "TASK ERROR: volume 'local-lvm:vm-100-disk-0' does not exist"]
stopped
```

Asking for something the VM's state does not allow is refused up front, with PVE's wording:

<!-- run -->
```python
async with fake() as (pve, api):
    pve.add_vm(100, 'web1', status='running')
    pve.add_vm(101, 'web2')
    pve.add_vm(9000, 'tmpl', template=True)
    show(await api.call('POST', '/nodes/pve1/qemu/100/status/start'))
    show(await api.call('POST', '/nodes/pve1/qemu/101/status/shutdown'))
    show(await api.call('POST', '/nodes/pve1/qemu/9000/status/start'))
    show(await api.call('POST', '/nodes/pve1/qemu/100/status/nonsense'))
```

<!-- output -->
```text
500 {"data": null, "message": "VM 100 already running\n"}
500 {"data": null, "message": "VM 101 not running\n"}
500 {"data": null, "message": "you can't start a vm if it's a template\n"}
501 {"data": null, "message": "Method 'POST /nodes/pve1/qemu/100/status/nonsense' not implemented\n"}
```

## Locks

PVE puts a `lock` on a guest while a backup, snapshot, clone, migration or hibernation is working on it. A lock left behind by an interrupted operation is a common real-world fault.

<!-- run -->
```python
async with fake() as (pve, api):
    pve.add_vm(100, 'web1', status='running')
    pve.snapshot_lock(100, 'snapshot')    # also: 'clone', 'rollback', 'backup', ...
    show(await api.call('POST', '/nodes/pve1/qemu/100/status/reboot'))
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048}))
    _, current = await api.call('GET', '/nodes/pve1/qemu/100/status/current')
    print('lock:', current['data']['lock'])
    pve.unlock(100)
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048}))
```

<!-- output -->
```text
500 {"data": null, "message": "VM is locked (snapshot)\n"}
500 {"data": null, "message": "VM is locked (snapshot)\n"}
lock: snapshot
200 {"data": null}
```

A different thing is the internal config lock that any running task holds. `pve.hold_config_lock(vmid, secs)` makes another worker hold it. Writes and tasks wait `pve.lock_wait` PVE seconds for it (10 by default), then fail as PVE does. This needs a non-zero `time_scale`, because at `0` nothing is ever "in progress":

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    pve.add_vm(100, 'web1')
    await pve.hold_config_lock(100, 60)     # held for 60 PVE seconds
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048}))
    _, body = await api.call('POST', '/nodes/pve1/qemu/100/status/start')
    task = await api.wait(body['data'])
    print(task['exitstatus'])
    await asyncio.sleep(0.5)                # the lock is released after 60 PVE seconds
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048}))
```

<!-- output -->
```text
500 {"data": null, "message": "can't lock file '/var/lock/qemu-server/lock-100.conf' - got timeout\n"}
can't lock file '/var/lock/qemu-server/lock-100.conf' - got timeout
200 {"data": null}
```

`await pve.hold_config_lock(vmid, None)` holds it until you call `pve.release_config_lock(vmid)`.

## Backup

`pve.backup(vmid, secs)` starts a `vzdump` task that holds lock `backup` for `secs` PVE seconds. Start, shutdown, reboot and config writes are refused while it runs.

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    pve.add_vm(100, 'web1', status='running')
    upid = await pve.backup(100, secs=60)
    show(await api.call('POST', '/nodes/pve1/qemu/100/status/shutdown'))
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048}))
    task = await api.wait(upid)
    print(task['type'], task['exitstatus'])
    print(await api.log(upid))
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048}))
```

<!-- output -->
```text
500 {"data": null, "message": "VM is locked (backup)\n"}
500 {"data": null, "message": "VM is locked (backup)\n"}
vzdump OK
['INFO: starting new backup job: vzdump 100', 'INFO: Finished Backup of VM 100', 'TASK OK']
200 {"data": null}
```

## Migration

`pve.migrate(vmid, target, secs)` holds lock `migrate` while it runs. When it finishes the VM lives on the target node, and the old path stops working.

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    pve.add_node('pve2')
    pve.add_vm(100, 'web1', status='running')
    upid = await pve.migrate(100, 'pve2', secs=20)
    show(await api.call('POST', '/nodes/pve1/qemu/100/status/stop'))
    task = await api.wait(upid)
    print(task['exitstatus'], '| now on', pve.vm(100).node)
    show(await api.call('GET', '/nodes/pve1/qemu/100/status/current'))
    status, body = await api.call('GET', '/nodes/pve2/qemu/100/status/current')
    print(status, body['data']['status'])
```

<!-- output -->
```text
500 {"data": null, "message": "VM is locked (migrate)\n"}
OK | now on pve2
500 {"data": null, "message": "Configuration file 'nodes/pve1/qemu-server/100.conf' does not exist\n"}
200 running
```

## High availability

A VM with `vm.ha_state` set is HA managed. A start or stop files a request (task types `hastart` and `hastop`) and the VM changes `pve.ha_delay` PVE seconds later, as the HA manager would do it. A client that checks the status straight after the task ends sees the old state.

<!-- run -->
```python
async with fake(time_scale=0.01, ha_delay=10) as (pve, api):
    vm = pve.add_vm(100, 'web1')
    vm.ha_state = 'stopped'
    _, body = await api.call('POST', '/nodes/pve1/qemu/100/status/start')
    task = await api.wait(body['data'])
    print(task['type'], task['exitstatus'], '| VM is', vm.status, '| ha', vm.ha_state)
    print(await api.log(body['data']))
    await asyncio.sleep(0.2)
    print('later: VM is', vm.status, '| ha', vm.ha_state)
    _, current = await api.call('GET', '/nodes/pve1/qemu/100/status/current')
    print(current['data']['ha'])
```

<!-- output -->
```text
hastart OK | VM is stopped | ha stopped
['Requesting HA start for VM 100', 'TASK OK']
later: VM is running | ha started
{'managed': 1, 'state': 'started'}
```

## Lost quorum

`pve.lose_quorum()` puts `/etc/pve` read-only: VM actions and config writes fail, reads keep working, and `/cluster/status` reports `quorate: 0`.

<!-- run -->
```python
async with fake() as (pve, api):
    pve.add_vm(100, 'web1')
    pve.lose_quorum()
    show(await api.call('POST', '/nodes/pve1/qemu/100/status/start'))
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048}))
    _, status = await api.call('GET', '/cluster/status')
    print(status['data'][0])
    pve.regain_quorum()
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048}))
```

<!-- output -->
```text
500 {"data": null, "message": "cluster not ready - no quorum?\n"}
500 {"data": null, "message": "cluster not ready - no quorum?\n"}
{'type': 'cluster', 'id': 'cluster', 'name': 'fakecluster', 'nodes': 1, 'quorate': 0, 'version': 1, 'online': 1}
200 {"data": null}
```

## Node offline

`pve.set_node_offline(node)` makes every request for that node fail with status 595 `No route to host` (PVE's proxy status when it cannot reach the node). Its VMs show as `unknown` in `/cluster/resources`.

<!-- run -->
```python
async with fake() as (pve, api):
    pve.add_node('pve2')
    pve.add_vm(100, 'web1', node='pve2', status='running')
    pve.set_node_offline('pve2')
    show(await api.call('GET', '/nodes/pve2/qemu/100/status/current'))
    _, res = await api.call('GET', '/cluster/resources', {'type': 'vm'})
    print([(r['name'], r['status']) for r in res['data']])
    _, nodes = await api.call('GET', '/nodes')
    print(nodes['data'])
    pve.set_node_offline('pve2', False)
    show(await api.call('GET', '/nodes/pve2/qemu/100/status/current'))
```

<!-- output -->
```text
595 {"data": null, "message": "No route to host\n"}
[('web1', 'unknown')]
[{'node': 'pve1', 'status': 'online', 'type': 'node'}, {'node': 'pve2', 'status': 'offline', 'type': 'node'}]
200 {"data": {"vmid": 100, "name": "web1", "status": "running", "qmpstatus": "running", "cpus": 1, "maxmem": 536870912, "cpu": 0.02, "mem": 67108864, "uptime": 0, "ha": {"managed": 0}, "running-qemu": "10.0.2"}}
```

## Slow and flaky networks

`pve.slow_network(latency, jitter)` delays every response by `latency` PVE seconds plus up to `jitter` random ones; with `node='pve2'` only requests for that node are slow. `pve.flaky_network(drop_rate, hang_rate, hang_secs, seed)` resets the connection for a share of requests (the client sees a connection error), or leaves a share unanswered for `hang_secs` (the client sees its own timeout). `seed` makes the sequence repeatable.

<!-- run -->
```python
import time

async with fake(time_scale=0.01) as (pve, api):
    pve.slow_network(latency=20)             # 20 PVE seconds = 0.2 s here
    started = time.monotonic()
    await api.call('GET', '/version')
    print('slow: %.1f s' % (time.monotonic() - started))

    pve.slow_network(latency=0)
    pve.flaky_network(drop_rate=1.0)         # every request is reset
    try:
        await api.call('GET', '/version')
    except aiohttp.ClientError as exc:
        print('dropped:', type(exc).__name__)

    pve.flaky_network(hang_rate=1.0, hang_secs=50)     # 0.5 s real: too long for this client
    try:
        await asyncio.wait_for(api.call('GET', '/version'), 0.2)
    except asyncio.TimeoutError:
        print('hung: client timeout')
    pve.flaky_network()                      # back to normal
    print((await api.call('GET', '/version'))[0])
```

<!-- output -->
```text
slow: 0.2 s
dropped: ServerDisconnectedError
hung: client timeout
200
```

`drop_rate` and `hang_rate` take a probability between 0 and 1. With `seed` set, the same requests are dropped on every run.

## Ceph

`pve.add_ceph_storage('ceph-pool')` adds an RBD storage. VMs with a disk on it feel the Ceph scenarios; VMs on other storages do not.

`pve.ceph_slow(secs)` makes every RBD-backed start, reboot and disk change take `secs` PVE seconds longer, and `/cluster/ceph/status` report `HEALTH_WARN`. `pve.ceph_down()` takes the cluster away: RBD storages go inactive, RBD-backed starts and changes to an existing RBD disk fail, content listings fail and `/cluster/ceph/status` errors. `pve.ceph_recover()` undoes both.

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    pve.add_ceph_storage('ceph-pool')
    pve.add_vm(100, 'db1', config={'scsi0': 'ceph-pool:vm-100-disk-0,size=32G'})
    pve.add_vm(101, 'web1', config={'scsi0': 'local-lvm:vm-101-disk-0,size=8G'})
    pve.ceph_down()
    show(await api.call('GET', '/cluster/ceph/status'))
    _, body = await api.call('POST', '/nodes/pve1/qemu/100/status/start')
    task = await api.wait(body['data'])
    print(task['exitstatus'])
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'scsi0': 'ceph-pool:vm-100-disk-0,size=64G'}))
    show(await api.call('GET', '/nodes/pve1/storage/ceph-pool/content'))
    _, body = await api.call('POST', '/nodes/pve1/qemu/101/status/start')
    print('local VM:', (await api.wait(body['data']))['exitstatus'])
    pve.ceph_recover()
    print((await api.call('GET', '/cluster/ceph/status'))[1])
```

<!-- output -->
```text
500 {"data": null, "message": "rados_connect failed - Connection timed out\n"}
rbd error: rbd: couldn't connect to the cluster! (Connection timed out)
500 {"data": null, "message": "rbd error: rbd: couldn't connect to the cluster! (Connection timed out)\n"}
500 {"data": null, "message": "rbd error: rbd: listing images failed: (110) Connection timed out\n"}
local VM: OK
{'data': {'health': {'status': 'HEALTH_OK'}, 'fsid': '00000000-fake-ceph'}}
```

## Storage full

Every storage can have an `avail` byte count in `pve.storages`. A download (`download-url`) or upload larger than what is left fails the task with `No space left on device`. The `local` storage starts with 50 GiB; `local-lvm` has no limit until you give it one.

<!-- run -->
```python
async with fake() as (pve, api):
    pve.storages['local']['avail'] = 1024 ** 2          # 1 MiB left
    status, body = await api.call('POST', '/nodes/pve1/storage/local/download-url', {
        'url': 'https://example.org/big.iso', 'filename': 'big.iso', 'content': 'iso', 'size': 10 * 1024 ** 2})
    print(status)
    task = await api.wait(body['data'])
    print(task['exitstatus'])
    print(await api.log(body['data']))
```

<!-- output -->
```text
200
unable to write to storage 'local': No space left on device
['downloading https://example.org/big.iso to big.iso', "unable to write to storage 'local': No space left on device", "TASK ERROR: unable to write to storage 'local': No space left on device"]
```

The optional `size` parameter in the request is how large the fake pretends the download is (1 MiB if absent). It is not a PVE parameter, so strict clients will not send it; set `pve.storages['local']['avail']` below 1 MiB instead.

## Storage, pools and the firewall

Writes to these areas persist and reads reflect them, so a Terraform plan or an Ansible play can create something and read it back. They follow the PVE sources (`pve-storage`, `pve-manager`'s `Pool.pm`, `pve-firewall`) down to the messages. Nothing is mounted, no pool grants anything by itself and no packet is filtered: it is the configuration that is kept.

A storage: create it, read it back, see the node's status change with the config, allocate a volume.

<!-- run -->
```python
async with fake() as (pve, api):
    show(await api.call('POST', '/storage', {'storage': 'vmstore', 'type': 'dir', 'path': '/srv/vmstore',
                                             'content': 'images,iso'}))
    _, cfg = await api.call('GET', '/storage/vmstore')
    print({k: cfg['data'][k] for k in ('storage', 'type', 'path', 'content')})
    show(await api.call('POST', '/storage', {'storage': 'vmstore', 'type': 'dir', 'path': '/srv/other'}))
    await api.call('PUT', '/storage/vmstore', {'disable': 1})
    status, body = await api.call('GET', '/nodes/pve1/storage/vmstore/content')
    print(status, body['message'].strip())
    await api.call('PUT', '/storage/vmstore', {'delete': 'disable'})
    _, volid = await api.call('POST', '/nodes/pve1/storage/vmstore/content',
                              {'filename': 'vm-100-disk-0.qcow2', 'vmid': 100, 'size': '4G'})
    print(volid['data'])
    _, listing = await api.call('GET', '/nodes/pve1/storage/vmstore/content')
    print([(item['volid'], item['size']) for item in listing['data']])
    _, status = await api.call('GET', '/nodes/pve1/storage/vmstore/status')
    print(status['data']['used'])
```

<!-- output -->
```text
```

A storage can be limited to some nodes (`nodes`), turned off (`disable`) or given other content types, and `/cluster/resources` and `/nodes/{node}/storage` follow. `type` decides which options are allowed and which are required: `lvm` needs `vgname`, `nfs` needs `server` and `export`, and an option the type does not have is `unexpected property`.

A pool: members are guests and storages, and the pool shows in the resources.

<!-- run -->
```python
async with fake() as (pve, api):
    pve.add_vm(100, 'web1')
    await api.call('POST', '/pools', {'poolid': 'dev', 'comment': 'development'})
    await api.call('PUT', '/pools/dev', {'vms': '100', 'storage': 'local'})
    _, pool = await api.call('GET', '/pools?poolid=dev')
    print([(m['id'], m['type']) for m in pool['data'][0]['members']])
    _, resources = await api.call('GET', '/cluster/resources?type=vm')
    print(resources['data'][0]['pool'])
    show(await api.call('PUT', '/pools/dev', {'vms': '100'}))
    show(await api.call('DELETE', '/pools/dev'))
    await api.call('PUT', '/pools/dev', {'vms': '100', 'storage': 'local', 'delete': 1})
    show(await api.call('DELETE', '/pools/dev'))
```

<!-- output -->
```text
```

The firewall: rules are an ordered list, new rules go on top and start disabled, and `digest` guards against a second writer.

<!-- run -->
```python
async with fake() as (pve, api):
    await api.call('POST', '/cluster/firewall/aliases', {'name': 'office', 'cidr': '198.51.100.0/24'})
    for port in (22, 443):
        await api.call('POST', '/cluster/firewall/rules', {'type': 'in', 'action': 'ACCEPT', 'proto': 'tcp',
                                                           'dport': str(port), 'source': 'office', 'enable': 1})
    _, rules = await api.call('GET', '/cluster/firewall/rules')
    print([(r['pos'], r['dport'], r['source'], r['ipversion']) for r in rules['data']])
    digest = rules['data'][0]['digest']
    show(await api.call('PUT', '/cluster/firewall/rules/1', {'moveto': 0, 'digest': digest}))
    show(await api.call('PUT', '/cluster/firewall/rules/1', {'comment': 'late', 'digest': digest}))
    show(await api.call('POST', '/cluster/firewall/rules', {'type': 'in', 'action': 'ACCEPT', 'dport': '80'}))
    show(await api.call('POST', '/nodes/pve1/qemu/100/firewall/rules', {'type': 'in', 'action': 'DROP',
                                                                          'source': '+nosuchset'}))
    _, rules = await api.call('GET', '/cluster/firewall/rules')
    print([r['dport'] for r in rules['data']])
```

<!-- output -->
```text
```

A guest's firewall is kept by its id: the `qemu` and the `lxc` path of the same id read the same rules, and neither needs the guest to exist, as on PVE.

## Permissions

Until the first `pve.grant`, every user may do everything. After it, only `root@pam` is exempt: other users need a grant on the right path. Grants are per path (`/`, `/vms`, `/vms/100`, `/pool/web`, `/storage/local`, ...) and inherit downwards. Add users with `pve.users['name@realm'] = 'password'`.

<!-- run -->
```python
async with fake(login=False) as (pve, api):
    pve.add_vm(100, 'web1')
    pve.users['ops@pve'] = 'pw'
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    await api.login('ops@pve', 'pw')
    show(await api.call('GET', '/nodes/pve1/qemu/100/status/current'))
    show(await api.call('POST', '/nodes/pve1/qemu/100/status/start'))
    pve.grant('ops@pve', '/vms/100', 'VM.PowerMgmt')
    print((await api.call('POST', '/nodes/pve1/qemu/100/status/start'))[0])
    show(await api.call('PUT', '/nodes/pve1/qemu/100/config', {'cores': 4}))
```

<!-- output -->
```text
200 {"data": {"vmid": 100, "name": "web1", "status": "stopped", "qmpstatus": "stopped", "cpus": 1, "maxmem": 536870912, "cpu": 0, "mem": 0, "uptime": 0, "ha": {"managed": 0}}}
403 {"data": null, "message": "Permission check failed (/vms/100, VM.PowerMgmt)\n"}
200
403 {"data": null, "message": "Permission check failed (/vms/100, VM.Config.CPU)\n"}
```

The generic (schema) endpoints use the permissions the PVE schema states, so a call you never modelled is still refused for a user without the right privilege, and a method with no stated permissions is root only.

<!-- run -->
```python
async with fake(login=False) as (pve, api):
    pve.users['ops@pve'] = 'pw'
    pve.grant('ops@pve', '/vms', 'VM.Audit')
    await api.login('ops@pve', 'pw')
    show(await api.call('GET', '/access/users'))
    show(await api.call('POST', '/pools', {'poolid': 'p1'}))
```

<!-- output -->
```text
200 {"data": [{"userid": "root@pam"}]}
403 {"data": null, "message": "Permission check failed (/pool/p1, Pool.Allocate)\n"}
```

## Expired tickets and tokens

`pve.ticket_ttl` is how long a ticket lasts (PVE: two hours, 7200). `pve.revoke_tickets()` forgets every ticket. In both cases the next request gets 401.

<!-- run -->
```python
async with fake() as (pve, api):
    show(await api.call('GET', '/version'))
    pve.revoke_tickets()
    show(await api.call('GET', '/version'))
    pve.ticket_ttl = -1                      # new tickets are already expired
    await api.login()
    show(await api.call('GET', '/version'))
```

<!-- output -->
```text
200 {"data": {"version": "9.0.10", "release": "9.0", "repoid": "fakepve"}}
401 {"data": null, "message": "permission denied - invalid PVE ticket\n"}
401 {"data": null, "message": "permission denied - invalid PVE ticket\n"}
```

A write without the CSRF token is also a 401. API tokens need no ticket and no CSRF token; register them in `pve.apitokens`:

<!-- run -->
```python
async with fake(login=False) as (pve, api):
    pve.apitokens['root@pam!ci'] = 's3cret'
    api.headers = {'Authorization': 'PVEAPIToken=root@pam!ci=s3cret'}
    show(await api.call('GET', '/version'))
    api.headers = {'Authorization': 'PVEAPIToken=root@pam!ci=wrong'}
    show(await api.call('GET', '/version'))
    await api.login()
    api.headers.pop('CSRFPreventionToken')
    show(await api.call('POST', '/nodes/pve1/qemu/100/status/start'))
```

<!-- output -->
```text
200 {"data": {"version": "9.0.10", "release": "9.0", "repoid": "fakepve"}}
401 {"data": null, "message": "authentication failure\n"}
401 {"data": null, "message": "Permission denied - invalid csrf token\n"}
```

A token has the privileges of its user (`root@pam!ci` is root); grants made to `user@realm!tokenid` apply to that token as well.

## Two-factor authentication

`pve.tfa = True` makes the ticket request answer as PVE does for a user with TFA: `NeedTFA` and a half-finished ticket that is no good for anything else. The fake does not model the second step (there is no code to submit), so use it to check that your client notices `NeedTFA` and stops, not to log in through TFA.

<!-- run -->
```python
async with fake(login=False, tfa=True) as (pve, api):
    status, body = await api.login()
    print(status, sorted(body['data']), body['data']['NeedTFA'])
    print(body['data']['ticket'].startswith('PVE:!tfa!'))
    api.headers = {'Cookie': 'PVEAuthCookie=' + body['data']['ticket']}
    show(await api.call('GET', '/version'))
```

<!-- output -->
```text
200 ['CSRFPreventionToken', 'NeedTFA', 'ticket', 'username'] 1
True
401 {"data": null, "message": "permission denied - invalid PVE ticket\n"}
```

## Arbitrary failures

`pve.fail(method, path_suffix, status, message)` answers any request whose path ends with the suffix with that error. It applies to requests that are logged in (an unauthenticated request gets its 401 and does not use up `times`), to the login request `POST /access/ticket`, and to the few endpoints that need no login, so a login outage can be simulated. It stays in force until you remove it from `pve.failures`, unless you give `times=n`.

<!-- run -->
```python
async with fake() as (pve, api):
    pve.add_vm(100, 'web1')
    pve.fail('GET', '/nodes/pve1/qemu/100/config', 500, 'internal error', times=1)
    show(await api.call('GET', '/nodes/pve1/qemu/100/config'))      # fails once
    print((await api.call('GET', '/nodes/pve1/qemu/100/config'))[0])  # then works
    pve.fail('GET', '/version', 503, 'Service Unavailable')
    show(await api.call('GET', '/version'))
    pve.failures.clear()
    print((await api.call('GET', '/version'))[0])
```

<!-- output -->
```text
500 {"data": null, "message": "internal error\n"}
200
503 {"data": null, "message": "Service Unavailable\n"}
200
```

`html=True` answers with a proxy's error page instead of JSON, which is what a load balancer in front of PVE does and what breaks clients that always parse JSON:

<!-- run -->
```python
async with fake() as (pve, api):
    pve.fail('GET', '/version', 502, '<html><body>Bad Gateway</body></html>', html=True)
    async with api.session.get('/api2/json/version', headers=api.headers) as rsp:
        print(rsp.status, rsp.content_type, await rsp.text())
```

<!-- output -->
```text
502 text/html <html><body>Bad Gateway</body></html>
```

The suffix may also be a schema template, which matches any node and VM: `pve.fail('POST', '/nodes/{node}/qemu/{vmid}/status/stop', 500, 'boom')`.

## Errors by catalogue name

PVE's real errors are catalogued per method. `pve.errors_for(method, path)` lists them, and `error='name'` in `pve.fail` raises one with PVE's status, wording and per-field errors. See [Errors](errors.md) for how the catalogue works.

<!-- run -->
```python
async with fake() as (pve, api):
    pve.add_vm(100, 'web1', status='running')
    path = '/nodes/pve1/qemu/100'
    names = [e['name'] for e in pve.errors_for('DELETE', path)]
    print('running_destroy_failed' in names, 'no_quorum' in names)
    pve.fail('DELETE', path, error='running_destroy_failed', times=1)
    show(await api.call('DELETE', path))
    print((await api.call('DELETE', path))[0])    # the failure was for one request only
```

<!-- output -->
```text
True True
500 {"data": null, "message": "VM 100 is running - destroy failed\n"}
200
```

Errors PVE raises inside a worker process (marked `in_task`) behave as they do on a real node: the request succeeds with a UPID, and the task ends with the error. `already_running` on a start is one of these.

<!-- run -->
```python
async with fake() as (pve, api):
    pve.add_vm(100, 'web1')
    path = '/nodes/pve1/qemu/100/status/start'
    entry = next(e for e in pve.errors_for('POST', path) if e['name'] == 'already_running')
    print(entry['in_task'], entry['status'], entry['message'])
    pve.fail('POST', path, error='already_running', times=1)
    status, body = await api.call('POST', path)
    print(status, body['data'].startswith('UPID:pve1:'))
    task = await api.wait(body['data'])
    print(task['exitstatus'])
    print(await api.log(body['data']))
    print(pve.vm(100).status)                     # nothing was started
```

<!-- output -->
```text
True 500 VM 100 already running
200 True
VM 100 already running
['VM 100 already running', 'TASK ERROR: VM 100 already running']
stopped
```

A name the method does not have is a `ValueError` listing the ones it does. The cross-cutting errors (`invalid_ticket`, `no_quorum`, `not_implemented`, `no_route_to_host`, `permission_denied`, ...) are available on every method they apply to.

## Guest agent

A VM answers agent calls only when it is running and `vm.agent` is set to a dict of answers. Without it, or when stopped, PVE's message comes back; `vm.agent_hangs = True` makes the agent time out. This holds for every `agent/*` command in the schema.

<!-- run -->
```python
async with fake() as (pve, api):
    vm = pve.add_vm(100, 'web1', status='running')
    show(await api.call('POST', '/nodes/pve1/qemu/100/agent/ping'))
    vm.agent = {'os': {'name': 'Debian GNU/Linux', 'version-id': '13'},
                'interfaces': [{'name': 'eth0', 'ip-addresses': [{'ip-address': '192.0.2.10'}]}]}
    show(await api.call('POST', '/nodes/pve1/qemu/100/agent/ping'))
    show(await api.call('GET', '/nodes/pve1/qemu/100/agent/get-osinfo'))
    vm.agent_hangs = True
    show(await api.call('POST', '/nodes/pve1/qemu/100/agent/ping'))
```

<!-- output -->
```text
500 {"data": null, "message": "QEMU guest agent is not running\n"}
200 {"data": {"result": {}}}
200 {"data": {"result": {"name": "Debian GNU/Linux", "version-id": "13"}}}
500 {"data": null, "message": "VM 100 qmp command 'guest-ping' failed - got timeout\n"}
```

Every other command answers a plausible result of the shape PVE returns (`vm.agent['get-timezone'] = {...}` replaces one). `agent/exec` and `agent/file-write` run and write nothing: the request is appended to `vm.agent_requests`, which a test can read back.

<!-- run -->
```python
async with fake() as (pve, api):
    vm = pve.add_vm(100, 'web1', status='running')
    vm.agent = {'exec': {'uptime -p': {'out-data': 'up 2 hours'}}}
    _, started = await api.call('POST', '/nodes/pve1/qemu/100/agent/exec', {'command': ['uptime', '-p']})
    show(await api.call('GET', '/nodes/pve1/qemu/100/agent/exec-status', {'pid': started['data']['pid']}))
    print(vm.agent_requests[0])
```

<!-- output -->
```text
200 {"data": {"exited": true, "exitcode": 0, "out-data": "up 2 hours", "err-data": ""}}
('exec', {'command': ['uptime', '-p']})
```

## Pending changes

Changing a running VM's hardware does not apply until the next start. The change shows in `/pending`, and `config` still shows the old value. Names, descriptions, tags and the like apply at once.

<!-- run -->
```python
async with fake() as (pve, api):
    vm = pve.add_vm(100, 'web1', status='running', config={'memory': 1024})
    await api.call('PUT', '/nodes/pve1/qemu/100/config', {'memory': 2048, 'description': 'hello'})
    _, cfg = await api.call('GET', '/nodes/pve1/qemu/100/config')
    print({k: cfg['data'][k] for k in ('memory', 'description')})
    _, pending = await api.call('GET', '/nodes/pve1/qemu/100/pending')
    print([p for p in pending['data'] if p['key'] == 'memory'])
    await api.call('POST', '/nodes/pve1/qemu/100/status/reboot')
    print(pve.vm(100).config['memory'], pve.vm(100).pending)
```

<!-- output -->
```text
{'memory': 1024, 'description': 'hello'}
[{'key': 'memory', 'value': 1024, 'pending': '2048'}]
2048 {}
```

## Containers

LXC containers keep state like VMs do: what a client writes it can read back, with PVE's rules and wording. `pve.add_ct` adds one (see [Containers](python-api.md#containers)); a client can also create one with `POST /nodes/pve1/lxc`. A create, like a clone, a snapshot or a destroy, is a task, and the container is visible (locked `create`) while it runs.

A running container takes some changes at once (cores, memory, swap, the network, a new mount point, names and tags) and keeps the rest pending until the next start or reboot, as `pct set` does. A stopped container takes them all.

<!-- run -->
```python
async with fake() as (pve, api):
    status, body = await api.call('POST', '/nodes/pve1/lxc', {
        'vmid': 100, 'hostname': 'web1', 'memory': 512, 'rootfs': 'local-lvm:8',
        'ostemplate': 'local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst',
        'net0': 'name=eth0,bridge=vmbr0,ip=192.0.2.10/24'})
    print(status, (await api.wait(body['data']))['exitstatus'])
    _, body = await api.call('POST', '/nodes/pve1/lxc/100/status/start')
    await api.wait(body['data'])
    await api.call('PUT', '/nodes/pve1/lxc/100/config', {'memory': 1024, 'searchdomain': 'example.test'})
    _, cfg = await api.call('GET', '/nodes/pve1/lxc/100/config')
    print({k: cfg['data'][k] for k in ('hostname', 'memory', 'rootfs', 'ostype')})
    _, now = await api.call('GET', '/nodes/pve1/lxc/100/config', {'current': 1})
    print({k: now['data'].get(k) for k in ('memory', 'searchdomain')})
    _, pending = await api.call('GET', '/nodes/pve1/lxc/100/pending')
    print([p for p in pending['data'] if p['key'] == 'searchdomain'])
    _, body = await api.call('POST', '/nodes/pve1/lxc/100/status/reboot')
    await api.wait(body['data'])
    print(pve.ct(100).config['searchdomain'], pve.ct(100).pending)
```

<!-- output -->
```text
200 OK
{'hostname': 'web1', 'memory': 1024, 'rootfs': 'local-lvm:vm-100-disk-0,size=8G', 'ostype': 'debian'}
{'memory': 1024, 'searchdomain': None}
[{'key': 'searchdomain', 'pending': 'example.test'}]
example.test {}
```

A shutdown that outlasts its timeout ends with `container did not stop` (`forceStop=1` kills the container instead), and a start can be made to fail:

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    ct = pve.add_ct(100, 'web1', status='running')
    ct.shutdown_secs = 90
    _, body = await api.call('POST', '/nodes/pve1/lxc/100/status/shutdown')
    print((await api.wait(body['data']))['exitstatus'], '| CT is', ct.status)
    _, body = await api.call('POST', '/nodes/pve1/lxc/100/status/shutdown', {'forceStop': 1})
    print((await api.wait(body['data']))['exitstatus'], '| CT is', ct.status)
    ct.start_error = 'lxc_init: 845 Failed to initialize container "100"'
    _, body = await api.call('POST', '/nodes/pve1/lxc/100/status/start')
    print((await api.wait(body['data']))['exitstatus'], '| CT is', ct.status)
    show(await api.call('POST', '/nodes/pve1/lxc/100/status/stop'))
```

<!-- output -->
```text
container did not stop | CT is running
OK | CT is stopped
lxc_init: 845 Failed to initialize container "100" | CT is stopped
500 {"data": null, "message": "CT 100 not running\n"}
```

Snapshots, clones, migrations and the rest hold the container's `lock` for as long as `pve.ct_secs` says, and refuse changes meanwhile:

<!-- run -->
```python
async with fake(time_scale=0.01) as (pve, api):
    pve.ct_secs['snapshot'] = 30
    pve.add_ct(100, 'web1')
    _, body = await api.call('POST', '/nodes/pve1/lxc/100/snapshot', {'snapname': 'before'})
    show(await api.call('PUT', '/nodes/pve1/lxc/100/config', {'onboot': 1}))
    print((await api.wait(body['data']))['exitstatus'])
    _, snaps = await api.call('GET', '/nodes/pve1/lxc/100/snapshot')
    print([s['name'] for s in snaps['data']])
    show(await api.call('PUT', '/nodes/pve1/lxc/100/config', {'onboot': 1}))
```

<!-- output -->
```text
500 {"data": null, "message": "CT is locked (snapshot)\n"}
OK
['before', 'current']
200 {"data": null}
```

What works as it does for VMs: `pve.fail(..., error=name)` on the container routes takes the `lxc` catalogue's names; `lose_quorum`, `set_node_offline`, `hold_config_lock`, `backup`, `migrate` and `snapshot_lock` take a container's id; and permissions follow PVE's `check_ct_modify_config_perm` (`VM.Config.CPU`, `Memory`, `Network`, `Disk` and `Options` by option, `Datastore.AllocateSpace` for a new volume, `Sys.Modify` for a privileged container, root only for bind mounts, device passthrough and hookscripts).
