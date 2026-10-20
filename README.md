# fakepve

<a href="https://ko-fi.com/qisback"><img src="docs/img/kofi.png" alt="Buy me a coffee at ko-fi.com" height="36"></a>

A lightweight fake of the Proxmox VE API, for testing code that drives Proxmox without needing a cluster, and for putting that code through the things a real cluster does to it: slow shutdowns, locked VMs, lost quorum, flaky networks, Ceph trouble.

It is for people writing Ansible modules, Terraform providers, proxmoxer scripts, and Go, Python or JavaScript clients for Proxmox, and for anyone who wants their tests and pipelines to run without a PVE host. It is one Python process on aiohttp: no PVE, QEMU, Ceph or corosync.

> **Test tool: bind it to loopback.** fakepve has no real security. Its default login, `root@pam` / `secret`, is public, so anyone who can reach the port can do anything to the fake. Run it on a loopback address (the default), publish container ports as `127.0.0.1:8006:8006`, and set `PVE_PASS` when anyone but you can reach the port. See the [security policy](SECURITY.md).

## Why

A real cluster is slow to build, hard to break on purpose and impossible to share between pipelines. The failures that matter to a client (a shutdown that outlasts its timeout, a VM locked by a backup, a node that disappears, a task that ends in `TASK ERROR`) are exactly the ones that are hard to produce. fakepve answers like PVE 8/9 does, with PVE's status codes and its own wording, and lets a test cause each of those failures with one line.

## Quick start

```console
pip install 'fakepve[crypto]'
fakepve examples/guests.json --time-scale 0
fakepve listening on https://127.0.0.2:8006
```

In another terminal (the login is `root@pam` / `secret`; `-k` because the certificate is self-signed):

```console
$ curl -sk -d username=root@pam -d password=secret https://127.0.0.2:8006/api2/json/access/ticket
{"data": {"ticket": "PVE:root@pam:...", "CSRFPreventionToken": "...", "username": "root@pam", "cap": {}}}
```

From pytest, with the plugin (`pip install 'fakepve[pytest]'`; see [pytest](docs/pytest.md)): the `fakepve` fixture is a started fake with a certificate your client can verify, and works with xdist.

```python
import requests

def test_vms(fakepve, fakepve_url, fakepve_cafile):
    fakepve.add_vm(100, 'vm1', status='running')
    ticket = requests.post(fakepve_url + '/api2/json/access/ticket', verify=fakepve_cafile,
                           data={'username': 'root@pam', 'password': 'secret'}).json()['data']['ticket']
    vms = requests.get(fakepve_url + '/api2/json/cluster/resources?type=vm', verify=fakepve_cafile,
                       cookies={'PVEAuthCookie': ticket}).json()['data']
    assert [vm['name'] for vm in vms] == ['vm1']
```

Or in the same process, by hand:

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
        ...  # drive https://{pve.host}:{pve.port} with your client
    finally:
        await pve.stop()
```

## What it does

- **Logins as PVE has them:** tickets with CSRF tokens and expiry, API tokens, optional per-path permissions, two-factor logins (the `NeedTFA` answer).
- **Every endpoint of the PVE 9 API schema answers:** 680 methods on 449 paths. Parameters, including property strings such as `net0=virtio,bridge=vmbr0`, are validated with PVE's wording (HTTP 400 with per-field `errors`), under `/api2/json` and `/api2/extjs`; permissions are checked as the schema states them, and answers have the shape PVE's `returns` declares.
- **Stateful where a client reads back what it did:** VM power, config and pending changes, tasks with real UPIDs that run, hold the VM config lock and keep a log, storage content, guest agent, consoles over websocket.
- **Real errors, by name:** 2314 errors PVE can return, catalogued per method from the PVE sources, each raised with `pve.fail(..., error='name')`. Errors raised in a PVE worker end a task with `TASK ERROR` as they do on a node.
- **Faults on demand:** slow or hanging guests, config and backup locks, migrations, HA, lost quorum, offline nodes, slow and flaky networks, Ceph slow or down, full storage, expired tickets, 403s, arbitrary failures.
- **Time you control:** `time_scale` turns PVE seconds into real ones, from "every task finishes at once" to real time.
- **Several fakes at once:** each instance takes its own loopback address, so all can use port 8006.
- **Easy to run in CI:** a command line, a pytest-friendly class, a Dockerfile, and recipes for GitHub, Forgejo and Gitea, and GitLab.

It is a fake, not a copy of PVE: outside the hand-written areas a write succeeds and changes nothing. The details and the [known gaps](docs/how-it-works.md#known-gaps) are in [How it works](docs/how-it-works.md).

## Documentation

- [Getting started](docs/getting-started.md): install, first requests with curl, from Python, the guests file.
- [Command line](docs/cli.md): every option and environment variable.
- [pytest](docs/pytest.md): the fixtures.
- [Python API](docs/python-api.md): every attribute and method of `FakePve` and `FakeVm`.
- [Scenarios](docs/scenarios.md): a recipe for each fault, with the exact response the client sees.
- [Errors](docs/errors.md): the catalogue, listing, triggering, placeholders, limits.
- [CI](docs/ci.md): pytest, background processes, containers, GitHub, Forgejo, GitLab, certificates.
- [How it works](docs/how-it-works.md): architecture and refreshing the data for a new PVE release.
- [Endpoint reference](docs/reference/endpoints.md): every path and method, generated.
- [Security policy](SECURITY.md): what the fake is and is not, and how to report a vulnerability.
- [Contributing](docs/contributing.md): checks, and building and publishing the documentation site.
- [`examples/`](examples): runnable examples for aiohttp, requests, proxmoxer, curl and CI.

## Support

fakepve is free and always will be. If it saves you time, you can buy me a coffee at [ko-fi.com/qisback](https://ko-fi.com/qisback).

<a href="https://ko-fi.com/qisback"><img src="docs/img/kofi.png" alt="Buy me a coffee at ko-fi.com" height="36"></a>

## Licence

Copyright Laurence Horrocks-Barlow. Licensed under the GNU Affero General Public License, version 3 or later; see `LICENSE`.

The files in `src/fakepve/data/` are derived from Proxmox VE: the API schema from its API viewer (`apidoc.js`), and the error messages from its sources at `https://git.proxmox.com`. Proxmox VE is also AGPL-3.0, so they are distributed under the same terms.

Not affiliated with or endorsed by Proxmox Server Solutions GmbH. Proxmox is a registered trademark of Proxmox Server Solutions GmbH.
