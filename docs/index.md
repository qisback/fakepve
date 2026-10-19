# fakepve

A lightweight fake of the Proxmox VE API, for testing code that drives Proxmox without needing a cluster, and for putting that code through the things a real cluster does to it: slow shutdowns, locked VMs, lost quorum, flaky networks, Ceph trouble.

It is for people writing Ansible modules, Terraform providers, proxmoxer scripts, and Go, Python or JavaScript clients for Proxmox, and for anyone who wants their tests and pipelines to run without a PVE host. It is one Python process on aiohttp: no PVE, QEMU, Ceph or corosync.

## Thirty seconds

```console
pip install '.[crypto]'
python -m fakepve examples/guests.json --time-scale 0
fakepve listening on https://127.0.0.2:8006
```

![Starting the fake and logging in](img/quick-start.svg)

Log in as `root@pam` with password `secret`. [Getting started](getting-started.md) goes on from here.

## What it does

- **Logins as PVE has them:** tickets with CSRF tokens and expiry, API tokens, optional per-path permissions, two-factor logins (the `NeedTFA` answer).
- **Every endpoint of the PVE 9 API schema answers:** 680 methods on 449 paths, validated with PVE's wording. See the [endpoint reference](reference/endpoints.md).
- **Stateful where a client reads back what it did:** VM power, config and pending changes, tasks with real UPIDs, storage content, guest agent, consoles.
- **Real errors, by name:** 2314 errors PVE can return, each raised with `pve.fail(..., error='name')`. See [Errors](errors.md).
- **Faults on demand:** slow guests, locks, migrations, HA, lost quorum, offline nodes, flaky networks, Ceph, full storage, expired tickets, 403s. See [Scenarios](scenarios.md).
- **Easy to run in CI:** a command line, a pytest-friendly class, a Dockerfile, and recipes for GitHub, Forgejo and Gitea, and GitLab. See [CI](ci.md).

It is a fake, not a copy of PVE; the [known gaps](how-it-works.md#known-gaps) are stated plainly.

## Licence

Licensed under the GNU Affero General Public License, version 3 or later. The data in `src/fakepve/data/` is derived from Proxmox VE (also AGPL-3.0). Not affiliated with or endorsed by Proxmox Server Solutions GmbH; Proxmox is a registered trademark of Proxmox Server Solutions GmbH.
