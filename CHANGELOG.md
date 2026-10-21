# Changelog

All notable changes to fakepve are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-10-21

### Added

- `tools/compare_real.py scenario` (phase 2 of the comparison with a real PVE) compares write operations and error responses. It runs a list of steps (storage, VM and container lifecycle with bad values, digests, snapshots, clones, templates, protection, pools and firewall rules) against a throwaway PVE 9 node, and records per step the HTTP status, the shape of the answer, the error text with every name and number removed, the keys of the per-field `errors` and the exit status and last log line of the task. It only touches objects it creates (vmids 9900-9999, names `fpcmp-*`, storage `fpcmp-dir`, pool `fpcmp-pool`), cleans up in a `finally` and verifies it, and refuses to start without `--i-understand-this-writes` and `--disposable-node` naming the only node of a target that holds no other guest. `--against-fake` runs the same list on an in-process fakepve and diffs step by step (exact and fuzzy text matches, status, error keys, task outcome); `--self-test-scenario` runs it on two fakes and expects no difference.
- The error templates of `tools/compare_real.py` keep the words of PVE's own messages (from the error catalogue), so they read as messages.
- `POST /nodes/{node}/qemu` creates a stateful VM through a `qmcreate` task (`qemu.py`). The parameters become the config, `STORAGE:SIZE` disks are allocated as volumes in the storage state (named as the storage plugin names them, `size=` written back, `format=` consumed), a MAC is made up for a NIC without one, and `boot`, `meta`, `smbios1` and `vmgenid` are added, as qemu-server does. `pool`, `protection`, `kvm` and `start` are honoured. A VM id in use is `unable to create VM N - VM N already exists on node '...'`; a disk that does not fit or a missing volume fails the task and leaves nothing behind.
- VM destroy, snapshots (list, create, delete, rollback, snapshot config), clone and template keep state. Destroy refuses a protected or running VM and frees the VM's volumes, pool membership and firewall rules; `destroy-unreferenced-disks` frees every image of the id. A template turns its volumes into `base-` ones and linked clones of it name their volume on the base. Snapshot reuse and deleting a missing snapshot end the task with `snapshot name 'x' already used` and `snapshot 'x' does not exist`; a clone to a used id, a template of a template and an unsnapshottable raw image answer as qemu-server does.
- `compare_real.py scenario --against-fake FILE` runs the fake without an appliance template when the recording noted `no-template`, so the container steps the recording skipped are skipped on the fake too.

### Changed

- Starting a VM is checked in the task, as `vm_start` does: a running VM, a locked one and a template are a task that ends with `VM N already running`, `VM is locked (x)` and `you can't start a vm if it's a template`, not an HTTP 500.
- A stale `digest` on a VM config write is `checksum mismatch (file change by other user?)`, qemu-server's wording.
- Parameters of a VM config write are checked before the VM is looked up, and a changed `name` shows in the VM list.
- A firewall rule's `dport`, `sport`, `proto`, `source` and `dest` errors carry the `invalid format - ` prefix of a registered format. Updating or deleting a rule when the guest, node or cluster has no firewall file (no rules, options, aliases or IP sets) fails with the Perl `Can't use an undefined value as an ARRAY reference` error PVE shows.
- PVE checks permissions before parameters: for a user other than the `root@pam` login, a permission path it cannot normalise (a pool name with a space) is a 403 with an empty path, not a 400.

## [0.4.0] - 2026-10-20

### Added

- `tools/compare_real.py` checks fakepve against a real PVE without writing to it. `record` walks every GET method of the schema with a read-only API token (read from a file, never from the command line), resolves path parameters from real objects found through the list endpoints, and writes a shape file: status, types and key names, and error text with names and numbers removed. No value is kept, and a self-check refuses to write a file that holds one. `diff` seeds an in-process fakepve with the counts in a shape file, records it the same way and lists status, key and type differences per method; `--self-test` diffs fakepve against itself. Writes and error paths need a disposable PVE and are not covered yet.
- `GET /access/permissions` answers from the grants (`pve.grant`).
- `tools/compare_real.py`: `record` keeps the names of the privileges of the token (from `GET /access/permissions`) and `diff` runs the fake as a user with the same privileges on `/`, so `403` compares like for like (`--as-root` for the old behaviour). Keys that depend on the object (a VM's config, a storage's options, a role's privileges) are not counted unless `--no-ignore-config-keys` is given, a value the real PVE sends as two types matches either, and keys the schema does not name are counted apart. The documentation says which differences are not defects.

### Changed

- Answers carry the keys a real PVE always sends and the types it sends them with, found by comparing a read-only recording of a PVE 9 cluster with the fake. The generic answers fill the optional properties PVE returns every time (`src/fakepve/shapes.py`: `OPTIONAL`, `HINTS`, `FIXUPS`), with invented values only. Hand-built answers gain the usage fields of `nodes`, `cluster/resources`, VM and container status and lists (including the pressure figures, `pid`, `balloon`, `clipboard`, `running-machine`); `GET /nodes/{node}/qemu` now lists the VMs of the node (it answered one sample entry); `ceph/status` has `health.checks` and `quorum`; the backup job, vzdump defaults, network, Ceph (mon, mgr, mds, osd, pool, metadata), cluster config, notification, disk, apt, certificate, subscription, SDN and snapshot answers have the keys of a real node.
- Types now follow PVE: `cluster/nextid`, `cluster/config/apiversion`, the corosync `nodeid` and `quorum_votes`, and a VM's `memory` are strings; the container interface `prefix` is a string; `has-dbus-vmstate` is a boolean.
- The task list shows the exit status in `status` and the token name in `tokenid`; the status of a task has no `endtime`. A permission refusal by the "self" rule or by none of several alternatives carries no reason, as in PVE, and a rule that names a path parameter the method does not take checks the parent path (`GET /cluster/acme/meta` for a user with `Sys.Audit`).

## [0.3.0] - 2026-10-20

### Added

- LXC containers keep state. `pve.add_ct()` and `FakeCt` add one, and `POST /nodes/{node}/lxc` creates one. Containers appear in `/cluster/resources` (type `lxc`) and `/nodes/{node}/lxc`, and share the VM id space (`VM 100 already exists on node 'pve1'`, `CT 100 already exists ...`). Create, destroy, `status/current`, `status/{start,stop,shutdown,reboot,suspend,resume}`, `config` (GET and PUT, with `digest`, `delete`, `revert`, `current` and `snapshot`), `pending`, `clone`, `template`, `migrate` (GET and POST), `resize`, `interfaces` and `snapshot` (list, create, delete, rollback, snapshot config) read and write that state, with PVE's messages, task types (`vzcreate`, `vzstart`, `vzstop`, `vzshutdown`, `vzreboot`, `vzdestroy`, `vzclone`, `vzsnapshot`, ...), locks and privileges.
- A running container takes cores, memory, swap, network changes, new mount points, names and tags at once and keeps the rest pending until the next start or reboot; a stopped one takes everything. Removed mount points become `unused` volumes.
- Container scenarios: `ct.start_secs`, `ct.stop_secs`, `ct.shutdown_secs`, `ct.start_error`, `ct.ha_state`, and `pve.ct_secs` for the other tasks. `lose_quorum`, `set_node_offline`, `hold_config_lock`, `backup`, `migrate`, `snapshot_lock`, `unlock` and `pve.fail(..., error=name)` work on containers. The guests file takes `"type": "lxc"`.
- Storage keeps state. `POST /storage`, `PUT /storage/{storage}` (with `digest` and `delete`) and `DELETE /storage/{storage}` change the storage config that `GET /storage` reads back, with each storage type's own options (required, fixed and unexpected ones are refused in PVE's words, `content` is cut to what the type supports). The node's storage list and status follow it (`disable`, `nodes`, content types, `total`, `used`, `avail`), and `/cluster/resources` lists a storage only on the nodes it is enabled on.
- Volumes: `POST .../content` allocates one (PVE's name and format rules), `GET`, `PUT` and `DELETE .../content/{volume}` read it, set `notes` and `protected` and remove it in an `imgdel` task. Disks that VM and container configs reference are listed with their owner and size, so a container's `rootfs` and mount points show in the content listing. `download-url` and `upload` take `vztmpl` as well as `iso`.
- Pools keep state: `POST`, `PUT` and `DELETE` on `/pools` and `/pools/{poolid}`, `GET /pools?poolid=` (and `type=`), members `vms` (VMs and containers) and `storage` with `delete` and `allow-move`, nested pools, and PVE's refusals (`already a pool member`, `is not empty`, ...). Membership shows as `pool` in `/cluster/resources` and carries the grants made on `/pool/<id>` to guests and storages. A container created or cloned with `pool=` joins the pool, and destroying it leaves.
- Firewall keeps state at the cluster, on a node and on a guest (`qemu` and `lxc` paths share the config): options, rules (with `pos`, `moveto`, `digest`, `delete`, every field checked as PVE does), aliases, IP sets, security groups, `refs` and `macros`. `pve.firewall_config(scope, node=None, vmid=None)` returns the stored config.
- `GET /cluster/nextid` skips the ids of VMs and containers, and refuses a requested id that either has.
- `pve.volume_exists(volid)` tells whether an OS template is on its storage: a container create task fails with `volume '...' does not exist` for a template missing from a storage that lists others.

### Changed

- The `lxc` routes no longer answer from the schema alone: a request for a container that does not exist fails as PVE's does (`Configuration file 'nodes/pve1/lxc/100.conf' does not exist`, or a start task that ends with it).
- `store_file` takes the content type (`iso` by default) and records the file as a volume. Storage status reports `total`, `used` and `avail`, and `local` and `local-lvm` carry `path`, `vgname` and `thinpool` in their config.

## [0.2.0] - 2026-10-20

### Added

- Every guest agent command in the schema now answers (25 `agent/*` methods; 22 used to answer 501). The agent scenarios (`vm.agent` absent, `vm.agent_hangs`) apply to all of them, and `exec` and the file commands record the request on `vm.agent_requests` without running or touching anything.
- Parameters with a `format` are validated as PVE does, with its wording: property strings (`net0`, `scsi1`, `ipconfig0`, `boot`, `rng0`, ... including unknown keys, missing required keys and `requires`) and the common named formats (`pve-vmid`, `pve-configid`, `pve-storage-id`, `pve-node`, `mac-addr`, `ipv4`, `ipv6`, `CIDR`, `pve-bridge-id`, `email`, `dns-name`, and more). The rest are listed in the docs as accepted without checking. `PUT` and `POST` on a VM's `config` are validated too.
- `/api2/extjs` is served: the same handlers and logins as `/api2/json`, answered in PVE's ExtJS envelope (HTTP 200, `data`, `success`, and for an error the `status`, `message` and `errors` in the body).
- A weekly check (and `tools/check_schema.py`) compares the hash of the online PVE `apidoc.js` with the vendored schema and opens an issue when PVE's API has changed.

### Changed

- A vmid out of range now fails with `invalid format - value does not look like a valid VM ID`, as on PVE, instead of a minimum or maximum message.
- Errors in array parameters are reported under `name[index]`, and a missing `requires` partner reads `missing property required by 'name'`.

### Fixed

- Repeated form or query parameters (`command=a&command=b`) are read as an array, as PVE does, instead of keeping the last value.
- A schema limit written as a string (`maximum: "16777216"`) no longer breaks validation.

## [0.1.0] - 2026-10-20

First public release.

### Added

- A fake Proxmox VE API on aiohttp, as a Python class (`FakePve`), a command line (`fakepve guests.json`) and a container image. No PVE, QEMU, Ceph or corosync is needed.
- Every endpoint of the PVE 9 API schema answers: 680 methods on 449 paths. Parameters are validated with PVE's wording (HTTP 400 with per-field `errors`), permissions are checked as the schema states them, and answers have the shape PVE's `returns` declares.
- Stateful behaviour where a client reads back what it did: logins (tickets with CSRF tokens and expiry, API tokens, per-path grants, two-factor `NeedTFA`), VM power, config and pending changes, tasks with real UPIDs that run, hold the VM config lock and keep a log, storage content and uploads, the guest agent, and consoles over websocket.
- An error catalogue of 2314 errors PVE can return, taken from the PVE sources, each raised by name with `pve.fail(..., error='name')`. Errors raised in a PVE worker end a task with `TASK ERROR`, as on a node.
- Scenarios for the failures that are hard to produce on a cluster: slow or hanging guests, config and backup locks, migrations, high availability, lost quorum, offline nodes, slow and flaky networks, Ceph slow or down, full storage, expired tickets and tokens, 403s and arbitrary failures.
- `time_scale`, to turn PVE seconds into real ones: from every task finishing at once to real time.
- Several fakes at once: each instance takes its own loopback address, so all can use port 8006.
- A self-signed certificate, made at start, for the command line and the fixtures.
- A pytest plugin: the fixtures `fakepve`, `fakepve_session`, `fakepve_url` and `fakepve_cafile`, and the `fakepve` marker for the user, password and time scale. Each fake listens on its own port, so tests and pytest-xdist workers do not collide.
- `fakepve --version` and `fakepve.__version__`.
- A Dockerfile, a published container image, and recipes for GitHub, Forgejo and Gitea, and GitLab pipelines, including service containers.
- A documentation site: user guide, scenario cookbook, error catalogue, CI recipes and a generated endpoint reference. Its code blocks are run by the tests.
- Examples for aiohttp, requests, proxmoxer, curl and CI, all tested.

### Security

- The login is checked before any failure rule or request body is read. Request bodies are limited in size and time, the request log is bounded, schema patterns are matched in linear time, malformed input gets a 400, and unexpected errors a plain 500 without a traceback.
- Credentials are redacted from the request log. The private key of the self-signed certificate is written readable by the owner only and removed once loaded.
- The command line warns when it listens on a non-loopback address with the default password. The documentation binds to loopback and sets `PVE_PASS` throughout. See `SECURITY.md`.
- Dependency floors are past the known advisories (aiohttp 3.14.3, cryptography 50.0.0), and CI tools, actions and the base image are pinned.

### Packaging

- Published to PyPI as `fakepve` (`pip install fakepve`; extras `crypto` and `pytest`), with trusted publishing, and to `ghcr.io/qisback/fakepve`. Python 3.10 and later.
- The self-signed certificate names `localhost`, `127.0.0.1` and the address it is served on (subject alternative names), so a client can verify it with the certificate as its CA.
- Licensed under the GNU Affero General Public License, version 3 or later.

[Unreleased]: https://github.com/qisback/fakepve/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/qisback/fakepve/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/qisback/fakepve/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/qisback/fakepve/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/qisback/fakepve/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/qisback/fakepve/releases/tag/v0.1.0
