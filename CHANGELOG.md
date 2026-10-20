# Changelog

All notable changes to fakepve are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/qisback/fakepve/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/qisback/fakepve/releases/tag/v0.1.0
