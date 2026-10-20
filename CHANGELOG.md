# Changelog

All notable changes to fakepve are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
