# Security policy

## What fakepve is

fakepve is a test tool: a fake of the Proxmox VE API, with made-up data, for testing clients without a cluster. It is not a security boundary and not a hardened server. Never put it where an untrusted party can reach it.

## Threat model

- **Loopback only.** The command line listens on `127.0.0.2` unless told otherwise, and the Python class on its own loopback address. Anything that can connect can log in and change the fake's state.
- **The default credentials are public.** `root@pam` with password `secret` is in the documentation. Start with `--password` or `PVE_PASS` whenever the fake is reachable by anyone but you. The command line prints a warning on stderr when it listens on a non-loopback address with the default password.
- **Containers.** The image listens on `0.0.0.0` inside the container, which a CI service container needs. Publish the port on loopback (`docker run -p 127.0.0.1:8006:8006 fakepve`), and set `PVE_PASS` if the container is reachable from other hosts.
- **The data is fake.** No hypervisor, guest, disk or real secret is behind it. The self-signed certificate is made at each start; its key is written readable by the owner only and removed once loaded.
- **Hostile clients are tolerated, not defended against.** Bodies are limited in size and time, the request log is bounded, schema patterns are matched in linear time, malformed input gets a 400, and unexpected errors a plain 500 without a traceback. There is no rate limiting, lockout or audit trail.

Reports about the fake being unsafe on an open network with the default credentials are out of scope: that is the documented state. In scope: a crafted request that hangs or crashes the process, grows its memory without bound, leaks a credential, reads or writes files, or runs code; and weaknesses in the release, packaging or CI files.

## Supported versions

Only the latest release, and the `main` branch, are supported. Fixes are made there.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on `qisback/fakepve`: open the repository's Security tab, choose "Report a vulnerability", and describe what you found, how to reproduce it and which version it affects. Please do not open a public issue or pull request for a vulnerability before it is fixed.
