# Errors

Clients are tested properly only when they meet the errors a real Proxmox VE gives. fakepve carries a catalogue of those errors, taken from the PVE sources, and can raise any of them by name.

Contents: [the catalogue](#the-catalogue) | [listing](#listing-errors) | [triggering](#triggering-an-error) | [placeholders](#placeholders) | [errors in tasks](#errors-in-tasks) | [cross-cutting errors](#cross-cutting-errors) | [the shape of an error](#the-shape-of-an-error) | [limits](#limits-and-approximations) | [regenerating](#regenerating-the-catalogue)

## The catalogue

`src/fakepve/data/pve-errors.json.gz` lists, per API method, the errors PVE can answer with. It was read from the PVE sources (the repositories and commits are recorded in `fakepve.errors.meta()`) and holds only message strings, status codes and source references. Each entry has:

| Field | Meaning |
|---|---|
| `name` | What you pass to `pve.fail(error=...)`. Made from the message text, unique within a method (a repeat gets `_2`). |
| `status` | The HTTP status: 400, 403, 500, ... |
| `message` | The message as a template, with `{placeholders}` for values only known at run time. |
| `errors` | For a 400, the per-field errors (`{'vmid': 'invalid format - value does not look like a valid VM ID\n'}`). Absent otherwise. |
| `in_task` | `true` if PVE raises it inside a worker process, so it ends a task instead of failing the request. |
| `source` | `repository/path:line` in the PVE sources, or `cross-cutting` for the ones added in code. |

At the time of writing it holds 2314 errors on 465 of the schema's 680 methods; 658 methods are mapped to their source, and the rest (such as the QEMU guest agent commands, which PVE builds in a loop) have none. `fakepve.errors.meta()` says exactly how many, from which commits, and when.

## Listing errors

`pve.errors_for(method, path)` returns the errors a method can produce at a concrete path, with the placeholders filled from the path. This is the quickest way to see what is available:

<!-- run -->
```python
from fakepve import FakePve

pve = FakePve()
entries = pve.errors_for('DELETE', '/nodes/pve1/qemu/100')
for entry in entries[:5]:
    print(entry['name'], entry['status'], entry['in_task'], '|', entry['message'])
print(len(entries) > 15)
print(sorted(entries[0]))
```

<!-- output -->
```text
param_skiplock_only_root_may 400 False | Parameter verification failed.
unable_remove_used_ha_resources 500 False | unable to remove VM 100 - used in HA resources and purge parameter not set.
running_destroy_failed 500 False | VM 100 is running - destroy failed
configuration_file_does_not_exist 500 False | Configuration file 'nodes/pve1/qemu-server/100.conf' does not exist
protection_mode_enabled 500 False | fake - protection mode enabled
True
['errors', 'in_task', 'message', 'name', 'source', 'status']
```

The same list for every method is in the generated [endpoint reference](reference/endpoints.md). `fakepve.errors.catalogue()` is the raw data, and `fakepve.errors.listing(method, path)` the templates before filling.

## Triggering an error

`pve.fail(method, path, error='name')` makes the next matching requests fail as PVE would:

<!-- run -->
```python
from fakepve import FakePve

pve = FakePve()
pve.fail('DELETE', '/nodes/pve1/qemu/100', error='running_destroy_failed')           # every time
pve.fail('POST', '/nodes/pve1/qemu/100/status/stop', error='no_quorum', times=1)    # the next one only
pve.fail('POST', '/nodes/{node}/qemu/{vmid}/status/start', error='locked')           # any node and VM
print(sorted(key[1] for key in pve.failures))
print(pve.failures[('POST', '/nodes/pve1/qemu/100/status/stop')]['times'])
```

<!-- output -->
```text
['/nodes/pve1/qemu/100', '/nodes/pve1/qemu/100/status/stop', '/nodes/{node}/qemu/{vmid}/status/start']
1
```

The recipe with the response the client sees is in [Scenarios](scenarios.md#errors-by-catalogue-name).

- `error=` takes a name from `errors_for`. A name the method does not have raises `ValueError` listing the ones it does, when the path is complete (starts with `/`); a partial suffix is checked when a request arrives, and a request for a name that does not fit gets 500 `fakepve: no error 'name' for ...`. `error=` cannot be combined with `status` and `message`.
- The path is matched against the end of the request path (`/qemu/100/status/start` matches any node), or, if it contains `{`, against the schema path, where `{node}` and `{vmid}` stand for anything.
- A failure persists until you delete it from `pve.failures`, unless you give `times=n`. This is the same for your own status and message.
- It works for the hand-written routes and the generic ones alike.
- Failures are checked before login, so a failing request fails even for a client with no ticket. The exception is an `in_task` error, which is raised after the login is checked, as it is in PVE.
- If several failures match, the first one added wins.

## Placeholders

Messages are templates. `{vmid}`, `{node}` and the other placeholders are filled from the request path and body. Any that the request does not supply get a plausible value: `{vmid}` 100, `{node}` `pve1`, `{storage}` `local`, `{lock}` `backup`, `{guest_type}` `VM` (or `CT` under `lxc`), `{userid}` `root@pam`, and `fake` for anything unknown. In a 400's `errors`, a key that is itself a placeholder (a parameter named at run time in PVE) becomes the first parameter the method has that the path does not fix.

<!-- run -->
```python
from fakepve import FakePve, errors

pve = FakePve()
template = errors.find('DELETE', '/nodes/pve1/qemu/100', 'running_destroy_failed')['message']
print(template)
filled = pve.errors_for('DELETE', '/nodes/pve1/qemu/222')
print(next(e['message'] for e in filled if e['name'] == 'running_destroy_failed'))
print(errors.fill('unable to find {thing} on {node}', {'node': 'pve9'}))
```

<!-- output -->
```text
VM {vmid} is running - destroy failed
VM 222 is running - destroy failed
unable to find fake on pve9
```

## Errors in tasks

Errors raised in a PVE worker process, marked `in_task`, do not fail the request. The request succeeds with a UPID, and the task ends with `exitstatus` set to the message and a log that ends `TASK ERROR: <message>`. This is what a client that only checks the HTTP status misses, and why it is important to test: starting a VM that is already running, in PVE's worker, is such an error. fakepve does the same for `in_task` entries, so the client has to read the task to find out.

## Cross-cutting errors

Some errors can happen to many methods and come from PVE's daemons rather than its API modules. They are added in code and listed with `source` `cross-cutting`:

| Name | Status | When it applies |
|---|---|---|
| `invalid_ticket` | 401 | `permission denied - invalid PVE ticket`: any method that needs a login. |
| `authentication_failure` | 401 | `authentication failure`: any method that needs a login. |
| `invalid_csrf` | 401 | `Permission denied - invalid csrf token`: writes. Kept at 401, as the fake's own login handling answers. |
| `no_quorum` | 500 | `cluster not ready - no quorum?`: writes. |
| `config_lock_timeout` | 500 | `can't lock file '/var/lock/qemu-server/lock-N.conf' - got timeout`: writes to a QEMU or LXC guest (the LXC path differs). |
| `not_implemented` | 501 | `Method 'METHOD path' not implemented`: every method. |
| `no_route_to_host` | 595 | `No route to host`: paths with a `{node}`. |
| `hostname_lookup_failed` | 500 | `hostname lookup 'node' failed - ...`: paths with a `{node}`. |
| `permission_denied` | 403 | `Permission check failed (path, privilege)`: methods that are not open to every user. |

## The shape of an error

PVE answers an error with the status code set, the first line of the message as the HTTP reason phrase, and a JSON body:

```json
{"data": null, "message": "VM 100 is running - destroy failed\n"}
```

A 400 from parameter validation adds the per-field errors:

```json
{"data": null, "message": "Parameter verification failed.\n", "errors": {"vmid": "invalid format - value does not look like a valid VM ID\n"}}
```

Messages carry PVE's trailing newline in the JSON, and none in the catalogue. PVE appends ` at /usr/share/perl5/... line N.` to a `die` without a newline; that is left out.

## Limits and approximations

The catalogue is an approximation, because it reads the code and does not run it:

- Errors in functions a method calls are followed two levels deep, and `eval {}` bodies are treated as caught. A few errors therefore belong to a branch the request would not take, and a few real ones deeper down are missed.
- Messages built at run time are templates with the variable's name as the placeholder, filled with a plausible value.
- 22 of the 680 methods could not be mapped to a source method at all (most are the guest agent commands, which PVE registers in a loop), and so have only the cross-cutting errors. Another 193 are mapped but raise nothing the extraction found, typically plain reads.
- `permission_denied` states the rule's first privilege, or `user != root@pam` for rules it cannot summarise, whatever the real rule is. The generic endpoints themselves evaluate the real rule when a user without the privilege calls them.
- Names come from the message text and can change when the catalogue is regenerated for another PVE release. Pin the catalogue (it is a file in the package), or check `pve.errors_for` before relying on a name after updating.

Known gaps in what the fake checks, from the schema: some formats are accepted without checking ([formats](how-it-works.md#formats)), and regular expressions that only Perl understands are not applied.

## Regenerating the catalogue

On a machine with shallow clones of `pve-manager`, `qemu-server`, `pve-container`, `pve-storage`, `pve-access-control`, `pve-cluster`, `pve-firewall`, `pve-network`, `pve-guest-common`, `pve-common`, `pve-ha-manager` and `proxmox-acme` (from `https://git.proxmox.com/git/<name>.git`) in one directory:

```console
python3 tools/extract_errors.py /path/to/clones
```

It reads the vendored schema, writes `src/fakepve/data/pve-errors.json.gz` (the repositories' commits and the date are in its `meta`), and prints the counts and the source methods it could not map. It uses only the Python standard library. The PVE sources are AGPL and nothing but messages and status codes is copied. [How it works](how-it-works.md#refreshing-the-schema-and-the-catalogue) has the whole refresh routine.
