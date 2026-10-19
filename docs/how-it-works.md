# How it works

A tour of the code for anyone who wants to change fakepve, trust its answers, or refresh it for a new PVE release. For using it, start with [Getting started](getting-started.md).

Contents: [the idea](#the-idea) | [modules](#modules) | [a request's path](#a-requests-path) | [hand-written routes](#hand-written-routes) | [the generic handler](#the-generic-handler) | [validation](#validation) | [permissions](#permissions) | [tasks](#the-task-model) | [locks](#locks) | [errors](#errors) | [known gaps](#known-gaps) | [data files](#data-files) | [refreshing](#refreshing-the-schema-and-the-catalogue) | [tests](#tests) | [documentation tooling](#documentation-tooling)

## The idea

The fake needs to know what a call returns and what it can fail with. It does not reimplement PVE. Two ideas follow:

1. **Outcomes and errors, not behaviour.** The PVE API schema says what every endpoint accepts and answers with; the PVE sources say which errors each one can raise. Both are vendored as data. Most endpoints are answered from the schema alone: a write succeeds and changes nothing, a read returns a value of the right shape.
2. **Behaviour only where a client reads back what it did.** A small set of endpoints (login, VM power, config, tasks, storage content) is hand-written and keeps state, because a client starts a VM and then asks whether it is running. These override the generic answers.

It stays one Python process on aiohttp. No PVE, QEMU, Ceph or corosync is run, and no PVE code is ported: only strings and the schema are taken from PVE.

## Modules

| Module | Role |
|---|---|
| `fakepve/server.py` | `FakePve`: the aiohttp application, the middleware, and the hand-written routes (access, version, nodes, cluster, tasks, storage, VM status/config/agent/consoles). |
| `fakepve/model.py` | `Model` (the state and the scenario methods) and `FakeVm`; `PveError` and `TaskError`. `FakePve` inherits from `Model`. |
| `fakepve/generic.py` | `GenericApi`, a mixin of `FakePve`: the catch-all route, which checks parameters and permissions against the schema and builds answers. |
| `fakepve/schema.py` | The schema: path matching, parameter validation with PVE's wording, sample values for `returns`. |
| `fakepve/errors.py` | The error catalogue: lookup by name, cross-cutting errors, placeholder filling. |
| `fakepve/certs.py` | The self-signed certificate. |
| `fakepve/__main__.py` | The command line. |
| `fakepve/data/` | The vendored PVE data: schema and error catalogue. |
| `tools/` | Scripts that refresh the data, generate the reference docs, run the docs' code, and take the screenshots. |

## A request's path

1. aiohttp matches the path against the hand-written routes, which are registered first. Anything else falls to the catch-all `/api2/json/{tail}` route, which is registered last.
2. The **middleware** (`FakePve._middleware`) wraps every request:
   1. records `(method, path, body)` in `pve.requests`;
   2. resolves the path against the schema, for the generic handler and for placeholders;
   3. applies the network scenarios: latency and jitter (global and per node), then a dropped connection (the transport is closed) or a hang (a sleep);
   4. looks for a matching `pve.fail` rule. A plain rule answers at once with its status and message, or an HTML page. A rule by catalogue name answers with the rendered error, or, if the catalogue says the error happens in a worker, remembers that a task has to fail and goes on;
   5. authenticates: an `Authorization: PVEAPIToken=` header, or the `PVEAuthCookie` ticket (checking expiry, and the `CSRFPreventionToken` header on writes). A few generic endpoints need no login; for those a failed login is not an error;
   6. returns 595 if the path's node is offline;
   7. runs the handler, or, for a pending task failure, starts the task that fails.
3. A `PveError` from anywhere becomes the response: the status, the first line of the message as the reason phrase, and `{"data": null, "message": "...\n"}` plus `errors` for a 400.

## Hand-written routes

`FakePve._build_app` lists them. They are the paths whose answers depend on what happened before:

- `access/ticket`, `access/password`, `version`;
- `nodes`, `cluster/resources`, `cluster/status`, `cluster/ceph/status`;
- per node: `tasks`, `tasks/{upid}/status`, `tasks/{upid}/log`, `storage`, `storage/{s}/content`, `storage/{s}/download-url`, `storage/{s}/upload`;
- per VM: `status/current`, `status/{start,stop,shutdown,reboot,reset,suspend,resume}`, `config` (GET, PUT, and POST as a task), `pending`, `termproxy`, `vncproxy`, `vncwebsocket`, `agent/{get-osinfo,network-get-interfaces,ping}`, `monitor`.

They follow PVE's rules: config writes on a running VM go to `pending` unless the key is hot-pluggable; a CD-ROM media change applies at once; `reboot` and a cold start apply pending changes and `reset` does not; `PUT config` checks the `digest`, validates the boot order against the VM's devices, and checks the privilege each key needs (`hookscript` is root only); starting a running VM, or acting on a stopped one, gets PVE's messages; templates cannot be started.

Two route families are claimed as a whole, so they hide generic answers: `status/{action}` (an action without a `_do_` handler answers 501) and `agent/{command}` (a command outside `AGENT_COMMANDS` answers 501). The [endpoint reference](reference/endpoints.md) marks the methods affected as "routed to a hand-written handler that answers 501". The LXC endpoints are all generic: they validate and answer, but a container is not modelled.

## The generic handler

`GenericApi.answer` handles every other request, in this order:

1. 404 if the path is not in the schema, 501 if the path is but the method is not.
2. **Validate** the parameters (path parameters included) against the method's schema. Errors give 400 with a per-field `errors` object.
3. 500 `hostname lookup ... failed` if the path names a node the model does not know.
4. **Check permissions** against `pve.grant`.
5. **Synthesise** the answer: a task if the method starts one, else a value built from `returns`.

### Synthesising answers

`schema.sample` builds a value from a `returns` schema: required properties are filled, optional ones only where the name says what to put (`node`, `vmid`, `storage`), lists have one item, numbers are their minimum or default, strings come from the `format` (a node name, a storage id, an IP address) or from a string that matches the `pattern`. Values come from the request path and the model where they can. A method with a `links` directory listing returns one entry per child path.

A method starts a task when it `returns` a string, is `protected`, and its description mentions a task or UPID (`schema.is_task`); `NOT_TASKS` in `generic.py` lists the exceptions. The task is real: it has a UPID, shows in `tasks`, and finishes `OK`. Its type is the last segment of the path (`start`, `vmid`, ...), not PVE's own (`qmstart`), unlike the hand-written and by-name-failed tasks.

## Validation

`schema.validate` checks, with PVE's wording: missing properties, properties the schema does not define (when it forbids extras), enums, types (booleans take 0/1, true/false, yes/no, on/off), minimum and maximum, string length and patterns, `requires` dependencies, and array item counts. Not checked: `format` property strings, and regular expressions that only Perl understands (they are skipped). Values come from the query string, a form body or a JSON body.

## Permissions

`pve.acl` is `None` until the first `grant()`, and everyone is allowed everything. After that only `root@pam` (or a token of it) is exempt, and `allowed(user, path, priv)` looks for a grant on the path or any parent, including pool paths for VMs.

The generic handler evaluates the schema's `permissions` field: `perm` with a path template, privileges and the options `any`, `require_param`; `and` and `or`; `userid-param`; `userid-group` (approximated as the privileges on `/access/groups`, since there is no group model); `perm-modify`; and `user: all` or `world`. `{param}` in a path is filled from the request. A method with no permissions in the schema, or a rule of a form not known here, is root only. The 403 reads `Permission check failed (/vms/100, VM.PowerMgmt)`.

## The task model

`Model.task(node, ttype, tid, user, body, vm=None, lock=True, log=())`:

1. makes a UPID, `UPID:<node>:<pid hex>:<pstart hex>:<start hex>:<type>:<id>:<user>:`, and a record that is stored in `pve.tasks` and `pve.tasklog`;
2. at `time_scale` 0 runs the task to the end before returning; otherwise schedules it on the event loop and returns the UPID at once;
3. the task takes the VM's config lock first (waiting `lock_wait` PVE seconds for another holder), runs `body()`, and releases it;
4. `body` may return a string, which is logged, and raises `TaskError` to fail;
5. at the end the record gets `status: stopped`, `exitstatus` (`OK` or the message), `endtime`, and the log gets `TASK OK` or `TASK ERROR: message`.

Everything that takes time (`vm.shutdown_secs`, `start_secs`, `pve.backup`, Ceph slowness) goes through `pause`, which scales it. That is the only reason one switch, `time_scale`, covers all of it.

## Locks

There are two, as on PVE. The **lock field** (`vm.lock`: `backup`, `migrate`, `snapshot`, ...) is visible in the config and `status/current`, and start, shutdown, reboot and config writes check it and answer `VM is locked (backup)`. The **config lock** (`vm.lock_holder`) is PVE's lock file: tasks and config writes take it and wait for it, and `hold_config_lock` takes it on behalf of a pretend worker. Waiting for a held lock times out after `lock_wait` PVE seconds with `can't lock file '/var/lock/qemu-server/lock-N.conf' - got timeout`. At `time_scale` 0 nothing waits, so a held config lock fails at once.

## Errors

Handlers raise `PveError(status, message, errors)`. Named errors come from `errors.py`: `listing(method, path)` is the catalogue's entries for the method plus the cross-cutting ones, `render` fills the placeholders, and the middleware turns the result into a response, or into a failing task for entries marked `in_task` ([Errors](errors.md)).

## Known gaps

Stated plainly, so nobody has to find them by surprise:

- **Most of the API keeps no state.** Outside the hand-written routes a write succeeds and changes nothing, and a read returns a made-up value of the right shape. Create a VM through `POST /nodes/pve1/qemu` and it does not exist afterwards; add VMs with `pve.add_vm` or the guests file.
- **Containers are not modelled.** The `lxc` endpoints validate and answer from the schema, but there are no containers to start, stop or list.
- **Guest agent commands:** only `ping`, `get-osinfo` and `network-get-interfaces` are modelled. The other 22 `agent/*` methods answer 501.
- **Two-factor logins stop at `NeedTFA`.** There is no second step to complete.
- **`/api2/extjs` is not served**, only `/api2/json`.
- **Property strings are not validated** (`format` schemas such as `virtio=...,bridge=...`), nor are regular expressions that only Perl understands.
- **Generic tasks have a simple type.** A task started by a generic method is named after the last path segment (`start`, `vmid`), not PVE's (`qmstart`, `qmdestroy`). Tasks of the hand-written routes and of failures by name use PVE's names.
- **Ceph changes are detected on existing disks.** `ceph_down` fails a config change to a disk that is already on RBD; adding a new RBD disk to a VM goes through.
- **`pve.latency` does nothing.** Use `slow_network()`.
- **The guests file** cannot set a pool, pending changes or anything but the fields in [Getting started](getting-started.md#the-guests-file).
- **The error catalogue is an approximation**, with its own list of limits in [Errors](errors.md#limits-and-approximations).

## Data files

`src/fakepve/data/` holds:

- `pve-api.json.gz`: the PVE API viewer's `apidoc.js`, trimmed to what answering needs (parameters, returns, permissions, `protected`, `allowtoken`; the prose is dropped except the `returns` description, which is how task methods are recognised), as `{"paths": {template: {METHOD: info}}}`.
- `pve-api.meta.json`: its source, date, SHA-256, and the counts.
- `pve-errors.json.gz`: `{"meta": ..., "errors": {"METHOD template": [entry, ...]}}`. The entry fields are in [Errors](errors.md).

Both are derived from Proxmox VE, which is AGPL-3.0, and are distributed under the same terms (see the licence section of the README).

## Refreshing the schema and the catalogue

For a new PVE release:

1. **Schema.** `python tools/fetch_schema.py [URL_OR_FILE]` downloads the API viewer's `apidoc.js` (the default is `https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js`), trims it, and writes `pve-api.json.gz` and `pve-api.meta.json`.
2. **Error catalogue.** Clone the twelve PVE repositories (listed in [Errors](errors.md#regenerating-the-catalogue)) into one directory and run `python3 tools/extract_errors.py /path/to/clones`. It writes `pve-errors.json.gz` and prints the counts and the source methods it could not map. It reads the code with a small Perl tokenizer; it does not run it.
3. **Version.** Update `Model.version` and `Model.release_version` in `model.py` if the answer of `/version` should follow.
4. **Tests.** Run the test suite. The coverage test sends a valid request to every method in the schema and checks the answer against its `returns`; the catalogue tests check names, placeholders and triggering.
5. **Docs.** Regenerate the derived documentation (below) and commit it with the data: the endpoint reference and the signature index change with the schema, and the output blocks in [Scenarios](scenarios.md) may change with the catalogue.

## Tests

`tests/` holds, besides the unit tests of the fake:

- `test_schema_api.py`: every method of the schema answers, and the answer matches `returns`; validation and permission behaviour of the generic handler.
- `test_error_catalogue.py`: the catalogue, `errors_for`, triggering by name, in-task errors.
- `test_scenarios.py` and `test_smoke.py`: the stateful behaviour and the scenarios.
- `test_docs.py`: the documentation (below). `test_examples.py`: the examples run.

Lint with `ruff check .` and run `pytest` from the repository root, with `src` on the path (`PYTHONPATH=src`) when the package is not installed.

![The test suite](img/tests.svg)

## Documentation tooling

The documentation is kept honest by code:

- `tools/gen_docs.py` generates `docs/reference/endpoints.md` (from the schema, the catalogue and the registered routes) and the signature index at the end of `docs/python-api.md` (from the code). `python tools/gen_docs.py` rewrites them; `--check` reports whether they are stale. A test runs the check.
- `tools/docs_runner.py` runs the code blocks in the docs. A `python` fence after a `<!-- run -->` line is executed (top-level `await` works, and the blocks of one file share a namespace). A `text` fence after a `<!-- output -->` line must equal what the block printed. `python tools/docs_runner.py --fill` rewrites the output blocks from a real run.
- `tools/screenshots.py` runs real commands against a running fake and renders them as SVG terminal images in `docs/img`. It needs `rich` (`pip install rich`), which is not a dependency of fakepve.
- `tests/test_docs.py` checks the relative links, the generated files, the run blocks, and that no page uses an em dash or en dash.
