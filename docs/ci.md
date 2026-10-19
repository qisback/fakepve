# Using fakepve in CI

fakepve is one Python process on aiohttp: no PVE, QEMU, Ceph or corosync, a few hundred milliseconds to start. That makes it cheap to run in every pipeline. This page covers the ways to run it, the choice of `time_scale`, certificates, and ready-made recipes for GitHub Actions, Forgejo and Gitea Actions, GitLab CI and plain pytest.

Contents: [three ways to run it](#three-ways-to-run-it) | [pytest](#pytest) | [a background process](#a-background-process) | [time_scale](#choosing-time_scale) | [several fakes](#several-fakes) | [certificates](#certificates) | [a container](#a-container) | [pipelines](#pipelines) | [when a pipeline fails](#when-a-pipeline-fails)

## Three ways to run it

| | In the test process | A background process | A container |
|---|---|---|---|
| Best for | Python tests, any client library you can call from Python | Anything that is not Python: Terraform, Ansible, Go, shell, a CLI | A pipeline that already uses service containers |
| How | `FakePve` in a fixture | `python -m fakepve` and wait for it | `docker run` or a service |
| Scenarios (locks, quorum, failures, ...) | All of them, set from the test | Only what the [command line](cli.md) sets, or a script like [`custom_server.py`](../examples/custom_server.py) | The same as a process |
| Start-up wait | None | Wait for the "listening" line or poll | Health check or poll |

If your client is not written in Python but you want the scenarios, write a small server script (as [`examples/custom_server.py`](../examples/custom_server.py) does), run it as a background process, and give it your tests' setup.

## pytest

### Async client (aiohttp, httpx)

The fake runs in the test's own event loop, so there is nothing to wait for. [`examples/aiohttp_pytest.py`](../examples/aiohttp_pytest.py) is a complete file; the core is two fixtures:

```python
import pytest
import pytest_asyncio
from fakepve import FakePve, settle
from fakepve.certs import make_cert


@pytest.fixture(scope='session')
def cert(tmp_path_factory):
    certfile, keyfile, _ = make_cert(str(tmp_path_factory.mktemp('pki')))
    return certfile, keyfile


@pytest_asyncio.fixture
async def pve(cert):
    fake = FakePve(user='root@pam', password='secret')
    await fake.start(*cert)
    yield fake                 # the test adds VMs and breaks things here
    await settle()
    await fake.stop()
```

VMs and scenarios can be set up after the fake has started, so the test body does the configuring. Add `asyncio_mode = "auto"` under `[tool.pytest.ini_options]` in `pyproject.toml` to drop the `pytest.mark.asyncio` marks. A function-scoped fixture gives every test a clean cluster; the session-scoped certificate keeps key generation out of the loop.

Within one process every fake gets its own loopback address, so any number of them can use port 8006. Separate processes do not know about each other: each `pytest-xdist` worker starts counting from `127.0.0.2` again, and so do two CI jobs on one machine. Give them different addresses or ports, for example `FakePve(host='127.0.0.{0}'.format(10 + worker_index))`.

### Sync client (requests, proxmoxer, the proxmoxer-based Ansible modules)

A synchronous client blocks the thread it runs in, so the fake needs a thread of its own. [`examples/requests_pytest.py`](../examples/requests_pytest.py) and [`examples/proxmoxer_pytest.py`](../examples/proxmoxer_pytest.py) show it. The idea is a loop in a background thread, and `run_coroutine_threadsafe` for the few calls that are coroutines:

```python
class ThreadedFake(object):
    def __init__(self, certfiles, **attrs):
        self.pve = FakePve(user='root@pam', password='secret')
        for name, value in attrs.items():
            setattr(self.pve, name, value)
        self.certfiles = certfiles
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)

    def run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(30)

    def __enter__(self):
        self.thread.start()
        self.run(self.pve.start(*self.certfiles))
        return self

    def __exit__(self, *exc):
        self.run(settle())
        self.run(self.pve.stop())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)
        self.loop.close()
```

Setting attributes (`vm.shutdown_secs = 90`, `pve.tfa = True`, `pve.fail(...)`) from the test thread is safe. Coroutine methods (`backup`, `migrate`, `hold_config_lock`) go through `fake.run(...)`.

### Checking what the client sent

`pve.requests` lists every request as `(method, path, body)`. It is the simplest way to assert that a module sent the right call, or did not send one:

```python
assert ('POST', '/api2/json/nodes/pve1/qemu/100/status/start', b'') in pve.requests
```

## A background process

For clients that are not Python, start the fake as a process and wait until it is up. The command prints one line, `fakepve listening on https://HOST:PORT`, after it is listening, so reading that line is a reliable "ready":

<!-- run -->
```python
import json
import ssl
import subprocess
import sys
import urllib.request

proc = subprocess.Popen([sys.executable, '-m', 'fakepve', 'examples/guests.json', '--host', '127.0.0.77',
                         '--time-scale', '0'], stdout=subprocess.PIPE, text=True)
try:
    print(proc.stdout.readline().strip())              # blocks until it is listening
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen('https://127.0.0.77:8006/api2/json/access/domains', context=ctx) as rsp:
        print(rsp.status, json.load(rsp))
finally:
    proc.terminate()
    proc.wait(10)
```

<!-- output -->
```text
fakepve listening on https://127.0.0.77:8006
200 {'data': [{'realm': 'fake', 'type': 'fake'}]}
```

From a shell, poll instead. `/access/domains` is one of the few endpoints that needs no login, which makes it a good probe:

```sh
python -m fakepve guests.json --host 127.0.0.2 --time-scale 0 > fakepve.log 2>&1 &
for i in $(seq 1 30); do
    curl -ksf https://127.0.0.2:8006/api2/json/access/domains >/dev/null && break
    sleep 1
done
curl -ksf https://127.0.0.2:8006/api2/json/access/domains >/dev/null || { cat fakepve.log; exit 1; }
```

Stop it with `kill %1`, or let the job end: CI runners clean up processes with the job. Keep its output in a file and print the file when the job fails.

## Choosing `time_scale`

Durations (a shutdown that takes 90 seconds, a lock held for a minute) are in PVE seconds, and `time_scale` is the number of real seconds per PVE second.

| `time_scale` | Use it for | Notes |
|---|---|---|
| `0` | Unit tests that check outcomes: what the client sends, what it does with an error | Every task finishes before the request returns. Durations (`shutdown_secs`, latency, `ha_delay`) do not wait, but a shutdown still fails when it exceeds its timeout. A held config lock cannot be observed. This is the class default. |
| `0.01` | Scenario tests where timing is the point: timeouts, polling a running task, locks, HA, migrations | 60 PVE seconds take 0.6 real seconds. Tasks show `running`, so the client must poll. Pick the smallest scale at which your client's own polling still sees the states. |
| `1` | The default of the command line; real-time behaviour, demos | Too slow for most pipelines. |

With a non-zero scale, a test that races a task needs to wait for it (poll `tasks/{upid}/status`) rather than sleep. The recipes in [Scenarios](scenarios.md) do this with a small `wait` helper.

## Several fakes

Each `FakePve` takes the next loopback address (`127.0.0.2`, `127.0.0.3`, ...), so any number of fakes can listen on port 8006 in one process or one machine at once. This is the way to test a client against several clusters or several sites:

<!-- run -->
```python
import tempfile

from fakepve import FakePve, settle
from fakepve.certs import make_cert

certfile, keyfile, _ = make_cert(tempfile.mkdtemp())
site_a = FakePve()
site_b = FakePve()
site_b.set_node_offline('pve1')
await site_a.start(certfile, keyfile)
await site_b.start(certfile, keyfile)
print(site_a.host != site_b.host, site_a.port == site_b.port == 8006)
await settle()
await site_a.stop()
await site_b.stop()
```

<!-- output -->
```text
True True
```

From the command line pass `--host` for each. This works on Linux, where all of `127.0.0.0/8` is local. Where only `127.0.0.1` is (macOS by default), give each fake that address and a different `--port`, or set the address explicitly with `FakePve(host='127.0.0.1', port=18006)`.

## Certificates

Without `--cert` and `--key` (and with `cryptography` installed) the fake makes a self-signed ECDSA certificate: P-256, valid for 30 days, common name `fakepve`, and no subject alternative names. A client that verifies host names rejects it, so there are two choices.

**Skip verification.** The usual flag in a test. It is the right choice when the code under test already has an option for self-signed PVE (the people who run Proxmox at home have it set). Typical forms, to be checked against your client's documentation:

| Client | Setting |
|---|---|
| curl | `-k` |
| Python requests | `verify=False` (and silence `InsecureRequestWarning`) |
| aiohttp | `TCPConnector(ssl=False)`, or an `SSLContext` with `check_hostname = False` and `verify_mode = ssl.CERT_NONE` |
| proxmoxer | `verify_ssl=False` |
| Go | `tls.Config{InsecureSkipVerify: true}` |
| Terraform providers | the provider's `insecure` option (`pm_tls_insecure` in telmate/proxmox) |
| Ansible `community.general.proxmox*` | `validate_certs: false` |

**Trust a certificate you made.** To test that your client verifies properly, make a certificate with the address as a subject alternative name, serve it with `--cert` and `--key`, and give the client the certificate as its CA:

```console
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout fake.key -out fake.crt -days 30 -subj "/CN=fakepve" \
    -addext "subjectAltName=IP:127.0.0.2,DNS:localhost"
fakepve examples/guests.json --cert fake.crt --key fake.key
curl --cacert fake.crt https://127.0.0.2:8006/api2/json/access/domains
```

If the key is in the same PEM file as the certificate, `--key` can be left out. The same file works as the trust anchor for Python (`requests.get(url, verify='fake.crt')`, `ssl.create_default_context(cafile='fake.crt')`) and through the environment variables `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE`. From Python, `await pve.start('fake.crt', 'fake.key')` takes the same files.

## A container

The repository's `Dockerfile` builds an image from `python:3.12-slim`, installs the package with the `crypto` extra, and runs `python -m fakepve`:

```console
docker build -t fakepve .
docker run --rm -p 8006:8006 fakepve
```

By default the container serves `examples/guests.json` (copied into the image as `guests.json`) on `0.0.0.0:8006` with `--time-scale 0`, runs as an unprivileged user, and has a health check that connects to the port. Arguments after the image name replace the default command:

```console
docker run --rm -p 8006:8006 fakepve guests.json --host 0.0.0.0 --time-scale 0.01
docker run --rm -p 8006:8006 -v "$PWD/mine.json:/opt/fakepve/mine.json:ro" fakepve mine.json --host 0.0.0.0
```

Remember `--host 0.0.0.0` whenever you replace the arguments: inside a container the default `127.0.0.2` is unreachable from outside. The certificate is self-signed with no SAN, as above, so clients skip verification or you mount your own with `--cert` and `--key`.

**As a CI service container.** The image is reachable by the service name (GitLab: the `alias`) or `localhost` on a published port (GitHub), at port 8006. Services cannot be given arguments on GitHub and Forgejo, so build an image that bakes in your guests file and `FROM` the fakepve one:

```dockerfile
FROM fakepve:latest
COPY ci/guests.json /opt/fakepve/guests.json
```

The workflows below use it. On GitLab the service's `command` can set the arguments instead.

## Pipelines

Complete files are in [`examples/ci/`](../examples/ci). They are examples: replace the test and smoke-test steps with the client you are testing. `ci/guests.json` and `ci/smoke.sh` stand for your own files ([`examples/curl.sh`](../examples/curl.sh) makes a start for the latter).

### GitHub Actions

[`examples/ci/github-actions.yml`](../examples/ci/github-actions.yml) has four jobs: in-process pytest, a background process, a container built in the job, and a service container. The background-process job is:

```yaml
background-process:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with:
        python-version: '3.12'
    - run: pip install 'fakepve[crypto]'
    - name: start fakepve
      run: |
        python -m fakepve ci/guests.json --host 127.0.0.2 --time-scale 0 > fakepve.log 2>&1 &
        for i in $(seq 1 30); do
          curl -ksf https://127.0.0.2:8006/api2/json/access/domains >/dev/null && exit 0
          sleep 1
        done
        cat fakepve.log
        exit 1
    - name: run the client under test
      env:
        PVE_URL: https://127.0.0.2:8006
      run: sh ci/smoke.sh
```

The step that starts the process must end: the `&` puts it in the background and the loop returns, leaving the process running for the following steps.

### Forgejo and Gitea Actions

[`examples/ci/forgejo-actions.yml`](../examples/ci/forgejo-actions.yml) is the same shape for `.forgejo/workflows/` or `.gitea/workflows/`. Self-hosted runners often have no `setup-python` or node available, so it uses the runner's `python3` and installs by name, as this repository's own workflow does (`python3 -m pip install ... aiohttp cryptography pytest pytest-asyncio`). Use `$RUNNER_TEMP` for the log file.

### GitLab CI

[`examples/ci/gitlab-ci.yml`](../examples/ci/gitlab-ci.yml) has pytest, a background process and a service container. GitLab starts a service next to the job and reaches it by its alias:

```yaml
service-container:
  image: python:3.12-slim
  services:
    - name: registry.example.org/yourteam/fakepve:latest
      alias: pve
      command: ["guests.json", "--host", "0.0.0.0", "--time-scale", "0"]
  variables:
    PVE_URL: https://pve:8006
  script:
    - sh ci/smoke.sh
```

### Plain pytest

No CI-specific files at all: `pip install 'fakepve[crypto]' pytest pytest-asyncio aiohttp` and `pytest`. The fake is part of the test process, so any CI that can run your tests can run it.

## When a pipeline fails

- **Address already in use.** Another fake or a real service holds the address and port, often a parallel job on the same runner. In one process fakes pick their own address; across processes use `--host` or `--port` (or `host=` and `port=`).
- **`ModuleNotFoundError: No module named 'cryptography'`.** Install the `crypto` extra, or pass `--cert` and `--key`.
- **`certificate verify failed`.** The client is verifying the self-signed certificate; see [certificates](#certificates).
- **Connection refused right after start.** The process was not ready. Wait for the "listening" line or poll as above.
- **A client sees `ServerDisconnectedError` or `Connection reset`.** A flaky-network scenario is on (`flaky_network`), or the process died. The server's stderr, kept in a file, says which.
- **Print what the client did.** `pve.requests` for in-process runs; for a background process there is no request log, so give the client a verbose flag.
