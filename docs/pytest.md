# pytest

fakepve comes with a pytest plugin. Install it with the extra and the fixtures are there, with nothing to import or register:

```console
pip install 'fakepve[pytest]'
```

(`pytest` is the extra that adds `cryptography`, which makes the certificate. The plugin is found through the `pytest11` entry point; `pytest -p no:fakepve` turns it off.)

```python
import requests


def test_list_vms(fakepve, fakepve_url, fakepve_cafile):
    fakepve.add_vm(100, 'web1', status='running')
    login = requests.post(fakepve_url + '/api2/json/access/ticket', verify=fakepve_cafile,
                          data={'username': 'root@pam', 'password': 'secret'}).json()['data']
    rsp = requests.get(fakepve_url + '/api2/json/cluster/resources?type=vm', verify=fakepve_cafile,
                       cookies={'PVEAuthCookie': login['ticket']})
    assert [vm['name'] for vm in rsp.json()['data']] == ['web1']
```

The test body is the usual shape: build the cluster (`add_vm`, scenarios such as `fakepve.fail(...)`), drive your client at the URL, check the result. The [scenarios](scenarios.md) and the [Python API](python-api.md) apply unchanged.

## Fixtures

| Fixture | Scope | Gives |
|---|---|---|
| `fakepve` | function | A started `FakePve` with `time_scale` 0, login `root@pam` / `secret`, no guests. It is stopped after the test, so every test starts clean. |
| `fakepve_session` | session | One started `FakePve` shared by every test that asks for it. State persists between tests, so use it for read-only checks or reset what you change. |
| `fakepve_url` | function | `https://host:port` of the `fakepve` fixture (the same as `fakepve.url`). |
| `fakepve_cafile` | session | The path of the certificate every fake serves. Hand it to the client as its CA bundle and the connection verifies: it names `localhost`, `127.0.0.1` and the listening address. |

The fake runs on an event loop of its own in a background thread. That is what makes the fixtures work for plain tests (requests, proxmoxer, a subprocess such as Terraform or Ansible) and for async ones alike, without pytest-asyncio and whatever the event loop scope of your tests. Setting up guests and faults from the test thread is fine: they are plain attributes. What the test cannot do is `await` the fake's own methods; there is nothing to await.

Scenarios are set as anywhere else:

```python
def test_shutdown_times_out(fakepve, fakepve_url, fakepve_cafile):
    vm = fakepve.add_vm(100, 'web1', status='running')
    vm.shutdown_secs = 90
    ...
```

## Options

The `fakepve` marker sets the login and the time scale for one test, class or module:

```python
import pytest


@pytest.mark.fakepve(user='ops@pve', password='hunter2', time_scale=0.01)
def test_with_a_login(fakepve):
    ...
```

`user` (default `root@pam`), `password` (`secret`) and `time_scale` (`0`, every task finishes before the request returns) are the only options; anything else is a usage error. `fakepve_session` always uses the defaults. For anything more, make your own fixture from `FakePve` and [`make_cert`](ci.md#certificates).

## Parallel tests and addresses

Each fake listens on `127.0.0.1` with a port the system chooses (`port=0`), so two fakes never collide, within one process or across processes. That covers pytest-xdist: every worker has its own session fixtures and its own function fixtures, with different ports. Do not hard-code 8006 or `127.0.0.2` in tests that use the fixtures; use `fakepve_url`, or `fakepve.host` and `fakepve.port`.

The same works outside pytest: `FakePve(host='127.0.0.1', port=0)`, then read `pve.port` after `start()`, or `pve.url`.

## Certificates

The certificate is made once per session in pytest's temporary directory, ECDSA P-256 with the subject alternative names above. The client trusts it by being given `fakepve_cafile`:

| Client | Setting |
|---|---|
| requests | `verify=fakepve_cafile` |
| `ssl` | `ssl.create_default_context(cafile=fakepve_cafile)` |
| aiohttp | `ssl=ssl.create_default_context(cafile=fakepve_cafile)` |
| proxmoxer | `verify_ssl=fakepve_cafile` |
| curl | `--cacert` |
| Anything else | `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` in the environment |

Skipping verification still works wherever your client has an option for it.
