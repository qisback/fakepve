"""The examples run, so they cannot rot. Ones that need an optional package are skipped without it."""

import asyncio
import importlib.util
import os
import shutil
import subprocess
import sys

import pytest

from fakepve import FakePve
from fakepve.certs import make_cert

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
EXAMPLES = os.path.join(ROOT, 'examples')
SRC = os.path.join(ROOT, 'src')


def have(module):
    return importlib.util.find_spec(module) is not None


# example file -> the packages it needs besides fakepve
PYTEST_EXAMPLES = {
    'aiohttp_pytest.py': ['aiohttp', 'pytest_asyncio'],
    'requests_pytest.py': ['requests'],
    'proxmoxer_pytest.py': ['proxmoxer', 'requests'],
}


@pytest.mark.parametrize('name', sorted(PYTEST_EXAMPLES))
def test_pytest_example_passes(name):
    missing = [m for m in PYTEST_EXAMPLES[name] if not have(m)]
    if missing:
        pytest.skip('needs ' + ', '.join(missing))
    env = dict(os.environ, PYTHONPATH=SRC + os.pathsep + os.environ.get('PYTHONPATH', ''))
    result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                             os.path.join('examples', name)], cwd=ROOT, env=env, capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-1000:]
    assert ' passed' in result.stdout


def load_custom_server():
    spec = importlib.util.spec_from_file_location('custom_server', os.path.join(EXAMPLES, 'custom_server.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_custom_server_builds_what_it_says(tmp_path):
    pve = load_custom_server().build(host='127.0.0.1')
    assert pve.apitokens == {'root@pam!ci': 's3cret'}
    assert pve.users == {'ops@pve': 'opspass'}
    assert pve.allowed('ops@pve', '/vms/100', 'VM.Audit') and not pve.allowed('ops@pve', '/vms/100', 'VM.PowerMgmt')
    assert ('DELETE', '/nodes/pve2/qemu/101') in pve.failures
    certfile, keyfile, _ = make_cert(str(tmp_path))
    pve.port = 0
    await pve.start(certfile, keyfile)
    await pve.stop()


def test_custom_server_runs_as_a_script():
    env = dict(os.environ, PYTHONPATH=SRC + os.pathsep + os.environ.get('PYTHONPATH', ''))
    proc = subprocess.Popen([sys.executable, os.path.join(EXAMPLES, 'custom_server.py'), '--host', '127.0.0.1',
                             '--port', '0'], stdout=subprocess.PIPE, text=True, env=env, cwd=ROOT)
    try:
        assert proc.stdout.readline().startswith('fakepve listening on https://127.0.0.1:')
    finally:
        proc.terminate()
        proc.wait(10)


# -------------------------------------------------------------------- curl.sh

CURL = os.path.join(EXAMPLES, 'curl.sh')


@pytest.mark.skipif(shutil.which('sh') is None, reason='needs sh')
def test_curl_script_has_valid_syntax():
    result = subprocess.run(['sh', '-n', CURL], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not (shutil.which('sh') and shutil.which('curl') and shutil.which('python3')),
                    reason='needs sh, curl and python3')
async def test_curl_script_runs_against_the_fake(tmp_path):
    certfile, keyfile, _ = make_cert(str(tmp_path))
    pve = FakePve(user='root@pam', password='secret')
    pve.add_vm(101, 'db1')
    await pve.start(certfile, keyfile)
    try:
        env = dict(os.environ, PVE_URL='https://{0}:{1}'.format(pve.host, pve.port))
        proc = await asyncio.create_subprocess_exec('sh', CURL, env=env, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 60)
    finally:
        await pve.stop()
    text = out.decode()
    assert proc.returncode == 0, text + err.decode()
    assert '"version": "9.0.10"' in text and 'TASK OK' in text and 'HTTP 400' in text
    assert pve.vm(101).status == 'running'


# ------------------------------------------------------------------- CI files

def test_ci_files_are_valid_yaml():
    yaml = pytest.importorskip('yaml')
    names = sorted(os.listdir(os.path.join(EXAMPLES, 'ci')))
    assert names == ['forgejo-actions.yml', 'github-actions.yml', 'gitlab-ci.yml']
    for name in names:
        with open(os.path.join(EXAMPLES, 'ci', name), encoding='utf-8') as fh:
            assert isinstance(yaml.safe_load(fh), dict), name


def test_dockerfile_runs_the_cli():
    with open(os.path.join(ROOT, 'Dockerfile'), encoding='utf-8') as fh:
        text = fh.read()
    assert 'EXPOSE 8006' in text
    assert 'ENTRYPOINT ["python", "-m", "fakepve"]' in text
    assert "'.[crypto]'" in text
    for path in ('pyproject.toml', 'README.md', 'LICENSE', os.path.join('examples', 'guests.json')):
        assert os.path.exists(os.path.join(ROOT, path)), path
