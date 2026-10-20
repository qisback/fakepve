"""The pytest plugin, run the way a user runs it: pytest in a subprocess against a test file."""

import importlib.util
import json
import os
import re
import subprocess
import sys
from importlib import metadata

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

HEADER = '''
import json
import os
import ssl
import urllib.request

import pytest


def login(url, cafile, user='root@pam', password='secret'):
    ctx = ssl.create_default_context(cafile=cafile)
    data = ('username=%s&password=%s' % (user, password)).encode()
    with urllib.request.urlopen(url + '/api2/json/access/ticket', data=data, context=ctx) as rsp:
        return json.load(rsp)['data']


def report(url):
    worker = os.environ.get('PYTEST_XDIST_WORKER', 'main')
    with open(os.path.join(os.environ['REPORT_DIR'], worker + '.json'), 'a') as out:
        out.write(json.dumps({'worker': worker, 'url': url}) + chr(10))
'''

BASIC = '''

def test_sync_fixture_verifies_with_the_cafile(fakepve, fakepve_url, fakepve_cafile):
    assert fakepve_url == fakepve.url and fakepve.port != 8006
    assert fakepve.time_scale == 0
    fakepve.add_vm(100, 'web1', status='running')
    assert login(fakepve_url, fakepve_cafile)['username'] == 'root@pam'
    report(fakepve_url)


@pytest.mark.fakepve(user='ops@pve', password='hunter2', time_scale=0.5)
def test_marker_sets_the_login_and_time_scale(fakepve, fakepve_url, fakepve_cafile):
    assert fakepve.time_scale == 0.5
    assert login(fakepve_url, fakepve_cafile, 'ops@pve', 'hunter2')['username'] == 'ops@pve'


def test_function_scope_gives_a_fresh_fake(fakepve):
    assert fakepve.vms == []


def test_session_fake_is_shared_and_keeps_state(fakepve_session, fakepve_cafile):
    fakepve_session.add_vm(200, 'shared')
    assert login(fakepve_session.url, fakepve_cafile)


def test_session_fake_state_is_still_there(fakepve_session):
    assert [vm.vmid for vm in fakepve_session.vms] == [200]
'''

ASYNC = '''

@pytest.mark.asyncio
async def test_async_test_can_use_the_fixture(fakepve, fakepve_url):
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.post(fakepve_url + '/api2/json/access/ticket', ssl=False,
                                data={'username': 'root@pam', 'password': 'secret'}) as rsp:
            assert rsp.status == 200
'''

PARALLEL = '''
import time


@pytest.mark.parametrize('n', range(8))
def test_parallel(n, fakepve, fakepve_cafile):
    fakepve.add_vm(300 + n, 'p%d' % n)
    time.sleep(0.2)
    assert login(fakepve.url, fakepve_cafile)
    report(fakepve.url)
'''

BAD_MARKER = '''
import pytest


@pytest.mark.fakepve(colour='red')
def test_bad(fakepve):
    pass
'''


def plugin_args():
    """Load the plugin explicitly unless the installed package already registers it."""
    entries = metadata.entry_points(group='pytest11')
    if any(e.value == 'fakepve.pytest_plugin' for e in entries):
        return []
    return ['-p', 'fakepve.pytest_plugin']


def run_pytest(tmp_path, source, *args, name='test_user.py'):
    (tmp_path / name).write_text(source)
    report = tmp_path / 'report'
    report.mkdir(exist_ok=True)
    env = dict(os.environ, REPORT_DIR=str(report), PYTHONPATH=os.path.join(ROOT, 'src'))
    env.pop('PYTEST_ADDOPTS', None)
    command = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--rootdir', str(tmp_path),
               *plugin_args(), *args, str(tmp_path / name)]
    result = subprocess.run(command, cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=300)
    reports = [json.loads(line) for path in sorted(report.glob('*.json')) for line in path.read_text().splitlines()]
    return result, reports


def test_fixtures_work_in_a_user_project(tmp_path):
    result, reports = run_pytest(tmp_path, HEADER + BASIC)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '5 passed' in result.stdout, result.stdout
    assert len(reports) == 1 and reports[0]['url'].startswith('https://127.0.0.1:')


@pytest.mark.skipif(importlib.util.find_spec('pytest_asyncio') is None, reason='needs pytest-asyncio')
def test_fixtures_work_in_async_tests(tmp_path):
    result, _ = run_pytest(tmp_path, HEADER + ASYNC, '-o', 'asyncio_mode=strict')
    assert result.returncode == 0, result.stdout + result.stderr
    assert '1 passed' in result.stdout, result.stdout


def test_unknown_marker_option_is_a_usage_error(tmp_path):
    result, _ = run_pytest(tmp_path, BAD_MARKER, name='test_bad.py')
    assert result.returncode != 0
    assert 'user, password and time_scale' in result.stdout + result.stderr


@pytest.mark.skipif(importlib.util.find_spec('xdist') is None, reason='needs pytest-xdist')
def test_xdist_workers_get_their_own_addresses(tmp_path):
    result, reports = run_pytest(tmp_path, HEADER + PARALLEL, '-p', 'xdist', '-n', '2')
    assert result.returncode == 0, result.stdout + result.stderr
    assert '8 passed' in result.stdout, result.stdout
    assert {r['worker'] for r in reports} == {'gw0', 'gw1'}
    # Every fake, in either worker, had a different address and port.
    urls = [r['url'] for r in reports]
    assert len(urls) == 8 and len(set(urls)) == 8


def test_entry_point_is_declared():
    with open(os.path.join(ROOT, 'pyproject.toml'), encoding='utf-8') as fh:
        text = fh.read()
    assert re.search(r'\[project\.entry-points\.pytest11\]\s+fakepve = "fakepve\.pytest_plugin"', text)
