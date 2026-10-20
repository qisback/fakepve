"""The command line: it starts, loads a guests file, and takes its login from options or the environment."""

import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
GUESTS = os.path.join(ROOT, 'examples', 'guests.json')


def free_port(host):
    with socket.socket() as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def env(**extra):
    out = dict(os.environ)
    out['PYTHONPATH'] = os.path.join(ROOT, 'src') + os.pathsep + out.get('PYTHONPATH', '')
    out.update(extra)
    return out


class Cli(object):
    """A running `python -m fakepve`, and a small client for it."""

    def __init__(self, args, host, port, **extra_env):
        self.host, self.port = host, port
        self.proc = subprocess.Popen([sys.executable, '-m', 'fakepve'] + args, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, env=env(**extra_env), cwd=ROOT)
        self.banner = self.proc.stdout.readline().strip()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx

    def call(self, path, data=None, headers=None, method=None):
        url = 'https://{0}:{1}/api2/json{2}'.format(self.host, self.port, path)
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        request = urllib.request.Request(url, body, headers or {}, method=method)
        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=10) as rsp:
                return rsp.status, json.load(rsp)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def login(self, user='root@pam', password='secret'):
        status, body = self.call('/access/ticket', {'username': user, 'password': password})
        if status != 200:
            return status, {}
        data = body['data']
        return status, {'Cookie': 'PVEAuthCookie=' + data['ticket'], 'CSRFPreventionToken': data['CSRFPreventionToken']}

    def stop(self):
        self.proc.terminate()
        self.proc.wait(10)


@pytest.fixture
def cli():
    started = []

    def start(args, host='127.0.0.1', **extra_env):
        port = free_port(host)
        process = Cli(args + ['--host', host, '--port', str(port)], host, port, **extra_env)
        started.append(process)
        return process
    yield start
    for process in started:
        process.stop()


def test_serves_the_guests_file(cli):
    server = cli([GUESTS, '--time-scale', '0'])
    assert server.banner == 'fakepve listening on https://{0}:{1}'.format(server.host, server.port)
    status, auth = server.login()
    assert status == 200
    _, body = server.call('/cluster/resources?type=vm', headers=auth)
    vms = dict((item['vmid'], item) for item in body['data'])
    assert sorted(vms) == [100, 101, 102, 103, 9000]
    assert vms[100]['status'] == 'running' and vms[9000]['template'] == 1
    _, body = server.call('/nodes/pve1/qemu/102/status/current', headers=auth)
    assert body['data']['qmpstatus'] == 'paused'


def test_a_guest_start_error_fails_the_task(cli):
    server = cli([GUESTS, '--time-scale', '0'])
    _, auth = server.login()
    _, body = server.call('/nodes/pve1/qemu/103/status/start', {}, auth, 'POST')
    _, task = server.call('/nodes/pve1/tasks/{0}/status'.format(body['data']), headers=auth)
    assert task['data']['exitstatus'] == "volume 'local-lvm:vm-103-disk-0' does not exist"


def test_login_from_options_and_environment(cli):
    by_option = cli([GUESTS, '--time-scale', '0', '--user', 'admin@pve', '--password', 'hunter2'])
    assert by_option.login('admin@pve', 'hunter2')[0] == 200
    assert by_option.login('root@pam', 'secret')[0] == 401
    by_env = cli([GUESTS, '--time-scale', '0'], PVE_USER='ops@pve', PVE_PASS='pw')
    assert by_env.login('ops@pve', 'pw')[0] == 200
    option_wins = cli([GUESTS, '--time-scale', '0', '--password', 'x'], PVE_PASS='pw')
    assert option_wins.login('root@pam', 'x')[0] == 200


def test_a_missing_guests_file_is_an_error(tmp_path):
    result = subprocess.run([sys.executable, '-m', 'fakepve', str(tmp_path / 'nope.json')], capture_output=True,
                            text=True, env=env(), cwd=ROOT, timeout=30)
    assert result.returncode != 0
    assert 'FileNotFoundError' in result.stderr


def test_guest_fields(cli, tmp_path):
    path = tmp_path / 'guests.json'
    path.write_text(json.dumps({'guests': [
        {'vmid': 200, 'name': 'x1', 'node': 'pve2', 'status': 'running', 'acpi': False, 'ha_state': 'started',
         'lock': 'backup', 'config': {'memory': 512}, 'agent': {'os': {'name': 'Debian'}},
         'shutdown_secs': 5, 'start_secs': 1, 'stop_secs': 2, 'start_error': 'boom', 'unknown_field': 1}]}))
    server = cli([str(path), '--time-scale', '0'])
    _, auth = server.login()
    _, body = server.call('/nodes/pve2/qemu/200/status/current', headers=auth)
    data = body['data']
    assert data['status'] == 'running' and data['lock'] == 'backup'
    assert data['ha'] == {'managed': 1, 'state': 'started'}
    _, config = server.call('/nodes/pve2/qemu/200/config', headers=auth)
    assert config['data']['memory'] == '512' and config['data']['name'] == 'x1'
    _, agent = server.call('/nodes/pve2/qemu/200/agent/get-osinfo', headers=auth)
    assert agent['data']['result'] == {'name': 'Debian'}


def test_container_in_the_guests_file(cli, tmp_path):
    path = tmp_path / 'guests.json'
    path.write_text(json.dumps({'guests': [
        {'type': 'lxc', 'vmid': 300, 'name': 'ct1', 'node': 'pve2', 'status': 'running', 'start_error': 'boom',
         'ostemplate': 'alpine-3.19-default_20240207_amd64.tar.xz', 'config': {'memory': 256}}]}))
    server = cli([str(path), '--time-scale', '0'])
    _, auth = server.login()
    _, body = server.call('/nodes/pve2/lxc/300/status/current', headers=auth)
    assert body['data']['status'] == 'running' and body['data']['name'] == 'ct1'
    _, config = server.call('/nodes/pve2/lxc/300/config', headers=auth)
    assert config['data']['memory'] == 256 and config['data']['ostype'] == 'alpine'


def test_own_certificate_with_key_in_the_same_file(cli, tmp_path):
    from fakepve.certs import make_cert
    certfile, keyfile, _ = make_cert(str(tmp_path))
    both = tmp_path / 'both.pem'
    both.write_text(open(certfile).read() + open(keyfile).read())
    server = cli([GUESTS, '--time-scale', '0', '--cert', str(both)])
    assert server.login()[0] == 200
