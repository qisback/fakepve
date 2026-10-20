"""Every guest agent command in the schema answers, and the agent scenarios apply to all of them."""

import re

import pytest

from conftest import Client
from fakepve import schema
from test_schema_api import conforms, valid_request

SCHEMA = schema.load()
VM = '/nodes/pve1/qemu/100'
AGENT = [(path, method) for path, methods in sorted(SCHEMA.paths.items())
         if re.match(r'^/nodes/\{node\}/qemu/\{vmid\}/agent/[^/]+$', path) for method in sorted(methods)]
IDS = ['{0} {1}'.format(m, p.rsplit('/', 1)[1]) for p, m in AGENT]


def request_for(path, method):
    return valid_request(path, method, SCHEMA.paths[path][method])


def test_every_agent_method_is_covered():
    assert len(AGENT) == 25


@pytest.mark.parametrize(('path', 'method'), AGENT, ids=IDS)
async def test_command_answers_in_its_shape(pve, api, path, method):
    pve.add_vm(100, 'vm1', status='running').agent = {}
    url, values = request_for(path, method)
    status, body = await api.call(method, url, values)
    assert status == 200, body
    assert conforms(SCHEMA.paths[path][method].get('returns') or {}, body['data']) is None, body


@pytest.mark.parametrize(('path', 'method'), AGENT, ids=IDS)
async def test_absent_agent_fails_every_command(pve, api, path, method):
    pve.add_vm(100, 'vm1', status='running')
    url, values = request_for(path, method)
    status, body = await api.call(method, url, values)
    assert (status, body['message']) == (500, 'QEMU guest agent is not running\n')
    pve.vms[0].status = 'stopped'
    pve.vms[0].agent = {}
    status, body = await api.call(method, url, values)
    assert (status, body['message']) == (500, 'QEMU guest agent is not running\n')


@pytest.mark.parametrize(('path', 'method'), AGENT, ids=IDS)
async def test_hanging_agent_times_out_every_command(pve, api, path, method):
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.agent, vm.agent_hangs = {}, True
    url, values = request_for(path, method)
    status, body = await api.call(method, url, values)
    assert status == 500 and 'got timeout' in body['message']
    assert vm.agent_requests == []


async def test_unknown_command_and_wrong_method_are_501(pve, api):
    pve.add_vm(100, 'vm1', status='running').agent = {}
    status, body = await api.call('GET', VM + '/agent/bogus')
    assert status == 501 and body['message'].startswith("Method 'GET ")
    status, body = await api.call('POST', VM + '/agent/get-osinfo')
    assert status == 501


async def test_modelled_commands_keep_their_state(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.agent = {'os': {'name': 'Debian'}, 'interfaces': [{'name': 'eth9'}]}
    assert (await api.data('GET', VM + '/agent/get-osinfo')) == {'result': {'name': 'Debian'}}
    assert (await api.data('GET', VM + '/agent/network-get-interfaces')) == {'result': [{'name': 'eth9'}]}
    assert (await api.data('POST', VM + '/agent/ping')) == {'result': {}}


async def test_other_commands_use_vm_agent_overrides_or_plausible_defaults(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running', config={'cores': 2})
    vm.agent = {'get-timezone': {'zone': 'Europe/London', 'offset': 3600}}
    assert (await api.data('GET', VM + '/agent/get-timezone')) == {'result': {'zone': 'Europe/London', 'offset': 3600}}
    assert (await api.data('GET', VM + '/agent/get-host-name')) == {'result': {'host-name': 'vm1'}}
    assert len((await api.data('GET', VM + '/agent/get-vcpus'))['result']) == 2
    assert isinstance((await api.data('GET', VM + '/agent/get-time'))['result'], int)


async def test_fsfreeze_state(pve, api):
    pve.add_vm(100, 'vm1', status='running').agent = {}
    assert (await api.data('POST', VM + '/agent/fsfreeze-status')) == {'result': 'thawed'}
    await api.data('POST', VM + '/agent/fsfreeze-freeze')
    assert (await api.data('POST', VM + '/agent/fsfreeze-status')) == {'result': 'frozen'}
    await api.data('POST', VM + '/agent/fsfreeze-thaw')
    assert (await api.data('POST', VM + '/agent/fsfreeze-status')) == {'result': 'thawed'}


async def test_exec_is_recorded_and_never_run(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.agent = {'exec': {'echo hi': {'out-data': 'hi\n'}}}
    first = await api.data('POST', VM + '/agent/exec', {'command': ['echo', 'hi'], 'input-data': 'x'})
    second = await api.data('POST', VM + '/agent/exec', {'command': ['touch', '/pwned']})
    assert second['pid'] == first['pid'] + 1
    status = await api.data('GET', VM + '/agent/exec-status', {'pid': first['pid']})
    assert status == {'exited': True, 'exitcode': 0, 'out-data': 'hi\n', 'err-data': ''}
    assert (await api.data('GET', VM + '/agent/exec-status', {'pid': second['pid']}))['out-data'] == ''
    assert vm.agent_requests == [
        ('exec', {'command': ['echo', 'hi'], 'input-data': 'x'}),
        ('exec', {'command': ['touch', '/pwned']}),
        ('exec-status', {'pid': first['pid']}), ('exec-status', {'pid': second['pid']})]


async def test_file_commands_are_recorded_and_touch_no_file(pve, api, tmp_path):
    target = tmp_path / 'out.txt'
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.agent = {'files': {'/etc/hostname': 'vm1\n'}}
    assert await api.data('GET', VM + '/agent/file-read', {'file': '/etc/hostname'}) == \
        {'content': 'vm1\n', 'truncated': False}
    assert (await api.data('GET', VM + '/agent/file-read', {'file': '/nope'}))['content'] == ''
    assert await api.data('POST', VM + '/agent/file-write', {'file': str(target), 'content': 'data'}) is None
    assert not target.exists()
    assert vm.agent_requests[-1] == ('file-write', {'file': str(target), 'content': 'data'})


async def test_password_is_not_recorded(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running')
    vm.agent = {}
    await api.data('POST', VM + '/agent/set-user-password', {'username': 'root', 'password': 'hunter22'})
    assert vm.agent_requests == [('set-user-password', {'username': 'root', 'password': '***'})]
    assert b'hunter22' not in b''.join(body for _, _, body in pve.requests)


async def test_parameters_are_validated(pve, api):
    pve.add_vm(100, 'vm1', status='running').agent = {}
    status, body = await api.call('POST', VM + '/agent/exec', {})
    assert status == 400 and body['errors'] == {'command': 'property is missing and it is not optional'}
    status, body = await api.call('GET', VM + '/agent/file-read', {'file': '/x', 'count': 99999999})
    assert status == 400 and body['errors'] == {'count': 'value must have a maximum value of 16777216'}
    status, body = await api.call('POST', VM + '/agent/set-user-password', {'username': 'r', 'password': 'abc'})
    assert status == 400 and 'password' in body['errors']


async def test_privileges_follow_the_schema(pve, api):
    pve.add_vm(100, 'vm1', status='running').agent = {}
    ops = Client(api.session)
    pve.users['ops@pve'] = 'pw'
    assert (await ops.login('ops@pve', 'pw'))[0] == 200
    pve.grant('ops@pve', '/vms/100', 'VM.GuestAgent.Audit')
    assert (await ops.call('GET', VM + '/agent/get-osinfo'))[0] == 200
    status, body = await ops.call('POST', VM + '/agent/exec', {'command': ['id']})
    assert (status, body['message']) == (403, 'Permission check failed (/vms/100, VM.GuestAgent.Unrestricted)\n')
    status, body = await ops.call('GET', VM + '/agent/file-read', {'file': '/x'})
    assert status == 403
    pve.grant('ops@pve', '/vms/100', 'VM.GuestAgent.FileRead')
    assert (await ops.call('GET', VM + '/agent/file-read', {'file': '/x'}))[0] == 200


async def test_unknown_vm_and_node(pve, api):
    pve.add_vm(100, 'vm1', status='running').agent = {}
    status, body = await api.call('GET', '/nodes/pve1/qemu/777/agent/get-osinfo')
    assert status == 500 and body['message'] == "Configuration file 'nodes/pve1/qemu-server/777.conf' does not exist\n"
    status, body = await api.call('GET', '/nodes/nope/qemu/100/agent/get-osinfo')
    assert status == 500 and body['message'].startswith("hostname lookup 'nope' failed")
