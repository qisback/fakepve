"""The error catalogue: PVE's real errors per method, triggered by name."""

import re

import pytest

from fakepve import errors, schema

SCHEMA = schema.load()
METHODS = [(method, path) for path, methods in sorted(SCHEMA.paths.items()) for method in sorted(methods)]
VALUES = {'node': 'pve1', 'vmid': '100', 'storage': 'local'}
# Measured on the first extraction: 658 of 680 methods are mapped, 465 have at least one extracted error.
MIN_MAPPED = 640
MIN_WITH_ERRORS = 440
# Cross-cutting errors are the same everywhere; these two methods carry them through the server.
CROSS_PATHS = ('/nodes/{node}/qemu/{vmid}/status/start', '/version')


def concrete(template):
    return re.sub(r'\{([^}]+)\}', lambda m: VALUES.get(m.group(1), 'fake'), template)


# ---------------------------------------------------------------- the catalogue

def test_catalogue_loads_with_its_origin():
    meta = errors.meta()
    assert meta['repos']['qemu-server'] and meta['date']
    assert meta['errors'] == sum(len(v) for v in errors.catalogue().values())


def test_catalogue_covers_the_schema():
    cat = errors.catalogue()
    keys = set('{0} {1}'.format(m, p) for m, p in METHODS)
    assert set(cat) <= keys
    assert len(cat) >= MIN_MAPPED
    assert sum(1 for v in cat.values() if v) >= MIN_WITH_ERRORS


def test_entries_are_well_formed():
    for key, entries in errors.catalogue().items():
        names = [e['name'] for e in entries]
        assert len(names) == len(set(names)), key
        for e in entries:
            assert e['status'] in range(400, 600) and e['message'] and isinstance(e['in_task'], bool), (key, e)
            assert not e['message'].endswith('\n') and re.match(r'^[\w-]+/.+:\d+$', e['source']), (key, e)


def test_known_real_messages_are_there():
    cat = errors.catalogue()
    start = {e['name']: e for e in cat['POST /nodes/{node}/qemu/{vmid}/status/start']}
    assert start['already_running']['message'] == 'VM {vmid} already running'
    assert start['already_running']['status'] == 500 and start['already_running']['in_task']
    stop = cat['POST /nodes/{node}/qemu/{vmid}/status/stop']
    assert any(e['message'] == 'VM quit/powerdown failed - got timeout' for e in stop)
    assert 'CT {vmid} not running' in [e['message'] for e in cat['POST /nodes/{node}/lxc/{vmid}/status/stop']]
    assert 'VM {vmid} is running - destroy failed' in [e['message'] for e in cat['DELETE /nodes/{node}/qemu/{vmid}']]


def test_param_errors_carry_their_fields():
    entry = next(e for e in errors.catalogue()['POST /nodes/{node}/qemu/{vmid}/status/stop']
                 if e['name'] == 'param_skiplock_only_root_may')
    assert entry['status'] == 400 and entry['message'] == 'Parameter verification failed.'
    assert entry['errors'] == {'skiplock': 'Only root may use this option.'}


def test_errors_for_fills_the_request(pve):
    found = {e['name']: e for e in pve.errors_for('POST', '/nodes/pve1/qemu/250/status/start')}
    assert found['already_running']['message'] == 'VM 250 already running'
    assert found['locked']['message'] == 'VM is locked (backup)'
    # cross-cutting
    assert found['no_quorum']['message'] == 'cluster not ready - no quorum?'
    assert found['config_lock_timeout']['message'] == \
        "can't lock file '/var/lock/qemu-server/lock-250.conf' - got timeout"
    assert pve.errors_for('GET', '/nodes/pve1/nonsense') == []


def test_lxc_wording_follows_the_guest_type():
    found = {e['name']: e for e in errors.errors_for('POST', '/api2/json/nodes/pve1/lxc/101/status/start')}
    assert found['locked']['message'] == 'CT is locked (backup)'
    assert found['config_lock_timeout']['message'] == \
        "can't lock file '/run/lock/lxc/pve-config-101.lock' - got timeout"


# ------------------------------------------------------------------- triggering

async def test_hand_written_route_fails_by_name(pve, api):
    pve.fail('POST', '/nodes/pve1/qemu/100/status/stop', error='quit_powerdown_failed_got_timeout', times=1)
    status, body = await api.call('POST', '/nodes/pve1/qemu/100/status/stop')
    # An error raised in PVE's worker: a UPID, and the task ends with the message.
    assert status == 200 and body['data'].startswith('UPID:pve1:')
    assert pve.tasks[body['data']]['exitstatus'] == 'VM quit/powerdown failed - got timeout'
    assert pve.tasks[body['data']]['log'][-1] == 'TASK ERROR: VM quit/powerdown failed - got timeout'


async def test_in_task_error_for_qemu_start(pve, api):
    pve.fail('POST', '/nodes/pve1/qemu/100/status/start', error='already_running')
    status, body = await api.call('POST', '/nodes/pve1/qemu/100/status/start')
    task = pve.tasks[body['data']]
    assert status == 200 and task['type'] == 'qmstart' and task['id'] == '100'
    assert task['exitstatus'] == 'VM 100 already running' and task['log'][-1] == 'TASK ERROR: VM 100 already running'


async def test_http_error_by_name_and_one_shot(pve, api):
    pve.add_vm(100, 'vm1')
    pve.fail('DELETE', '/nodes/pve1/qemu/100', error='running_destroy_failed', times=1)
    status, body = await api.call('DELETE', '/nodes/pve1/qemu/100')
    assert (status, body['message']) == (500, 'VM 100 is running - destroy failed\n')
    assert (await api.call('DELETE', '/nodes/pve1/qemu/100'))[0] == 200  # the second goes through
    pve.fail('PUT', '/nodes/pve1/qemu/100/config', error='no_quorum')  # persistent, like fail(status, message)
    for _ in range(2):
        status, body = await api.call('PUT', '/nodes/pve1/qemu/100/config')
        assert (status, body['message']) == (500, 'cluster not ready - no quorum?\n')


async def test_generic_route_and_param_errors(pve, api):
    pve.fail('POST', '/access/users', error='user_already_exists')
    status, body = await api.call('POST', '/access/users', {'userid': 'ops@pve'})
    assert status == 500 and body['message'] == "user 'root@pam' already exists\n"
    pve.fail('POST', '/nodes/{node}/qemu/{vmid}/status/stop', error='param_skiplock_only_root_may')
    status, body = await api.call('POST', '/nodes/pve1/qemu/100/status/stop')
    assert status == 400 and body['errors'] == {'skiplock': 'Only root may use this option.'}
    assert body['message'] == 'Parameter verification failed.\n'


async def test_existing_fail_still_works_and_bad_names_are_refused(pve, api):
    pve.fail('GET', '/version', 503, 'maintenance')
    assert (await api.call('GET', '/version'))[0] == 503
    with pytest.raises(ValueError, match='known:.*already_running'):
        pve.fail('POST', '/nodes/pve1/qemu/100/status/start', error='nope')
    with pytest.raises(ValueError):
        pve.fail('POST', '/x', 500, 'boom', error='no_quorum')
    with pytest.raises(TypeError):
        pve.fail('POST', '/x')
    pve.fail('GET', 'cluster/status', error='nope')  # a partial suffix is not checked until asked
    status, body = await api.call('GET', '/cluster/status')
    assert status == 500 and 'no error' in body['message']


async def test_every_catalogued_error_can_be_triggered(pve, api):
    """Every error of every method, through the server. Bodies are not needed: the failure comes first."""
    bad = []
    count = 0
    for method, template in METHODS:
        path = concrete(template)
        for expected in pve.errors_for(method, path):
            if expected['source'] == 'cross-cutting' and template not in CROSS_PATHS:
                continue
            pve.fail(method, path, error=expected['name'], times=1)
            status, body = await api.call(method, path)
            count += 1
            if expected['in_task']:
                task = pve.tasks.get(body.get('data'))
                got = (status, task and task['exitstatus'], task and task['log'][-1])
                want = (200, expected['message'], 'TASK ERROR: ' + expected['message'])
            else:
                got = (status, (body.get('message') or '').rstrip('\n'), body.get('errors'))
                want = (expected['status'], expected['message'], expected.get('errors'))
            if got != want:
                bad.append((method, template, expected['name'], got, want))
    assert count >= errors.meta()['errors']  # all of the catalogue, and the cross-cutting sample
    assert not bad, bad[:5]
