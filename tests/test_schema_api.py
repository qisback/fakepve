"""The generic, schema-driven part of the API: every endpoint answers."""

import re
import urllib.parse

import pytest
from aiohttp.test_utils import make_mocked_request

from conftest import Client
from fakepve import schema

SCHEMA = schema.load()
METHODS = [(path, method) for path, methods in sorted(SCHEMA.paths.items()) for method in sorted(methods)]
CTX = {'node': 'pve1', 'vmid': 100, 'storage': 'local'}
# Request bodies are JSON, so the same call works for GET.
API = '/api2/json'


def test_schema_has_every_method():
    assert len(SCHEMA.paths) >= 440
    assert len(METHODS) == 680


def test_router_prefers_literals_and_takes_variables():
    match = SCHEMA.match('/nodes/pve1/qemu/100/config')
    assert match.template == '/nodes/{node}/qemu/{vmid}/config'
    assert match.params == {'node': 'pve1', 'vmid': '100'}
    assert sorted(match.methods) == ['GET', 'POST', 'PUT']
    assert SCHEMA.match('/nodes/pve1/nonsense') is None


# ----------------------------------------------------------------- coverage

def valid_request(path, method, info):
    """A path and body that satisfy the schema, from its required parameters."""
    props = (info.get('parameters') or {}).get('properties', {})
    inpath = re.findall(r'\{([^}]+)\}', path)
    values = dict((name, schema.sample(sch, name, CTX)) for name, sch in props.items()
                  if not sch.get('optional') or name in inpath)
    # `requires`: an optional parameter that something we send depends on.
    for name, sch in props.items():
        if name in values and sch.get('requires') and sch['requires'] not in values:
            values[sch['requires']] = schema.sample(props[sch['requires']], sch['requires'], CTX)
    url = re.sub(r'\{([^}]+)\}', lambda m: urllib.parse.quote(str(values.pop(m.group(1), 'fake')), safe=''), path)
    return url, values


def conforms(sch, data, where='data'):
    """Why data does not match a `returns` schema, or None. Written apart from the server's sampler."""
    kind = sch.get('type')
    if kind is None and 'properties' in sch:
        kind = 'object'
    if kind in (None, 'any'):
        return None
    if kind == 'null':
        return None if data is None else '{0}: not null'.format(where)
    if kind == 'string':
        if not isinstance(data, str):
            return '{0}: not a string: {1!r}'.format(where, data)
        if 'enum' in sch and data not in sch['enum']:
            return '{0}: {1!r} not in enum'.format(where, data)
        rx = schema._pattern(sch['pattern']) if sch.get('pattern') else None  # None: Perl-only syntax
        if rx is not None and not rx.match(data):
            return '{0}: {1!r} does not match the pattern'.format(where, data)
        return None
    if kind in ('integer', 'number'):
        if isinstance(data, bool) or not isinstance(data, (int, float)) or (kind == 'integer' and data != int(data)):
            return '{0}: not a {1}: {2!r}'.format(where, kind, data)
        if 'minimum' in sch and data < sch['minimum']:
            return '{0}: below the minimum'.format(where)
        if 'maximum' in sch and data > sch['maximum']:
            return '{0}: above the maximum'.format(where)
        return None
    if kind == 'boolean':
        return None if data in (0, 1) else '{0}: not a boolean: {1!r}'.format(where, data)
    if kind == 'array':
        if not isinstance(data, list):
            return '{0}: not an array'.format(where)
        for n, item in enumerate(data):
            why = conforms(sch.get('items') or {}, item, '{0}[{1}]'.format(where, n))
            if why:
                return why
        return None
    if kind == 'object':
        if not isinstance(data, dict):
            return '{0}: not an object'.format(where)
        for key, sub in (sch.get('properties') or {}).items():
            if key in data:
                why = conforms(sub, data[key], where + '.' + key)
                if why:
                    return why
            elif not sub.get('optional'):
                return '{0}: missing {1}'.format(where, key)
        return None
    return 'unknown type {0}'.format(kind)


async def hand_written(pve, path, method):
    """True if a route other than the catch-all takes this request."""
    request = make_mocked_request(method, API + path)
    info = await pve.runner.app.router.resolve(request)
    return 'tail' not in info


async def test_every_method_answers(pve, api):
    pve.add_vm(100, 'vm1')
    answered = hand = 0
    failures = []
    for path, method in METHODS:
        info = SCHEMA.paths[path][method]
        url, values = valid_request(path, method, info)
        if await hand_written(pve, url, method):
            # Modelled by hand, with its own state rules: it only has to be routed.
            async with api.session.request(method, API + url, json=values, headers=api.headers) as rsp:
                assert rsp.status not in (404, 405), (method, path, rsp.status)
            hand += 1
            continue
        status, body = await api.call(method, url, values)
        if status != 200:
            failures.append((method, path, status, body))
            continue
        why = conforms(info.get('returns') or {}, body.get('data'))
        if why:
            failures.append((method, path, 'response', why))
            continue
        answered += 1
    assert not failures, failures[:10]
    # Everything not handled by a hand-written route answers from the schema.
    assert answered + hand == len(METHODS)
    print('{0} of {1} methods answer ({2} by hand-written routes)'.format(answered + hand, len(METHODS), hand))


async def test_requests_are_recorded(pve, api):
    await api.call('GET', '/pools')
    assert ('GET', API + '/pools', b'') in pve.requests


# --------------------------------------------------------------- validation

async def errors_of(api, method, path, data=None):
    status, body = await api.call(method, path, data)
    assert status == 400, (status, body)
    assert body['data'] is None
    return body['errors']


async def test_missing_property(api):
    assert await errors_of(api, 'POST', '/pools', {}) == {'poolid': 'property is missing and it is not optional'}


async def test_unknown_property(api):
    errors = await errors_of(api, 'POST', '/pools', {'poolid': 'p1', 'bogus': 1})
    assert errors == {'bogus': 'property is not defined in schema and the schema does not allow additional properties'}


async def test_enum(api):
    errors = await errors_of(api, 'GET', '/pools', {'poolid': 'p1', 'type': 'bad'})
    assert errors == {'type': "value 'bad' does not have a value in the enumeration 'qemu, lxc, storage'"}


async def test_integer_type_in_path(api):
    errors = await errors_of(api, 'POST', '/nodes/pve1/lxc/abc/status/start')
    assert errors == {'vmid': "type check ('integer') failed - got 'abc'"}


async def test_minimum_and_maximum(api):
    assert await errors_of(api, 'POST', '/nodes/pve1/lxc/5/status/start') == {
        'vmid': 'value must have a minimum value of 100'}
    assert await errors_of(api, 'POST', '/nodes/pve1/lxc/1000000000/status/start') == {
        'vmid': 'value must have a maximum value of 999999999'}


async def test_max_length(api):
    errors = await errors_of(api, 'POST', '/nodes/pve1/aplinfo', {'storage': 'local', 'template': 'a' * 256})
    assert errors == {'template': 'value may only be 255 characters long'}


async def test_pattern(api):
    errors = await errors_of(api, 'GET', '/nodes/pve1/replication/abc/status')
    assert errors == {'id': 'value does not match the regex pattern'}


async def test_booleans_take_pves_spellings(api):
    for good in (0, 1, 'true', 'false', 'yes', 'no', 'on', 'off'):
        status, _ = await api.call('POST', '/nodes/pve1/lxc/100/status/start', {'skiplock': good})
        assert status == 200, good
    errors = await errors_of(api, 'POST', '/nodes/pve1/lxc/100/status/start', {'skiplock': 'maybe'})
    assert errors == {'skiplock': "type check ('boolean') failed - got 'maybe'"}


async def test_every_error_is_reported_at_once(api):
    errors = await errors_of(api, 'POST', '/nodes/pve1/aplinfo', {'template': 'a' * 256, 'bogus': 1})
    assert sorted(errors) == ['bogus', 'storage', 'template']


# -------------------------------------------------------------- permissions

async def user_client(pve, api, user='ops@pve'):
    pve.users[user] = 'pw'
    client = Client(api.session)
    assert (await client.login(user, 'pw'))[0] == 200
    return client


async def test_permission_denied_then_granted(pve, api):
    pve.add_vm(100, 'vm1')
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    status, body = await ops.call('POST', '/nodes/pve1/lxc/100/status/start')
    assert status == 403
    assert body['message'].strip() == 'Permission check failed (/vms/100, VM.PowerMgmt)'
    pve.grant('ops@pve', '/vms/100', 'VM.PowerMgmt')
    status, body = await ops.call('POST', '/nodes/pve1/lxc/100/status/start')
    assert status == 200, body


async def test_any_of_privileges(pve, api):
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/storage/local', 'Datastore.Audit')
    status, _ = await ops.call('GET', '/nodes/pve1/storage/local/status')
    assert status == 200
    other = await user_client(pve, api, 'other@pve')
    pve.grant('other@pve', '/vms/100', 'VM.Audit')
    status, body = await other.call('GET', '/nodes/pve1/storage/local/status')
    assert status == 403
    assert 'Datastore.Audit|Datastore.AllocateSpace' in body['message']


async def test_userid_self(pve, api):
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    assert (await ops.call('GET', '/access/users/ops@pve/token'))[0] == 200
    assert (await ops.call('GET', '/access/users/other@pve/token'))[0] == 403


async def test_validation_comes_before_permissions(pve, api):
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    assert (await ops.call('POST', '/nodes/pve1/lxc/abc/status/start'))[0] == 400


async def test_world_endpoint_needs_no_login(pve, api):
    api.headers = {}
    status, body = await api.call('GET', '/access/domains')
    assert status == 200 and isinstance(body['data'], list)
    assert (await api.call('GET', '/pools'))[0] == 401


async def test_unrouted_permissions_are_root_only(pve, api):
    # A method with no permissions in the schema.
    path = next(p for p, m in METHODS if SCHEMA.paths[p][m].get('permissions') is None
                and '{' not in p)
    method = next(m for m in SCHEMA.paths[path] if SCHEMA.paths[path][m].get('permissions') is None)
    ops = await user_client(pve, api)
    pve.grant('ops@pve', '/', 'Sys.Audit')
    status, body = await ops.call(method, path)
    assert status in (400, 403), (path, body)


# --------------------------------------------------------------------- tasks

async def test_task_returning_endpoint_gives_a_real_upid(pve, api):
    pve.add_vm(100, 'vm1')
    upid = await api.data('POST', '/nodes/pve1/lxc/100/status/start')
    assert upid.startswith('UPID:pve1:')
    status = await api.data('GET', '/nodes/pve1/tasks/{0}/status'.format(upid))
    assert status['status'] == 'stopped' and status['exitstatus'] == 'OK'
    log = await api.data('GET', '/nodes/pve1/tasks/{0}/log'.format(upid))
    assert log[-1]['t'] == 'TASK OK'
    assert any(t['upid'] == upid for t in await api.data('GET', '/nodes/pve1/tasks'))


async def test_non_task_strings_are_not_upids(api):
    assert not str(await api.data('POST', '/cluster/sdn/lock')).startswith('UPID:')


# -------------------------------------------------------------- routing rules

async def test_unknown_path_is_404(api):
    async with api.session.get(API + '/nodes/pve1/nonsense', headers=api.headers) as rsp:
        assert rsp.status == 404


async def test_known_path_unknown_method_is_501(api):
    status, body = await api.call('DELETE', '/version')
    assert status == 501
    assert 'not implemented' in body['message']


async def test_unknown_node(api):
    status, body = await api.call('GET', '/nodes/nope/aplinfo')
    assert status == 500
    assert "hostname lookup 'nope' failed" in body['message']


async def test_hand_written_routes_keep_priority(pve, api):
    pve.add_vm(100, 'vm1')
    assert (await api.data('GET', '/nodes/pve1/qemu/100/status/current'))['vmid'] == 100
    # The generic answer for this path would be a stub; the real one carries the VM's config.
    assert (await api.data('GET', '/nodes/pve1/qemu/100/config'))['name'] == 'vm1'


async def test_generic_collections_use_the_path(api):
    pools = await api.data('GET', '/pools')
    assert isinstance(pools, list)


@pytest.mark.parametrize('value,kind,ok', [('12', 'integer', True), ('1.5', 'integer', False),
                                           ('1.5', 'number', True), (True, 'integer', False)])
def test_check_value_types(value, kind, ok):
    _, err = schema.check_value({'type': kind}, value)
    assert (err is None) == ok
