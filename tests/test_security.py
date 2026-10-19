"""Hardening: hostile input must not hang, exhaust memory, leak secrets or crash the server."""

import asyncio
import contextlib
import json
import ssl
import time
import urllib.parse

import aiohttp
import pytest
from conftest import Client

from fakepve import FakePve, schema

OCI_PATTERN = schema.load().paths['/nodes/{node}/query-oci-repo-tags']['GET']['parameters']['properties'][
    'reference']['pattern']


# ------------------------------------------------------- F2: pattern matching

async def test_crafted_oci_reference_is_refused_quickly(pve, api):
    start = time.monotonic()
    for hostile in ('a' * 40 + '!', 'a' * 64 + '!', 'a-' * 30 + '!'):
        status, body = await api.call('GET', '/nodes/pve1/query-oci-repo-tags?reference=' +
                                      urllib.parse.quote(hostile))
        assert status == 400 and body['errors'] == {'reference': 'value does not match the regex pattern'}
    assert time.monotonic() - start < 0.5


async def test_valid_oci_references_still_pass(pve, api):
    for ref in ('alpine', 'docker.io/library/nginx', 'registry.example.org:5000/team/app-v2_x.y', 'a--b/c__d'):
        status, body = await api.call('GET', '/nodes/pve1/query-oci-repo-tags?reference=' +
                                      urllib.parse.quote(ref))
        assert status == 200, (ref, body)


def test_linear_oci_pattern_accepts_what_the_original_did():
    import re
    old = re.compile('^(?:' + OCI_PATTERN + ')$', re.S)
    new = schema._pattern(OCI_PATTERN)
    for text in ('a', 'a-b', 'a--b', 'a_b', 'a__b', 'a___b', 'a.b', 'a-', '-a', 'a-_b', 'A', 'a/b', 'a//b', 'a:b',
                 'ab--cd/ef_gh.ij', 'host:5000/a', '', '/', 'a b'):
        assert bool(old.match(text)) == bool(new.match(text)), text


def test_no_pattern_in_the_schema_is_exponential():
    patterns = set()

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get('pattern'), str):
                patterns.add(node['pattern'])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(schema.load().paths)
    start = time.monotonic()
    for pattern in patterns:
        rx = schema._pattern(pattern)
        if rx is None:
            continue
        for char in 'a1-_.,= ;:':
            rx.match(char * 200 + '!')
    assert time.monotonic() - start < 2


def test_values_over_the_cap_fail_patterns_without_matching():
    sch = {'type': 'string', 'pattern': '[a-z]+'}
    assert schema.check_value(sch, 'a' * schema.MAX_PATTERN_VALUE)[1] is None
    assert schema.check_value(sch, 'a' * (schema.MAX_PATTERN_VALUE + 1))[1] == 'value does not match the regex pattern'


# ------------------------------------------------------------------ helpers

@contextlib.asynccontextmanager
async def serving(cert, **attrs):
    """A started FakePve with these attributes set, and a logged-in client for it."""
    fake = FakePve(user='root@pam', password='secret')
    for name, value in attrs.items():
        setattr(fake, name, value)
    await fake.start(cert[0], cert[1])
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        async with aiohttp.ClientSession(base_url='https://{0}:{1}'.format(fake.host, fake.port),
                                         connector=aiohttp.TCPConnector(ssl=ctx)) as session:
            client = Client(session)
            await client.login()
            yield fake, client
    finally:
        await fake.stop()


async def raw(api, method, path, body=None, content_type=None, headers=None, auth=True):
    """Send exact bytes; returns (status, text)."""
    sent = dict(api.headers if auth else {})
    sent.update(headers or {})
    if content_type:
        sent['Content-Type'] = content_type
    async with api.session.request(method, '/api2/json' + path, data=body, headers=sent) as rsp:
        return rsp.status, await rsp.text()


def login_as(pve, name, password, *grants):
    pve.users[name] = password
    pve.grant('root@pam', '/', 'Sys.Audit')  # switches permission checking on
    for path, *privs in grants:
        pve.grant(name, path, *privs)


async def as_user(api, name, password):
    other = Client(api.session)
    status, body = await other.login(name, password)
    assert status == 200, body
    return other


# ----------------------------------------------------- F3: memory and body size

async def test_request_body_limit_is_configurable_and_enforced(cert):
    async with serving(cert, client_max_size=1024) as (pve, api):
        status, _ = await raw(api, 'POST', '/access/ticket', b'x' * 5000, 'application/x-www-form-urlencoded')
        assert status == 413
        status, _ = await raw(api, 'POST', '/access/ticket', b'username=root@pam&password=secret',
                              'application/x-www-form-urlencoded')
        assert status == 200


def test_default_body_limit_is_realistic():
    assert FakePve().client_max_size == 64 * 1024 ** 2


async def test_unauthenticated_bodies_are_not_read(cert):
    async with serving(cert, client_max_size=1024) as (pve, api):
        status, _ = await raw(api, 'POST', '/nodes/pve1/qemu/100/status/start', b'x' * 5000, auth=False,
                              content_type='application/x-www-form-urlencoded')
        assert status == 401
        assert pve.requests[-1] == ('POST', '/api2/json/nodes/pve1/qemu/100/status/start', b'')


async def test_request_log_is_bounded(pve, api):
    pve.max_requests = 5
    for n in range(12):
        await api.call('GET', '/version?n=%d' % n)
    await api.call('GET', '/pools')
    assert len(pve.requests) == 5
    assert pve.requests[-1] == ('GET', '/api2/json/pools', b'')
    assert pve.requests[0][1] == '/api2/json/version'


def test_default_request_log_is_generous_and_list_like():
    pve = FakePve()
    assert pve.max_requests == 10000 and isinstance(pve.requests, list)


async def test_recorded_bodies_are_cut(pve, api):
    await raw(api, 'POST', '/access/ticket', b'username=root@pam&password=secret&x=' + b'a' * 200000,
              'application/x-www-form-urlencoded')
    assert len(pve.requests[-1][2]) <= 64 * 1024


# ----------------------------------------- F8: failures only hit logged-in requests

async def test_unauthenticated_probes_do_not_use_up_failures(pve, api):
    pve.fail('GET', '/version', 503, 'down', times=2)
    for _ in range(5):
        status, _ = await raw(api, 'GET', '/version', auth=False)
        assert status == 401
    assert pve.failures[('GET', '/version')]['times'] == 2
    assert (await api.call('GET', '/version'))[0] == 503
    assert (await api.call('GET', '/version'))[0] == 503
    assert (await api.call('GET', '/version'))[0] == 200


async def test_a_login_outage_can_still_be_simulated(pve, api):
    pve.fail('POST', '/access/ticket', 503, 'login down', times=1)
    status, body = await Client(api.session).login()
    assert status == 503 and body['message'] == 'login down\n'
    assert (await Client(api.session).login())[0] == 200


# ------------------------------------------------- F9: slow request bodies

async def test_a_stalled_request_body_times_out(cert):
    async with serving(cert, body_timeout=0.3) as (pve, api):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(pve.host, pve.port, ssl=ctx)
        writer.write(b'POST /api2/json/access/ticket HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n'
                     b'Content-Type: application/x-www-form-urlencoded\r\n\r\nusername=')
        await writer.drain()
        started = time.monotonic()
        head = await asyncio.wait_for(reader.readline(), 5)
        assert b' 408 ' in head and time.monotonic() - started < 3
        writer.close()
        assert pve.requests[-1][0] == 'POST'


# ----------------------------------------------------- F10: tasks and passwords

async def bob_call(api, upid):
    bob = await as_user(api, 'bob@pve', 'bobspass12')
    return await bob.call('GET', '/nodes/pve1/tasks/{0}/status'.format(upid))


async def test_tasks_are_visible_to_their_owner_or_sys_audit(pve, api):
    pve.add_vm(100, 'vm1')
    login_as(pve, 'alice@pve', 'alicepass1', ('/vms/100', 'VM.Audit', 'VM.PowerMgmt'))
    login_as(pve, 'bob@pve', 'bobspass12', ('/vms/100', 'VM.Audit'))
    login_as(pve, 'carol@pve', 'carolpass1', ('/nodes/pve1', 'Sys.Audit'))
    upid = await api.data('POST', '/nodes/pve1/qemu/100/status/start')  # root's task
    base = '/nodes/pve1/tasks/{0}/'.format(upid)
    alice = await as_user(api, 'alice@pve', 'alicepass1')
    for leaf in ('status', 'log'):
        status, body = await alice.call('GET', base + leaf)
        assert status == 403 and body['message'] == 'Permission check failed (/nodes/pve1, Sys.Audit)\n'
    assert await alice.data('GET', '/nodes/pve1/tasks') == []
    carol = await as_user(api, 'carol@pve', 'carolpass1')
    assert (await carol.data('GET', base + 'status'))['upid'] == upid
    assert await carol.data('GET', base + 'log')
    # Alice's own task is hers to read.
    pve.vm(100).status = 'stopped'
    mine = await alice.data('POST', '/nodes/pve1/qemu/100/status/start')
    assert (await alice.data('GET', '/nodes/pve1/tasks/{0}/status'.format(mine)))['user'] == 'alice@pve'
    assert (await bob_call(api, mine))[0] == 403


async def test_password_change_rules(pve, api):
    pve.users['alice@pve'] = 'alicepass1'
    alice = await as_user(api, 'alice@pve', 'alicepass1')
    # A user must confirm the old password.
    status, body = await alice.call('PUT', '/access/password', {'userid': 'alice@pve', 'password': 'newpass123'})
    assert status == 400 and body['errors'] == {'confirmation-password': 'password is required to modify user'}
    status, body = await alice.call('PUT', '/access/password', {
        'userid': 'alice@pve', 'password': 'newpass123', 'confirmation-password': 'wrongpass'})
    assert status == 500 and body['message'] == 'authentication failure\n'
    assert pve.users['alice@pve'] == 'alicepass1'
    # Not another user's.
    status, _ = await alice.call('PUT', '/access/password', {
        'userid': 'root@pam', 'password': 'newpass123', 'confirmation-password': 'alicepass1'})
    assert status == 403
    status, _ = await alice.call('PUT', '/access/password', {
        'userid': 'alice@pve', 'password': 'newpass123', 'confirmation-password': 'alicepass1'})
    assert status == 200 and pve.users['alice@pve'] == 'newpass123'
    # root needs no confirmation.
    assert (await api.call('PUT', '/access/password', {'userid': 'alice@pve', 'password': 'rootsets1'}))[0] == 200
    assert pve.users['alice@pve'] == 'rootsets1'


async def test_api_tokens_cannot_change_passwords(pve, api):
    pve.apitokens['root@pam!ci'] = 'tokensecret'
    body = json.dumps({'userid': 'root@pam', 'password': 'newpass123'}).encode()
    status, text = await raw(api, 'PUT', '/access/password', body, 'application/json',
                             {'Authorization': 'PVEAPIToken=root@pam!ci=tokensecret'}, auth=False)
    assert status == 403 and pve.password == 'secret', text


async def test_password_must_be_given_and_long_enough(pve, api):
    status, body = await api.call('PUT', '/access/password', {'userid': 'root@pam'})
    assert status == 400 and body['errors'] == {'password': 'property is missing and it is not optional'}
    status, body = await api.call('PUT', '/access/password', {'userid': 'root@pam', 'password': 'short'})
    assert status == 400 and 'password' in body['errors']
    assert pve.password == 'secret'


# --------------------------------------------------- F11: secrets in the request log

async def test_credentials_are_redacted_in_recorded_requests(pve, api):
    await raw(api, 'POST', '/access/ticket?username=root@pam&password=secret', auth=False)
    await raw(api, 'POST', '/access/ticket', b'username=root%40pam&password=secret&otp=123456',
              'application/x-www-form-urlencoded', auth=False)
    nested = {'userid': 'root@pam', 'password': 'newpass123', 'nested': {'ticket': 'abc'}}
    await raw(api, 'PUT', '/access/password', json.dumps(nested).encode(), 'application/json')
    dump = repr(pve.requests)
    for secret in ('secret', '123456', 'newpass123', 'abc'):
        assert secret not in dump, secret
    assert not any('?' in path for _, path, _ in pve.requests)
    bodies = [body for _, _, body in pve.requests]
    assert b'username=root%40pam&password=***&otp=***' in bodies
    assert any(json.loads(b)['password'] == '***' for b in bodies if b.startswith(b'{'))


async def test_query_string_login_still_works(pve, api):
    status, body = await raw(api, 'POST', '/access/ticket?username=root@pam&password=secret', auth=False)
    assert status == 200 and 'ticket' in json.loads(body)['data']


# ------------------------------------------------------ F13: malformed input

FORM = 'application/x-www-form-urlencoded'
BAD = [
    ('POST', '/nodes/pve1/qemu/100/status/start', b'[1, 2]', 'application/json'),
    ('POST', '/nodes/pve1/qemu/100/status/start', b'null', 'application/json'),
    ('POST', '/nodes/pve1/qemu/100/status/start', b'[' * 200000 + b']' * 200000, 'application/json'),
    ('POST', '/nodes/pve1/qemu/100/status/start', b'{"a": ' * 5000, 'application/json'),
    ('POST', '/nodes/pve1/qemu/100/status/start', b'not json', 'application/json'),
    ('POST', '/nodes/pve1/qemu/100/status/start', b'a=\xff\xfe', FORM),
    ('POST', '/nodes/pve1/qemu/100/status/shutdown', b'timeout=abc', FORM),
    ('GET', '/nodes/pve1/tasks?limit=abc', None, None),
    ('GET', '/nodes/pve1/tasks?start=-1', None, None),
    ('GET', '/nodes/pve1/tasks/UPID:pve1:0:0:0:x:y:z:/log?limit=abc', None, None),
    ('POST', '/nodes/pve1/storage/local/download-url', b'content=iso&url=http://x/a.iso', FORM),
    ('POST', '/nodes/pve1/storage/local/download-url',
     b'content=iso&url=http://x/a.iso&filename=a.iso&size=abc', FORM),
    ('PUT', '/access/password', b'userid=root@pam', FORM),
    ('PUT', '/access/password', b'[1]', 'application/json'),
    ('POST', '/nodes/pve1/qemu/100/monitor', b'command=%20%20', FORM),
    ('POST', '/nodes/pve1/qemu/100/monitor', b'', None),
    ('GET', '/nodes/pve1/qemu/abc/status/current', None, None),
    ('POST', '/nodes/pve1/storage/local/upload', b'x', 'multipart/form-data'),
    ('POST', '/nodes/pve1/storage/local/upload', b'--b\r\nnonsense\r\n--b--\r\n', 'multipart/form-data; boundary=b'),
    ('POST', '/pools', b'\xff', 'application/json'),
]


@pytest.mark.parametrize('method,path,body,content_type', BAD, ids=[str(n) for n in range(len(BAD))])
async def test_malformed_requests_get_400_not_500(pve, api, method, path, body, content_type):
    pve.add_vm(100, 'vm1', status='running')
    status, text = await raw(api, method, path, body, content_type)
    assert status == 400, (status, text[:300])
    assert 'Traceback' not in text
    assert json.loads(text)['data'] is None


async def test_unexpected_errors_are_a_plain_500_without_traceback(pve, api, caplog):
    def boom(*args):
        raise RuntimeError('internal detail /srv/secret/path')
    pve.answer = boom
    status, text = await raw(api, 'GET', '/pools')
    assert status == 500
    body = json.loads(text)
    assert body['data'] is None and body['message'] == 'internal error\n'
    assert 'secret' not in text and 'Traceback' not in text
    assert 'internal detail' in caplog.text  # logged for the operator
    assert (await api.call('GET', '/version'))[0] == 200


# ---------------------------------------------------------------- F7: consoles

async def ws_status(api, vm_path, ticket, who=None):
    """Open the VNC websocket; returns the HTTP status (101 when it opens)."""
    who = who or api
    url = '/api2/json{0}/vncwebsocket?port=5900&vncticket={1}'.format(vm_path, urllib.parse.quote(ticket))
    try:
        async with who.session.ws_connect(url, headers={'Cookie': who.headers['Cookie']}, protocols=('binary',)):
            return 101
    except aiohttp.WSServerHandshakeError as exc:
        return exc.status


async def test_console_ticket_checks(pve, api):
    vm = '/nodes/pve1/qemu/100'
    pve.add_vm(100, 'vm1', status='running')
    # No ticket issued yet: refused, and nothing crashes.
    assert await ws_status(api, vm, '') == 401
    ticket = (await api.data('POST', vm + '/termproxy'))['ticket']
    assert await ws_status(api, vm, '') == 401
    assert await ws_status(api, vm, 'PVEVNC:wrong') == 401
    # Bound to the user that asked for it.
    login_as(pve, 'dave@pve', 'davepass12', ('/vms/100', 'VM.Console'))
    dave = await as_user(api, 'dave@pve', 'davepass12')
    assert await ws_status(api, vm, ticket, dave) == 401
    # Used once.
    assert await ws_status(api, vm, ticket) == 101
    assert await ws_status(api, vm, ticket) == 401


async def test_console_needs_vm_console_privilege(pve, api):
    vm = '/nodes/pve1/qemu/100'
    pve.add_vm(100, 'vm1', status='running')
    login_as(pve, 'erin@pve', 'erinspass12', ('/vms/100', 'VM.Audit'))
    erin = await as_user(api, 'erin@pve', 'erinspass12')
    ticket = (await api.data('POST', vm + '/termproxy'))['ticket']
    assert await ws_status(api, vm, ticket, erin) == 403
    assert (await erin.call('POST', vm + '/termproxy'))[0] == 403


async def test_console_ticket_expires(pve, api):
    vm = '/nodes/pve1/qemu/100'
    pve.add_vm(100, 'vm1', status='running')
    pve.vnc_ticket_ttl = 0.05
    ticket = (await api.data('POST', vm + '/vncproxy', {'websocket': 1}))['ticket']
    await asyncio.sleep(0.1)
    assert await ws_status(api, vm, ticket) == 401


async def test_terminal_still_works_with_a_good_ticket(pve, api):
    vm = '/nodes/pve1/qemu/100'
    pve.add_vm(100, 'vm1', status='running')
    data = await api.data('POST', vm + '/termproxy')
    url = '/api2/json{0}/vncwebsocket?port=5900&vncticket={1}'.format(vm, urllib.parse.quote(data['ticket']))
    async with api.session.ws_connect(url, headers={'Cookie': api.headers['Cookie']}) as ws:
        await ws.send_str('{0}:{1}\n'.format(data['user'], data['ticket']))
        assert (await ws.receive()).data == b'OK'
        await ws.receive()
        await ws.send_str('0:5:hello')
        assert (await ws.receive()).data == b'hello'
    assert pve.termdata == ['0:5:hello']
