"""/api2/extjs: the same handlers and auth as /api2/json, in PVE's ExtJS envelope."""

from conftest import Client

EXT = '/api2/extjs'
VM = '/nodes/pve1/qemu/100'


class Ext(Client):
    """The test client, pointed at the ExtJS prefix: (HTTP status, body)."""

    async def call(self, method, path, data=None):
        kwargs = {'headers': self.headers}
        if data is not None:
            kwargs['data' if method == 'POST' and path == '/access/ticket' else 'json'] = data
        async with self.session.request(method, EXT + path, **kwargs) as rsp:
            assert rsp.content_type == 'application/json'
            return rsp.status, await rsp.json()


async def ext(api):
    client = Ext(api.session)
    status, body = await client.login()
    assert status == 200 and body['success'] == 1
    return client


async def test_login_and_success_envelope(pve, api):
    client = await ext(api)
    status, body = await client.call('GET', '/version')
    assert status == 200
    assert body == {'data': {'version': pve.version, 'release': pve.release_version, 'repoid': 'fakepve'},
                    'success': 1}


async def test_same_data_as_json(pve, api):
    pve.add_vm(100, 'vm1', status='running')
    client = await ext(api)
    for path in ('/nodes', '/cluster/resources', VM + '/status/current', VM + '/config', '/pools', '/access/users'):
        status, body = await client.call('GET', path)
        assert status == 200 and body['success'] == 1 and set(body) == {'data', 'success'}, (path, body)
        assert body['data'] == (await api.data('GET', path)), path


async def test_hand_written_error_is_a_200_with_the_status_in_the_body(pve, api):
    pve.add_vm(100, 'vm1', status='running')
    client = await ext(api)
    status, body = await client.call('POST', VM + '/status/start')
    assert status == 200
    assert body == {'data': None, 'message': 'VM 100 already running\n', 'status': 500, 'success': 0}
    # JSON keeps the real status for the same call.
    assert (await api.call('POST', VM + '/status/start'))[0] == 500


async def test_validation_errors_carry_errors_and_the_400(pve, api):
    pve.add_vm(100, 'vm1')
    client = await ext(api)
    status, body = await client.call('PUT', VM + '/config', {'net0': 'virtio,bogus=1'})
    assert status == 200
    assert body == {'data': None, 'message': 'Parameter verification failed.\n', 'status': 400, 'success': 0,
                    'errors': {'net0': 'invalid format - invalid key in comma-separated list property: bogus\n'}}
    status, body = await client.call('POST', '/pools', {})
    assert status == 200 and body['status'] == 400
    assert body['errors'] == {'poolid': 'property is missing and it is not optional'}


async def test_generic_endpoints_and_tasks(pve, api):
    pve.add_vm(100, 'vm1')
    client = await ext(api)
    status, body = await client.call('POST', VM + '/status/start')
    assert status == 200 and body['success'] == 1 and body['data'].startswith('UPID:pve1:')
    status, body = await client.call('POST', '/pools', {'poolid': 'dev'})
    assert (status, body['success']) == (200, 1)
    status, body = await client.call('GET', '/pools/dev')
    assert body['success'] == 1


async def test_writes_through_extjs_change_the_same_state(pve, api):
    vm = pve.add_vm(100, 'vm1')
    client = await ext(api)
    status, body = await client.call('PUT', VM + '/config', {'memory': 2048})
    assert body == {'data': None, 'success': 1}
    assert vm.config['memory'] == 2048


async def test_authentication_failures_are_enveloped(pve, api):
    anonymous = Ext(api.session)
    status, body = await anonymous.call('GET', '/version')
    assert status == 200
    assert body == {'data': None, 'message': 'permission denied - invalid PVE ticket\n', 'status': 401, 'success': 0}
    status, body = await anonymous.call('POST', '/access/ticket', {'username': 'root@pam', 'password': 'wrong'})
    assert (status, body['status'], body['message']) == (200, 401, 'authentication failure\n')
    # A write without the CSRF token.
    client = await ext(api)
    client.headers = {'Cookie': client.headers['Cookie']}
    status, body = await client.call('POST', '/pools', {'poolid': 'x'})
    assert (status, body['status']) == (200, 401)
    assert body['message'] == 'Permission denied - invalid csrf token\n'


async def test_api_tokens_work(pve, api):
    pve.apitokens['root@pam!ci'] = 'tok'
    client = Ext(api.session)
    client.headers = {'Authorization': 'PVEAPIToken=root@pam!ci=tok'}
    status, body = await client.call('GET', '/version')
    assert body['success'] == 1


async def test_permission_errors(pve, api):
    pve.add_vm(100, 'vm1')
    pve.users['ops@pve'] = 'pw'
    ops = Ext(api.session)
    assert (await ops.login('ops@pve', 'pw'))[1]['success'] == 1
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    status, body = await ops.call('POST', '/nodes/pve1/lxc/100/status/start')
    assert status == 200 and body['status'] == 403 and body['success'] == 0
    assert body['message'] == 'Permission check failed (/vms/100, VM.PowerMgmt)\n'


async def test_unknown_path_and_method(api):
    client = await ext(api)
    status, body = await client.call('GET', '/nodes/pve1/nonsense')
    assert status == 200 and body['success'] == 0 and body['status'] == 404
    assert body['message']
    status, body = await client.call('DELETE', '/version')
    assert status == 200 and body['status'] == 501
    assert body['message'] == "Method 'DELETE /api2/extjs/version' not implemented\n"


async def test_injected_failures_and_named_errors_apply(pve, api):
    pve.add_vm(100, 'vm1', status='stopped')
    client = await ext(api)
    pve.fail('POST', VM + '/status/start', 500, 'boom', times=1)
    status, body = await client.call('POST', VM + '/status/start')
    assert (status, body['status'], body['message'], body['success']) == (200, 500, 'boom\n', 0)
    pve.fail('POST', VM + '/status/start', error='no_quorum', times=1)
    status, body = await client.call('POST', VM + '/status/start')
    assert (status, body['status'], body['success']) == (200, 500, 0)
    assert 'quorum' in body['message']


async def test_requests_are_recorded_with_their_path(pve, api):
    client = await ext(api)
    await client.call('GET', '/version')
    assert ('GET', EXT + '/version', b'') in pve.requests


async def test_agent_and_config_post_under_extjs(pve, api):
    vm = pve.add_vm(100, 'vm1', status='running')
    client = await ext(api)
    status, body = await client.call('GET', VM + '/agent/get-osinfo')
    assert body['status'] == 500 and body['message'] == 'QEMU guest agent is not running\n'
    vm.agent = {}
    status, body = await client.call('POST', VM + '/agent/ping')
    assert body == {'data': {'result': {}}, 'success': 1}
    status, body = await client.call('POST', VM + '/config', {'net0': 'virtio'})
    assert body['success'] == 1 and body['data'].startswith('UPID:')


async def test_json_prefix_is_untouched(pve, api):
    status, body = await api.call('GET', '/version')
    assert status == 200 and 'success' not in body
    async with api.session.request('GET', '/api2/json/nodes/pve1/nonsense', headers=api.headers) as rsp:
        assert rsp.status == 404
