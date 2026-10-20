"""tools/compare_real.py: read-only recording of response shapes, the sanitiser and the diff."""

import importlib.util
import json
import os

import pytest

from fakepve import schema

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SECRET = '11111111-2222-4333-8444-555555555555'
TOKEN = 'root@pam!probe=' + SECRET


@pytest.fixture(scope='module')
def tool():
    spec = importlib.util.spec_from_file_location('compare_real', os.path.join(ROOT, 'tools', 'compare_real.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def vocab(tool):
    return tool.Vocab(schema.load())


def quiet(*_):
    pass


async def test_self_test_finds_no_difference(tool):
    assert await tool.self_test(quiet) == 0


def test_sanitiser_rejects_a_leaked_string_value(tool, vocab):
    leaks = [
        {'t': 'object', 'keys': {'name': {'t': 'string', 'value': 'web01'}}},
        {'t': 'web01'},
        {'t': 'object', 'keys': {'web01': {'t': 'string'}}},
        {'t': 'object', 'keys': {'name': 'web01'}},
        {'t': 'array', 'items': {'t': 'string', 'example': '192.0.2.7'}},
    ]
    for leak in leaks:
        with pytest.raises(tool.Leak):
            tool.check_shape(leak, vocab)
    tool.check_shape({'t': 'object', 'keys': {'name': {'t': 'string'}, '<key>': {'t': 'integer'}}}, vocab)


def test_shape_keeps_types_and_drops_values_and_odd_keys(tool, vocab):
    data = {'web01': {'name': 'web01', 'gandalf': '192.0.2.7', 'cpu': 0.5, 'template': 1, 'lock': None},
            'db02': {'name': 'db02', 'lock': 'backup'}}
    shaped = tool.shape(data, vocab.known)
    text = json.dumps(shaped)
    for leaked in ('web01', 'db02', '192.0.2.7', '0.5'):
        assert leaked not in text
    assert list(shaped['keys']) == ['<key>']
    inner = shaped['keys']['<key>']
    assert inner['keys']['template'] == {'t': 'integer'} and inner['keys']['<key>'] == {'t': 'string'}
    assert inner['keys']['lock'] == {'t': 'string', 'nullable': True}
    tool.check_shape(shaped, vocab)


def test_error_templates_carry_no_names_or_numbers(tool, vocab):
    text = tool.error_template("Configuration file 'nodes/gandalf7/qemu-server/100.conf' does not exist", vocab)
    assert 'gandalf7' not in text and '100' not in text
    assert tool.error_template(text, vocab) == text
    assert tool.error_template(None, vocab) == '<x>'


def test_dump_refuses_a_document_with_an_error_value_or_a_credential(tool, vocab):
    bad = 'node web01 does not exist'
    doc = {'format': 1, 'skipped': [], 'inventory': {'node': 1},
           'endpoints': {'GET /version': {'status': 500, 'errors': [{'status': 500, 'error': bad}]}}}
    with pytest.raises(tool.Leak):
        tool.dump(doc, vocab)
    doc['endpoints']['GET /version']['errors'][0]['error'] = tool.error_template(bad, vocab)
    assert 'web01' not in doc['endpoints']['GET /version']['errors'][0]['error']
    assert tool.dump(doc, vocab)
    with pytest.raises(tool.Leak):
        tool.dump(doc, vocab, ['node'])
    doc['endpoints']['GET /nope'] = {'status': 200}
    with pytest.raises(tool.Leak):
        tool.dump(doc, vocab)


async def test_the_client_refuses_anything_but_get(tool):
    async with tool.Client('https://192.0.2.1:8006', TOKEN, tls=False) as client:
        for method in ('POST', 'PUT', 'DELETE', 'get', None):
            with pytest.raises(tool.ReadOnlyViolation):
                await client.request(method, '/nodes')
        assert client.sent == 0


def test_skip_reasons(tool):
    rrd = {'description': 'Read statistics.'}
    assert tool.skip_reason('/nodes/{node}/qemu/{vmid}/rrddata', rrd) == 'rrd'
    assert tool.skip_reason('/nodes/{node}/qemu/{vmid}/rrddata', rrd, include_rrd=True) is None
    assert tool.skip_reason('/nodes/{node}/qemu/{vmid}/vncproxy', rrd) == 'console'
    assert tool.skip_reason('/nodes/{node}/lxc/{vmid}/termproxy', rrd) == 'console'
    assert tool.skip_reason('/nodes/{node}/aplinfo', rrd) == 'download'
    assert tool.skip_reason('/nodes/{node}/scan/nfs', rrd) == 'probe'
    assert tool.skip_reason('/nodes/{node}/qemu/{vmid}/agent/get-fsinfo', rrd) == 'guest-agent'
    assert tool.skip_reason('/nodes/{node}/status', {'description': 'Creates a report.'}) == 'side-effect'
    assert tool.skip_reason('/nodes/{node}/status', {'description': 'Node status.'}) is None
    needs = {'parameters': {'properties': {'node': {}, 'host': {'type': 'string'}}}}
    assert tool.skip_reason('/nodes/{node}/thing', needs) == 'required-param'


async def test_recording_sends_only_allowed_gets_and_lists_skips(tool, vocab):
    async with tool.Fake({'node': 1, 'qemu': 2, 'lxc': 1, 'storage': 2, 'pool': 1}) as fake:
        async with tool.Client(fake.pve.url, tool.Fake.TOKEN, tls=False) as client:
            doc, _ = await tool.record(client)
        sent = [(m, p) for m, p, _ in fake.pve.requests]
    assert sent and all(m == 'GET' for m, _ in sent)
    for _, path in sent:
        assert not any(bad in path for bad in ('vncproxy', 'termproxy', 'spiceproxy', 'vncwebsocket', 'rrd', 'aplinfo',
                                               '/scan', '/agent'))
    reasons = {s['reason'] for s in doc['skipped']}
    assert {'rrd', 'console', 'download', 'probe', 'guest-agent'} <= reasons
    assert doc['inventory'] == {'node': 1, 'qemu': 2, 'lxc': 1, 'storage': 2, 'pool': 1}
    assert 'GET /nodes/{node}/qemu/{vmid}/config' in doc['endpoints']
    tool.dump(doc, vocab)


async def test_the_request_cap_and_the_param_limit_hold(tool):
    async with tool.Fake({'node': 1, 'qemu': 5, 'lxc': 0, 'storage': 2, 'pool': 0}) as fake:
        async with tool.Client(fake.pve.url, tool.Fake.TOKEN, tls=False, limit=12) as client:
            doc, _ = await tool.record(client)
        assert client.sent == 12 and len(fake.pve.requests) == 12
        assert any(s['reason'] == 'request-cap' for s in doc['skipped'])
    async with tool.Fake({'node': 1, 'qemu': 5}) as fake:
        async with tool.Client(fake.pve.url, tool.Fake.TOKEN, tls=False) as client:
            await tool.record(client, per_param=1)
        vmids = {p.split('/')[6] for _, p, _ in fake.pve.requests if p.startswith('/api2/json/nodes/pve1/qemu/')}
        assert len(vmids) == 1


async def run(tool, argv):
    lines = []
    code = await tool.amain(argv, lines.append)
    return code, '\n'.join(lines)


async def test_the_token_never_reaches_output_files_or_errors(tool, tmp_path, capsys):
    good = tmp_path / 'good.token'
    good.write_text(tool.Fake.TOKEN + '\n')
    wrong = tmp_path / 'wrong.token'
    wrong.write_text('root@pam!compare=99999999-9999-4999-8999-999999999999')
    junk = tmp_path / 'junk.token'
    junk.write_text('hunter2-not-a-token')
    seen = []
    async with tool.Fake({'node': 1, 'qemu': 1}) as fake:
        for name, url, tok, cap in (('good', fake.pve.url, good, 1500), ('wrong', fake.pve.url, wrong, 1500),
                                    ('down', 'https://127.0.0.1:1', good, 40)):
            out = tmp_path / (name + '.json')
            code, text = await run(tool, ['record', '--url', url, '--token-file', str(tok), '--insecure',
                                          '--out', str(out), '--max-requests', str(cap), '--timeout', '5'])
            assert code == 0
            seen += [text, out.read_text()]
        with pytest.raises(tool.ToolError) as err:
            await run(tool, ['record', '--url', fake.pve.url, '--token-file', str(junk), '--insecure'])
        seen.append(str(err.value))
        with pytest.raises(tool.ToolError) as err:
            await run(tool, ['record', '--url', fake.pve.url, '--token-file', str(tmp_path / 'absent'), '--insecure'])
        seen.append(str(err.value))
    seen += list(capsys.readouterr())
    for text in seen:
        for secret in (SECRET, tool.Fake.TOKEN, tool.Fake.TOKEN.partition('=')[2], '99999999', 'hunter2', 'compare'):
            assert secret not in text
    assert json.loads((tmp_path / 'wrong.json').read_text())['endpoints']['GET /version']['status'] == 401


async def test_a_token_on_the_command_line_is_not_accepted(tool):
    with pytest.raises(SystemExit):
        await tool.amain(['record', '--url', 'https://192.0.2.1:8006', '--token', TOKEN])


async def test_record_then_diff_through_files(tool, tmp_path):
    token = tmp_path / 't'
    token.write_text(tool.Fake.TOKEN)
    out = tmp_path / 'shape.json'
    async with tool.Fake({'node': 2, 'qemu': 2, 'lxc': 1, 'storage': 2}) as fake:
        code, _ = await run(tool, ['record', '--url', fake.pve.url, '--token-file', str(token), '--insecure',
                                   '--out', str(out)])
    assert code == 0
    code, text = await run(tool, ['diff', str(out), '--strict'])
    assert code == 0 and ' 0 differences' in text
    code, text = await run(tool, ['diff', str(out), '--against', str(out), '--strict'])
    assert code == 0


def test_diff_reports_status_keys_and_types(tool):
    def doc(**endpoints):
        return {'format': 1, 'skipped': [], 'inventory': {}, 'endpoints': endpoints}

    def obj(**keys):
        return {'t': 'object', 'keys': keys}
    real = doc(**{
        'GET /version': {'status': 200, 'shape': obj(release={'t': 'string'}, repoid={'t': 'string'},
                                                   version={'t': 'string'})},
        'GET /pools': {'status': 200, 'shape': {'t': 'array', 'items': obj(poolid={'t': 'string'})}},
        'GET /storage': {'status': 200, 'shape': {'t': 'array', 'items': obj(storage={'t': 'string'})}},
    })
    fake = doc(**{
        'GET /version': {'status': 200, 'shape': obj(release={'t': 'integer'}, version={'t': 'string'},
                                                   extra={'t': 'string'})},
        'GET /pools': {'status': 403, 'samples': 1},
    })
    found = tool.compare(real, fake)
    kinds = sorted((n, k, w) for n, k, w, _ in found)
    assert ('GET /version', 'missing-key', '.repoid') in kinds
    assert ('GET /version', 'extra-key', '.extra') in kinds
    assert ('GET /version', 'type', '.release') in kinds
    assert ('GET /pools', 'status', '') in kinds
    assert ('GET /storage', 'unsampled', '') in kinds
    lines = []
    assert tool.report(real, fake, found, lines.append) == 4
    assert '4 differences' in lines[-1]
    assert tool.compare(real, real) == []
