"""tools/compare_real.py: the recorded privileges, the restricted fake user and the key filters."""

import importlib.util
import json
import os

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture(scope='module')
def tool():
    spec = importlib.util.spec_from_file_location('compare_real', os.path.join(ROOT, 'tools', 'compare_real.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def vocab(tool):
    from fakepve import schema
    return tool.Vocab(schema.load())


def obj(**keys):
    return {'t': 'object', 'keys': keys}


def shape_doc(**endpoints):
    return {'format': 1, 'skipped': [], 'inventory': {}, 'endpoints': endpoints}


async def run(tool, argv):
    lines = []
    code = await tool.amain(argv, lines.append)
    return code, '\n'.join(lines)


async def test_record_keeps_the_privilege_names_of_the_token_and_no_paths(tool, vocab):
    async with tool.Fake({'node': 1}, privileges=['Sys.Audit', 'VM.Audit']) as fake:
        fake.pve.grant(tool.Fake.USER, '/vms/100', 'VM.Console')
        async with tool.Client(fake.pve.url, fake.token, tls=False) as client:
            doc, _ = await tool.record(client)
    assert doc['privileges'] == ['Sys.Audit', 'VM.Audit', 'VM.Console']
    text = tool.dump(doc, vocab)
    assert '/vms' not in text and '"privileges"' in text
    tool.check_doc(json.loads(text), vocab)


def test_the_sanitiser_rejects_privileges_that_are_not_names(tool, vocab):
    base = shape_doc()
    base['inventory'] = {}
    for bad in (['/vms/100'], ['web01'], ['VM.Audit', 'Sys.Audit'], ['VM.Audit', 'VM.Audit'], 'VM.Audit',
                [{'/': ['VM.Audit']}]):
        with pytest.raises(tool.Leak):
            tool.check_doc(dict(base, privileges=bad), vocab)
    tool.check_doc(dict(base, privileges=['Sys.Audit', 'VM.Audit']), vocab)
    tool.check_doc(dict(base, privileges=[]), vocab)
    with pytest.raises(tool.Leak):
        tool.check_doc(dict(base, other=1), vocab)


def test_privileges_come_from_the_file_or_the_shape_of_the_permissions_answer(tool):
    assert tool.doc_privileges(dict(shape_doc(), privileges=['VM.Audit'])) == ['VM.Audit']
    every = sorted(tool.PRIVILEGES)
    assert tool.doc_privileges(dict(shape_doc(), privileges=every)) is None
    assert tool.doc_privileges(shape_doc()) is None
    inner = obj(**{'Sys.Audit': {'t': 'integer'}, 'VM.Audit': {'t': 'integer'}})
    old = shape_doc(**{'GET /access/permissions': {'status': 200, 'shape': obj(**{'<key>': inner})}})
    assert tool.doc_privileges(old) == ['Sys.Audit', 'VM.Audit']
    denied = shape_doc(**{'GET /access/permissions': {'status': 403}})
    assert tool.doc_privileges(denied) is None


async def test_the_fake_runs_as_a_user_with_the_recorded_privileges(tool):
    async with tool.Fake({'node': 1}, privileges=['Sys.Audit']) as fake:
        assert fake.token.startswith(tool.Fake.USER + '!')
        assert fake.pve.acl == {tool.Fake.USER: [('/', {'Sys.Audit'})]}
        async with tool.Client(fake.pve.url, fake.token, tls=False) as client:
            assert (await client.request('GET', '/nodes/pve1/status')).status == 200
            assert (await client.request('GET', '/cluster/backup-info')).status == 403
    async with tool.Fake({'node': 1}) as root:
        assert root.pve.acl is None and root.token == tool.Fake.TOKEN


async def test_diff_creates_the_restricted_user_from_the_recorded_privileges(tool, tmp_path, monkeypatch):
    seen = []
    real = tool.record_fake

    async def spy(inv, **kwargs):
        seen.append(kwargs.get('privileges'))
        return await real(inv, **kwargs)
    monkeypatch.setattr(tool, 'record_fake', spy)
    doc = dict(shape_doc(**{'GET /version': {'status': 200, 'shape': obj(version={'t': 'string'})}}),
               privileges=['Sys.Audit', 'VM.Audit'])
    doc['inventory'] = {'node': 1}
    path = tmp_path / 'shape.json'
    path.write_text(json.dumps(doc))
    await run(tool, ['diff', str(path)])
    await run(tool, ['diff', str(path), '--as-root'])
    assert seen == [['Sys.Audit', 'VM.Audit'], None]


async def test_a_403_on_both_sides_is_no_difference_when_the_rights_match(tool, vocab):
    async def walk(privileges):
        doc, _ = await tool.record_fake({'node': 1}, privileges=privileges)
        return json.loads(tool.dump(doc, vocab))
    recorded = await walk(['Sys.Audit'])
    again = await walk(tool.doc_privileges(recorded))
    assert recorded['endpoints']['GET /cluster/backup-info']['status'] == 403
    assert [d for d in tool.compare(recorded, again) if d[1] in tool.FATAL] == []
    as_root = await walk(None)
    assert any(d[1] == 'status' for d in tool.compare(recorded, as_root))


def test_config_dependent_keys_are_not_counted_unless_asked(tool):
    cfg = '/nodes/{node}/qemu/{vmid}/config'
    real = shape_doc(**{'GET ' + cfg: {'status': 200, 'shape': obj(
        digest={'t': 'string'}, memory={'t': 'string'}, tags={'t': 'string'}, ide2={'t': 'string'})}})
    fake = shape_doc(**{'GET ' + cfg: {'status': 200, 'shape': obj(
        memory={'t': 'integer'}, extra={'t': 'string'})}})
    default = tool.compare(real, fake)
    kinds = sorted((k, w) for _, k, w, _ in default)
    assert ('config-dependent', '.tags') in kinds and ('config-dependent', '.extra') in kinds
    assert ('missing-key', '.digest') in kinds and ('type', '.memory') in kinds
    assert not any(k in ('missing-key', 'extra-key') and w in ('.tags', '.ide2', '.extra') for k, w in kinds)
    strict = tool.compare(real, fake, ignore_config_keys=False)
    assert ('missing-key', '.tags') in sorted((k, w) for _, k, w, _ in strict)
    lines = []
    assert tool.report(real, fake, default, lines.append) == 2
    assert 'not defects: 3 keys that depend on the object' in lines[-1]


def test_keys_of_a_storage_or_role_that_depend_on_the_object_are_ignored(tool):
    def storage(**keys):
        return {'status': 200, 'shape': {'t': 'array', 'items': obj(storage={'t': 'string'}, **keys)}}
    real = shape_doc(**{'GET /storage': storage(pool={'t': 'string'}),
                        'GET /access/roles/{roleid}': {'status': 200, 'shape': obj(**{'VM.Audit': {'t': 'integer'}})}})
    fake = shape_doc(**{'GET /storage': storage(path={'t': 'string'}),
                        'GET /access/roles/{roleid}': {'status': 200,
                                                       'shape': obj(**{'Sys.Audit': {'t': 'integer'}})}})
    assert [d for d in tool.compare(real, fake) if d[1] in tool.FATAL] == []
    assert len([d for d in tool.compare(real, fake, ignore_config_keys=False) if d[1] in tool.FATAL]) == 4


def test_a_value_the_real_pve_sends_as_two_types_matches_either(tool):
    mixed = {'t': 'mixed', 'of': [{'t': 'boolean'}, {'t': 'integer'}]}

    def doc(shape):
        return shape_doc(**{'GET /version': {'status': 200, 'shape': obj(version=shape)}})
    assert tool.compare(doc(mixed), doc({'t': 'integer'})) == []
    assert [d[1] for d in tool.compare(doc(mixed), doc({'t': 'string'}))] == ['type']
    assert [d[1] for d in tool.compare(doc({'t': 'integer'}), doc(mixed))] == ['type']


def test_keys_the_schema_does_not_name_are_counted_apart(tool):
    real = shape_doc(**{'GET /version': {'status': 200, 'shape': obj(**{'<key>': {'t': 'string'}})}})
    fake = shape_doc(**{'GET /version': {'status': 200, 'shape': obj(version={'t': 'string'})}})
    found = tool.compare(real, fake)
    assert sorted(d[1] for d in found) == ['extra-key', 'undocumented']
    assert tool.report(real, fake, found, lambda _: None) == 1


async def test_the_no_ignore_flag_reaches_the_comparison(tool, tmp_path):
    cfg = 'GET /nodes/{node}/qemu/{vmid}/config'
    first = tmp_path / 'a.json'
    first.write_text(json.dumps(shape_doc(**{cfg: {'status': 200, 'shape': obj(tags={'t': 'string'})}})))
    second = tmp_path / 'b.json'
    second.write_text(json.dumps(shape_doc(**{cfg: {'status': 200, 'shape': obj(name={'t': 'string'})}})))
    code, text = await run(tool, ['diff', str(first), '--against', str(second), '--strict'])
    assert code == 0 and 'config-dependent' in text
    code, text = await run(tool, ['diff', str(first), '--against', str(second), '--strict',
                                  '--no-ignore-config-keys'])
    assert code == 1
