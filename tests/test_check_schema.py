"""tools/check_schema.py and the weekly workflow that runs it."""

import hashlib
import importlib.util
import json
import os

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'schema-check.yml')


@pytest.fixture(scope='module')
def tool():
    spec = importlib.util.spec_from_file_location('check_schema', os.path.join(ROOT, 'tools', 'check_schema.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(tmp_path, stored, served=b'var pveapi = [];'):
    meta = tmp_path / 'meta.json'
    meta.write_text(json.dumps({'source': str(tmp_path / 'apidoc.js'), 'sha256': stored}))
    (tmp_path / 'apidoc.js').write_bytes(served)
    return str(meta)


def test_same_hash_exits_0(tool, tmp_path, capsys):
    stored = hashlib.sha256(b'var pveapi = [];').hexdigest()
    assert tool.main(['--meta', prepare(tmp_path, stored)]) == 0
    assert capsys.readouterr().out == 'old: {0}\nnew: {0}\n'.format(stored)


def test_changed_hash_exits_1_and_prints_both(tool, tmp_path, capsys):
    old = '0' * 64
    assert tool.main(['--meta', prepare(tmp_path, old)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out == ['old: ' + old, 'new: ' + hashlib.sha256(b'var pveapi = [];').hexdigest()]


def test_source_argument_overrides_the_meta_source(tool, tmp_path):
    meta = prepare(tmp_path, hashlib.sha256(b'other').hexdigest())
    other = tmp_path / 'other.js'
    other.write_bytes(b'other')
    assert tool.main(['--meta', meta]) == 1
    assert tool.main([str(other), '--meta', meta]) == 0


def test_unreadable_source_exits_2(tool, tmp_path, capsys):
    meta = prepare(tmp_path, '0' * 64)
    assert tool.main([str(tmp_path / 'missing.js'), '--meta', meta]) == 2
    assert 'cannot read the schema' in capsys.readouterr().err


def test_the_vendored_meta_has_a_hash_the_tool_can_compare(tool):
    with open(tool.META, encoding='utf-8') as fh:
        meta = json.load(fh)
    assert len(meta['sha256']) == 64 and meta['source'].startswith('https://')


# ------------------------------------------------------------------ workflow

def load_workflow():
    yaml = pytest.importorskip('yaml')
    with open(WORKFLOW, encoding='utf-8') as fh:
        return yaml.safe_load(fh)


def test_workflow_triggers_weekly_and_by_hand():
    triggers = load_workflow()[True]  # YAML reads the key `on` as a boolean
    assert set(triggers) == {'schedule', 'workflow_dispatch'}
    fields = triggers['schedule'][0]['cron'].split()
    assert len(fields) == 5 and fields[2:4] == ['*', '*'] and fields[4] != '*'


def test_workflow_permissions_are_minimal():
    wf = load_workflow()
    assert wf['permissions'] == {'contents': 'read'}
    jobs = wf['jobs']
    writers = [name for name, job in jobs.items() if 'issues' in job.get('permissions', {})]
    assert writers == ['report']
    assert jobs['report']['permissions'] == {'issues': 'write'}
    assert 'permissions' not in jobs['check']


def test_workflow_keeps_untrusted_context_out_of_scripts():
    wf = load_workflow()
    for job in wf['jobs'].values():
        for step in job['steps']:
            assert '${{' not in step.get('run', ''), step
    checkout = [s for s in wf['jobs']['check']['steps'] if s.get('uses', '').startswith('actions/checkout@')]
    assert checkout and checkout[0]['with']['persist-credentials'] is False


def test_workflow_pins_the_actions_and_uses_the_job_token():
    with open(WORKFLOW, encoding='utf-8') as fh:
        text = fh.read()
    assert 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1' in text
    assert 'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0' in text
    assert 'GH_TOKEN: ${{ github.token }}' in text
    assert 'gh issue list --state open' in text and 'gh issue create' in text
