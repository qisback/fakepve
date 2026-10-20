"""tools/compare_real.py scenario: the write guards, the clean-up, the sanitiser and the fake-against-fake test."""

import importlib.util
import json
import os

import pytest

from fakepve import schema

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture(scope='module')
def tool():
    spec = importlib.util.spec_from_file_location('compare_real', os.path.join(ROOT, 'tools', 'compare_real.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def vocab(tool):
    return tool.Vocab(schema.load())


async def run(tool, argv):
    lines = []
    code = await tool.amain(argv, lines.append)
    return code, '\n'.join(lines)


def live(tool, fake, tmp_path, *extra, node='pve1', flag=True):
    token = tmp_path / 'tok'
    token.write_text(fake.token)
    argv = ['scenario', '--url', fake.pve.url, '--token-file', str(token), '--insecure',
            '--out', str(tmp_path / 'out.json')]
    if flag:
        argv.append('--i-understand-this-writes')
    if node:
        argv += ['--disposable-node', node]
    return argv + list(extra)


def writes(fake):
    return [(m, p) for m, p, _ in fake.pve.requests if m != 'GET']


def ours(fake):
    pve = fake.pve
    names = [g.name for g in list(pve.vms) + list(pve.cts)] + list(pve.storages) + list(pve.pools) + \
        list(pve.pool_info)
    return [n for n in names if str(n).startswith('fpcmp-')]


# ------------------------------------------------------------------ guards

async def test_a_run_needs_the_flag_and_the_node_name(tool, tmp_path):
    async with tool.scenario_fake() as fake:
        for argv in (live(tool, fake, tmp_path, flag=False), live(tool, fake, tmp_path, node=None)):
            with pytest.raises(tool.ToolError, match='refusing'):
                await run(tool, argv)
        assert writes(fake) == [] and not (tmp_path / 'out.json').exists()


async def test_a_node_name_that_does_not_match_is_refused(tool, tmp_path):
    async with tool.scenario_fake() as fake:
        with pytest.raises(tool.ToolError, match='does not match'):
            await run(tool, live(tool, fake, tmp_path, node='pve9'))
        assert writes(fake) == []


async def test_more_than_one_node_is_refused(tool, tmp_path):
    async with tool.Fake({'node': 2}) as fake:
        with pytest.raises(tool.ToolError, match='single node'):
            await run(tool, live(tool, fake, tmp_path))
        assert writes(fake) == []


async def test_guests_the_tool_did_not_create_are_refused_and_never_touched(tool, tmp_path):
    async with tool.scenario_fake() as fake:
        fake.pve.add_vm(100, 'web', node='pve1', status='running')
        fake.pve.add_ct(101, 'cache', node='pve1')
        with pytest.raises(tool.ToolError, match='did not create'):
            await run(tool, live(tool, fake, tmp_path))
        assert writes(fake) == []
        code, text = await run(tool, live(tool, fake, tmp_path, '--allow-existing-guests'))
        assert code == 0 and 'clean-up verified' in text
        assert sorted(g.vmid for g in fake.pve.vms + fake.pve.cts) == [100, 101]
        assert all(g.status == 'running' for g in fake.pve.vms)
        assert not any('/qemu/100' in p or '/lxc/101' in p for _, p in writes(fake))


async def test_a_guest_in_the_reserved_range_is_refused_even_with_the_allow_flag(tool, tmp_path):
    async with tool.scenario_fake() as fake:
        fake.pve.add_vm(9950, 'mine', node='pve1')
        with pytest.raises(tool.ToolError, match='reserved range'):
            await run(tool, live(tool, fake, tmp_path, '--allow-existing-guests'))
        assert writes(fake) == []


async def test_leftover_objects_of_an_earlier_run_are_refused(tool, tmp_path):
    async with tool.scenario_fake() as fake:
        fake.pve.pools['fpcmp-pool'] = set()
        fake.pve.pool_info['fpcmp-pool'] = {'comment': None, 'storage': set()}
        with pytest.raises(tool.ToolError, match='already there'):
            await run(tool, live(tool, fake, tmp_path))
        assert writes(fake) == []


@pytest.mark.parametrize('method, path, params', [
    ('PUT', '/nodes/pve1/qemu/100/config', {'memory': 256}),
    ('DELETE', '/nodes/pve1/lxc/101', {}),
    ('POST', '/nodes/pve1/qemu', {'vmid': 100, 'name': 'fpcmp-x'}),
    ('POST', '/nodes/pve1/qemu/9900/clone', {'newid': 100}),
    ('POST', '/nodes/pve1/qemu', {'vmid': 9900, 'scsi0': 'local:1'}),
    ('POST', '/nodes/pve1/lxc', {'vmid': 9910, 'rootfs': 'local:1'}),
    ('POST', '/nodes/pve1/aplinfo', {'storage': 'local', 'template': 'x'}),
    ('DELETE', '/storage/local', {}),
    ('PUT', '/storage/fpcmp-dir/extra', {}),
    ('POST', '/storage', {'storage': 'other', 'type': 'dir'}),
    ('POST', '/pools', {'poolid': 'prod'}),
    ('DELETE', '/pools/prod', {}),
    ('PUT', '/pools/fpcmp-pool', {'vms': '100'}),
    ('DELETE', '/nodes/pve1/tasks/UPID:pve1:00000001:00000002:00000003:x:1:u:', {}),
    ('POST', '/nodes/other/qemu', {'vmid': 9900}),
    ('POST', '/nodes/pve1/status', {'command': 'reboot'}),
    ('POST', '/nodes/pve1/qemu/9900/status/start/../../100', {}),
    ('POST', '/access/users', {'userid': 'a@pve'}),
    ('PATCH', '/nodes/pve1/qemu/9900/config', {}),
])
async def test_the_scope_guard_refuses_a_write_to_anything_else(tool, method, path, params):
    async with tool.scenario_fake() as fake:
        async with tool.WriteClient(fake.pve.url, fake.token, 'pve1', tls=False) as client:
            with pytest.raises(tool.ToolError):
                await client.request(method, path, params)
            assert client.sent == 0 and fake.pve.requests == []


async def test_the_scope_guard_lets_the_reserved_objects_through(tool):
    guard = tool.ScopeGuard('pve1')
    for method, path, params in (
            ('POST', '/nodes/pve1/qemu', {'vmid': 9900, 'scsi0': 'fpcmp-dir:1,format=qcow2'}),
            ('POST', '/nodes/pve1/qemu', {'vmid': 99}),
            ('POST', '/nodes/pve1/qemu/9900/clone', {'newid': 9901}),
            ('POST', '/nodes/pve1/qemu/9900/clone', {'newid': 99}),
            ('DELETE', '/nodes/pve1/lxc/9910', {'purge': 1}),
            ('PUT', '/pools/fpcmp-pool', {'vms': '9900,9910', 'delete': 1}),
            ('POST', '/storage', {'storage': 'fpcmp-dir', 'type': 'dir', 'path': '/x'}),
            ('GET', '/nodes/pve1/qemu/100/config', None)):
        guard.check(method, path, params)


# ----------------------------------------------------------------- clean-up

async def test_the_clean_up_runs_when_a_step_fails(tool, vocab):
    seen = {}

    class Failing(tool.Scenario):
        async def execute(self, spec):
            if spec['name'] == 'ct-snapshot-list':
                seen['before'] = ours(fake)
                raise tool.ToolError('injected failure')
            return await super().execute(spec)

    async with tool.scenario_fake() as fake:
        async with tool.WriteClient(fake.pve.url, fake.token, 'pve1', tls=False) as client:
            with pytest.raises(tool.ToolError, match='injected'):
                await Failing(client, 'pve1', vocab, poll=0.01).run()
        assert 'fpcmp-dir' in seen['before'] and 'fpcmp-ct' in seen['before']
        assert ours(fake) == [] and fake.pve.vms == [] and fake.pve.cts == []
        assert [s for s in fake.pve.storages if s.startswith('fpcmp-')] == []


async def test_the_clean_up_removes_protected_running_and_pooled_guests(tool, vocab):
    async with tool.scenario_fake() as fake:
        async with tool.WriteClient(fake.pve.url, fake.token, 'pve1', tls=False) as client:
            scn = tool.Scenario(client, 'pve1', vocab, poll=0.01, steps=[
                tool.step('s', 'POST', '/storage', {'storage': '{store}', 'type': 'dir', 'path': '{dir}',
                                                    'content': 'images,rootdir,vztmpl'}, 'storage')])
            await scn.run()
        assert 'fpcmp-dir' not in fake.pve.storages
        ct = fake.pve.add_ct(9920, 'fpcmp-held', node='pve1', status='running', config={'protection': 1})
        fake.pve.pools['fpcmp-pool'] = {9920}
        fake.pve.pool_info['fpcmp-pool'] = {'comment': None, 'storage': set()}
        fake.pve._sync_pools()
        assert ct.pool == 'fpcmp-pool'
        async with tool.WriteClient(fake.pve.url, fake.token, 'pve1', tls=False) as client:
            await tool.Scenario(client, 'pve1', vocab, poll=0.01).cleanup()
        assert ours(fake) == []


async def test_a_clean_up_that_leaves_something_is_an_error(tool, vocab):
    class Stubborn(tool.Scenario):
        async def destroy(self, kind, vmid):
            return None

        async def execute(self, spec):
            if spec['name'] == 'ct-snapshot-list':
                raise tool.ToolError('injected failure')
            return await super().execute(spec)

    async with tool.scenario_fake() as fake:
        async with tool.WriteClient(fake.pve.url, fake.token, 'pve1', tls=False) as client:
            with pytest.raises(tool.CleanupFailed, match='remain'):
                await Stubborn(client, 'pve1', vocab, poll=0.01).run()


# ---------------------------------------------------------------- sanitiser

async def test_the_sanitiser_rejects_values_in_a_scenario_file(tool, vocab):
    doc = await tool.scenario_on_fake(vocab)
    good = json.loads(tool.dump_scenario(doc, vocab))
    assert good['steps'] and tool.dump_scenario(good, vocab)
    named = next(s for s in good['steps'] if s.get('errors'))
    task = next(s for s in good['steps'] if s.get('task'))
    shaped = next(s for s in good['steps'] if s.get('shape'))

    def broken(step, edit):
        bad = json.loads(json.dumps(good))
        edit(next(s for s in bad['steps'] if s['step'] == step['step']))
        with pytest.raises(tool.Leak):
            tool.dump_scenario(bad, vocab)
    broken(named, lambda s: s.update(error='node web01 does not exist'))
    broken(named, lambda s: s.update(errors={'web01': '<x>'}))
    broken(named, lambda s: s['errors'].update({next(iter(s['errors'])): 'vm gandalf7 is not running'}))
    broken(task, lambda s: s['task'].update(log='TASK ERROR: 192.0.2.7 refused'))
    broken(task, lambda s: s['task'].update(exitstatus='failed on web01'))
    broken(task, lambda s: s['task'].update(extra='x'))
    broken(shaped, lambda s: s.update(shape={'t': 'string', 'value': 'web01'}))
    broken(shaped, lambda s: s.update(status='200'))
    broken(shaped, lambda s: s.update(step='made-up-step'))
    broken(shaped, lambda s: s.update(value='x'))
    for edit in (lambda d: d.update(notes=['a name']), lambda d: d.update(format=2), lambda d: d.update(extra=1)):
        bad = json.loads(json.dumps(good))
        edit(bad)
        with pytest.raises(tool.Leak):
            tool.dump_scenario(bad, vocab)


async def test_names_and_credentials_are_scanned_for_in_the_text(tool, vocab):
    doc = await tool.scenario_on_fake(vocab)
    tool.dump_scenario(doc, vocab, ['not-in-there'], ['pve1'])
    with pytest.raises(tool.Leak, match='name'):
        tool.dump_scenario(doc, vocab, [], ['does'])
    with pytest.raises(tool.Leak, match='credential'):
        tool.dump_scenario(doc, vocab, ['TASK OK'], [])


async def test_the_node_and_template_names_are_removed_from_messages(tool, vocab):
    async with tool.scenario_fake() as fake:
        async with tool.WriteClient(fake.pve.url, fake.token, 'pve1', tls=False) as client:
            scn = tool.Scenario(client, 'pve1', vocab, names=['pve.example.org'])
            scn.ctx['template'] = 'running'
            text = scn.text("node pve1 not running at pve.example.org: 'running' CT 9900 /var/lib/fpcmp-dir/x")
    assert 'pve1' not in text and 'example' not in text and 'running' not in text and '9900' not in text
    assert 'fpcmp' not in text and 'var' not in text


async def test_a_real_looking_run_keeps_no_name_id_path_or_address(tool, vocab):
    doc = await tool.scenario_on_fake(vocab)
    text = tool.dump_scenario(doc, vocab)
    for leaked in ('pve1', 'fpcmp', '99', '3.20', '/var', '127.0.0.1', 'UPID', 'root@pam'):
        assert leaked not in text


# ----------------------------------------------------------- tokens, outputs

async def test_the_token_never_reaches_the_scenario_outputs(tool, tmp_path, capsys):
    async with tool.scenario_fake() as fake:
        code, text = await run(tool, live(tool, fake, tmp_path))
        assert code == 0 and ours(fake) == []
        wrong = tmp_path / 'wrong'
        wrong.write_text('root@pam!compare=99999999-9999-4999-8999-999999999999')
        argv = live(tool, fake, tmp_path)
        argv[argv.index('--token-file') + 1] = str(wrong)
        with pytest.raises(tool.ToolError) as err:
            await run(tool, argv)
        junk = tmp_path / 'junk'
        junk.write_text('hunter2')
        argv[argv.index('--token-file') + 1] = str(junk)
        with pytest.raises(tool.ToolError) as err2:
            await run(tool, argv)
    seen = [text, (tmp_path / 'out.json').read_text(), str(err.value), str(err2.value)] + list(capsys.readouterr())
    for out in seen:
        for secret in (tool.Fake.TOKEN, tool.Fake.SECRET, '99999999', 'hunter2'):
            assert secret not in out


# ------------------------------------------------------------ the diff itself

async def test_self_test_scenario_finds_no_difference(tool):
    lines = []
    assert await tool.self_test_scenario(lines.append) == 0
    assert 'self-test-scenario:' in lines[-1] and ' 0 differences' in lines[-1]
    code, text = await run(tool, ['--self-test-scenario'])
    assert code == 0 and ' 0 differences' in text


async def test_the_scenario_covers_the_asked_for_operations(tool):
    names = set(tool.STEP_NAMES)
    for wanted in ('vm-create', 'vm-config-get', 'vm-config-put', 'vm-config-put-bad-enum',
                   'vm-config-put-bad-property-string', 'vm-config-put-out-of-range', 'vm-create-bad-vmid',
                   'vm-config-put-unknown-key', 'vm-config-put-digest', 'vm-start', 'vm-start-again', 'vm-stop',
                   'vm-stop-again', 'vm-snapshot-create', 'vm-snapshot-list', 'vm-snapshot-delete',
                   'vm-snapshot-reuse', 'vm-clone', 'vm-template', 'vm-template-start', 'vm-destroy-protected',
                   'vm-destroy-running', 'vm-destroy', 'ct-create', 'ct-destroy', 'storage-add', 'storage-update',
                   'storage-delete', 'pool-create', 'pool-add-member', 'pool-remove-member', 'pool-delete',
                   'pool-delete-not-empty', 'fw-rule-add', 'fw-rule-move', 'fw-rule-delete'):
        assert wanted in names
    assert len(names) == len(tool.STEPS)
    assert {s['group'] for s in tool.STEPS} == set(tool.GROUPS)


async def test_the_container_steps_are_skipped_with_a_note_without_a_template(tool, vocab):
    class NoIndex(tool.Scenario):
        def hook_pick_template(self, res, _out):
            self.ctx['template'] = None

    async with tool.scenario_fake() as fake:
        async with tool.WriteClient(fake.pve.url, fake.token, 'pve1', tls=False) as client:
            doc = await NoIndex(client, 'pve1', vocab, poll=0.01).run()
    assert doc['notes'] == ['no-template']
    skipped = [s['step'] for s in doc['steps'] if 'skipped' in s]
    assert 'ct-create' in skipped and 'apl-download' in skipped and 'vm-create' not in skipped
    tool.check_scenario(doc, vocab)


async def test_the_diff_counts_status_error_keys_and_task_differences(tool, vocab):
    doc = await tool.scenario_on_fake(vocab)
    other = json.loads(json.dumps(doc))
    assert tool.diff_scenarios(doc, other) == []
    by = dict((s['step'], s) for s in other['steps'])
    by['vm-create-bad-vmid']['status'] = 500
    by['storage-add-again']['error'] = 'something else entirely happened here'
    by['vm-create-bad-name']['errors'] = {'node': 'x'}
    by['ct-start']['task']['exitstatus'] = 'unable to start'
    by['ct-stop-again']['error'] = by['ct-stop-again']['error'].replace('not running', 'is not running')
    by['vm-create-bad-enum']['skipped'] = 'no-template'
    found = tool.diff_scenarios(doc, other)
    kinds = sorted((n, k) for n, k, _ in found)
    assert ('vm-create-bad-vmid', 'status') in kinds
    assert ('storage-add-again', 'error-text') in kinds
    assert ('vm-create-bad-name', 'errors-keys') in kinds
    assert ('ct-start', 'task') in kinds
    assert ('ct-stop-again', 'fuzzy') in kinds
    lines = []
    assert tool.report_scenario(doc, other, found, lines.append) == 4 + 1
    assert 'fuzzy text matches' in lines[-1] and '1 fuzzy' in lines[-1]


async def test_a_recorded_scenario_is_diffed_against_the_fake_through_files(tool, tmp_path):
    async with tool.scenario_fake() as fake:
        code, _ = await run(tool, live(tool, fake, tmp_path))
    assert code == 0
    out = str(tmp_path / 'out.json')
    code, text = await run(tool, ['scenario', '--against-fake', out])
    assert code == 0 and ' 0 with a difference' in text
    doc = json.loads((tmp_path / 'out.json').read_text())
    next(s for s in doc['steps'] if s['step'] == 'vm-start-again')['status'] = 599
    (tmp_path / 'edited.json').write_text(json.dumps(doc))
    code, text = await run(tool, ['scenario', '--against-fake', str(tmp_path / 'edited.json')])
    assert code == 1 and 'vm-start-again' in text and 'status' in text
    (tmp_path / 'bad.json').write_text('{"format": 1}')
    with pytest.raises(tool.Leak):
        await run(tool, ['scenario', '--against-fake', str(tmp_path / 'bad.json')])


async def test_live_run_with_against_fake_diffs_in_one_go(tool, tmp_path):
    async with tool.scenario_fake() as fake:
        code, text = await run(tool, live(tool, fake, tmp_path, '--against-fake'))
    assert code == 0 and ' 0 with a difference' in text


async def test_groups_limit_the_run(tool, tmp_path):
    async with tool.scenario_fake() as fake:
        code, text = await run(tool, live(tool, fake, tmp_path, '--groups', 'storage,pool'))
        assert code == 0 and ours(fake) == []
        with pytest.raises(tool.ToolError):
            await run(tool, live(tool, fake, tmp_path, '--groups', 'nonsense'))
    doc = json.loads((tmp_path / 'out.json').read_text())
    assert {s['step'].split('-')[0] for s in doc['steps']} == {'storage', 'pool'}
