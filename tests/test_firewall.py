"""The firewall config remembers what is written, with pve-firewall's rules and wording."""

import pytest

from conftest import Client

CL = '/cluster/firewall'
NODE = '/nodes/pve1/firewall'
QEMU = '/nodes/pve1/qemu/100/firewall'
LXC = '/nodes/pve1/lxc/100/firewall'
STALE = 'detected modified configuration - file changed by other user? Try again.'


async def ops_client(pve, api, user='ops@pve'):
    pve.users[user] = 'pw'
    client = Client(api.session)
    assert (await client.login(user, 'pw'))[0] == 200
    return client


async def fails(api, method, path, data=None, status=500):
    """The message of a plain error, or the per-field errors of a 400."""
    got, body = await api.call(method, path, data)
    assert got == status, (got, body)
    if status == 400:
        assert body['message'].strip() == 'Parameter verification failed.'
        return body['errors']
    return body['message'].strip()


def rule(**extra):
    return dict({'type': 'in', 'action': 'ACCEPT', 'proto': 'tcp', 'enable': 1}, **extra)


# --------------------------------------------------------------- options

async def test_options_keep_what_is_set(api):
    assert list(await api.data('GET', CL + '/options')) == ['digest']
    await api.data('PUT', CL + '/options', {'enable': 1, 'policy_in': 'DROP', 'policy_out': 'ACCEPT'})
    opts = await api.data('GET', CL + '/options')
    assert (opts['enable'], opts['policy_in'], opts['policy_out']) == (1, 'DROP', 'ACCEPT')
    assert await fails(api, 'PUT', CL + '/options', {'policy_in': 'ACCEPT', 'digest': '0' * 40}) == STALE
    await api.data('PUT', CL + '/options', {'delete': 'policy_out', 'policy_forward': 'DROP', 'digest': opts['digest']})
    new = await api.data('GET', CL + '/options')
    assert 'policy_out' not in new and new['policy_forward'] == 'DROP' and new['digest'] != opts['digest']
    assert await fails(api, 'PUT', CL + '/options', {'delete': 'bogus'}, status=400) == {
        'delete': "no such option 'bogus'"}


async def test_node_and_guest_options_are_separate(api):
    await api.data('PUT', NODE + '/options', {'enable': 1, 'nosmurfs': 1})
    await api.data('PUT', QEMU + '/options', {'enable': 1, 'dhcp': 1, 'macfilter': 0})
    assert (await api.data('GET', NODE + '/options'))['nosmurfs'] == 1
    guest = await api.data('GET', QEMU + '/options')
    assert (guest['dhcp'], guest['macfilter'], guest['enable']) == (1, 0, 1)
    # Container and VM share the code, and a guest is only an id: another id starts empty.
    assert (await api.data('GET', LXC + '/options'))['dhcp'] == 1
    assert list(await api.data('GET', '/nodes/pve1/qemu/101/firewall/options')) == ['digest']
    assert list(await api.data('GET', CL + '/options')) == ['digest']
    assert await fails(api, 'PUT', NODE + '/options', {'delete': 'dhcp'}, status=400) == {
        'delete': "no such option 'dhcp'"}


# ----------------------------------------------------------------- rules

async def test_rules_are_an_ordered_list(api):
    for port in (22, 80, 443):
        await api.data('POST', CL + '/rules', rule(dport=str(port)))
    rules = await api.data('GET', CL + '/rules')
    # New rules go on top.
    assert [r['dport'] for r in rules] == ['443', '80', '22']
    assert [r['pos'] for r in rules] == [0, 1, 2]
    assert len({r['digest'] for r in rules}) == 1
    assert (await api.data('GET', CL + '/rules/1'))['dport'] == '80'
    await api.data('POST', CL + '/rules', {'type': 'out', 'action': 'DROP'})
    assert (await api.data('GET', CL + '/rules/0'))['enable'] == 0


async def test_update_with_digest_and_delete_of_fields(api):
    await api.data('POST', CL + '/rules', rule(dport='22', comment='ssh'))
    first = await api.data('GET', CL + '/rules/0')
    await api.data('PUT', CL + '/rules/0', {'comment': 'admin', 'log': 'info', 'digest': first['digest']})
    second = await api.data('GET', CL + '/rules/0')
    assert (second['comment'], second['log']) == ('admin', 'info') and second['digest'] != first['digest']
    assert await fails(api, 'PUT', CL + '/rules/0', {'comment': 'late', 'digest': first['digest']}) == STALE
    await api.data('PUT', CL + '/rules/0', {'delete': 'comment,log'})
    assert 'comment' not in await api.data('GET', CL + '/rules/0')
    await api.data('PUT', CL + '/rules/0', {'enable': 0, 'dport': '-'})
    assert 'dport' not in await api.data('GET', CL + '/rules/0')
    assert await fails(api, 'PUT', CL + '/rules/0', {'delete': 'type'}, status=400) == {
        'delete': "unable to delete required property 'type'"}
    assert await fails(api, 'PUT', CL + '/rules/0', {'delete': 'bogus'}, status=400) == {
        'delete': "no such property ('bogus')"}


async def test_moveto_places_the_rule_before_the_one_now_there(api):
    for port in (3, 2, 1):
        await api.data('POST', CL + '/rules', rule(dport=str(port)))

    async def order():
        return [r['dport'] for r in await api.data('GET', CL + '/rules')]
    assert await order() == ['1', '2', '3']
    await api.data('PUT', CL + '/rules/0', {'moveto': 2})
    assert await order() == ['2', '1', '3']
    await api.data('PUT', CL + '/rules/2', {'moveto': 0})
    assert await order() == ['3', '2', '1']
    await api.data('PUT', CL + '/rules/0', {'moveto': 3})
    assert await order() == ['2', '1', '3']
    await api.data('PUT', CL + '/rules/1', {'moveto': 1, 'comment': 'same place means an ordinary update'})
    assert (await api.data('GET', CL + '/rules/1'))['comment'].startswith('same place')
    stale = (await api.data('GET', CL + '/rules/0'))['digest']
    await api.data('PUT', CL + '/rules/0', {'moveto': 2, 'digest': stale})
    assert await fails(api, 'PUT', CL + '/rules/0', {'moveto': 1, 'digest': stale}) == STALE


async def test_delete_and_missing_positions(api):
    for port in (1, 2):
        await api.data('POST', CL + '/rules', rule(dport=str(port)))
    digest = (await api.data('GET', CL + '/rules'))[0]['digest']
    assert await fails(api, 'DELETE', CL + '/rules/0', {'digest': '0' * 40}) == STALE
    assert await api.data('DELETE', CL + '/rules/0', {'digest': digest}) is None
    assert [r['dport'] for r in await api.data('GET', CL + '/rules')] == ['1']
    for method in ('GET', 'PUT', 'DELETE'):
        assert await fails(api, method, CL + '/rules/5') == 'no rule at position 5'


@pytest.mark.parametrize('extra,field,message', [
    ({'proto': None, 'dport': '80'}, 'proto', "missing property - 'dport' requires this property"),
    ({'dport': '99999'}, 'dport', "invalid port '99999'"),
    ({'dport': '90:80'}, 'dport', "backwards range '90:80' not allowed, did you mean '80:90'?"),
    ({'dport': 'nosuchservice'}, 'dport', "invalid port 'nosuchservice'"),
    ({'dport': '80,81,'}, 'dport', 'extraneous commas in list'),
    ({'dport': '80,,81'}, 'dport', "invalid port ''"),
    ({'proto': 'icmp', 'dport': '80,echo-request'}, 'dport', 'ICMP ports not allowed in port range'),
    ({'proto': 'icmp', 'icmp-type': 'bogus'}, 'icmp-type', "invalid icmp-type 'bogus' for proto 'icmp'"),
    ({'proto': 'ospf', 'dport': '80'}, 'dport', "protocol 'ospf' does not support ports"),
    ({'proto': 'nosuch'}, 'proto', "unknown protocol 'nosuch'"),
    ({'sport': '70000'}, 'sport', "invalid port '70000'"),
    ({'source': '192.0.2.1,2001:db8::1'}, 'source',
     "detected mixed ipv4/ipv6 addresses in address list '192.0.2.1,2001:db8::1'"),
    ({'source': '192.0.2.1-192.0.2.9,192.0.2.20'}, 'source', "you can't use a range in a list"),
    ({'source': '192.0.2.300'}, 'source', 'not a valid IP or CIDR: 192.0.2.300'),
    ({'dest': '+nosuch'}, 'dest', "no such ipset 'nosuch'"),
    ({'source': 'nosuch'}, 'source', "no such alias 'nosuch'"),
    ({'macro': 'nosuch', 'proto': None}, 'macro', "unknown macro 'nosuch'"),
    ({'type': 'forward', 'action': 'REJECT'}, 'action', 'cannot define REJECT rules on forward chain'),
    ({'action': 'maybe'}, 'action', "unknown action 'maybe'"),
])
async def test_rules_are_validated_like_pve(api, extra, field, message):
    data = dict((k, v) for k, v in rule(**extra).items() if v is not None)
    assert await fails(api, 'POST', CL + '/rules', data, status=400) == {field: message}
    assert await api.data('GET', CL + '/rules') == []


async def test_rule_details_pve_derives(api):
    await api.data('POST', CL + '/rules', {'type': 'in', 'action': 'ACCEPT', 'macro': 'ssh',
                                           'source': '192.0.2.0/24'})
    await api.data('POST', CL + '/rules', {'type': 'in', 'action': 'ACCEPT', 'proto': 'icmp',
                                           'icmp-type': 'echo-request'})
    await api.data('POST', CL + '/rules', {'type': 'in', 'action': 'DROP', 'source': '2001:db8::/32', 'dport': ''})
    rules = await api.data('GET', CL + '/rules')
    assert (rules[0]['ipversion'], rules[0]['source']) == (6, '2001:db8::/32')
    assert rules[1]['ipversion'] == 4 and rules[1]['icmp-type'] == 'echo-request'
    assert (rules[2]['macro'], rules[2]['ipversion']) == ('SSH', 4)
    macros = await api.data('GET', CL + '/macros')
    assert {'macro': 'SSH', 'descr': 'Secure shell traffic'} in macros


async def test_rules_per_environment(api):
    await api.data('POST', QEMU + '/rules', rule(iface='net0', dport='443'))
    assert [r['dport'] for r in await api.data('GET', LXC + '/rules')] == ['443']
    assert await api.data('GET', NODE + '/rules') == [] and await api.data('GET', CL + '/rules') == []
    assert await fails(api, 'POST', QEMU + '/rules', rule(iface='eth0'), status=400) == {
        'iface': "value does not match the regex pattern 'net\\d+'"}
    assert await fails(api, 'POST', QEMU + '/rules', {'type': 'forward', 'action': 'ACCEPT'}, status=400) == {
        'type': "invalid rule type 'forward' for rule_env 'vm'"}
    await api.data('POST', NODE + '/rules', {'type': 'forward', 'action': 'ACCEPT', 'iface': 'vmbr0'})
    assert (await api.data('GET', NODE + '/rules'))[0]['iface'] == 'vmbr0'
    assert await api.data('GET', '/nodes/pve1/qemu/101/firewall/rules') == []


# ---------------------------------------------------------------- aliases

async def test_aliases(api):
    await api.data('POST', CL + '/aliases', {'name': 'Office', 'cidr': '198.51.100.0/24', 'comment': 'hq'})
    listed = await api.data('GET', CL + '/aliases')
    assert [(a['name'], a['cidr'], a['comment'], a['ipversion']) for a in listed] == [
        ('Office', '198.51.100.0/24', 'hq', 4)]
    assert (await api.data('GET', CL + '/aliases/office'))['name'] == 'Office'
    assert await fails(api, 'POST', CL + '/aliases', {'name': 'OFFICE', 'cidr': '192.0.2.1'}, status=400) == {
        'name': "alias 'OFFICE' already exists"}
    await api.data('POST', CL + '/rules', rule(source='office', dport='22'))
    assert (await api.data('GET', CL + '/rules/0'))['ipversion'] == 4
    await api.data('PUT', CL + '/aliases/Office', {'cidr': '198.51.100.0/25', 'rename': 'HQ', 'digest': listed[0]['digest']})
    after = await api.data('GET', CL + '/aliases')
    assert [(a['name'], a['cidr'], 'comment' in a) for a in after] == [('HQ', '198.51.100.0/25', False)]
    assert await fails(api, 'PUT', CL + '/aliases/HQ', {'cidr': '192.0.2.1', 'digest': listed[0]['digest']}) == STALE
    assert await fails(api, 'GET', CL + '/aliases/nosuch', status=400) == {'name': 'no such alias'}
    assert await fails(api, 'PUT', CL + '/aliases/nosuch', {'cidr': '192.0.2.1'}, status=400) == {
        'name': 'no such alias'}
    assert await api.data('DELETE', CL + '/aliases/HQ') is None
    assert await api.data('DELETE', CL + '/aliases/HQ') is None
    assert await api.data('GET', CL + '/aliases') == []


async def test_guest_aliases_see_cluster_ones(api):
    await api.data('POST', CL + '/aliases', {'name': 'dns', 'cidr': '203.0.113.53'})
    await api.data('POST', QEMU + '/aliases', {'name': 'mine', 'cidr': '2001:db8::5'})
    assert [a['name'] for a in await api.data('GET', LXC + '/aliases')] == ['mine']
    await api.data('POST', QEMU + '/rules', rule(dest='dns', dport='53'))
    await api.data('POST', QEMU + '/rules', rule(dest='guest/mine', dport='53'))
    assert [r['ipversion'] for r in await api.data('GET', QEMU + '/rules')] == [6, 4]
    assert await fails(api, 'POST', CL + '/rules', rule(dest='mine'), status=400) == {'dest': "no such alias 'mine'"}


# ------------------------------------------------------------------ ipset

async def test_ipsets_and_their_entries(api):
    await api.data('POST', CL + '/ipset', {'name': 'trusted', 'comment': 'ops'})
    lst = await api.data('GET', CL + '/ipset')
    assert [(s['name'], s['comment']) for s in lst] == [('trusted', 'ops')]
    assert await fails(api, 'POST', CL + '/ipset', {'name': 'trusted'}, status=400) == {
        'name': "IPSet 'trusted' already exists"}
    await api.data('POST', CL + '/ipset/trusted', {'cidr': '203.0.113.7'})
    await api.data('POST', CL + '/ipset/trusted', {'cidr': '192.0.2.0/24', 'comment': 'lab', 'nomatch': 1})
    # Host bits are cleaned and a full-length prefix dropped, as PVE does.
    await api.data('POST', CL + '/ipset/trusted', {'cidr': '198.51.100.9/24'})
    await api.data('POST', CL + '/ipset/trusted', {'cidr': '203.0.113.9/32'})
    entries = await api.data('GET', CL + '/ipset/trusted')
    assert [e['cidr'] for e in entries] == ['203.0.113.9', '198.51.100.0/24', '192.0.2.0/24', '203.0.113.7']
    assert (entries[2]['comment'], entries[2]['nomatch']) == ('lab', 1)
    assert await fails(api, 'POST', CL + '/ipset/trusted', {'cidr': '203.0.113.7'}, status=400) == {
        'cidr': "address '203.0.113.7' already exists"}
    assert await fails(api, 'POST', CL + '/ipset/trusted', {'cidr': '0.0.0.0/0'}, status=400) == {
        'cidr': 'a zero prefix is not allowed in ipset entries'}
    assert (await api.data('GET', CL + '/ipset/trusted/203.0.113.7'))['cidr'] == '203.0.113.7'
    assert (await api.data('GET', CL + '/ipset/trusted/192.0.2.0%2F24'))['comment'] == 'lab'
    assert await fails(api, 'GET', CL + '/ipset/trusted/192.0.2.99', status=400) == {'cidr': 'no such IP/Network'}
    await api.data('PUT', CL + '/ipset/trusted/192.0.2.0%2F24', {'comment': 'lab net', 'digest': entries[0]['digest']})
    assert (await api.data('GET', CL + '/ipset/trusted/192.0.2.0%2F24')) .get('nomatch') is None
    await api.data('POST', CL + '/rules', rule(source='+trusted', dport='22'))
    await api.data('DELETE', CL + '/ipset/trusted/203.0.113.7')
    assert len(await api.data('GET', CL + '/ipset/trusted')) == 3
    assert await fails(api, 'DELETE', CL + '/ipset/trusted') == "IPSet 'trusted' is not empty"
    await api.data('POST', CL + '/ipset', {'name': 'ops', 'rename': 'trusted', 'digest': lst[0]['digest']})
    assert [s['name'] for s in await api.data('GET', CL + '/ipset')] == ['ops']
    assert await fails(api, 'GET', CL + '/ipset/trusted') == "no such IPSet 'trusted'"
    assert await fails(api, 'POST', CL + '/ipset', {'name': 'x', 'rename': 'nope'}, status=400) == {
        'name': "IPSet 'nope' does not exist"}
    assert await api.data('DELETE', CL + '/ipset/ops', {'force': 1}) is None
    assert await api.data('GET', CL + '/ipset') == []


async def test_ipset_entries_can_be_aliases(api):
    await api.data('POST', CL + '/aliases', {'name': 'everything', 'cidr': '0.0.0.0/0'})
    await api.data('POST', CL + '/aliases', {'name': 'lab', 'cidr': '192.0.2.0/24'})
    await api.data('POST', QEMU + '/ipset', {'name': 'peers'})
    assert await fails(api, 'POST', QEMU + '/ipset/peers', {'cidr': 'everything'}, status=400) == {
        'cidr': 'a zero prefix alias is not allowed in ipset entries'}
    await api.data('POST', QEMU + '/ipset/peers', {'cidr': 'dc/lab'})
    assert [e['cidr'] for e in await api.data('GET', LXC + '/ipset/peers')] == ['dc/lab']
    assert await fails(api, 'POST', QEMU + '/ipset/peers', {'cidr': 'nosuch'}) == "no such alias 'nosuch'"


# ------------------------------------------------------- groups and refs

async def test_security_groups(api):
    await api.data('POST', CL + '/groups', {'group': 'web', 'comment': 'web rules'})
    assert [(g['group'], g['comment']) for g in await api.data('GET', CL + '/groups')] == [('web', 'web rules')]
    assert await fails(api, 'POST', CL + '/groups', {'group': 'web'}, status=400) == {
        'group': "Security group 'web' already exists"}
    await api.data('POST', CL + '/groups/web', rule(dport='443'))
    assert (await api.data('GET', CL + '/groups/web'))[0]['dport'] == '443'
    assert (await api.data('GET', CL + '/groups/web/0'))['action'] == 'ACCEPT'
    await api.data('PUT', CL + '/groups/web/0', {'comment': 'https'})
    assert await fails(api, 'POST', CL + '/groups/web', rule(iface='net0'), status=400) == {
        'type': 'parameter -i not allowed for this rule type'}
    assert await fails(api, 'POST', CL + '/groups/web', {'type': 'group', 'action': 'web'}, status=400) == {
        'type': "invalid rule type 'group' for rule_env 'group'"}
    assert await fails(api, 'GET', CL + '/groups/nope') == "no such security group 'nope'"
    # A rule can name the group; renaming the group follows it into every ruleset.
    await api.data('POST', CL + '/rules', {'type': 'group', 'action': 'web'})
    await api.data('POST', QEMU + '/rules', {'type': 'group', 'action': 'web', 'enable': 1})
    digest = (await api.data('GET', CL + '/groups'))[0]['digest']
    await api.data('POST', CL + '/groups', {'group': 'frontend', 'rename': 'web', 'digest': digest})
    assert [g['group'] for g in await api.data('GET', CL + '/groups')] == ['frontend']
    assert (await api.data('GET', CL + '/rules/0'))['action'] == 'frontend'
    assert (await api.data('GET', QEMU + '/rules/0'))['action'] == 'frontend'
    assert (await api.data('GET', CL + '/groups/frontend/0'))['comment'] == 'https'
    assert await fails(api, 'DELETE', CL + '/groups/frontend') == "Security group 'frontend' is not empty"
    await api.data('DELETE', CL + '/groups/frontend/0')
    assert await api.data('DELETE', CL + '/groups/frontend') is None
    assert await api.data('GET', CL + '/groups') == []


async def test_refs_list_aliases_and_ipsets_by_scope(api):
    await api.data('POST', CL + '/aliases', {'name': 'dns', 'cidr': '203.0.113.53', 'comment': 'resolver'})
    await api.data('POST', CL + '/ipset', {'name': 'trusted'})
    await api.data('POST', QEMU + '/aliases', {'name': 'peer', 'cidr': '192.0.2.5'})
    assert await api.data('GET', CL + '/refs') == [
        {'type': 'ipset', 'name': 'trusted', 'ref': '+trusted', 'scope': 'dc'},
        {'type': 'alias', 'name': 'dns', 'ref': 'dns', 'scope': 'dc', 'comment': 'resolver'}]
    guest = await api.data('GET', QEMU + '/refs?type=alias')
    assert [(r['ref'], r['scope']) for r in guest] == [('dns', 'dc'), ('peer', 'guest')]
    assert [r['scope'] for r in await api.data('GET', LXC + '/refs')] == ['dc', 'dc', 'guest']


# ------------------------------------------------------------ permissions

async def test_cluster_firewall_permissions(pve, api):
    ops = await ops_client(pve, api)
    pve.grant('ops@pve', '/', 'Sys.Audit')
    assert await ops.data('GET', CL + '/rules') == []
    for method, path, data in (('POST', CL + '/rules', rule()), ('PUT', CL + '/options', {'enable': 1}),
                               ('POST', CL + '/aliases', {'name': 'a', 'cidr': '192.0.2.1'}),
                               ('POST', CL + '/ipset', {'name': 'a'}), ('POST', CL + '/groups', {'group': 'g'})):
        status, body = await ops.call(method, path, data)
        assert status == 403, (method, path, body)
        assert body['message'].strip() == 'Permission check failed (/, Sys.Modify)'
    pve.grant('ops@pve', '/', 'Sys.Modify')
    assert (await ops.call('POST', CL + '/rules', rule(dport='22')))[0] == 200


async def test_node_and_guest_firewall_permissions(pve, api):
    ops = await ops_client(pve, api)
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    pve.grant('ops@pve', '/nodes/pve1', 'Sys.Audit')
    assert await ops.data('GET', QEMU + '/rules') == [] and await ops.data('GET', NODE + '/rules') == []
    status, body = await ops.call('POST', QEMU + '/rules', rule())
    assert status == 403 and body['message'].strip() == 'Permission check failed (/vms/100, VM.Config.Network)'
    status, body = await ops.call('POST', NODE + '/rules', rule())
    assert status == 403 and body['message'].strip() == 'Permission check failed (/nodes/pve1, Sys.Modify)'
    pve.grant('ops@pve', '/vms/100', 'VM.Config.Network')
    assert (await ops.call('POST', LXC + '/rules', rule()))[0] == 200
    assert (await ops.call('PUT', QEMU + '/options', {'enable': 1}))[0] == 200
    status, body = await ops.call('GET', '/nodes/pve1/qemu/101/firewall/rules')
    assert status == 403 and body['message'].strip() == 'Permission check failed (/vms/101, VM.Audit)'
