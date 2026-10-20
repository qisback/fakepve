"""Parameters with a `format` are validated as PVE::JSONSchema does, with its wording."""

# ruff: noqa: E501 (the tables read best one case per line)

import time

import pytest

from fakepve import formats, schema

VM = '/nodes/pve1/qemu/100'

# name -> (valid values, {invalid value: PVE's message})
CASES = {
    'urlencoded': (['a%20b', ''], {'a b': 'invalid urlencoded string: a b'}),
    'pve-configid': (['scsi0', 'a-b_1'], {'0net': "invalid configuration ID '0net'", 'a': "invalid configuration ID 'a'"}),
    'pve-storage-id': (['local', 'a.b-c_d', 'ab'],
                       {'a': "storage ID 'a' cannot be shorter than 2 characters",
                        '1ab': "storage ID '1ab' contains illegal characters",
                        'ab-': "storage ID 'ab-' contains illegal characters"}),
    'pve-bridge-id': (['vmbr0', 'a-b.c_d'], {'vm br': "invalid bridge ID 'vm br'", '': "invalid bridge ID ''"}),
    'pve-vmid': (['100', '999999999'], {'99': 'value does not look like a valid VM ID',
                                        '0100': 'value does not look like a valid VM ID',
                                        '1000000000': 'value does not look like a valid VM ID'}),
    'pve-node': (['pve1', 'a', 'a-b'], {'-a': 'value does not look like a valid node name',
                                        'a_b': 'value does not look like a valid node name'}),
    'mac-addr': (['BC:24:11:00:00:01', 'bc:24:11:aa:bb:cc'],
                 {'BC:24:11:00:00': 'value does not look like a valid unicast MAC address',
                  '01:24:11:00:00:01': 'value does not look like a valid unicast MAC address',
                  'bc-24-11-00-00-01': 'value does not look like a valid unicast MAC address'}),
    'ipv4': (['192.0.2.1', '0.0.0.0', '255.255.255.255'],
             {'256.0.0.1': 'value does not look like a valid IPv4 address',
              '01.0.0.1': 'value does not look like a valid IPv4 address',
              '1.2.3': 'value does not look like a valid IPv4 address'}),
    'ipv6': (['fd00::1', '::', '2001:db8:0:0:0:0:0:1'],
             {'fd00::g': 'value does not look like a valid IPv6 address',
              'fe80::1%eth0': 'value does not look like a valid IPv6 address',
              '192.0.2.1': 'value does not look like a valid IPv6 address'}),
    'ip': (['192.0.2.1', 'fd00::1'], {'host': 'value does not look like a valid IP address'}),
    'ipv4mask': (['255.255.255.0', '0.0.0.0'], {'255.0.255.0': 'value does not look like a valid IP netmask'}),
    'CIDRv4': (['192.0.2.0/24', '1.2.3.4/8'], {'192.0.2.0/7': 'value does not look like a valid IPv4 CIDR network',
                                              '192.0.2.0/33': 'value does not look like a valid IPv4 CIDR network',
                                              '192.0.2.0': 'value does not look like a valid IPv4 CIDR network'}),
    'CIDRv6': (['fd00::/64', 'fd00::/8'], {'fd00::/129': 'value does not look like a valid IPv6 CIDR network',
                                           '192.0.2.0/24': 'value does not look like a valid IPv6 CIDR network'}),
    'CIDR': (['192.0.2.0/24', 'fd00::/64'], {'192.0.2.0/4': 'value does not look like a valid CIDR network'}),
    'pve-ipv4-config': (['dhcp', 'manual', '192.0.2.5/24'],
                        {'auto': 'value does not look like a valid ipv4 network configuration'}),
    'pve-ipv6-config': (['auto', 'dhcp', 'manual', 'fd00::5/64'],
                        {'192.0.2.5/24': 'value does not look like a valid ipv6 network configuration'}),
    'email': (['root@localhost', 'a.b+c@example.org'], {'root': 'value does not look like a valid email address',
                                                         'a@b@c': 'value does not look like a valid email address',
                                                         '@x.org': 'value does not look like a valid email address'}),
    'email-or-username': (['root@localhost', 'root'],
                          {'a b': 'value does not look like a valid email address or user name'}),
    'dns-name': (['host', 'a.b-c.example.org'], {'-a.org': 'value does not look like a valid DNS name',
                                                  'a..b': 'value does not look like a valid DNS name',
                                                  'a.org.': 'value does not look like a valid DNS name'}),
    'pve-iface': (['vmbr0', 'eth0.100', 'bond0:1'], {'0eth': "invalid network interface name '0eth'",
                                                      'a': "invalid network interface name 'a'"}),
    'pve-vlan-id-or-range': (['2', '4094', '10-20'],
                             {'1': "invalid VLAN tag '1'", '4095': "invalid VLAN tag '4095'",
                              '20-10': "VLAN range must go from lower to higher tag '20-10'",
                              'x': "invalid VLAN configuration 'x'"}),
    'address': (['192.0.2.1', 'host.example.org', 'fd00::1'],
                {'-bad': 'value does not look like a valid address: -bad'}),
    'disk-size': (['32G', '512M', '1.5T', '100', '4KiB'],
                  {'32GB': 'value does not look like a valid disk size: 32GB', 'G': 'value does not look like a valid disk size: G'}),
    'pve-tag': (['web', 'a-b.c+d'], {'a b': 'invalid characters in tag', '-a': 'invalid characters in tag'}),
    'pve-startup-order': (['order=1', '3', 'order=1,up=30,down=60'], {'up=x': 'unable to parse startup options',
                                                                       '': 'unable to parse startup options'}),
    'pve-hotplug-features': (['network,disk', '0', '1'], {'sound': "invalid hotplug feature 'sound'"}),
    'ldap-simple-attr': (['uid', 'cn2'], {'a-b': "value 'a-b' does not look like a simple ldap attribute name"}),
    'pve-userid': (['root@pam', 'a.b@my-realm'],
                   {'ab': "user name 'ab' is too short", 'root': "value 'root' does not look like a valid user name",
                    'root@1x': "value 'root@1x' does not look like a valid user name",
                    'a' * 65 + '@pam': 'user name \'{0}@pam\' is too long (69 > 64)'.format('a' * 65)}),
    'pve-tokenid': (['root@pam!ci'], {'root@pam': "value 'root@pam' does not look like a valid token ID"}),
    'pve-realm': (['pam', 'my-realm'], {'1x': 'value does not look like a valid realm',
                                         'p': 'value does not look like a valid realm'}),
    'pve-poolid': (['dev', 'a/b/c'], {'a/b/c/d': "pool name 'a/b/c/d' nested too deeply (max levels = 3)",
                                       'a b': "pool name 'a b' contains invalid characters"}),
    'pve-groupid': (['admins'], {'a b': "group name 'a b' contains invalid characters"}),
    'pve-roleid': (['Auditor'], {'a b': "role name 'a b' contains invalid characters"}),
    'pve-storage-path': (['/var/lib/vz'], {'var': 'value does not look like a valid absolute path',
                                           '/;': 'value does not look like a valid absolute path'}),
    'pve-storage-server': (['192.0.2.5', 'nas.example.org'],
                           {'-': 'value does not look like a valid server name or IP address'}),
    'pve-storage-content': (['iso', 'images'], {'isos': "invalid content type 'isos'"}),
    'pve-volume-id': (['local:iso/a.iso', 'local-zfs:vm-100-disk-0'],
                      {'iso/a.iso': "unable to parse volume ID 'iso/a.iso'",
                       'x:y': "unable to parse volume ID 'x:y'", 'local:': "unable to parse volume ID 'local:'"}),
    'pve-volume-id-or-absolute-path': (['/dev/sda', 'local:100/disk.raw'], {'disk': "unable to parse volume ID 'disk'"}),
    'pve-volume-id-or-qm-path': (['none', 'cdrom', '/dev/sda', 'local:iso/a.iso'], {'disk': "unable to parse volume ID 'disk'"}),
    'IPorCIDR': (['192.0.2.1', '192.0.2.0/24', 'fd00::/64'],
                 {'192.0.2.0/33': 'value does not look like a valid IP address or CIDR network',
                  'host': 'value does not look like a valid IP address or CIDR network'}),
    'IPorCIDRorAlias': (['192.0.2.1', 'dc/office', 'guest/web1', 'office'],
                        {'1bad': 'value does not look like a valid IP address or CIDR network'}),
    'pve-fw-comment-spec': (['fine', ''], {'a\nb': 'comment must not contain a line feed'}),
}


@pytest.mark.parametrize('name', sorted(CASES))
def test_valid_values_pass(name):
    for value in CASES[name][0]:
        assert formats.check(name, value) is None, (name, value)


@pytest.mark.parametrize('name', sorted(CASES))
def test_invalid_values_fail_with_pves_message(name):
    for value, message in CASES[name][1].items():
        assert formats.check(name, value) == message, (name, value)


def test_every_implemented_format_is_tested():
    assert sorted(set(formats.NAMED) - {'string'}) == sorted(CASES)


def test_list_and_opt_variants():
    assert formats.check('pve-configid-list', 'net0,scsi1;ide2 virtio3') is None
    assert formats.check('pve-configid-list', 'net0,0bad') == "invalid configuration ID '0bad'"
    assert formats.check('pve-configid-list', '') is None
    assert formats.check('pve-vmid-list', '100 101,102') is None
    assert formats.check('pve-vmid-list', '100,5') == 'value does not look like a valid VM ID'
    assert formats.check('email-opt', '') is None
    assert formats.check('email-opt', 'nope') == 'value does not look like a valid email address'
    assert formats.check('pve-configid-list', 'ab\0b0\0') is None


def test_unimplemented_formats_accept_anything():
    for name in ('pve-calendar-event', 'pve-priv-list', 'pve-qm-bootdev-list', 'no-such-format'):
        assert formats.check(name, 'whatever ;; \n') is None


def test_long_values_are_cut_and_checked_in_linear_time():
    started = time.monotonic()
    for name in sorted(set(formats.NAMED) - {'string'}):
        for text in ('a' * (formats.MAX_FORMAT_VALUE + 1), 'a-' * 2000 + '!', '1.' * 2000, ('a.' * 2000) + '-'):
            formats.check(name, text)
    assert time.monotonic() - started < 2
    assert formats.check('pve-node', 'a' * (formats.MAX_FORMAT_VALUE + 1)) == \
        'value may only be {0} characters long'.format(formats.MAX_FORMAT_VALUE)
    assert formats.check('pve-node', 'a' * formats.MAX_FORMAT_VALUE) is None


# ------------------------------------------------------------ property strings

def props(**kw):
    return {'properties': dict((k, v) for k, v in kw.items())}


NET = {'type': 'string', 'format': {
    'model': {'type': 'string', 'enum': ['virtio', 'e1000'], 'default_key': 1},
    'virtio': {'alias': 'macaddr', 'keyAlias': 'model'},
    'macaddr': {'type': 'string', 'format': 'mac-addr', 'optional': 1},
    'bridge': {'type': 'string', 'format': 'pve-bridge-id', 'optional': 1},
    'tag': {'type': 'integer', 'minimum': 1, 'maximum': 4094, 'optional': 1},
    'firewall': {'type': 'boolean', 'optional': 1},
    'gw': {'type': 'string', 'optional': 1, 'requires': 'bridge'},
}, 'optional': 1}


def check(value):
    return schema.check_value(NET, value)[1]


def test_property_string_valid_forms():
    assert check('virtio,bridge=vmbr0') is None
    assert check('model=virtio,bridge=vmbr0,tag=5,firewall=1') is None
    assert check('virtio=BC:24:11:00:00:01,bridge=vmbr0') is None
    assert check('e1000,firewall=yes') is None
    assert check('virtio,,bridge=vmbr0,') is None


def test_property_string_unknown_key():
    assert check('virtio,bogus=1') == 'invalid format - invalid key in comma-separated list property: bogus\n'


def test_property_string_missing_required_key():
    assert check('bridge=vmbr0') == 'invalid format - format error\nmodel: property is missing and it is not optional\n'


def test_property_string_value_errors_are_listed_by_path():
    assert check('virtio,tag=0,bridge=vm br,firewall=maybe,macaddr=zz') == (
        'invalid format - format error\n'
        "bridge: invalid format - invalid bridge ID 'vm br'\n"
        '\n'
        "firewall: type check ('boolean') failed - got 'maybe'\n"
        'macaddr: invalid format - value does not look like a valid unicast MAC address\n'
        '\n'
        'tag: value must have a minimum value of 1\n')


def test_property_string_syntax_errors():
    assert check('virtio,virtio') == 'invalid format - duplicate key in comma-separated list property: model\n'
    assert check('virtio,model=e1000') == 'invalid format - duplicate key in comma-separated list property: model\n'
    assert check('virtio,=x') == 'invalid format - missing key in comma-separated list property\n'
    assert check('virtio,bridge=') == 'invalid format - missing key in comma-separated list property\n'
    assert check('virtio,bridge=a\nb') == 'invalid format - properties must not contain newlines\n'
    assert check('tag=1,tag=2') == 'invalid format - duplicate key in comma-separated list property: tag\n'
    assert check('virtio,gw=1.1.1.1') == (
        "invalid format - format error\nbridge: missing property required by 'gw'\n")


def test_property_string_without_a_default_key():
    sch = {'type': 'string', 'format': {'a': {'type': 'string', 'optional': 1}}}
    assert schema.check_value(sch, 'x')[1] == \
        'invalid format - value without key, but schema does not define a default key\n'


def test_nested_property_string_errors_carry_the_whole_path():
    sch = {'type': 'string', 'format': {'inner': {'type': 'string', 'format': {'n': {'type': 'integer'}}}}}
    err = schema.check_value(sch, 'inner=n=x')[1]
    assert err == ("invalid format - format error\ninner: invalid format - format error\n"
                   "inner.n: type check ('integer') failed - got 'x'\n\n")


def test_property_string_over_the_cap_is_refused():
    err = schema.check_value(NET, 'virtio,bridge=' + 'a' * 5000)[1]
    assert err == 'invalid format - value may only be {0} characters long\n'.format(formats.MAX_FORMAT_VALUE)


def test_array_items_are_keyed_by_index():
    sch = {'type': 'array', 'items': {'type': 'integer', 'format': 'pve-vmid'}}
    errs = {}
    schema._check(sch, [100, 5, 200, 7], 'vms', errs)
    assert errs == {'vms[1]': 'invalid format - value does not look like a valid VM ID\n',
                    'vms[3]': 'invalid format - value does not look like a valid VM ID\n'}


# --------------------------------------------------------- the API, end to end

async def test_numbered_parameters_use_their_pattern(pve, api):
    pve.add_vm(100, 'vm1')
    ok = {'net0': 'virtio,bridge=vmbr0', 'scsi1': 'local:100/disk.raw,size=32G', 'ipconfig2': 'ip=10.0.0.5/24,gw=10.0.0.1'}
    assert await api.data('PUT', VM + '/config', ok) is None
    assert pve.vms[0].config['net0'] == 'virtio,bridge=vmbr0'
    status, body = await api.call('PUT', VM + '/config', {'net0': 'virtio,bogus=1', 'scsi1': 'local:iso/a,size=12X'})
    assert status == 400 and body['message'] == 'Parameter verification failed.\n'
    assert body['errors']['net0'] == 'invalid format - invalid key in comma-separated list property: bogus\n'
    assert body['errors']['scsi1'].startswith('invalid format - format error\nscsi1.size: invalid format - '
                                              'value does not look like a valid disk size: 12X')


async def test_config_post_is_validated_too(pve, api):
    pve.add_vm(100, 'vm1')
    status, body = await api.call('POST', VM + '/config', {'net0': 'bridge=vmbr0'})
    assert status == 400
    assert body['errors'] == {'net0': 'invalid format - format error\nnet0.model: property is missing and it is not optional\n'}


async def test_ipconfig_is_a_named_property_format(pve, api):
    pve.add_vm(100, 'vm1')
    status, body = await api.call('PUT', VM + '/config', {'ipconfig0': 'gw=10.0.0.1'})
    assert status == 400
    assert body['errors'] == {
        'ipconfig0': "invalid format - format error\nipconfig0.ip: missing property required by 'ipconfig0.gw'\n"}
    status, body = await api.call('PUT', VM + '/config', {'ipconfig0': 'ip=10.0.0.5'})
    assert body['errors'] == {'ipconfig0': 'invalid format - format error\nipconfig0.ip: invalid format - '
                                           'value does not look like a valid ipv4 network configuration\n\n'}
    assert await api.data('PUT', VM + '/config', {'ipconfig0': 'ip=10.0.0.5/24,gw=10.0.0.1,ip6=auto'}) is None


async def test_delete_is_a_list_of_config_ids(pve, api):
    pve.add_vm(100, 'vm1', config={'net0': 'virtio,bridge=vmbr0'})
    status, body = await api.call('PUT', VM + '/config', {'delete': 'net0,0bad'})
    assert status == 400
    assert body['errors'] == {'delete': "invalid format - invalid configuration ID '0bad'\n"}
    assert await api.data('PUT', VM + '/config', {'delete': 'net0'}) is None


async def test_cdrom_uses_the_ide_drive_format(pve, api):
    pve.add_vm(100, 'vm1')
    status, body = await api.call('PUT', VM + '/config', {'cdrom': 'local:iso/a.iso,media=floppy'})
    assert status == 400 and 'cdrom.media' in body['errors']['cdrom']
    assert await api.data('PUT', VM + '/config', {'ide2': 'local:iso/a.iso,media=cdrom'}) is None


async def test_create_validates_names_and_formats(api):
    status, body = await api.call('POST', '/nodes/pve1/qemu', {'vmid': 50, 'net0': 'virtio'})
    assert status == 400 and body['errors']['vmid'] == 'invalid format - value does not look like a valid VM ID\n'
    status, body = await api.call('POST', '/nodes/pve1/qemu', {'vmid': 150, 'net1000': 'virtio'})
    assert status == 400 and body['errors'] == {'net1000': 'property is not defined in schema and the schema does '
                                                           'not allow additional properties'}


async def test_other_formats_through_the_api(api):
    status, body = await api.call('POST', '/pools', {'poolid': 'a b'})
    assert status == 400 and body['errors'] == {'poolid': "invalid format - pool name 'a b' contains invalid characters\n"}
    status, body = await api.call('POST', '/access/users', {'userid': 'bob@pve', 'email': 'nope'})
    assert status == 400 and body['errors'] == {'email': 'invalid format - value does not look like a valid email address\n'}
    status, body = await api.call('POST', '/access/users', {'userid': 'bob@pve', 'email': ''})
    assert status == 200
    status, body = await api.call('POST', '/access/users', {'userid': 'bo', 'email': ''})
    assert status == 400 and body['errors'] == {'userid': "invalid format - user name 'bo' is too short\n"}


# ----------------------------------------------------------------------- docs

def schema_format_names():
    names = set()

    def walk(sch):
        if not isinstance(sch, dict):
            return
        fmt = sch.get('format')
        if isinstance(fmt, str):
            names.add(fmt)
        elif isinstance(fmt, dict):
            for sub in fmt.values():
                walk(sub)
        for sub in (sch.get('properties') or {}).values():
            walk(sub)
        walk(sch.get('items'))
        for sub in sch.get('oneOf', []):
            walk(sub)
    for methods in schema.load().paths.values():
        for info in methods.values():
            walk(info.get('parameters') or {})
    return names


def test_docs_list_every_format_in_the_schema():
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs', 'how-it-works.md')
    with open(path, encoding='utf-8') as fh:
        text = fh.read()
    section = text.split('### Formats')[1].split('\n## ')[0]
    listed = set(__import__('re').findall(r'`([^`\s]+)`', section))
    unchecked = set()
    for name in schema_format_names():
        base = name[:-5] if name.endswith('-list') else name[:-4] if name.endswith('-opt') else name
        if base not in formats.NAMED and schema.registered(name) is None:
            unchecked.add(base)
    assert unchecked
    assert not (unchecked - listed), sorted(unchecked - listed)
    assert not (set(formats.NAMED) - {'string'} - listed), sorted(set(formats.NAMED) - listed)
    assert not (set(formats.REGISTERED) - listed)
