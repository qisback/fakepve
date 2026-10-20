"""PVE's named string formats (PVE::JSONSchema and the modules that register more).

Each checker takes the value and returns None when it is acceptable, or PVE's
message without the trailing newline. Matching is linear: values are cut at
MAX_FORMAT_VALUE before any check, and the character classes are tested with
set membership or anchored patterns that cannot backtrack badly.
"""

import ipaddress
import re

__all__ = ['MAX_FORMAT_VALUE', 'NAMED', 'REGISTERED', 'check', 'split_list']

# Longest value a format is checked on; longer ones fail. PVE has no such limit.
MAX_FORMAT_VALUE = 4096

ALNUM = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
DIGITS = frozenset('0123456789')

# Dict formats PVE registers by name; the schema only names them. Sub-schemas as PVE defines them.
REGISTERED = {
    'pve-qm-ipconfig': {
        'ip': {'type': 'string', 'format': 'pve-ipv4-config', 'optional': 1, 'default': 'dhcp'},
        'gw': {'type': 'string', 'format': 'ipv4', 'optional': 1, 'requires': 'ip'},
        'ip6': {'type': 'string', 'format': 'pve-ipv6-config', 'optional': 1, 'default': 'dhcp'},
        'gw6': {'type': 'string', 'format': 'ipv6', 'optional': 1, 'requires': 'ip6'},
    },
    'pve-qm-boot': {
        'legacy': {'type': 'string', 'optional': 1, 'default_key': 1, 'pattern': '[acdn]{1,4}'},
        'order': {'type': 'string', 'optional': 1, 'format': 'pve-qm-bootdev-list'},
    },
    'pve-qm-rng': {
        'source': {'type': 'string', 'enum': ['/dev/urandom', '/dev/random', '/dev/hwrng'], 'default_key': 1},
        'max_bytes': {'type': 'integer', 'optional': 1, 'default': 1024},
        'period': {'type': 'integer', 'optional': 1, 'default': 1000},
    },
    'pve-qm-watchdog': {
        'model': {'type': 'string', 'enum': ['i6300esb', 'ib700'], 'default_key': 1, 'optional': 1},
        'action': {'type': 'string', 'enum': ['reset', 'shutdown', 'poweroff', 'pause', 'debug', 'none'],
                   'optional': 1},
    },
}


def _in(chars, text):
    return all(c in chars for c in text)


def _fullmatch(pattern):
    rx = re.compile(pattern)
    return lambda text: rx.fullmatch(text) is not None


# ------------------------------------------------------------------ addresses

def _octet(part):
    return bool(part) and _in(DIGITS, part) and (part == '0' or part[0] != '0') and int(part) <= 255


def is_ipv4(text):
    parts = text.split('.')
    return len(parts) == 4 and all(_octet(p) for p in parts)


def is_ipv6(text):
    if not text or '%' in text or '/' in text or not _in('0123456789abcdefABCDEF:.', text):
        return False
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _cidr(text, version):
    ip, sep, bits = text.partition('/')
    if not sep or not bits or not _in(DIGITS, bits):
        return False
    if version == 4:
        return is_ipv4(ip) and 7 < int(bits) <= 32
    return is_ipv6(ip) and 7 < int(bits) <= 128


def is_dns_name(text):
    for label in text.split('.'):
        if not label or label[0] == '-' or label[-1] == '-' or not _in(ALNUM | {'-'}, label):
            return False
    return True


MASKS = frozenset('.'.join(str((((0xffffffff << (32 - n)) & 0xffffffff) >> s) & 255) for s in (24, 16, 8, 0))
                  for n in range(33))
REALM = _fullmatch(r'[A-Za-z][A-Za-z0-9.\-_]+')
STORAGE_ID = _fullmatch(r'[A-Za-z][A-Za-z0-9\-_.]*[A-Za-z0-9]')
USER_PART = re.compile(r'[\w+\-~]+(?:\.[\w+\-~]+)*', re.A)
DOMAIN_PART = re.compile(r'[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*')
CONTENT_TYPES = ('images', 'rootdir', 'vztmpl', 'iso', 'backup', 'snippets', 'import')


def _ip_or_cidr(text):
    ip, sep, bits = text.partition('/')
    if sep and not (bits and _in(DIGITS, bits)):
        return False
    if is_ipv4(ip):
        return not sep or int(bits) <= 32
    return is_ipv6(ip) and (not sep or int(bits) <= 128)


# --------------------------------------------------------------------- checks

def _bad(message, ok):
    return None if ok else message


def _vlan_id_or_range(text):
    start, sep, end = text.partition('-')
    if not start or not _in(DIGITS, start) or (sep and (not end or not _in(DIGITS, end))):
        return "invalid VLAN configuration '{0}'".format(text)
    for tag in (start, end) if sep else (start,):
        if int(tag) < 2 or int(tag) > 4094:
            return "invalid VLAN tag '{0}'".format(tag)
    if sep and int(end) and int(start) >= int(end):
        return "VLAN range must go from lower to higher tag '{0}'".format(text)
    return None


def _disk_size(text):
    body = text
    for unit in ('KiB', 'MiB', 'GiB', 'TiB', 'K', 'M', 'G', 'T'):
        if body.endswith(unit):
            body = body[:-len(unit)]
            break
    whole, dot, frac = body.partition('.')
    ok = bool(whole) and _in(DIGITS, whole) and (not dot or (bool(frac) and _in(DIGITS, frac)))
    return _bad('value does not look like a valid disk size: {0}'.format(text), ok)


def _startup_order(text):
    seen = False
    for part in text.split(','):
        if not part.strip():
            continue
        seen = True
        value = part.split('=', 1)[1] if part.startswith(('order=', 'up=', 'down=')) else part
        if not value or not _in(DIGITS, value):
            return 'unable to parse startup options'
    return None if seen else 'unable to parse startup options'


def _userid(text):
    if len(text) < 3:
        return "user name '{0}' is too short".format(text)
    if len(text) > 64:
        return "user name '{0}' is too long ({1} > 64)".format(text, len(text))
    user, _, realm = text.rpartition('@')
    if user and not any(c.isspace() or c in ':/' for c in user) and REALM(realm):
        return None
    return "value '{0}' does not look like a valid user name".format(text)


def _tokenid(text):
    user, bang, sub = text.partition('!')
    if bang and _userid(user) is None and REALM(sub):
        return None
    return "value '{0}' does not look like a valid token ID".format(text)


def _email(text):
    local, at, domain = text.partition('@')
    return at and USER_PART.fullmatch(local) and DOMAIN_PART.fullmatch(domain)


def _poolid(text):
    parts = text.split('/')
    if len(parts) > 3:
        return "pool name '{0}' nested too deeply (max levels = 3)".format(text)
    if not all(p and _in(ALNUM | set('.-_'), p) for p in parts):
        return "pool name '{0}' contains invalid characters".format(text)
    return None


def _storage_id(text):
    if len(text) < 2:
        return "storage ID '{0}' cannot be shorter than 2 characters".format(text)
    return _bad("storage ID '{0}' contains illegal characters".format(text), STORAGE_ID(text))


def _volume_id(text):
    store, colon, rest = text.partition(':')
    if colon and rest and STORAGE_ID(store) and '\n' not in rest:
        return None
    return "unable to parse volume ID '{0}'".format(text)


def _ip_or_cidr_or_alias(text):
    body = text[3:] if text.startswith('dc/') else text[6:] if text.startswith('guest/') else text
    if len(body) > 1 and body[0].isalpha() and body[0] in ALNUM and _in(ALNUM | set('-_'), body):
        return None
    return _bad('value does not look like a valid IP address or CIDR network', _ip_or_cidr(text))


def _hotplug(text):
    if text in ('0', '1'):
        return None
    for feature in split_list(text):
        if feature not in ('network', 'disk', 'cpu', 'memory', 'usb', 'cloudinit'):
            return "invalid hotplug feature '{0}'".format(feature)
    return None


# name -> checker
NAMED = {
    'string': lambda v: None,
    'urlencoded': lambda v: _bad('invalid urlencoded string: {0}'.format(v),
                                 _in(ALNUM | set("-%_.!~*'()"), v)),
    'pve-configid': lambda v: _bad("invalid configuration ID '{0}'".format(v),
                                   _fullmatch(r'[A-Za-z][A-Za-z0-9_\-]+')(v)),
    'pve-storage-id': _storage_id,
    'pve-bridge-id': lambda v: _bad("invalid bridge ID '{0}'".format(v), bool(v) and _in(ALNUM | set('-_.'), v)),
    'pve-vmid': lambda v: _bad('value does not look like a valid VM ID', _fullmatch(r'[1-9][0-9]{2,8}')(v)),
    'pve-node': lambda v: _bad('value does not look like a valid node name',
                               _fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?')(v)),
    'mac-addr': lambda v: _bad('value does not look like a valid unicast MAC address',
                               _fullmatch(r'[a-fA-F0-9][02468aceACE](?::[a-fA-F0-9]{2}){5}')(v)),
    'ipv4': lambda v: _bad('value does not look like a valid IPv4 address', is_ipv4(v)),
    'ipv6': lambda v: _bad('value does not look like a valid IPv6 address', is_ipv6(v)),
    'ip': lambda v: _bad('value does not look like a valid IP address', is_ipv4(v) or is_ipv6(v)),
    'ipv4mask': lambda v: _bad('value does not look like a valid IP netmask', v in MASKS),
    'CIDRv4': lambda v: _bad('value does not look like a valid IPv4 CIDR network', _cidr(v, 4)),
    'CIDRv6': lambda v: _bad('value does not look like a valid IPv6 CIDR network', _cidr(v, 6)),
    'CIDR': lambda v: _bad('value does not look like a valid CIDR network', _cidr(v, 4) or _cidr(v, 6)),
    'pve-ipv4-config': lambda v: _bad('value does not look like a valid ipv4 network configuration',
                                      v in ('dhcp', 'manual') or _cidr(v, 4)),
    'pve-ipv6-config': lambda v: _bad('value does not look like a valid ipv6 network configuration',
                                      v in ('auto', 'dhcp', 'manual') or _cidr(v, 6)),
    'email': lambda v: _bad('value does not look like a valid email address', _email(v)),
    'email-or-username': lambda v: _bad('value does not look like a valid email address or user name',
                                        _email(v) or USER_PART.fullmatch(v)),
    'dns-name': lambda v: _bad('value does not look like a valid DNS name', is_dns_name(v)),
    'pve-iface': lambda v: _bad("invalid network interface name '{0}'".format(v),
                                _fullmatch(r'[A-Za-z][A-Za-z0-9_]{1,20}(?:[:.][0-9]+)?')(v)),
    'pve-vlan-id-or-range': _vlan_id_or_range,
    'address': lambda v: _bad('value does not look like a valid address: {0}'.format(v),
                              is_ipv4(v) or is_ipv6(v) or is_dns_name(v)),
    'disk-size': _disk_size,
    'pve-tag': lambda v: _bad('invalid characters in tag', _fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_\-+.]*')(v)),
    'pve-startup-order': _startup_order,
    'pve-hotplug-features': _hotplug,
    'ldap-simple-attr': lambda v: _bad("value '{0}' does not look like a simple ldap attribute name".format(v),
                                       bool(v) and _in(ALNUM, v)),
    'pve-userid': _userid,
    'pve-tokenid': _tokenid,
    'pve-realm': lambda v: _bad('value does not look like a valid realm', REALM(v)),
    'pve-poolid': _poolid,
    'pve-groupid': lambda v: _bad("group name '{0}' contains invalid characters".format(v),
                                  bool(v) and _in(ALNUM | set('.-_'), v)),
    'pve-roleid': lambda v: _bad("role name '{0}' contains invalid characters".format(v),
                                 bool(v) and _in(ALNUM | set('.-_'), v)),
    'pve-storage-path': lambda v: _bad('value does not look like a valid absolute path',
                                       len(v) > 1 and v[0] == '/' and v[1] not in ';()'),
    'pve-storage-server': lambda v: _bad('value does not look like a valid server name or IP address',
                                         is_ipv4(v) or is_ipv6(v) or is_dns_name(v)),
    'pve-storage-content': lambda v: _bad("invalid content type '{0}'".format(v), v in CONTENT_TYPES),
    'pve-volume-id': _volume_id,
    'pve-volume-id-or-absolute-path': lambda v: None if v.startswith('/') else _volume_id(v),
    'pve-volume-id-or-qm-path': lambda v: None if v in ('none', 'cdrom') or v.startswith('/') else _volume_id(v),
    'IPorCIDR': lambda v: _bad('value does not look like a valid IP address or CIDR network', _ip_or_cidr(v)),
    'IPorCIDRorAlias': _ip_or_cidr_or_alias,
    'pve-fw-comment-spec': lambda v: 'comment must not contain a line feed' if '\n' in v or '\r' in v else None,
}


def split_list(text):
    """PVE's split_list: NUL, or commas, semicolons and white space, separate items."""
    if '\0' in text:
        items = text.split('\0')
        while items and not items[-1]:  # Perl's split drops trailing empty fields
            items.pop()
        return items
    return text.replace(',', ' ').replace(';', ' ').split()


def check(name, value):
    """Check a string against a named format (with PVE's -list and -opt suffixes).

    Returns None if it is acceptable or the format is not implemented, else PVE's message
    without the trailing newline.
    """
    kind = ''
    base = name
    for suffix in ('list', 'opt'):
        if name.endswith('-' + suffix):
            base, kind = name[:-len(suffix) - 1], suffix
    if base not in NAMED:
        return None
    if len(value) > MAX_FORMAT_VALUE:
        return 'value may only be {0} characters long'.format(MAX_FORMAT_VALUE)
    checker = NAMED[base]
    if kind == 'list':
        for item in split_list(value):
            why = checker(item)
            if why:
                return why
        return None
    if kind == 'opt' and not value:
        return None
    return checker(value)
