"""The PVE API schema: path routing, parameter validation and sample values.

The schema is the trimmed apidoc from the PVE API viewer (see
tools/fetch_schema.py). Nothing here knows PVE's behaviour; it only knows
what PVE accepts and what shape it answers with.
"""

import functools
import gzip
import json
import pkgutil
import re

from . import formats

try:
    from re import _parser as sre_parse
except ImportError:  # Python < 3.11
    import sre_parse

__all__ = ['Match', 'Schema', 'is_task', 'load', 'sample', 'validate']

# PVE booleans.
TRUE = ('1', 'true', 'yes', 'on')
FALSE = ('0', 'false', 'no', 'off')


class Match(object):
    """A request path resolved against the schema."""

    def __init__(self, template, params, methods):
        self.template = template
        self.params = params
        self.methods = methods


class Schema(object):
    def __init__(self, paths):
        self.paths = paths
        # Trie: {'lit': {segment: node}, 'var': (name, node), 'path': template}
        self.root = {}
        for template in paths:
            node = self.root
            for seg in template.strip('/').split('/') if template != '/' else []:
                if seg.startswith('{') and seg.endswith('}'):
                    name, node = node.setdefault('var', (seg[1:-1], {}))
                else:
                    node = node.setdefault('lit', {}).setdefault(seg, {})
            node['path'] = template

    def match(self, path):
        """Resolve '/nodes/pve1/qemu' to a Match, or None."""
        segs = [s for s in path.strip('/').split('/')] if path.strip('/') else []

        def walk(node, i, params):
            if i == len(segs):
                return (node['path'], params) if 'path' in node else None
            seg = segs[i]
            nxt = node.get('lit', {}).get(seg)
            if nxt is not None:
                found = walk(nxt, i + 1, params)
                if found:
                    return found
            if 'var' in node and seg:
                name, nxt = node['var']
                return walk(nxt, i + 1, dict(params, **{name: seg}))
            return None
        found = walk(self.root, 0, {})
        if found is None:
            return None
        return Match(found[0], found[1], self.paths[found[0]])

    def children(self, template):
        """Literal child segments of a path template."""
        prefix = template.rstrip('/') + '/'
        return sorted(set(p[len(prefix):].split('/')[0] for p in self.paths
                          if p.startswith(prefix) and not p[len(prefix):].startswith('{')))


@functools.lru_cache(maxsize=None)
def load():
    """The vendored PVE schema, as a Schema."""
    raw = pkgutil.get_data('fakepve', 'data/pve-api.json.gz')
    return Schema(json.loads(gzip.decompress(raw))['paths'])


# ------------------------------------------------------------------ validation

def _type_error(kind, val):
    return "type check ('{0}') failed - got '{1}'".format(kind, val if not isinstance(val, (list, dict)) else
                                                         'ARRAY' if isinstance(val, list) else 'HASH')


def _is_int(val):
    if isinstance(val, bool):
        return False
    if isinstance(val, int):
        return True
    return isinstance(val, str) and re.match(r'^[+-]?\d+$', val) is not None


def _is_number(val):
    if isinstance(val, bool):
        return False
    if isinstance(val, (int, float)):
        return True
    try:
        float(val)
        return isinstance(val, str) and val.strip() == val and val.lower() not in ('nan', 'inf', '-inf')
    except (TypeError, ValueError):
        return False


# Longest value matched against a schema pattern; longer ones fail as PVE's own length limits would.
MAX_PATTERN_VALUE = 1024
# Constructs of the PVE schema that make Python's backtracking matcher exponential, with equivalent
# linear forms. `[-]*` may match nothing, so the separator in (sep [a-z\d]+)* let a run of letters
# split in any number of ways; requiring at least one dash accepts the same strings.
LINEAR_FORMS = (('(?:[._]|__|[-]*)', '(?:[._]|__|[-]+)'),)


@functools.lru_cache(maxsize=None)
def _pattern(pattern):
    for slow, linear in LINEAR_FORMS:
        pattern = pattern.replace(slow, linear)
    try:
        return re.compile('^(?:' + pattern + ')$', re.S)
    except re.error:
        return None


def check_value(sch, val):
    """Check one value against a schema. Returns (coerced value, error or None)."""
    errs = {}
    out = _check(sch, val, '', errs)
    return out, next(iter(errs.values()), None)


def _check(sch, val, path, errs):
    """Check val against sch as PVE's check_prop does, recording errors by path. Returns the coerced value."""
    kind = sch.get('type')
    if kind == 'array':
        items = val if isinstance(val, list) else [val]
        before = len(errs)
        out = [_check(sch.get('items') or {}, item, '{0}[{1}]'.format(path, n), errs) for n, item in enumerate(items)]
        if len(errs) == before and len(out) < sch.get('minItems', 0):
            errs[path] = 'array must have at least {0} items'.format(sch['minItems'])
        return out
    if kind == 'object':
        if not (isinstance(val, dict) or val in ('', None) or isinstance(val, str)):
            errs[path] = _type_error('object', val)
        return val
    if isinstance(val, (list, dict)):
        errs[path] = _type_error(kind or 'string', val)
        return val
    # A format sees the text as sent ('0100'), not the coerced number.
    raw = str(val) if not isinstance(val, bool) else ('1' if val else '0')
    if kind == 'integer':
        if not _is_int(val):
            errs[path] = _type_error('integer', val)
            return val
        val = int(val)
    elif kind == 'number':
        if not _is_number(val):
            errs[path] = _type_error('number', val)
            return val
        val = float(val)
        val = int(val) if val == int(val) else val
    elif kind == 'boolean':
        text = str(val).lower() if not isinstance(val, bool) else ('1' if val else '0')
        if text in TRUE:
            return 1
        if text in FALSE:
            return 0
        errs[path] = _type_error('boolean', val)
        return val
    elif kind in (None, 'string', 'any'):
        val = str(val) if not isinstance(val, bool) else ('1' if val else '0')
    # The order is PVE's: format, pattern, lengths, range, enumeration.
    if sch.get('format'):
        why = _check_format(sch['format'], raw, path)
        if why:
            errs[path] = 'invalid format - ' + why
            return val
    if isinstance(val, str) and sch.get('pattern'):
        rx = _pattern(sch['pattern'])
        if rx is not None and (len(val) > MAX_PATTERN_VALUE or not rx.match(val)):
            errs[path] = 'value does not match the regex pattern'
            return val
    if isinstance(val, str):
        if 'maxLength' in sch and len(val) > sch['maxLength']:
            errs[path] = 'value may only be {0} characters long'.format(sch['maxLength'])
            return val
        if 'minLength' in sch and len(val) < sch['minLength']:
            errs[path] = 'value must be at least {0} characters long'.format(sch['minLength'])
            return val
    # The schema states some limits as strings ("16777216").
    if 'maximum' in sch and isinstance(val, (int, float)) and val > float(sch['maximum']):
        errs[path] = 'value must have a maximum value of {0}'.format(sch['maximum'])
    elif 'minimum' in sch and isinstance(val, (int, float)) and val < float(sch['minimum']):
        errs[path] = 'value must have a minimum value of {0}'.format(sch['minimum'])
    elif 'enum' in sch and val not in sch['enum'] and str(val) not in [str(e) for e in sch['enum']]:
        errs[path] = "value '{0}' does not have a value in the enumeration '{1}'".format(
            val, ', '.join(str(e) for e in sch['enum']))
    return val


# ------------------------------------------------------------------- formats

@functools.lru_cache(maxsize=None)
def registered(name):
    """The sub-schemas of a named property-string format, or None if the name is not one."""
    if name in formats.REGISTERED:
        return formats.REGISTERED[name]
    if name == 'pve-qm-ide':  # the schema spells it out on ide[n]
        props = load().paths['/nodes/{node}/qemu']['POST']['parameters']['properties']
        return props['ide[n]']['format']
    return None


def _check_format(fmt, text, path):
    """PVE's message (with its trailing newline) if text breaks the format, else None."""
    sub = fmt if isinstance(fmt, dict) else registered(fmt) if isinstance(fmt, str) else None
    if sub is not None:
        return _property_string(sub, text, path)
    if not isinstance(fmt, str):
        return None
    why = formats.check(fmt, text)
    return why + '\n' if why else None


def parse_boolean(text):
    """PVE's boolean spellings: '1' or '0', or None if it is not one."""
    low = text.lower()
    return '1' if low in TRUE else '0' if low in FALSE else None


def _property_string(sub, text, path):
    """Check 'key=value,...' against its sub-schemas. Returns PVE's message or None."""
    if len(text) > formats.MAX_FORMAT_VALUE:
        return 'value may only be {0} characters long\n'.format(formats.MAX_FORMAT_VALUE)
    res = {}
    bare = False
    for part in text.split(','):
        if not part.strip():
            continue
        key, eq, val = part.partition('=')
        if '\n' in part:
            return 'properties must not contain newlines\n'
        if eq and key and val:
            if key in res:
                return 'duplicate key in comma-separated list property: {0}\n'.format(key)
            entry = sub.get(key) or {}
            if entry.get('alias'):
                if entry.get('keyAlias'):
                    if entry['keyAlias'] in res:
                        return "key alias '{0}' is already defined\n".format(entry['keyAlias'])
                    res[entry['keyAlias']] = key
                key = entry['alias']
                entry = sub.get(key) or {}
                if key in res:
                    return "key '{0}' is already defined (via alias)\n".format(key)
            if not entry:
                return 'invalid key in comma-separated list property: {0}\n'.format(key)
            res[key] = (parse_boolean(val) or val) if entry.get('type') == 'boolean' else val
        elif not eq:
            default = next((k for k, v in sub.items() if v.get('default_key')), None)
            if bare:
                return 'duplicate key in comma-separated list property: {0}\n'.format(default)
            if default is None:
                return 'value without key, but schema does not define a default key\n'
            if res.get(default):
                return 'duplicate key in comma-separated list property: {0}\n'.format(default)
            bare = True
            res[default] = (parse_boolean(part) or part) if sub[default].get('type') == 'boolean' else part
        else:
            return 'missing key in comma-separated list property\n'
    errs = {}
    for key, entry in sub.items():
        if entry.get('alias'):
            continue
        where = '{0}.{1}'.format(path, key) if path else key
        if key not in res:
            if not entry.get('optional'):
                errs[where] = 'property is missing and it is not optional'
            continue
        _check(entry, res[key], where, errs)
        needs = entry.get('requires')
        if needs and needs not in res:
            errs['{0}.{1}'.format(path, needs) if path else needs] = "missing property required by '{0}'".format(where)
    if errs:
        return 'format error\n' + ''.join('{0}: {1}\n'.format(k, errs[k]) for k in sorted(errs))
    return None


# Highest index (exclusive) of PVE's numbered options such as net0 and scsi30.
MAX_INDEX = {'net': 32, 'ipconfig': 32, 'ide': 4, 'sata': 6, 'scsi': 31, 'virtio': 16, 'unused': 256, 'numa': 8,
             'hostpci': 16, 'usb': 14, 'virtiofs': 10, 'serial': 4, 'parallel': 3, 'mp': 256, 'dev': 256}


def _prop(props, name):
    """The schema of a request parameter; a numbered one (net0) is found under its pattern (net[n])."""
    if name in props:
        return props[name]
    base = name.rstrip('0123456789')
    index = name[len(base):]
    if base and index and base + '[n]' in props and index == str(int(index)) and \
            int(index) < MAX_INDEX.get(base, 10 ** 9):
        return props[base + '[n]']
    return None


def validate(spec, values):
    """Check request values against a method's parameter schema.

    Returns (coerced values, {param: message}) with PVE's wording.
    """
    spec = spec or {}
    props = spec.get('properties', {})
    errors = {}
    out = {}
    for name, val in values.items():
        sch = _prop(props, name)
        if sch is None:
            if spec.get('additionalProperties', 1) in (0, '0', False):
                errors[name] = 'property is not defined in schema and the schema does not allow additional properties'
            else:
                out[name] = val
            continue
        out[name] = _check(sch, val, name, errors)
    for name, sch in props.items():
        if name not in values and not sch.get('optional') and '[n]' not in name:
            errors[name] = 'property is missing and it is not optional'
    for name in values:
        other = (_prop(props, name) or {}).get('requires')
        if other and other not in values:
            errors[other] = "missing property required by '{0}'".format(name)
    return out, errors


# --------------------------------------------------------------------- results

def is_task(method, info):
    """True if the method starts a worker task and so answers with a UPID."""
    returns = info.get('returns') or {}
    if method == 'GET' or returns.get('type') != 'string' or not info.get('protected'):
        return False
    text = (returns.get('description') or '').lower()
    return not text or 'task' in text or 'upid' in text


# Values for PVE's string formats.
FORMATS = {
    'pve-node': 'pve1', 'pve-storage-id': 'local', 'pve-userid': 'root@pam', 'pve-realm': 'pam',
    'pve-poolid': 'pool1', 'pve-groupid': 'group1', 'pve-roleid': 'role1', 'pve-iface': 'vmbr0',
    'pve-configid': 'scsi0', 'pve-volume-id': 'local:iso/fake.iso', 'pve-storage-path': '/var/lib/vz',
    'pve-calendar-event': 'daily', 'pve-tag-list': 'tag1', 'pve-priv-list': 'VM.Audit',
    'pve-storage-server': '10.0.0.5', 'ip': '10.0.0.1', 'ipv4': '10.0.0.1', 'ipv6': 'fd00::1',
    'address': '10.0.0.1', 'dns-name': 'host.example.org', 'CIDR': '10.0.0.0/24', 'IPorCIDR': '10.0.0.1',
    'IPorCIDRorAlias': '10.0.0.1', 'FullRangeCIDR': '10.0.0.0/24', 'mac-addr': 'BC:24:11:00:00:01',
    'email-or-username': 'root@pam', 'email-opt': 'root@localhost', 'pve-vmid': 100,
    'pve-ha-resource-or-vm-id': 'vm:100', 'pve-replication-job-id': '100-0',
    'pve-sdn-fabric-id': 'fabric1', 'pve-sdn-route-map-id': 'rm1', 'pve-sdn-prefix-list-id': 'pl1',
    'pve-sdn-subnet-id': 'zone1-10.0.0.0-24', 'pve-fw-comment-spec': 'fake',
    'pve-bridge-id': 'vmbr0', 'disk-size': '32G', 'urlencoded': 'fake', 'pve-tokenid': 'root@pam!token1',
    'pve-volume-id-or-qm-path': 'local:iso/fake.iso', 'pve-volume-id-or-absolute-path': '/var/lib/vz/fake.img',
    'pve-storage-content': 'iso', 'ldap-simple-attr': 'uid', 'pve-hotplug-features': 'network',
    'pve-startup-order': 'order=1', 'ipv4mask': '255.255.255.0', 'CIDRv4': '10.0.0.0/24', 'CIDRv6': 'fd00::/64',
    'pve-ipv4-config': 'dhcp', 'pve-ipv6-config': 'dhcp', 'email': 'root@example.org', 'pve-tag': 'tag1',
    'pve-vlan-id-or-range': '10',
}


def _regex_sample(pattern):
    """A string a regular expression matches, built from its parse tree."""
    def gen(parsed):
        out = ''
        for op, arg in parsed:
            name = str(op)
            if name == 'LITERAL':
                out += chr(arg)
            elif name == 'NOT_LITERAL':
                out += 'a' if arg != ord('a') else 'b'
            elif name == 'ANY':
                out += 'a'
            elif name == 'IN':
                out += _pick(arg)
            elif name in ('MAX_REPEAT', 'MIN_REPEAT', 'POSSESSIVE_REPEAT'):
                low, _, sub = arg
                out += gen(sub) * max(low, 0)
            elif name == 'SUBPATTERN':
                out += gen(arg[-1])
            elif name == 'BRANCH':
                out += gen(arg[1][0])
            elif name == 'ATOMIC_GROUP':
                out += gen(arg)
        return out

    def _pick(items):
        negate = any(str(op) == 'NEGATE' for op, _ in items)
        for op, arg in items:
            name = str(op)
            if negate:
                continue
            if name == 'LITERAL':
                return chr(arg)
            if name == 'RANGE':
                return chr(arg[0])
            if name == 'CATEGORY':
                return {'CATEGORY_DIGIT': '1', 'CATEGORY_SPACE': ' ', 'CATEGORY_WORD': 'a'}.get(str(arg), 'a')
        return 'a'
    try:
        return gen(sre_parse.parse(pattern))
    except Exception:  # noqa: BLE001 - an exotic pattern falls back to the caller's guess
        return None


def _string(sch, name, ctx):
    fmt = sch.get('format')
    named = registered(fmt) if isinstance(fmt, str) else None
    if isinstance(fmt, dict) or named:
        # A property string: its required keys.
        parts = []
        for key, sub in (named or fmt).items():
            if not sub.get('optional') and not sub.get('alias'):
                parts.append('{0}={1}'.format(key, sample(sub, key, ctx)))
        return ','.join(parts)
    if isinstance(fmt, str):
        base = fmt[:-5] if fmt.endswith('-list') and fmt not in FORMATS else fmt
        if base in FORMATS:
            return str(FORMATS[base])
    default = sch.get('default')
    if isinstance(default, str) and default:
        return default
    val = 'fake'
    if sch.get('pattern'):
        guess = _regex_sample(sch['pattern'])
        if guess is not None:
            val = guess
    return val


def _fit(sch, val):
    """Make a string satisfy the length limits."""
    if not isinstance(val, str):
        return val
    if len(val) < sch.get('minLength', 0):
        val += 'a' * (sch['minLength'] - len(val))
    return val[:sch['maxLength']] if 'maxLength' in sch else val


def sample(sch, name='', ctx=None):
    """A value that satisfies a schema. ctx maps property names to preferred values."""
    ctx = ctx or {}
    kind = sch.get('type')
    if 'oneOf' in sch and kind is None:
        return sample(sch['oneOf'][0], name, ctx)
    if name in ctx and kind in ('string', 'integer', 'number', None):
        val = ctx[name]
        if kind == 'integer' and _is_int(val):
            return int(val)
        if kind in ('string', None):
            val = str(val)
            if not sch.get('pattern') or (_pattern(sch['pattern']) or re.compile('')).match(val):
                return val
    if 'enum' in sch:
        return sch['enum'][0]
    if kind in ('integer', 'number'):
        val = sch.get('default', sch.get('minimum', 0))
        if 'maximum' in sch and val > sch['maximum']:
            val = sch['maximum']
        return val
    if kind == 'boolean':
        return 1 if sch.get('default') else 0
    if kind == 'string':
        val = _fit(sch, _string(sch, name, ctx))
        if sch.get('pattern'):
            rx = _pattern(sch['pattern'])
            if rx is not None and (len(val) > MAX_PATTERN_VALUE or not rx.match(val)):
                guess = _regex_sample(sch['pattern'])
                if guess is not None:
                    val = _fit(sch, guess)
        return val
    if kind == 'array':
        if not sch.get('items'):
            return []
        return [sample(sch['items'], name, ctx)]
    if kind == 'null':
        return None
    if kind == 'any':
        return None
    props = sch.get('properties')
    if kind == 'object' or props is not None:
        out = {}
        for key, sub in (props or {}).items():
            # Optional properties only where the name tells what to put there.
            if not sub.get('optional') or key in ctx:
                out[key] = sample(sub, key, ctx)
        return out
    return None
