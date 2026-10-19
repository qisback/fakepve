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


def _pattern(pattern):
    try:
        return re.compile('^(?:' + pattern + ')$', re.S)
    except re.error:
        return None


def check_value(sch, val):
    """Check one value against a schema. Returns (coerced value, error or None)."""
    kind = sch.get('type')
    if kind == 'array':
        items = val if isinstance(val, list) else [val]
        out = []
        for item in items:
            item, err = check_value(sch.get('items') or {}, item)
            if err:
                return val, err
            out.append(item)
        if len(out) < sch.get('minItems', 0):
            return val, 'array must have at least {0} items'.format(sch['minItems'])
        return out, None
    if kind == 'object':
        return val, None if isinstance(val, dict) or val in ('', None) or isinstance(val, str) else \
            _type_error('object', val)
    if isinstance(val, (list, dict)):
        return val, _type_error(kind or 'string', val)
    if kind == 'integer':
        if not _is_int(val):
            return val, _type_error('integer', val)
        val = int(val)
    elif kind == 'number':
        if not _is_number(val):
            return val, _type_error('number', val)
        val = float(val)
        val = int(val) if val == int(val) else val
    elif kind == 'boolean':
        text = str(val).lower() if not isinstance(val, bool) else ('1' if val else '0')
        if text in TRUE:
            return 1, None
        if text in FALSE:
            return 0, None
        return val, _type_error('boolean', val)
    elif kind in (None, 'string', 'any'):
        val = str(val) if not isinstance(val, bool) else ('1' if val else '0')
    if 'enum' in sch and val not in sch['enum'] and str(val) not in [str(e) for e in sch['enum']]:
        return val, "value '{0}' does not have a value in the enumeration '{1}'".format(
            val, ', '.join(str(e) for e in sch['enum']))
    if 'minimum' in sch and isinstance(val, (int, float)) and val < sch['minimum']:
        return val, 'value must have a minimum value of {0}'.format(sch['minimum'])
    if 'maximum' in sch and isinstance(val, (int, float)) and val > sch['maximum']:
        return val, 'value must have a maximum value of {0}'.format(sch['maximum'])
    if isinstance(val, str):
        if 'minLength' in sch and len(val) < sch['minLength']:
            return val, 'value must be at least {0} characters long'.format(sch['minLength'])
        if 'maxLength' in sch and len(val) > sch['maxLength']:
            return val, 'value may only be {0} characters long'.format(sch['maxLength'])
        if sch.get('pattern'):
            rx = _pattern(sch['pattern'])
            if rx is not None and not rx.match(val):
                return val, 'value does not match the regex pattern'
    return val, None


def validate(spec, values):
    """Check request values against a method's parameter schema.

    Returns (coerced values, {param: message}) with PVE's wording.
    """
    spec = spec or {}
    props = spec.get('properties', {})
    errors = {}
    out = {}
    for name, val in values.items():
        if name not in props:
            if spec.get('additionalProperties', 1) in (0, '0', False):
                errors[name] = 'property is not defined in schema and the schema does not allow additional properties'
            else:
                out[name] = val
            continue
        out[name], err = check_value(props[name], val)
        if err:
            errors[name] = err
    for name, sch in props.items():
        if name not in values and not sch.get('optional'):
            errors[name] = 'property is missing and it is not optional'
        elif name in values and name not in errors and sch.get('requires'):
            other = sch['requires']
            if other not in values:
                errors[other] = 'property is missing and it is not optional'
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
    if isinstance(fmt, dict):
        # A property string: its required keys.
        parts = []
        for key, sub in fmt.items():
            if not sub.get('optional'):
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
            if rx is not None and not rx.match(val):
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
