#!/usr/bin/env python3
"""Compare fakepve's answers with a real PVE, read-only, keeping only shapes.

    compare_real.py record --url https://HOST:8006 --token-file FILE (--insecure | --cafile CA) [--out shape.json]
    compare_real.py diff shape.json [--against other.json] [--strict] [--as-root] [--no-ignore-config-keys]
    compare_real.py --self-test
    compare_real.py scenario --url https://HOST:8006 --token-file FILE (--insecure | --cafile CA) --out scenario.json
        --i-understand-this-writes --disposable-node NAME [--against-fake] [--allow-existing-guests]
    compare_real.py scenario --against-fake scenario.json
    compare_real.py --self-test-scenario

record walks every GET method of the vendored schema, with GET and nothing else, and writes a shape file:
per method the status, the types and key names of the answer and the error text with every name and number
removed. No value is kept; a self-check refuses to write a file that holds one. The token is read from a file,
never from the command line, and is never printed or written.

record also keeps the names of the privileges the token holds (from GET /access/permissions, names only).

diff runs the same walk against an in-process fakepve seeded with the counts in the shape file, as a user holding
the same privileges (or compares two shape files), and lists, per method, status, key and type differences.
Keys that depend on what one object has set (a VM's config keys, the options of a storage) are not counted
unless --no-ignore-config-keys is given.

scenario (phase 2) WRITES, so it is only for a throwaway PVE: it creates, changes and destroys a few objects of
its own (vmids 9900-9999, names fpcmp-*, storage fpcmp-dir, pool fpcmp-pool), records per step the status, the
error text with every name removed and the outcome of the task, and cleans up. See docs/how-it-works.md.
"""

import argparse
import asyncio
import difflib
import gzip
import json
import os
import pkgutil
import re
import ssl
import sys
import tempfile
import urllib.parse

try:
    import aiohttp
except ImportError:
    sys.exit('compare_real: needs aiohttp (pip install aiohttp)')

try:
    from fakepve import schema as fschema
    from fakepve.shapes import PRIVILEGES
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))
    from fakepve import schema as fschema
    from fakepve.shapes import PRIVILEGES

FORMAT = 1
KEY = '<key>'
UNKNOWN = '<x>'
TYPES = ('null', 'boolean', 'integer', 'number', 'string', 'object', 'array', 'mixed')
SHAPE_FIELDS = {'t', 'keys', 'optional', 'items', 'of', 'nullable'}
DOC_FIELDS = {'format', 'endpoints', 'skipped', 'inventory'}
PERMISSIONS = '/access/permissions'
ENTRY_FIELDS = {'status', 'shape', 'errors', 'samples'}
MAX_BODY = 8 * 1024 ** 2
API = '/api2/json'
TOKEN_RX = re.compile(r'^[^\s!=]+@[^\s!=]+![^\s=]+=\S+$')

# Words of PVE's own generic messages that the schema and the catalogue may lack.
BASE_WORDS = ('parameter', 'verification', 'failed', 'invalid', 'format', 'value', 'does', 'look', 'like', 'valid',
              'match', 'exist', 'property', 'defined', 'schema', 'additional', 'properties', 'allowed', 'not',
              'task', 'ok', 'warnings')

# Skip reasons are fixed strings, so a skip list cannot carry a value either.
REASONS = ('console', 'rrd', 'download', 'probe', 'guest-agent', 'heavy', 'side-effect', 'required-param',
           'no-sample', 'request-cap')
CONSOLE = {'vncproxy', 'termproxy', 'spiceproxy', 'vncwebsocket', 'mtunnelwebsocket'}
SIDE_EFFECT = re.compile(r'\b(creates?|starts?|stops?|generates?|triggers?|downloads?|deletes?|removes?|'
                         r'allocates?|spawns?|executes?)\b')
# Path parameter -> key of the list item that holds its value (default: the parameter's own name, then id, name).
ITEM_KEYS = {'volume': ['volid'], 'snapname': ['name'], 'domain': ['realm']}


class ToolError(Exception):
    """A failure whose message is safe to print."""


class Leak(ToolError):
    """The shape file would hold something other than types and key names."""


class ReadOnlyViolation(ToolError):
    """A request that is not a GET."""


class CapReached(Exception):
    pass


# ------------------------------------------------------------------- schema

def schema_words(sch):
    """Lowercase words of the schema descriptions and the error catalogue: the only words an error template keeps."""
    words = {'x', 'network', 'error', 'timeout', 'non', 'json', 'unknown', 'http', 'ok'}

    def walk(node):
        if isinstance(node, str):
            words.update(re.findall(r'[a-z]+', node.lower()))
        elif isinstance(node, dict):
            for key, val in node.items():
                if isinstance(val, str) and key not in ('description', 'title'):
                    continue
                walk(val)
        elif isinstance(node, list):
            for val in node:
                walk(val)
    walk(sch.paths)
    try:
        catalogue = json.loads(gzip.decompress(pkgutil.get_data('fakepve', 'data/pve-errors.json.gz')))
        for entries in catalogue['errors'].values():
            for entry in entries:
                words.update(re.findall(r'[a-z]+', str(entry.get('message', '')).lower()))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass
    words.update(BASE_WORDS)
    return words


def known_keys(sch):
    """Predicate for the key names the schema documents (and the numbered forms such as net0)."""
    names, bases = set(), set()

    def walk(node):
        if isinstance(node, dict):
            for key, val in node.items():
                if key in ('properties', 'format') and isinstance(val, dict):
                    for name in val:
                        if name.endswith('[n]'):
                            bases.add(name[:-3])
                        else:
                            names.add(name)
                walk(val)
        elif isinstance(node, list):
            for val in node:
                walk(val)
    walk(sch.paths)

    def known(key):
        if key == KEY or key in names:
            return True
        m = re.fullmatch(r'(.+?)\d+', key)
        return bool(m and m.group(1) in bases)
    return known


class Vocab(object):
    """What may appear in a shape file: key names and error words the schema knows."""

    def __init__(self, sch):
        self.sch = sch
        self.known = known_keys(sch)
        self.words = schema_words(sch)
        self.templates = set(t for t, m in sch.paths.items() if 'GET' in m)


# -------------------------------------------------------------------- shapes

def parts(s):
    """The non-mixed shapes a shape is made of; null counts when nullable."""
    out = list(s['of']) if s['t'] == 'mixed' else [{k: v for k, v in s.items() if k != 'nullable'}]
    return out + [{'t': 'null'}] if s.get('nullable') else out


def merge_same(a, b):
    if a['t'] == 'object':
        keys = dict(a['keys'])
        optional = set(a.get('optional', ())) | set(b.get('optional', ())) | (set(a['keys']) ^ set(b['keys']))
        for k, v in b['keys'].items():
            keys[k] = merge(keys[k], v) if k in keys else v
        out = {'t': 'object', 'keys': dict(sorted(keys.items()))}
        if optional:
            out['optional'] = sorted(optional)
        return out
    if a['t'] == 'array':
        items = merge(a.get('items'), b.get('items'))
        return {'t': 'array', 'items': items} if items else {'t': 'array'}
    return a


def merge(a, b):
    """Union of two shapes."""
    if a is None or b is None:
        return a or b
    by = {}
    for p in parts(a) + parts(b):
        by[p['t']] = merge_same(by[p['t']], p) if p['t'] in by else p
    nullable = 'null' in by and len(by) > 1
    if nullable:
        del by['null']
    out = next(iter(by.values())) if len(by) == 1 else {'t': 'mixed', 'of': [by[t] for t in sorted(by)]}
    return dict(out, nullable=True) if nullable else out


def shape(value, known, k=5):
    """The type structure of a JSON value. Dict keys the schema does not name become '<key>'."""
    if value is None:
        return {'t': 'null'}
    if isinstance(value, bool):
        return {'t': 'boolean'}
    if isinstance(value, int):
        return {'t': 'integer'}
    if isinstance(value, float):
        return {'t': 'number'}
    if isinstance(value, list):
        items = None
        for item in value[:k]:
            items = merge(items, shape(item, known, k))
        return {'t': 'array', 'items': items} if items else {'t': 'array'}
    if isinstance(value, dict):
        keys = {}
        for key, val in value.items():
            name = key if isinstance(key, str) and known(key) else KEY
            keys[name] = merge(keys.get(name), shape(val, known, k))
        return {'t': 'object', 'keys': dict(sorted(keys.items()))}
    return {'t': 'string'}


def error_template(message, vocab):
    """An error message with every name, number and path removed; only schema words stay."""
    def word(m):
        run = m.group(0).rstrip('.:,')
        if not re.search(r'[A-Za-z0-9]', m.group(0)):
            return m.group(0)
        tail = m.group(0)[len(run):]
        return (run if re.fullmatch(r'[A-Za-z]+', run) and run.lower() in vocab.words else UNKNOWN) + tail
    text = re.sub(r"[A-Za-z0-9_.:/@!=+\-%$#~*]+", word, str(message or '')).strip()
    return re.sub(r'(?:<x>[ ]*){2,}', UNKNOWN + ' ', text)[:200].strip() or UNKNOWN


# ----------------------------------------------------------------- the check

def check_shape(s, vocab, where='data'):
    """Raise Leak unless s is made of type names and key names only."""
    if not isinstance(s, dict) or not set(s) <= SHAPE_FIELDS or s.get('t') not in TYPES:
        raise Leak('not a shape at ' + where)
    if s.get('nullable', True) is not True:
        raise Leak('bad nullable at ' + where)
    kind = s['t']
    if kind == 'object':
        keys = s.get('keys')
        if not isinstance(keys, dict) or set(s) - {'t', 'keys', 'optional', 'nullable'}:
            raise Leak('bad object at ' + where)
        for key, val in keys.items():
            if not isinstance(key, str) or not vocab.known(key):
                raise Leak('key name that is not a schema name at ' + where)
            check_shape(val, vocab, where + '.' + key)
        if not isinstance(s.get('optional', []), list) or not set(s.get('optional', [])) <= set(keys):
            raise Leak('bad optional at ' + where)
    elif kind == 'array':
        if set(s) - {'t', 'items', 'nullable'}:
            raise Leak('bad array at ' + where)
        if 'items' in s:
            check_shape(s['items'], vocab, where + '[]')
    elif kind == 'mixed':
        if set(s) - {'t', 'of', 'nullable'} or not isinstance(s.get('of'), list) or len(s['of']) < 2:
            raise Leak('bad mixed at ' + where)
        for part in s['of']:
            if not isinstance(part, dict) or part.get('t') in ('mixed', 'null', None):
                raise Leak('bad mixed part at ' + where)
            check_shape(part, vocab, where)
    elif set(s) - {'t', 'nullable'}:
        raise Leak('a scalar carries more than its type at ' + where)


def check_doc(doc, vocab):
    """Raise Leak unless the whole shape file holds no value."""
    if not isinstance(doc, dict) or not DOC_FIELDS <= set(doc) <= DOC_FIELDS | {'privileges'} or \
            doc['format'] != FORMAT:
        raise Leak('not a shape file')
    privs = doc.get('privileges', [])
    if not isinstance(privs, list) or any(p not in PRIVILEGES for p in privs) or privs != sorted(set(privs)):
        raise Leak('bad privileges')
    for name, entry in doc['endpoints'].items():
        method, _, template = name.partition(' ')
        if method != 'GET' or template not in vocab.templates:
            raise Leak('endpoint that is not a schema GET')
        if not isinstance(entry, dict) or not set(entry) <= ENTRY_FIELDS or not isinstance(entry.get('status'), int):
            raise Leak('bad entry for ' + template)
        if 'shape' in entry:
            check_shape(entry['shape'], vocab, template)
        for err in entry.get('errors', []):
            if set(err) != {'status', 'error'} or not isinstance(err['status'], int) or \
                    error_template(err['error'], vocab) != err['error']:
                raise Leak('error text that is not a template for ' + template)
    for skip in doc['skipped']:
        if set(skip) != {'endpoint', 'reason'} or skip['reason'] not in REASONS or \
                skip['endpoint'] not in vocab.templates:
            raise Leak('bad skip entry')
    for key, val in doc['inventory'].items():
        if key not in ('node', 'qemu', 'lxc', 'storage', 'pool') or not isinstance(val, int) or isinstance(val, bool):
            raise Leak('bad inventory entry')


def dump(doc, vocab, secrets=()):
    """The shape file text, after the self-check and a scan for the credentials."""
    check_doc(doc, vocab)
    text = json.dumps(doc, indent=1, sort_keys=True) + '\n'
    for secret in secrets:
        if secret and secret in text:
            raise Leak('a credential would be written')
    return text


# --------------------------------------------------------------------- client

def read_token(path):
    """The API token from a file. Nothing of the contents is ever put in a message."""
    try:
        with open(path, encoding='utf-8') as fh:
            token = fh.read().strip()
    except OSError:
        raise ToolError('cannot read the token file') from None
    if not TOKEN_RX.match(token):
        raise ToolError('the token file does not hold user@realm!id=secret')
    return token


class Result(object):
    def __init__(self, status, data=None, message=None, errors=None):
        self.status = status
        self.data = data
        self.message = message
        self.errors = errors


class Client(object):
    """GET-only PVE client."""

    def __init__(self, base, token, tls=None, timeout=20.0, limit=1500, concurrency=4):
        self.base = base.rstrip('/')
        self.token = token
        self.tls = tls
        self.timeout = timeout
        self.limit = limit
        self.sent = 0
        self.concurrency = concurrency
        self.session = None
        self.slots = None

    async def __aenter__(self):
        self.slots = asyncio.Semaphore(self.concurrency)
        tls = self.tls if self.tls is not None else ssl.create_default_context()
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=tls, limit=self.concurrency),
            timeout=aiohttp.ClientTimeout(total=self.timeout), headers={'Authorization': 'PVEAPIToken=' + self.token})
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    async def request(self, method, path):
        """Send one request. Anything but GET is refused before it is built."""
        if method != 'GET':
            raise ReadOnlyViolation('refusing {0}: this tool only sends GET'.format(str(method)[:10]))
        return await self._send('GET', path)

    async def _send(self, method, path, params=None):
        async with self.slots:
            if self.sent >= self.limit:
                raise CapReached()
            self.sent += 1
            query = params if method in ('GET', 'DELETE') else None
            form = params if method in ('POST', 'PUT') else None
            try:
                async with self.session.request(method, self.base + API + path, params=query, data=form,
                                                allow_redirects=False) as rsp:
                    raw = await rsp.content.read(MAX_BODY)
                    status, reason = rsp.status, rsp.reason
            except asyncio.TimeoutError:
                return Result(0, message='timeout')
            except (aiohttp.ClientError, OSError):
                return Result(0, message='network error')
        try:
            body = json.loads(raw.decode('utf-8'))
        except ValueError:
            return Result(status, message=None if status < 300 else (reason or 'non json'))
        if isinstance(body, dict):
            return Result(status, body.get('data'), body.get('message') or reason, body.get('errors'))
        return Result(status, body, reason)


# --------------------------------------------------------------------- walking

def skip_reason(template, info, include_rrd=False):
    """Why this GET is not sent, or None."""
    segs = [s for s in template.split('/') if s]
    if CONSOLE & set(segs):
        return 'console'
    if not include_rrd and {'rrd', 'rrddata'} & set(segs):
        return 'rrd'
    if 'aplinfo' in segs or 'download' in segs:
        return 'download'
    if 'scan' in segs or any(s.startswith('query-') for s in segs):
        return 'probe'
    if 'agent' in segs:
        return 'guest-agent'
    if 'report' in segs or 'file-restore' in segs:
        return 'heavy'
    if SIDE_EFFECT.search(((info.get('description') or '') + ' ' + (info.get('name') or '')).lower()):
        return 'side-effect'
    params = (info.get('parameters') or {}).get('properties', {})
    placeholders = set(s[1:-1] for s in segs if s.startswith('{'))
    if any(not p.get('optional') for n, p in params.items() if n not in placeholders):
        return 'required-param'
    return None


def item_ids(data, name):
    """Values of the path parameter `name` in a list answer."""
    keys = ITEM_KEYS.get(name) or [name, 'id', 'name']
    out = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict):
            val = next((item[k] for k in keys if isinstance(item.get(k), (str, int)) and item[k] != ''), None)
            if val is not None and str(val) not in out:
                out.append(str(val))
    return out


class Walker(object):
    def __init__(self, client, sch, vocab, per_param=2, k=5, include_rrd=False):
        self.client = client
        self.sch = sch
        self.vocab = vocab
        self.per_param = per_param
        self.k = k
        self.include_rrd = include_rrd
        self.cache = {}
        self.results = {}

    def get(self, path, template):
        if path not in self.cache:
            self.cache[path] = asyncio.ensure_future(self._fetch(path, template))
        return self.cache[path]

    async def _fetch(self, path, template):
        res = await self.client.request('GET', path)
        self.results.setdefault(template, []).append((path, res))
        return res

    async def concrete(self, template):
        """Up to per_param real paths for a template, found through the list endpoints above each parameter."""
        segs = [s for s in template.split('/') if s]
        out = []

        async def rec(i, prefix):
            if len(out) >= self.per_param:
                return
            if i == len(segs):
                out.append('/' + '/'.join(prefix))
                return
            seg = segs[i]
            if not seg.startswith('{'):
                return await rec(i + 1, prefix + [seg])
            parent = '/' + '/'.join(segs[:i])
            if parent not in self.vocab.templates:
                raise LookupError()
            res = await self.get('/' + '/'.join(prefix), parent)
            if not 200 <= res.status < 300:
                raise LookupError()
            for val in item_ids(res.data, seg[1:-1])[:self.per_param]:
                await rec(i + 1, prefix + [urllib.parse.quote(val, safe='')])
        await rec(0, [])
        if not out:
            raise LookupError()
        return out

    async def one(self, template):
        """Skip reason for the template, or None once it is recorded."""
        why = skip_reason(template, self.sch.paths[template]['GET'], self.include_rrd)
        if why:
            return why
        try:
            for path in await self.concrete(template):
                await self.get(path, template)
        except LookupError:
            return 'no-sample'
        except CapReached:
            return 'request-cap'
        return None

    async def run(self):
        templates = sorted(self.vocab.templates)
        skips = await asyncio.gather(*(self.one(t) for t in templates))
        doc = {'format': FORMAT, 'endpoints': {}, 'skipped': [], 'inventory': {}}
        for template, why in zip(templates, skips, strict=True):
            got = sorted(self.results.get(template, []), key=lambda pr: pr[0])
            if why and not got:
                doc['skipped'].append({'endpoint': template, 'reason': why})
            if got:
                doc['endpoints']['GET ' + template] = self.entry([res for _, res in got])
        doc['inventory'] = self.inventory()
        privs = self.privileges()
        if privs is not None:
            doc['privileges'] = privs
        return doc

    def privileges(self):
        """Names of the privileges the token holds anywhere, from GET /access/permissions; None if not answered."""
        found = [r for _, r in self.results.get(PERMISSIONS, []) if 200 <= r.status < 300 and isinstance(r.data, dict)]
        if not found:
            return None
        names = set()
        for held in found[0].data.values():
            if isinstance(held, dict):
                names.update(p for p, on in held.items() if p in PRIVILEGES and on)
        return sorted(names)

    def entry(self, results):
        good = [r for r in results if 200 <= r.status < 300]
        bad = [r for r in results if not 200 <= r.status < 300]
        entry = {'status': (good or bad)[0].status, 'samples': len(results)}
        if good:
            s = None
            for r in good:
                s = merge(s, shape(r.data, self.vocab.known, self.k))
            entry['shape'] = s
        errors = set((r.status, error_template(r.message, self.vocab)) for r in bad)
        if errors:
            entry['errors'] = [{'status': s, 'error': e} for s, e in sorted(errors)]
        return entry

    def inventory(self):
        """Counts of what the real PVE holds, from /cluster/resources; no names."""
        found = [r for _, r in self.results.get('/cluster/resources', []) if 200 <= r.status < 300]
        items = [i for i in (found[0].data if found else None) or [] if isinstance(i, dict)]
        inv = {}
        for kind in ('node', 'qemu', 'lxc', 'pool'):
            inv[kind] = sum(1 for i in items if i.get('type') == kind)
        pools = [r for _, r in self.results.get('/pools', []) if 200 <= r.status < 300]
        inv['pool'] = len(pools[0].data) if pools and isinstance(pools[0].data, list) else 0
        inv['storage'] = len(set(i.get('storage') for i in items if i.get('type') == 'storage'))
        return inv


async def record(client, sch=None, per_param=2, k=5, include_rrd=False):
    sch = sch or fschema.load()
    vocab = Vocab(sch)
    doc = await Walker(client, sch, vocab, per_param, k, include_rrd).run()
    return doc, vocab


# ----------------------------------------------------------------------- diff

def view(s):
    """Shape as a map of type -> part; integer and number are one type, null says nothing."""
    out = {}
    for p in parts(s):
        t = 'number' if p['t'] == 'integer' else p['t']
        if t != 'null':
            out[t] = p
    return out


def diff_shapes(real, fake, where, out):
    rv, fv = view(real), view(fake)
    if not rv or not fv:
        return
    # A value the real PVE sends as more than one type (a boolean here, a number there) matches any of them.
    if not set(fv) <= set(rv):
        out.append(('type', where, '{0} in real, {1} in fake'.format('/'.join(sorted(rv)), '/'.join(sorted(fv)))))
    for t in sorted(set(rv) & set(fv)):
        a, b = rv[t], fv[t]
        if t == 'object':
            for key in sorted(set(a['keys']) - set(b['keys'])):
                if key == KEY:
                    kind = 'undocumented'
                else:
                    kind = 'missing-optional' if key in a.get('optional', ()) else 'missing-key'
                out.append((kind, where + '.' + key, 'in real, not in fake'))
            for key in sorted(set(b['keys']) - set(a['keys'])):
                out.append(('undocumented' if key == KEY else 'extra-key', where + '.' + key,
                            'in fake, not in real'))
            for key in sorted(set(a['keys']) & set(b['keys'])):
                diff_shapes(a['keys'][key], b['keys'][key], where + '.' + key, out)
        elif t == 'array' and a.get('items') and b.get('items'):
            diff_shapes(a['items'], b['items'], where + '[]', out)


# Answers whose keys depend on what one object holds: a VM's config keys, the options of a storage type, the
# privileges of a role. Missing or extra keys there are not defects, apart from the top-level keys listed (always
# sent); None lists none.
VARIES = {
    '/nodes/{node}/qemu/{vmid}/config': ('digest',),
    '/nodes/{node}/lxc/{vmid}/config': ('digest',),
    '/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/config': ('snaptime', 'description'),
    '/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/config': ('snaptime', 'description'),
    '/storage': ('storage', 'type', 'content', 'digest'),
    '/storage/{storage}': ('storage', 'type', 'content', 'digest'),
    '/nodes/{node}/storage/{storage}/content': ('volid', 'content', 'format', 'size', 'ctime'),
    '/access/roles/{roleid}': None,
    '/access/permissions': None,
}
KEY_KINDS = ('missing-key', 'missing-optional', 'extra-key')
TOP_LEVEL = re.compile(r'^(\[\])?\.([^.\[\]]+)$')


def varies(name, kind, where):
    """True if the difference is a key that depends on the object (see VARIES)."""
    template = name.partition(' ')[2]
    if template not in VARIES or kind not in KEY_KINDS:
        return False
    keep = VARIES[template]
    if keep is None:
        return True
    m = TOP_LEVEL.match(where)
    return bool(m) and m.group(2) not in keep


def compare(real, fake, ignore_config_keys=True):
    """Differences between two shape files, as (method path, kind, where, detail)."""
    out = []
    for name in sorted(real['endpoints']):
        if name not in fake['endpoints']:
            out.append((name, 'unsampled', '', 'the fake could not be asked'))
            continue
        a, b = real['endpoints'][name], fake['endpoints'][name]
        found = []
        if a['status'] != b['status']:
            found.append(('status', '', '{0} in real, {1} in fake'.format(a['status'], b['status'])))
        elif 'shape' in a and 'shape' in b:
            diff_shapes(a['shape'], b['shape'], '', found)
        elif a.get('errors') != b.get('errors') and 'shape' not in a:
            found.append(('error-message', '', 'error text differs'))
        out.extend((name, 'config-dependent' if ignore_config_keys and varies(name, f[0], f[1]) else f[0]) + f[1:]
                   for f in found)
    return out


# Not counted: missing-optional (sent only sometimes) and undocumented (keys the schema does not name).
QUIET = ('unsampled', 'config-dependent', 'undocumented')
FATAL = ('status', 'missing-key', 'extra-key', 'type', 'error-message')


def report(real, fake, differences, write=print):
    both = [n for n in real['endpoints'] if n in fake['endpoints']]
    counts = {}
    for _, kind, _, _ in differences:
        counts[kind] = counts.get(kind, 0) + 1
    last = None
    for name, kind, where, detail in differences:
        if kind in QUIET:
            continue
        if name != last:
            write(name)
            last = name
        write('  {0}: {1} {2}'.format(kind, where or '(response)', detail).rstrip())
    write('compared {0} methods; {1} not sampled in the fake; {2} differences{3}'.format(
        len(both), counts.get('unsampled', 0), sum(v for k, v in counts.items() if k != 'unsampled'),
        ''.join('; {0} {1}'.format(v, k) for k, v in sorted(counts.items()) if k != 'unsampled')))
    if counts.get('config-dependent') or counts.get('undocumented'):
        write('not defects: {0} keys that depend on the object, {1} keys the schema does not name'.format(
            counts.get('config-dependent', 0), counts.get('undocumented', 0)))
    return sum(counts.get(k, 0) for k in FATAL)


# ------------------------------------------------------------------- the fake

def seed(pve, inv):
    """Give a FakePve the counts of an inventory: nodes, guests, storages and pools, with made-up names."""
    for n in range(2, max(inv.get('node', 1), 1) + 1):
        pve.add_node('pve{0}'.format(n))
    nodes = sorted(pve.nodes)
    for n in range(inv.get('qemu', 0)):
        pve.add_vm(100 + n, 'vm{0}'.format(n), node=nodes[n % len(nodes)],
                   status='running' if n % 2 == 0 else 'stopped',
                   config={'memory': 512, 'cores': 1, 'tags': 'example',
                           'scsi0': 'local:100/vm-100-disk-0.raw,size=8G'})
    for n in range(inv.get('lxc', 0)):
        pve.add_ct(200 + n, 'ct{0}'.format(n), node=nodes[n % len(nodes)],
                   status='running' if n % 2 == 0 else 'stopped', config={'tags': 'example'})
    want = inv.get('storage')
    if want is not None:
        for name in sorted(pve.storages)[want:]:
            del pve.storages[name]
        n = 0
        while len(pve.storages) < want:
            n += 1
            pve.storages['store{0}'.format(n)] = {'type': 'dir', 'active': 1, 'content': 'iso,backup', 'files': set(),
                                                  'path': '/srv/store{0}'.format(n)}
    for n in range(inv.get('pool', 0)):
        pve.pools['pool{0}'.format(n)] = set()
        pve.pool_info['pool{0}'.format(n)] = {'comment': 'Example pool', 'storage': set()}


def doc_privileges(doc):
    """The privilege names a shape file records: its `privileges`, else those in the shape of /access/permissions.

    None if neither is there, or the token holds every privilege (the fake then runs as root).
    """
    names = doc_privilege_names(doc)
    return None if names is None or set(PRIVILEGES) <= set(names) else names


def doc_privilege_names(doc):
    if 'privileges' in doc:
        return list(doc['privileges'])
    entry = doc['endpoints'].get('GET ' + PERMISSIONS)
    if not entry or 'shape' not in entry or entry['status'] != 200:
        return None
    names = set()
    for part in view(entry['shape']).get('object', {}).get('keys', {}).values():
        for sub in view(part).get('object', {}).get('keys', {}):
            if sub in PRIVILEGES:
                names.add(sub)
    return sorted(names)


class Fake(object):
    """An in-process fakepve on loopback, with one API token.

    With `privileges` (names) the token belongs to a user that holds exactly those on `/`, so a 403 for a
    method comes out as on a real PVE with a narrow role; without, the token is root@pam's.
    """

    SECRET = '00000000-0000-4000-8000-000000000000'
    USER = 'compare@pve'
    TOKEN = 'root@pam!compare=' + SECRET

    def __init__(self, inv=None, privileges=None):
        self.inv = inv or {}
        self.privileges = privileges
        self.pve = None
        self.tmp = None
        self.token = self.TOKEN if privileges is None else '{0}!compare={1}'.format(self.USER, self.SECRET)

    @staticmethod
    def make_pve():
        from fakepve import FakePve
        return FakePve(host='127.0.0.1', port=0)

    async def __aenter__(self):
        try:
            from fakepve.certs import make_cert
        except ImportError:
            raise ToolError('the in-process fake needs the cryptography package') from None
        self.tmp = tempfile.TemporaryDirectory(prefix='fakepve-compare-')
        self.pve = self.make_pve()
        self.pve.apitokens[self.token.partition('=')[0]] = self.SECRET
        if self.privileges is not None:
            self.pve.grant(self.USER, '/', *self.privileges)
        seed(self.pve, self.inv)
        cert, key, _ = make_cert(self.tmp.name)
        await self.pve.start(cert, key)
        await self.seed_more()
        return self

    async def seed_more(self):
        """What the counts do not give: a finished task and a file in a storage that takes ISOs."""
        node = sorted(self.pve.nodes)[0]

        async def body():
            return None
        await self.pve.task(node, 'vzdump', 100, self.token.partition('=')[0], body)
        for name, store in sorted(self.pve.storages.items()):
            if 'iso' in str(store.get('content', '')):
                self.pve.store_file(name, 'example.iso', 1048576)
                break

    async def __aexit__(self, *exc):
        from fakepve import settle
        await settle()
        await self.pve.stop()
        self.tmp.cleanup()


async def record_fake(inv, per_param=2, k=5, include_rrd=False, limit=1500, privileges=None):
    async with Fake(inv, privileges) as fake:
        async with Client(fake.pve.url, fake.token, tls=False, limit=limit) as client:
            return await record(client, per_param=per_param, k=k, include_rrd=include_rrd)


async def self_test(write=print):
    """Record a seeded fake, record a second one seeded from the first file, expect no difference."""
    inv = {'node': 2, 'qemu': 3, 'lxc': 2, 'storage': 3, 'pool': 1}
    first, vocab = await record_fake(inv)
    text = dump(first, vocab, [Fake.TOKEN, Fake.SECRET])
    first = json.loads(text)
    second, _ = await record_fake(first['inventory'])
    second = json.loads(dump(second, vocab))
    found = compare(first, second)
    report(first, second, found, write)
    write('self-test: {0} methods recorded, {1} differences'.format(len(first['endpoints']),
                                                                    sum(1 for d in found if d[1] in FATAL)))
    return sum(1 for d in found if d[1] in FATAL)


# ------------------------------------------------------- scenario (phase 2, writes)

SCN_FORMAT = 1
PREFIX = 'fpcmp-'
RESERVED = range(9900, 10000)
STORE = 'fpcmp-dir'
POOL = 'fpcmp-pool'
STORE_PATH = '/var/lib/fpcmp-dir'
IDS = {'vm': 9900, 'vm2': 9901, 'vm3': 9902, 'vmx': 9909, 'ct': 9910, 'ct2': 9911}
SNAP = 'fpcmp-snap'
UPID_RX = re.compile(r'^UPID:[^:]+:[0-9A-F]{8}:[0-9A-F]{8}:[0-9A-F]{8}:')
DISK_KEY = re.compile(r'^((scsi|ide|sata|virtio|unused|mp)\d+|efidisk0|tpmstate0|rootfs|ostemplate|storage|'
                      r'targetstorage)$')
NOTES = ('no-template',)
SCN_FIELDS = {'step', 'skipped', 'status', 'shape', 'error', 'errors', 'task'}
BAD_DIGEST = '0' * 40


class ScopeViolation(ToolError):
    """A write to something this tool did not create."""


class CleanupFailed(ToolError):
    """Objects of the reserved range are still there after the clean-up."""


def reserved(value, invalid_ok=False):
    """True if a vmid is in the reserved range; with invalid_ok also one PVE always rejects (so nothing is made)."""
    if not re.fullmatch(r'[0-9]{1,12}', str(value)):
        return invalid_ok
    n = int(str(value))
    return n in RESERVED or (invalid_ok and not 100 <= n <= 999999999)


class ScopeGuard(object):
    """Every write is checked here, before a request is built: only the objects of the reserved set pass."""

    def __init__(self, node):
        self.node = node
        self.started = set()

    def refuse(self, why):
        raise ScopeViolation('refusing a write outside the reserved objects ({0})'.format(why))

    def check(self, method, path, params=None):
        if method == 'GET':
            return
        if method not in ('POST', 'PUT', 'DELETE'):
            raise ReadOnlyViolation('refusing {0}'.format(str(method)[:10]))
        params = params or {}
        raw = path.partition('?')[0]
        segs = [urllib.parse.unquote(s) for s in raw.strip('/').split('/')]
        if not raw.startswith('/') or any(s in ('', '.', '..') or '/' in s or '\\' in s for s in segs):
            self.refuse('path')
        top = segs[0]
        if top == 'storage':
            if (segs[1] if len(segs) > 1 else params.get('storage')) != STORE or len(segs) > 2:
                self.refuse('storage')
        elif top == 'pools':
            name = segs[1] if len(segs) > 1 else params.get('poolid')
            if not str(name).startswith(PREFIX) or len(segs) > 2:
                self.refuse('pool')
            if not all(reserved(v) for v in str(params.get('vms', '')).split(',') if v):
                self.refuse('pool member')
        elif top == 'nodes' and len(segs) > 2 and segs[1] == self.node:
            self.check_node(method, segs[2:], params)
        else:
            self.refuse('path')
        for key, val in params.items():
            if DISK_KEY.match(key) and str(val).partition(':')[0] not in (STORE, 'none', 'cloudinit'):
                self.refuse('volume')

    def check_node(self, method, segs, params):
        kind = segs[0]
        if kind in ('qemu', 'lxc'):
            if len(segs) == 1:
                if not reserved(params.get('vmid'), invalid_ok=True):
                    self.refuse('vmid')
            elif not reserved(segs[1]):
                self.refuse('vmid')
            elif segs[2:3] == ['clone'] and not reserved(params.get('newid'), invalid_ok=True):
                self.refuse('newid')
        elif kind == 'aplinfo':
            if params.get('storage') != STORE:
                self.refuse('storage')
        elif kind == 'tasks':
            if method != 'DELETE' or len(segs) != 2 or segs[1] not in self.started:
                self.refuse('task')
        elif kind == 'storage':
            if len(segs) < 2 or segs[1] != STORE:
                self.refuse('storage')
        else:
            self.refuse('path')


class WriteClient(Client):
    """Client that may write, but only inside the ScopeGuard."""

    def __init__(self, base, token, node, tls=None, timeout=60.0, limit=800, concurrency=1):
        super().__init__(base, token, tls, timeout, limit, concurrency)
        self.guard = ScopeGuard(node)

    async def request(self, method, path, params=None):
        self.guard.check(method, path, params)
        return await self._send(method, path, params)


def step(name, method, path, params=None, group='qemu', **opts):
    return dict(opts, name=name, method=method, path=path, params=params or {}, group=group)


Q = '/nodes/{node}/qemu'
L = '/nodes/{node}/lxc'
VM = Q + '/{vm}'
CT = L + '/{ct}'
DISK = '{store}:1,format=qcow2'
RULES = VM + '/firewall/rules'
LX = {'group': 'lxc', 'needs': 'template'}

# The scenario: one dict per step. A path or a string parameter may use {node} {store} {pool} {snap} {dir}
# {template} and the ids {vm} {vm2} {vm3} {vmx} {ct} {ct2}. A step is a request; the answer is recorded, and a
# task it starts is waited for. Steps run in this order; add one by appending a step() call.
STEPS = [
    step('storage-add', 'POST', '/storage', {'storage': '{store}', 'type': 'dir', 'path': '{dir}',
                                              'content': 'images,rootdir,vztmpl,iso', 'nodes': '{node}'}, 'storage'),
    step('storage-add-again', 'POST', '/storage', {'storage': '{store}', 'type': 'dir', 'path': '{dir}'}, 'storage'),
    step('storage-add-bad-type', 'POST', '/storage', {'storage': '{store}', 'type': 'nope'}, 'storage'),
    step('storage-add-bad-content', 'POST', '/storage', {'storage': '{store}', 'type': 'dir', 'path': '{dir}',
                                                         'content': 'nonsense'}, 'storage'),
    step('storage-get', 'GET', '/storage/{store}', group='storage'),
    step('storage-get-missing', 'GET', '/storage/fpcmp-missing', group='storage'),
    step('storage-status', 'GET', '/nodes/{node}/storage/{store}/status', group='storage', varies=True),
    step('storage-update', 'PUT', '/storage/{store}', {'content': 'images,rootdir,vztmpl'}, 'storage'),
    step('storage-update-bad-content', 'PUT', '/storage/{store}', {'content': 'nonsense'}, 'storage'),
    step('storage-update-unknown-key', 'PUT', '/storage/{store}', {'nosuchkey': 1}, 'storage'),
    step('storage-update-digest', 'PUT', '/storage/{store}', {'digest': BAD_DIGEST, 'content': 'images'}, 'storage'),

    step('vm-create', 'POST', Q, {'vmid': '{vm}', 'name': 'fpcmp-vm', 'memory': 128, 'cores': 1, 'kvm': 0,
                                  'ostype': 'l26', 'scsihw': 'virtio-scsi-pci', 'scsi0': DISK}),
    step('vm-create-again', 'POST', Q, {'vmid': '{vm}', 'name': 'fpcmp-vm'}),
    step('vm-create-bad-vmid', 'POST', Q, {'vmid': 99, 'name': 'fpcmp-vm'}),
    step('vm-create-bad-name', 'POST', Q, {'vmid': '{vmx}', 'name': 'fpcmp bad_name!'}),
    step('vm-create-bad-enum', 'POST', Q, {'vmid': '{vmx}', 'name': 'fpcmp-vmx', 'ostype': 'nope'}),
    step('vm-create-unknown-key', 'POST', Q, {'vmid': '{vmx}', 'name': 'fpcmp-vmx', 'nosuchkey': 1}),
    step('vm-create-bad-property-string', 'POST', Q, {'vmid': '{vmx}', 'name': 'fpcmp-vmx', 'net0': 'virtio=zz'}),
    step('vm-config-get', 'GET', VM + '/config', varies=True),
    step('vm-config-get-missing', 'GET', Q + '/{vmx}/config'),
    step('vm-config-put', 'PUT', VM + '/config', {'description': 'fpcmp', 'tags': 'fpcmp', 'memory': 192,
                                                  'cores': 2}),
    step('vm-pending', 'GET', VM + '/pending', varies=True),
    step('vm-config-put-bad-enum', 'PUT', VM + '/config', {'ostype': 'nope'}),
    step('vm-config-put-bad-property-string', 'PUT', VM + '/config', {'net0': 'virtio=zz'}),
    step('vm-config-put-out-of-range', 'PUT', VM + '/config', {'cores': 0}),
    step('vm-config-put-bad-type', 'PUT', VM + '/config', {'memory': 'lots'}),
    step('vm-config-put-unknown-key', 'PUT', VM + '/config', {'nosuchkey': 1}),
    step('vm-config-put-digest', 'PUT', VM + '/config', {'digest': BAD_DIGEST, 'description': 'other'}),
    step('vm-start', 'POST', VM + '/status/start'),
    step('vm-status', 'GET', VM + '/status/current', varies=True),
    step('vm-start-again', 'POST', VM + '/status/start'),
    step('vm-config-put-running', 'PUT', VM + '/config', {'memory': 160}),
    step('vm-pending-running', 'GET', VM + '/pending', varies=True),
    step('vm-stop', 'POST', VM + '/status/stop'),
    step('vm-stop-again', 'POST', VM + '/status/stop'),
    step('vm-snapshot-create', 'POST', VM + '/snapshot', {'snapname': '{snap}', 'description': 'fpcmp'}),
    step('vm-snapshot-list', 'GET', VM + '/snapshot', varies=True),
    step('vm-snapshot-reuse', 'POST', VM + '/snapshot', {'snapname': '{snap}'}),
    step('vm-snapshot-bad-name', 'POST', VM + '/snapshot', {'snapname': '1 bad name'}),
    step('vm-snapshot-delete', 'DELETE', VM + '/snapshot/{snap}'),
    step('vm-snapshot-delete-missing', 'DELETE', VM + '/snapshot/{snap}'),
    step('vm-clone', 'POST', VM + '/clone', {'newid': '{vm2}', 'name': 'fpcmp-clone', 'full': 1}),
    step('vm-clone-id-in-use', 'POST', VM + '/clone', {'newid': '{vm2}', 'name': 'fpcmp-clone'}),
    step('vm-clone-bad-newid', 'POST', VM + '/clone', {'newid': 99, 'name': 'fpcmp-clone'}),
    step('vm-template', 'POST', Q + '/{vm2}/template'),
    step('vm-template-again', 'POST', Q + '/{vm2}/template'),
    step('vm-template-start', 'POST', Q + '/{vm2}/status/start'),
    step('vm-template-clone', 'POST', Q + '/{vm2}/clone', {'newid': '{vm3}', 'name': 'fpcmp-lclone'}),

    step('pool-create', 'POST', '/pools', {'poolid': '{pool}', 'comment': 'fpcmp'}, 'pool'),
    step('pool-create-again', 'POST', '/pools', {'poolid': '{pool}'}, 'pool'),
    step('pool-create-bad-name', 'POST', '/pools', {'poolid': 'fpcmp-bad name'}, 'pool'),
    step('pool-add-member', 'PUT', '/pools/{pool}', {'vms': '{vm}'}, 'pool'),
    step('pool-get', 'GET', '/pools/{pool}', group='pool', varies=True),
    step('pool-add-missing-member', 'PUT', '/pools/{pool}', {'vms': '{vmx}'}, 'pool'),
    step('pool-delete-not-empty', 'DELETE', '/pools/{pool}', group='pool'),
    step('pool-remove-member', 'PUT', '/pools/{pool}', {'vms': '{vm}', 'delete': 1}, 'pool'),
    step('pool-remove-member-again', 'PUT', '/pools/{pool}', {'vms': '{vm}', 'delete': 1}, 'pool'),
    step('pool-delete', 'DELETE', '/pools/{pool}', group='pool'),
    step('pool-delete-again', 'DELETE', '/pools/{pool}', group='pool'),

    step('fw-rule-add', 'POST', RULES, {'type': 'in', 'action': 'ACCEPT', 'enable': 0, 'proto': 'tcp',
                                        'dport': '22', 'comment': 'fpcmp'}, 'firewall'),
    step('fw-rule-add-second', 'POST', RULES, {'type': 'in', 'action': 'DROP', 'enable': 0}, 'firewall'),
    step('fw-rule-add-bad-action', 'POST', RULES, {'type': 'in', 'action': 'MAYBE'}, 'firewall'),
    step('fw-rule-add-bad-port', 'POST', RULES, {'type': 'in', 'action': 'ACCEPT', 'proto': 'tcp', 'dport': 'http!'},
         'firewall'),
    step('fw-rule-list', 'GET', RULES, group='firewall', varies=True),
    step('fw-rule-move', 'PUT', RULES + '/1', {'moveto': 0}, 'firewall'),
    step('fw-rule-get', 'GET', RULES + '/0', group='firewall', varies=True),
    step('fw-rule-delete', 'DELETE', RULES + '/0', group='firewall'),
    step('fw-rule-delete-again', 'DELETE', RULES + '/0', group='firewall'),
    step('fw-rule-delete-missing', 'DELETE', RULES + '/7', group='firewall'),

    step('vm-lclone-destroy', 'DELETE', Q + '/{vm3}', {'purge': 1, 'destroy-unreferenced-disks': 1}),
    step('vm-template-destroy', 'DELETE', Q + '/{vm2}', {'purge': 1, 'destroy-unreferenced-disks': 1}),
    step('vm-protect', 'PUT', VM + '/config', {'protection': 1}),
    step('vm-destroy-protected', 'DELETE', VM),
    step('vm-unprotect', 'PUT', VM + '/config', {'protection': 0}),
    step('vm-start-second', 'POST', VM + '/status/start'),
    step('vm-destroy-running', 'DELETE', VM),
    step('vm-stop-second', 'POST', VM + '/status/stop'),
    step('vm-destroy', 'DELETE', VM, {'purge': 1, 'destroy-unreferenced-disks': 1}),
    step('vm-destroy-again', 'DELETE', VM),

    step('apl-list', 'GET', '/nodes/{node}/aplinfo', group='lxc', hook='pick_template', varies=True),
    step('apl-download', 'POST', '/nodes/{node}/aplinfo', {'storage': '{store}', 'template': '{template}'},
         hook='downloaded', **LX),
    step('ct-create', 'POST', L, {'vmid': '{ct}', 'hostname': 'fpcmp-ct', 'ostemplate': '{store}:vztmpl/{template}',
                                  'rootfs': '{store}:1', 'memory': 128, 'swap': 0, 'cores': 1, 'unprivileged': 1,
                                  'start': 0}, **LX),
    step('ct-create-again', 'POST', L, {'vmid': '{ct}', 'hostname': 'fpcmp-ct',
                                        'ostemplate': '{store}:vztmpl/{template}'}, **LX),
    step('ct-create-bad-vmid', 'POST', L, {'vmid': 99, 'hostname': 'fpcmp-ct',
                                           'ostemplate': '{store}:vztmpl/{template}'}, **LX),
    step('ct-create-bad-name', 'POST', L, {'vmid': '{vmx}', 'hostname': 'fpcmp bad_name!',
                                           'ostemplate': '{store}:vztmpl/{template}'}, **LX),
    step('ct-config-get', 'GET', CT + '/config', varies=True, **LX),
    step('ct-config-get-missing', 'GET', L + '/{vmx}/config', **LX),
    step('ct-config-put', 'PUT', CT + '/config', {'description': 'fpcmp', 'memory': 192}, **LX),
    step('ct-config-put-bad-enum', 'PUT', CT + '/config', {'ostype': 'nope'}, **LX),
    step('ct-config-put-bad-property-string', 'PUT', CT + '/config', {'net0': 'name=eth0,bridge='}, **LX),
    step('ct-config-put-out-of-range', 'PUT', CT + '/config', {'cores': 0}, **LX),
    step('ct-config-put-unknown-key', 'PUT', CT + '/config', {'nosuchkey': 1}, **LX),
    step('ct-config-put-digest', 'PUT', CT + '/config', {'digest': BAD_DIGEST, 'description': 'other'}, **LX),
    step('ct-start', 'POST', CT + '/status/start', **LX),
    step('ct-start-again', 'POST', CT + '/status/start', **LX),
    step('ct-stop', 'POST', CT + '/status/stop', **LX),
    step('ct-stop-again', 'POST', CT + '/status/stop', **LX),
    step('ct-snapshot-create', 'POST', CT + '/snapshot', {'snapname': '{snap}', 'description': 'fpcmp'}, **LX),
    step('ct-snapshot-list', 'GET', CT + '/snapshot', varies=True, **LX),
    step('ct-snapshot-reuse', 'POST', CT + '/snapshot', {'snapname': '{snap}'}, **LX),
    step('ct-snapshot-delete', 'DELETE', CT + '/snapshot/{snap}', **LX),
    step('ct-snapshot-delete-missing', 'DELETE', CT + '/snapshot/{snap}', **LX),
    step('ct-clone', 'POST', CT + '/clone', {'newid': '{ct2}', 'hostname': 'fpcmp-ctclone', 'full': 1}, **LX),
    step('ct-clone-id-in-use', 'POST', CT + '/clone', {'newid': '{ct2}'}, **LX),
    step('ct-template', 'POST', L + '/{ct2}/template', **LX),
    step('ct-template-start', 'POST', L + '/{ct2}/status/start', **LX),
    step('ct-template-destroy', 'DELETE', L + '/{ct2}', {'purge': 1, 'destroy-unreferenced-disks': 1}, **LX),
    step('ct-protect', 'PUT', CT + '/config', {'protection': 1}, **LX),
    step('ct-destroy-protected', 'DELETE', CT, **LX),
    step('ct-unprotect', 'PUT', CT + '/config', {'protection': 0}, **LX),
    step('ct-start-second', 'POST', CT + '/status/start', **LX),
    step('ct-destroy-running', 'DELETE', CT, **LX),
    step('ct-stop-second', 'POST', CT + '/status/stop', **LX),
    step('ct-destroy', 'DELETE', CT, {'purge': 1, 'destroy-unreferenced-disks': 1}, **LX),
    step('ct-destroy-again', 'DELETE', CT, **LX),

    step('storage-delete', 'DELETE', '/storage/{store}', group='storage'),
    step('storage-delete-again', 'DELETE', '/storage/{store}', group='storage'),
]
STEP_NAMES = frozenset(s['name'] for s in STEPS)
GROUPS = ('storage', 'qemu', 'pool', 'firewall', 'lxc')


def pick_template(data):
    """The newest small Alpine container template of the appliance index, or None."""
    names = [d['template'] for d in data if isinstance(d, dict) and d.get('type') == 'lxc' and
             isinstance(d.get('template'), str) and str(d.get('package', '')).startswith('alpine-')]
    return max(names) if names else None


class Scenario(object):
    """Runs STEPS against one node through a WriteClient and cleans up after itself, also on failure."""

    def __init__(self, client, node, vocab, steps=None, groups=None, allow_existing=False, poll=1.0,
                 task_timeout=300.0, names=()):
        self.client = client
        self.node = node
        self.vocab = vocab
        self.steps = STEPS if steps is None else steps
        self.groups = groups
        self.allow_existing = allow_existing
        self.poll = poll
        self.task_timeout = task_timeout
        self.names = [node] + [n for n in names if n]
        self.ctx = dict(IDS, node=node, store=STORE, pool=POOL, snap=SNAP, dir=STORE_PATH)
        self.notes = []
        self.N = '/nodes/' + node

    # ------------------------------------------------------------ recording

    def text(self, message):
        """A message as a template: our own node and template names go first, then only schema words stay."""
        message = str(message or '')
        for name in sorted(self.names + [str(self.ctx.get('template') or '')], key=len, reverse=True):
            if name:
                message = re.sub(r'(?<![A-Za-z0-9])' + re.escape(name) + r'(?![A-Za-z0-9])', '0', message,
                                 flags=re.IGNORECASE)
        return error_template(message, self.vocab)

    def fill(self, value):
        return value.format_map(self.ctx) if isinstance(value, str) else value

    def entry(self, name, res):
        out = {'step': name, 'status': res.status}
        if 200 <= res.status < 300:
            out['shape'] = shape(res.data, self.vocab.known)
        else:
            out['error'] = self.text(res.message)
            if isinstance(res.errors, dict) and res.errors:
                keys = {}
                for key, msg in sorted(res.errors.items()):
                    keys.setdefault(str(key) if self.vocab.known(str(key)) else KEY, self.text(msg))
                out['errors'] = keys
        return out

    async def wait(self, upid):
        """Poll a task to its end; the exit status and the last log line as templates."""
        quoted = urllib.parse.quote(upid, safe='')
        path = '{0}/tasks/{1}'.format(self.N, quoted)
        self.client.guard.started.add(upid)
        waited = 0.0
        status = None
        while waited <= self.task_timeout:
            res = await self.client.request('GET', path + '/status')
            status = res.data if 200 <= res.status < 300 and isinstance(res.data, dict) else {}
            if status.get('status') == 'stopped':
                break
            await asyncio.sleep(self.poll)
            waited += self.poll
        else:
            await self.client.request('DELETE', path)
            return {'exitstatus': 'timeout', 'log': 'timeout'}
        log = await self.client.request('GET', path + '/log', {'start': 0, 'limit': 10000})
        lines = [x for x in (log.data if isinstance(log.data, list) else []) if isinstance(x, dict)]
        last = max(lines, key=lambda x: x.get('n') or 0).get('t') if lines else None
        exit_ = status.get('exitstatus')
        return {'exitstatus': 'OK' if exit_ == 'OK' else self.text(exit_), 'log': self.text(last)}

    async def execute(self, spec):
        name = spec['name']
        need = spec.get('needs')
        if need and not self.ctx.get(need):
            if 'no-' + need not in self.notes:
                self.notes.append('no-' + need)
            return {'step': name, 'skipped': 'no-' + need}
        params = dict((k, self.fill(v)) for k, v in spec['params'].items())
        res = await self.client.request(spec['method'], self.fill(spec['path']), params)
        if res.status == 0:
            raise ToolError('a request to the target failed ({0})'.format(res.message))
        out = self.entry(name, res)
        if 200 <= res.status < 300 and isinstance(res.data, str) and UPID_RX.match(res.data):
            out['task'] = await self.wait(res.data)
        if spec.get('hook'):
            getattr(self, 'hook_' + spec['hook'])(res, out)
        return out

    def hook_pick_template(self, res, _out):
        self.ctx['template'] = pick_template(res.data) if isinstance(res.data, list) else None

    def hook_downloaded(self, _res, out):
        if out.get('status') != 200 or out.get('task', {}).get('exitstatus') != 'OK':
            self.ctx['template'] = None

    # --------------------------------------------------------------- the run

    async def listing(self, path, key):
        res = await self.client.request('GET', path)
        data = res.data if 200 <= res.status < 300 and isinstance(res.data, list) else None
        return None if data is None else [x for x in data if isinstance(x, dict) and key in x]

    async def preflight(self):
        """Refuse unless the target is a single node, empty of guests and of our names."""
        nodes = await self.listing('/nodes', 'node')
        if nodes is None:
            raise ToolError('refusing: cannot list the nodes of the target')
        if len(nodes) != 1:
            raise ToolError('refusing: the target must be a single node, it lists {0}'.format(len(nodes)))
        if nodes[0]['node'] != self.node:
            raise ToolError('refusing: --disposable-node does not match the only node of the target')
        guests = await self.listing('/cluster/resources?type=vm', 'vmid')
        if guests is None:
            raise ToolError('refusing: cannot list the guests of the target')
        if any(reserved(g['vmid']) for g in guests):
            raise ToolError('refusing: a guest already holds an id of the reserved range 9900-9999')
        if guests and not self.allow_existing:
            raise ToolError('refusing: the target holds {0} guests this tool did not create '
                            '(--allow-existing-guests)'.format(len(guests)))
        stores = await self.listing('/storage', 'storage')
        pools = await self.listing('/pools', 'poolid')
        if stores is None or pools is None:
            raise ToolError('refusing: cannot list the storages and pools of the target')
        if any(x['storage'].startswith(PREFIX) for x in stores) or any(x['poolid'].startswith(PREFIX) for x in pools):
            raise ToolError('refusing: objects named fpcmp-* are already there (an earlier run?)')

    async def run(self):
        await self.preflight()
        results = []
        try:
            for spec in self.steps:
                if self.groups is None or spec['group'] in self.groups:
                    results.append(await self.execute(spec))
        finally:
            await self.cleanup()
        return {'format': SCN_FORMAT, 'kind': 'scenario', 'steps': results, 'notes': sorted(self.notes)}

    # -------------------------------------------------------------- clean-up

    async def ours(self):
        """(kind, vmid) of the guests in the reserved range that carry our prefix; None for a kind that fails."""
        found = []
        for kind in ('lxc', 'qemu'):
            data = await self.listing('{0}/{1}'.format(self.N, kind), 'vmid')
            for g in data or []:
                if reserved(g['vmid']) and str(g.get('name', '')).startswith(PREFIX):
                    found.append((kind, int(g['vmid'])))
        return sorted(found, key=lambda kv: kv[1], reverse=True)

    async def settle(self, res):
        if 200 <= res.status < 300 and isinstance(res.data, str) and UPID_RX.match(res.data):
            await self.wait(res.data)

    async def destroy(self, kind, vmid):
        c = self.client
        base = '{0}/{1}/{2}'.format(self.N, kind, vmid)
        cfg = await c.request('GET', base + '/config')
        if isinstance(cfg.data, dict) and cfg.data.get('protection'):
            await c.request('PUT', base + '/config', {'protection': 0})
        cur = await c.request('GET', base + '/status/current')
        if isinstance(cur.data, dict) and cur.data.get('status') == 'running':
            await self.settle(await c.request('POST', base + '/status/stop'))
        snaps = await c.request('GET', base + '/snapshot')
        for snap in snaps.data if isinstance(snaps.data, list) else []:
            if isinstance(snap, dict) and snap.get('name') not in (None, 'current'):
                await self.settle(await c.request('DELETE', '{0}/snapshot/{1}'.format(
                    base, urllib.parse.quote(str(snap['name']), safe='')), {'force': 1}))
        await self.settle(await c.request('DELETE', base, {'purge': 1, 'destroy-unreferenced-disks': 1}))

    async def drop_pool(self, poolid):
        c = self.client
        quoted = urllib.parse.quote(poolid, safe='')
        info = await c.request('GET', '/pools/' + quoted)
        members = info.data.get('members') if isinstance(info.data, dict) else None
        vms = [str(m['vmid']) for m in members or [] if isinstance(m, dict) and m.get('vmid') is not None]
        stores = [str(m['storage']) for m in members or [] if isinstance(m, dict) and m.get('storage') and
                  m.get('vmid') is None]
        if vms:
            await c.request('PUT', '/pools/' + quoted, {'vms': ','.join(vms), 'delete': 1})
        if stores:
            await c.request('PUT', '/pools/' + quoted, {'storage': ','.join(stores), 'delete': 1})
        await c.request('DELETE', '/pools/' + quoted)

    async def cleanup(self):
        """Destroy what the run made, then check nothing of the reserved set is left. Raises CleanupFailed."""
        self.client.limit += 600
        for kind, vmid in await self.ours():
            await self.attempt(self.destroy(kind, vmid))
        for pool in await self.listing('/pools', 'poolid') or []:
            if pool['poolid'].startswith(PREFIX):
                await self.attempt(self.drop_pool(pool['poolid']))
        for store in await self.listing('/storage', 'storage') or []:
            if store['storage'] == STORE:
                await self.attempt(self.client.request('DELETE', '/storage/' + STORE))
        left = len(await self.ours())
        left += sum(1 for x in await self.listing('/pools', 'poolid') or [] if x['poolid'].startswith(PREFIX))
        left += sum(1 for x in await self.listing('/storage', 'storage') or [] if x['storage'].startswith(PREFIX))
        if left:
            raise CleanupFailed('clean-up incomplete: {0} fpcmp-* objects remain on the target'.format(left))

    @staticmethod
    async def attempt(coro):
        try:
            await coro
        except (ToolError, CapReached):
            pass


# ---------------------------------------------------- the scenario file, checked

def check_scenario(doc, vocab):
    """Raise Leak unless the scenario file holds only statuses, types, key names and templates."""
    if not isinstance(doc, dict) or set(doc) != {'format', 'kind', 'steps', 'notes'} or \
            doc['format'] != SCN_FORMAT or doc['kind'] != 'scenario':
        raise Leak('not a scenario file')
    if not isinstance(doc['notes'], list) or not set(doc['notes']) <= set(NOTES):
        raise Leak('bad notes')

    def template(text, where):
        if not isinstance(text, str) or error_template(text, vocab) != text:
            raise Leak('text that is not a template at ' + where)
    for item in doc['steps']:
        name = item.get('step') if isinstance(item, dict) else None
        if name not in STEP_NAMES or not set(item) <= SCN_FIELDS:
            raise Leak('bad step entry')
        if 'skipped' in item:
            if set(item) != {'step', 'skipped'} or item['skipped'] not in NOTES:
                raise Leak('bad skip at ' + name)
            continue
        status = item.get('status')
        if not isinstance(status, int) or isinstance(status, bool) or not 0 <= status < 600:
            raise Leak('bad status at ' + name)
        if 'shape' in item:
            check_shape(item['shape'], vocab, name)
        if 'error' in item:
            template(item['error'], name)
        if 'errors' in item:
            if not isinstance(item['errors'], dict):
                raise Leak('bad errors at ' + name)
            for key, text in item['errors'].items():
                if not isinstance(key, str) or not vocab.known(key):
                    raise Leak('field name that is not a schema name at ' + name)
                template(text, name)
        if 'task' in item:
            task = item['task']
            if not isinstance(task, dict) or set(task) != {'exitstatus', 'log'}:
                raise Leak('bad task at ' + name)
            template(task['exitstatus'], name)
            template(task['log'], name)


def dump_scenario(doc, vocab, secrets=(), names=()):
    """The scenario file text, after the check, a scan for credentials and a scan for the target's names."""
    check_scenario(doc, vocab)
    text = json.dumps(doc, indent=1, sort_keys=True) + '\n'
    for secret in secrets:
        if secret and secret in text:
            raise Leak('a credential would be written')
    for name in names:
        if name and re.search(r'(?<![A-Za-z0-9])' + re.escape(name) + r'(?![A-Za-z0-9])', text, re.IGNORECASE):
            raise Leak('a name of the target would be written')
    return text


def load_scenario(path):
    try:
        with open(path, encoding='utf-8') as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        raise ToolError('cannot read the scenario file') from None
    check_scenario(doc, Vocab(fschema.load()))
    return doc


# ------------------------------------------------------ scenario against a fake

def scenario_fake(template=True):
    """A Fake whose node serves the appliance index (one Alpine template), which the generic answer lacks.

    Without `template` the index is empty (null), as on a node that cannot reach the appliance servers: the
    container steps are then skipped, as in a recording made there."""
    from fakepve import FakePve

    class ApplianceFake(FakePve):
        TEMPLATE = 'alpine-3.20-default_20240908_amd64.tar.xz'

        def _routes_aplinfo(self):
            path = '/nodes/{node}/aplinfo'
            return [('GET', path, self._apl_list), ('POST', path, self._apl_download)]

        async def _apl_list(self, _values, _user):
            if not template:
                return None
            return [{'template': self.TEMPLATE, 'package': 'alpine-3.20-default', 'type': 'lxc', 'section': 'system',
                     'os': 'alpine-3.20', 'headline': 'Alpine Linux', 'version': '3.20',
                     'description': 'Example appliance.', 'infopage': 'https://example.org/', 'location': 'x'}]

        async def _apl_download(self, values, user):
            async def body():
                self.store_file(values['storage'], values['template'], 1048576, 'vztmpl')
            return await self.task(values['node'], 'download', values['storage'], user, body)

    class ScenarioFake(Fake):
        @staticmethod
        def make_pve():
            return ApplianceFake(host='127.0.0.1', port=0)

        async def seed_more(self):
            pass
    return ScenarioFake({'node': 1})


async def scenario_on_fake(vocab=None, steps=None, groups=None, scenario=Scenario, template=True):
    """The scenario against a fresh in-process fake; the file's document."""
    vocab = vocab or Vocab(fschema.load())
    async with scenario_fake(template) as fake:
        node = sorted(fake.pve.nodes)[0]
        async with WriteClient(fake.pve.url, fake.token, node, tls=False) as client:
            return await scenario(client, node, vocab, steps, groups, poll=0.01).run()


def same_text(a, b):
    """'exact', 'fuzzy' (the same words, give or take a few) or None."""
    if a == b:
        return 'exact'
    words = [[w for w in re.findall(r'[a-z]+', t.lower()) if w != 'x'] for t in (a, b)]
    return 'fuzzy' if difflib.SequenceMatcher(None, words[0], words[1]).ratio() >= 0.8 else None


SCN_FATAL = ('status', 'error-text', 'errors-keys', 'errors-text', 'task', 'shape', 'skipped', 'missing')


def diff_scenarios(real, fake):
    """Differences step by step, as (step, kind, detail); kind 'fuzzy' is a match that is not exact."""
    out = []
    varies = dict((s['name'], s.get('varies')) for s in STEPS)
    mine = dict((s['step'], s) for s in fake['steps'])
    for a in real['steps']:
        name = a['step']
        b = mine.get(name)
        if b is None:
            out.append((name, 'missing', 'step not run on the fake'))
            continue
        if ('skipped' in a) != ('skipped' in b):
            out.append((name, 'skipped', 'skipped on one side only'))
            continue
        if 'skipped' in a:
            continue
        if a['status'] != b['status']:
            out.append((name, 'status', '{0} in real, {1} in fake'.format(a['status'], b['status'])))
            continue
        if 'shape' in a and 'shape' in b and not varies.get(name):
            found = []
            diff_shapes(a['shape'], b['shape'], '', found)
            out.extend((name, 'shape', '{0} {1} {2}'.format(k, w or '(response)', d)) for k, w, d in found
                       if k in ('missing-key', 'extra-key', 'type'))
        for field, kind in (('error', 'error-text'),):
            if field in a or field in b:
                out.extend(compare_text(name, kind, a.get(field, ''), b.get(field, '')))
        ka, kb = a.get('errors', {}), b.get('errors', {})
        if set(ka) != set(kb):
            out.append((name, 'errors-keys', '{0} in real, {1} in fake'.format(
                ','.join(sorted(ka)) or '-', ','.join(sorted(kb)) or '-')))
        for key in sorted(set(ka) & set(kb)):
            out.extend(compare_text(name, 'errors-text', ka[key], kb[key], key))
        ta, tb = a.get('task'), b.get('task')
        if ta or tb:
            if not ta or not tb:
                out.append((name, 'task', 'a task in {0} only'.format('real' if ta else 'fake')))
            else:
                out.extend(compare_text(name, 'task', ta['exitstatus'], tb['exitstatus'], 'exitstatus'))
                out.extend(compare_text(name, 'task', ta['log'], tb['log'], 'log'))
    for name in mine:
        if name not in {s['step'] for s in real['steps']}:
            out.append((name, 'missing', 'step not run on the real side'))
    return out


def compare_text(name, kind, a, b, where=''):
    how = same_text(a, b)
    if how == 'exact':
        return []
    tag = (where + ': ') if where else ''
    if how == 'fuzzy':
        return [(name, 'fuzzy', '{0}{1!r} in real, {2!r} in fake'.format(tag, a, b))]
    return [(name, kind, '{0}{1!r} in real, {2!r} in fake'.format(tag, a, b))]


def report_scenario(real, fake, found, write=print):
    last = None
    for name, kind, detail in found:
        if kind == 'fuzzy':
            continue
        if name != last:
            write(name)
            last = name
        write('  {0}: {1}'.format(kind, detail))
    bad = set(n for n, k, _ in found if k != 'fuzzy')
    counts = {}
    for _, kind, _ in found:
        counts[kind] = counts.get(kind, 0) + 1
    ran = [s for s in real['steps'] if 'skipped' not in s]
    write('compared {0} steps ({1} skipped): {2} identical, {3} with a difference{4}; {5} fuzzy text matches'.format(
        len(ran), len(real['steps']) - len(ran), len(ran) - len(bad & {s['step'] for s in ran}), len(bad),
        ''.join('; {0} {1}'.format(v, k) for k, v in sorted(counts.items()) if k != 'fuzzy'), counts.get('fuzzy', 0)))
    return sum(v for k, v in counts.items() if k in SCN_FATAL)


async def self_test_scenario(write=print):
    """The scenario against two fresh fakes: both files must pass the check and agree on every step."""
    vocab = Vocab(fschema.load())
    docs = []
    for _ in range(2):
        doc = await scenario_on_fake(vocab)
        docs.append(json.loads(dump_scenario(doc, vocab, [Fake.TOKEN, Fake.SECRET], ['pve1'])))
    found = diff_scenarios(*docs)
    report_scenario(docs[0], docs[1], found, write)
    bad = sum(1 for d in found if d[1] in SCN_FATAL)
    write('self-test-scenario: {0} steps, {1} differences'.format(len(docs[0]['steps']), bad))
    return bad


# ------------------------------------------------------------------------ CLI

def parser():
    ap = argparse.ArgumentParser(allow_abbrev=False,
                                 description='Compare fakepve with a real PVE, read-only, keeping only shapes.')
    ap.add_argument('--self-test', action='store_true', help='record an in-process fakepve and diff it against itself')
    ap.add_argument('--self-test-scenario', action='store_true',
                    help='run the write scenario against two in-process fakes and expect no difference')
    sub = ap.add_subparsers(dest='mode')
    rec = sub.add_parser('record', allow_abbrev=False, help='walk the GET methods of a PVE and write a shape file')
    rec.add_argument('--url', required=True, help='https://host:8006')
    rec.add_argument('--token-file', required=True, help='file holding user@realm!id=secret')
    tls = rec.add_mutually_exclusive_group()
    tls.add_argument('--insecure', action='store_true', help='do not verify the certificate')
    tls.add_argument('--cafile', help='CA bundle to verify the certificate with')
    rec.add_argument('--out', default='pve-shape.json')
    rec.add_argument('--per-param', type=int, default=2, help='real values tried per path parameter (default 2)')
    rec.add_argument('--max-requests', type=int, default=1500)
    rec.add_argument('--concurrency', type=int, default=4)
    rec.add_argument('--timeout', type=float, default=20.0, help='seconds per request')
    rec.add_argument('--list-items', type=int, default=5, help='list items merged into one shape')
    rec.add_argument('--include-rrd', action='store_true')
    dif = sub.add_parser('diff', allow_abbrev=False,
                         help='compare a shape file with a seeded fakepve, or with another shape file')
    dif.add_argument('shape')
    dif.add_argument('--against', help='a second shape file instead of an in-process fakepve')
    dif.add_argument('--strict', action='store_true', help='exit 1 when there are differences')
    dif.add_argument('--include-rrd', action='store_true')
    dif.add_argument('--as-root', action='store_true',
                     help='run the fake as root instead of a user with the privileges the shape file records')
    dif.add_argument('--ignore-config-keys', action=argparse.BooleanOptionalAction, default=True,
                     help='do not count keys that depend on what one object holds (VM config, storage options)')
    scn = sub.add_parser('scenario', allow_abbrev=False,
                         help='WRITES: run the write and error scenario on a disposable PVE, or on a fake')
    scn.add_argument('--url', help='https://host:8006 of the disposable node')
    scn.add_argument('--token-file', help='file holding user@realm!id=secret')
    stls = scn.add_mutually_exclusive_group()
    stls.add_argument('--insecure', action='store_true', help='do not verify the certificate')
    stls.add_argument('--cafile', help='CA bundle to verify the certificate with')
    scn.add_argument('--i-understand-this-writes', action='store_true',
                     help='required: the run creates, changes and destroys objects on the target')
    scn.add_argument('--disposable-node', help='name of the target node; must be its only node')
    scn.add_argument('--allow-existing-guests', action='store_true',
                     help='run although guests this tool did not create exist (it never touches them)')
    scn.add_argument('--against-fake', nargs='?', const=True, default=False, metavar='FILE',
                     help='also run the scenario on an in-process fake and diff step by step; with a scenario '
                          'file, diff that file and do not contact any PVE')
    scn.add_argument('--out', default='pve-scenario.json')
    scn.add_argument('--groups', help='comma list of {0} (default all)'.format(', '.join(GROUPS)))
    scn.add_argument('--timeout', type=float, default=60.0, help='seconds per request')
    scn.add_argument('--task-timeout', type=float, default=300.0, help='seconds per task')
    scn.add_argument('--max-requests', type=int, default=800)
    return ap


def load_doc(path):
    try:
        with open(path, encoding='utf-8') as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        raise ToolError('cannot read the shape file') from None
    check_doc(doc, Vocab(fschema.load()))
    return doc


async def scenario_main(args, write):
    groups = None
    if args.groups:
        groups = [g.strip() for g in args.groups.split(',')]
        if not set(groups) <= set(GROUPS):
            raise ToolError('--groups takes {0}'.format(', '.join(GROUPS)))
    vocab = Vocab(fschema.load())
    if isinstance(args.against_fake, str):
        real = load_scenario(args.against_fake)
        # A recording made without a template skipped the container steps: the fake has none either.
        doc = await scenario_on_fake(vocab, groups=groups, template='no-template' not in real['notes'])
        fake = json.loads(dump_scenario(doc, vocab, [Fake.TOKEN, Fake.SECRET]))
        return 1 if report_scenario(real, fake, diff_scenarios(real, fake), write) else 0
    if not (args.url and args.token_file):
        raise ToolError('scenario needs --url and --token-file, or --against-fake FILE')
    if not args.i_understand_this_writes:
        raise ToolError('refusing: scenario writes to the target; pass --i-understand-this-writes, '
                        'and only for a throwaway PVE')
    if not args.disposable_node:
        raise ToolError('refusing: pass --disposable-node NAME, the only node of the throwaway PVE')
    if not args.url.startswith('https://'):
        raise ToolError('--url must start with https://')
    token = read_token(args.token_file)
    tls = False if args.insecure else ssl.create_default_context(cafile=args.cafile) if args.cafile else None
    host = urllib.parse.urlsplit(args.url).hostname
    async with WriteClient(args.url, token, args.disposable_node, tls, args.timeout, args.max_requests) as client:
        scn = Scenario(client, args.disposable_node, vocab, groups=groups, allow_existing=args.allow_existing_guests,
                       task_timeout=args.task_timeout, names=[host])
        doc = await scn.run()
    text = dump_scenario(doc, vocab, [token, token.partition('=')[2]], [args.disposable_node, host])
    with open(args.out, 'w', encoding='utf-8') as fh:
        fh.write(text)
    write('ran {0} steps with {1} requests into {2}; clean-up verified'.format(
        len(doc['steps']), client.sent, args.out))
    if args.against_fake:
        fake = json.loads(dump_scenario(await scenario_on_fake(vocab, groups=groups), vocab, [Fake.TOKEN, Fake.SECRET]))
        return 1 if report_scenario(json.loads(text), fake, diff_scenarios(json.loads(text), fake), write) else 0
    return 0


async def amain(argv=None, write=print):
    args = parser().parse_args(argv)
    if args.self_test:
        return 1 if await self_test(write) else 0
    if args.self_test_scenario:
        return 1 if await self_test_scenario(write) else 0
    if args.mode == 'scenario':
        return await scenario_main(args, write)
    if args.mode == 'record':
        if not args.url.startswith('https://'):
            raise ToolError('--url must start with https://')
        token = read_token(args.token_file)
        tls = False if args.insecure else ssl.create_default_context(cafile=args.cafile) if args.cafile else None
        async with Client(args.url, token, tls, args.timeout, args.max_requests, args.concurrency) as client:
            doc, vocab = await record(client, per_param=args.per_param, k=args.list_items, include_rrd=args.include_rrd)
        text = dump(doc, vocab, [token, token.partition('=')[2]])
        with open(args.out, 'w', encoding='utf-8') as fh:
            fh.write(text)
        write('recorded {0} methods with {1} requests into {2}'.format(len(doc['endpoints']), client.sent, args.out))
        for skip in doc['skipped']:
            write('skipped GET {0}: {1}'.format(skip['endpoint'], skip['reason']))
        return 0
    if args.mode == 'diff':
        real = load_doc(args.shape)
        if args.against:
            fake = load_doc(args.against)
        else:
            privileges = None if args.as_root else doc_privileges(real)
            fake, _ = await record_fake(real['inventory'], include_rrd=args.include_rrd, privileges=privileges)
            fake = json.loads(dump(fake, Vocab(fschema.load())))
        found = report(real, fake, compare(real, fake, args.ignore_config_keys), write)
        return 1 if args.strict and found else 0
    parser().print_usage(sys.stderr)
    return 2


def main(argv=None):
    try:
        return asyncio.run(amain(argv))
    except ToolError as e:
        print('compare_real: ' + str(e), file=sys.stderr)
    except Exception as e:
        # Only the class: library messages can carry a URL.
        print('compare_real: failed ({0})'.format(type(e).__name__), file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
