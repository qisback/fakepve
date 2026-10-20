#!/usr/bin/env python3
"""Compare fakepve's answers with a real PVE, read-only, keeping only shapes.

    compare_real.py record --url https://HOST:8006 --token-file FILE (--insecure | --cafile CA) [--out shape.json]
    compare_real.py diff shape.json [--against other.json] [--strict]
    compare_real.py --self-test

record walks every GET method of the vendored schema, with GET and nothing else, and writes a shape file:
per method the status, the types and key names of the answer and the error text with every name and number
removed. No value is kept; a self-check refuses to write a file that holds one. The token is read from a file,
never from the command line, and is never printed or written.

diff runs the same walk against an in-process fakepve seeded with the counts in the shape file (or compares two
shape files) and lists, per method, status, key and type differences.
"""

import argparse
import asyncio
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
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))
    from fakepve import schema as fschema

FORMAT = 1
KEY = '<key>'
UNKNOWN = '<x>'
TYPES = ('null', 'boolean', 'integer', 'number', 'string', 'object', 'array', 'mixed')
SHAPE_FIELDS = {'t', 'keys', 'optional', 'items', 'of', 'nullable'}
ENTRY_FIELDS = {'status', 'shape', 'errors', 'samples'}
MAX_BODY = 8 * 1024 ** 2
API = '/api2/json'
TOKEN_RX = re.compile(r'^[^\s!=]+@[^\s!=]+![^\s=]+=\S+$')

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
    words = {'x', 'network', 'error', 'timeout', 'non', 'json', 'unknown', 'http'}

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
        walk(json.loads(gzip.decompress(pkgutil.get_data('fakepve', 'data/pve-errors.json.gz'))))
    except (OSError, ValueError, TypeError):
        pass
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
    if not isinstance(doc, dict) or set(doc) != {'format', 'endpoints', 'skipped', 'inventory'} or \
            doc['format'] != FORMAT:
        raise Leak('not a shape file')
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
    def __init__(self, status, data=None, message=None):
        self.status = status
        self.data = data
        self.message = message


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
        async with self.slots:
            if self.sent >= self.limit:
                raise CapReached()
            self.sent += 1
            try:
                async with self.session.get(self.base + API + path, allow_redirects=False) as rsp:
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
            return Result(status, body.get('data'), body.get('message') or reason)
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
        return doc

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
    if set(rv) != set(fv):
        out.append(('type', where, '{0} in real, {1} in fake'.format('/'.join(sorted(rv)), '/'.join(sorted(fv)))))
    for t in sorted(set(rv) & set(fv)):
        a, b = rv[t], fv[t]
        if t == 'object':
            for key in sorted(set(a['keys']) - set(b['keys'])):
                kind = 'missing-optional' if key in a.get('optional', ()) else 'missing-key'
                out.append((kind, where + '.' + key, 'in real, not in fake'))
            for key in sorted(set(b['keys']) - set(a['keys'])):
                out.append(('extra-key', where + '.' + key, 'in fake, not in real'))
            for key in sorted(set(a['keys']) & set(b['keys'])):
                diff_shapes(a['keys'][key], b['keys'][key], where + '.' + key, out)
        elif t == 'array' and a.get('items') and b.get('items'):
            diff_shapes(a['items'], b['items'], where + '[]', out)


def compare(real, fake):
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
        out.extend((name,) + f for f in found)
    return out


FATAL = ('status', 'missing-key', 'extra-key', 'type', 'error-message')


def report(real, fake, differences, write=print):
    both = [n for n in real['endpoints'] if n in fake['endpoints']]
    counts = {}
    for _, kind, _, _ in differences:
        counts[kind] = counts.get(kind, 0) + 1
    last = None
    for name, kind, where, detail in differences:
        if kind == 'unsampled':
            continue
        if name != last:
            write(name)
            last = name
        write('  {0}: {1} {2}'.format(kind, where or '(response)', detail).rstrip())
    write('compared {0} methods; {1} not sampled in the fake; {2} differences{3}'.format(
        len(both), counts.get('unsampled', 0), sum(v for k, v in counts.items() if k != 'unsampled'),
        ''.join('; {0} {1}'.format(v, k) for k, v in sorted(counts.items()) if k != 'unsampled')))
    return sum(counts.get(k, 0) for k in FATAL)


# ------------------------------------------------------------------- the fake

def seed(pve, inv):
    """Give a FakePve the counts of an inventory: nodes, guests, storages and pools, with made-up names."""
    for n in range(2, max(inv.get('node', 1), 1) + 1):
        pve.add_node('pve{0}'.format(n))
    nodes = sorted(pve.nodes)
    for n in range(inv.get('qemu', 0)):
        pve.add_vm(100 + n, 'vm{0}'.format(n), node=nodes[n % len(nodes)], status='running' if n % 2 == 0 else 'stopped',
                   config={'memory': 512, 'cores': 1})
    for n in range(inv.get('lxc', 0)):
        pve.add_ct(200 + n, 'ct{0}'.format(n), node=nodes[n % len(nodes)], status='running' if n % 2 == 0 else 'stopped')
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
        pve.pool_info['pool{0}'.format(n)] = {'comment': None, 'storage': set()}


class Fake(object):
    """An in-process fakepve on loopback, with one API token."""

    TOKEN = 'root@pam!compare=00000000-0000-4000-8000-000000000000'

    def __init__(self, inv=None):
        self.inv = inv or {}
        self.pve = None
        self.tmp = None

    async def __aenter__(self):
        from fakepve import FakePve
        try:
            from fakepve.certs import make_cert
        except ImportError:
            raise ToolError('the in-process fake needs the cryptography package') from None
        self.tmp = tempfile.TemporaryDirectory(prefix='fakepve-compare-')
        self.pve = FakePve(host='127.0.0.1', port=0)
        self.pve.apitokens['root@pam!compare'] = self.TOKEN.partition('=')[2]
        seed(self.pve, self.inv)
        cert, key, _ = make_cert(self.tmp.name)
        await self.pve.start(cert, key)
        return self

    async def __aexit__(self, *exc):
        from fakepve import settle
        await settle()
        await self.pve.stop()
        self.tmp.cleanup()


async def record_fake(inv, per_param=2, k=5, include_rrd=False, limit=1500):
    async with Fake(inv) as fake:
        async with Client(fake.pve.url, Fake.TOKEN, tls=False, limit=limit) as client:
            return await record(client, per_param=per_param, k=k, include_rrd=include_rrd)


async def self_test(write=print):
    """Record a seeded fake, record a second one seeded from the first file, expect no difference."""
    inv = {'node': 2, 'qemu': 3, 'lxc': 2, 'storage': 3, 'pool': 1}
    first, vocab = await record_fake(inv)
    text = dump(first, vocab, [Fake.TOKEN, Fake.TOKEN.partition('=')[2]])
    first = json.loads(text)
    second, _ = await record_fake(first['inventory'])
    second = json.loads(dump(second, vocab))
    found = compare(first, second)
    report(first, second, found, write)
    write('self-test: {0} methods recorded, {1} differences'.format(len(first['endpoints']),
                                                                    sum(1 for d in found if d[1] in FATAL)))
    return sum(1 for d in found if d[1] in FATAL)


# ------------------------------------------------------------------------ CLI

def parser():
    ap = argparse.ArgumentParser(allow_abbrev=False, description='Compare fakepve with a real PVE, read-only, keeping only shapes.')
    ap.add_argument('--self-test', action='store_true', help='record an in-process fakepve and diff it against itself')
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
    dif = sub.add_parser('diff', allow_abbrev=False, help='compare a shape file with a seeded fakepve, or with another shape file')
    dif.add_argument('shape')
    dif.add_argument('--against', help='a second shape file instead of an in-process fakepve')
    dif.add_argument('--strict', action='store_true', help='exit 1 when there are differences')
    dif.add_argument('--include-rrd', action='store_true')
    return ap


def load_doc(path):
    try:
        with open(path, encoding='utf-8') as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        raise ToolError('cannot read the shape file') from None
    check_doc(doc, Vocab(fschema.load()))
    return doc


async def amain(argv=None, write=print):
    args = parser().parse_args(argv)
    if args.self_test:
        return 1 if await self_test(write) else 0
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
            fake, _ = await record_fake(real['inventory'], include_rrd=args.include_rrd)
            fake = json.loads(dump(fake, Vocab(fschema.load())))
        found = report(real, fake, compare(real, fake), write)
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
