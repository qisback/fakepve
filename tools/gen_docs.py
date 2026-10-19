#!/usr/bin/env python3
"""Generate the reference parts of the docs from the code, so they cannot drift.

    python tools/gen_docs.py            # rewrite docs/reference/endpoints.md and the signature index
    python tools/gen_docs.py --check    # exit 1 if either would change (the test suite does this)

Sources: the vendored PVE schema and error catalogue (src/fakepve/data), the
routes FakePve registers, and the public signatures of the package.
"""

import asyncio
import inspect
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'src'))

from aiohttp.test_utils import make_mocked_request  # noqa: E402

from fakepve import certs, errors, schema  # noqa: E402
from fakepve import FakePve, FakeVm  # noqa: E402
from fakepve.generic import NOT_TASKS  # noqa: E402
from fakepve.server import AGENT_COMMANDS, API  # noqa: E402

ENDPOINTS = os.path.join(ROOT, 'docs', 'reference', 'endpoints.md')
PYTHON_API = os.path.join(ROOT, 'docs', 'python-api.md')
BEGIN = '<!-- BEGIN GENERATED: signatures (tools/gen_docs.py) -->'
END = '<!-- END GENERATED: signatures -->'


# -------------------------------------------------------------------- endpoints

def hand_written(pve, app, path, method):
    """How a request for this schema path is routed: 'stateful', 'unmodelled' or 'generic'."""
    concrete = '/'.join('x' if seg.startswith('{') else seg for seg in path.split('/'))
    request = make_mocked_request(method, API + concrete)
    if 'tail' in asyncio.run(app.router.resolve(request)):
        return 'generic'
    segs = path.split('/')
    if '/qemu/' in path and segs[-2] == 'status' and segs[-1] != 'current':
        if not hasattr(pve, '_do_' + segs[-1]):
            return 'unmodelled'
    if '/qemu/' in path and segs[-2] == 'agent' and segs[-1] not in AGENT_COMMANDS:
        return 'unmodelled'
    return 'stateful'


def render_check(check):
    """The schema's permission rule as a short line."""
    form = check[0]
    if form == 'perm':
        opts = dict(zip(check[3::2], check[4::2], strict=False))
        privs = (' or ' if opts.get('any') else ', ').join(check[2]) or 'no privilege'
        return '{0}: {1}'.format(check[1], privs)
    if form in ('and', 'or'):
        return '(' + ' {0} '.format(form).join(render_check(sub) for sub in check[1:]) + ')'
    if form == 'userid-param':
        return 'the user itself' if check[1] == 'self' else 'realm of the userid: ' + str(check[1])
    if form == 'userid-group':
        return 'on /access/groups: ' + ', '.join(check[1])
    if form == 'perm-modify':
        return 'Permissions.Modify on the given path'
    return form


def access(info):
    perms = info.get('permissions')
    if not perms:
        return 'root only'
    if perms.get('user') == 'world':
        return 'no login'
    if perms.get('user') == 'all' and 'check' not in perms:
        return 'any logged-in user'
    if 'check' in perms:
        return render_check(perms['check'])
    return 'root only'


def method_lines(pve, app, path, method, info):
    kind = hand_written(pve, app, path, method)
    label = {'stateful': 'stateful (hand-written)', 'generic': 'generic (from the schema)',
             'unmodelled': 'routed to a hand-written handler that answers 501'}[kind]
    if kind == 'generic' and schema.is_task(method, info) and (method, path) not in NOT_TASKS:
        label += ', starts a task'
    props = (info.get('parameters') or {}).get('properties', {})
    required = [name for name, sch in props.items() if not sch.get('optional')]
    optional = len(props) - len(required)
    names = errors.listing(method, path)
    specific = [e for e in names if e['source'] != 'cross-cutting']
    direct = ['`{0}`'.format(e['name']) for e in specific if not e['in_task']]
    in_task = ['`{0}`'.format(e['name']) for e in specific if e['in_task']]
    out = ['- **{0}**: {1}'.format(method, label),
           '  - Access: {0}'.format(access(info)),
           '  - Required: {0}{1}'.format(', '.join('`{0}`'.format(n) for n in required) or 'none',
                                          ' (+{0} optional)'.format(optional) if optional else '')]
    if direct:
        out.append('  - Errors: ' + ', '.join(direct))
    if in_task:
        out.append('  - Errors in the task: ' + ', '.join(in_task))
    return out, kind


def endpoints_md():
    pve = FakePve(host='127.0.0.2')
    app = pve._build_app()
    paths = schema.load().paths
    areas = {}
    counts = {'stateful': 0, 'generic': 0, 'unmodelled': 0}
    for path in sorted(paths):
        area = path.strip('/').split('/')[0] or '(root)'
        lines = ['', '### `{0}`'.format(path), '']
        for method in sorted(paths[path]):
            out, kind = method_lines(pve, app, path, method, paths[path][method])
            counts[kind] += 1
            lines += out
        areas.setdefault(area, []).append('\n'.join(lines))
    total = sum(counts.values())
    head = [
        '# Endpoint reference',
        '',
        '<!-- Generated by tools/gen_docs.py from the vendored schema and error catalogue. Do not edit. -->',
        '',
        'Every path and method of the PVE API schema that fakepve answers, under `{0}`: {1} methods on {2} paths.'
        .format(API, total, len(paths)),
        '',
        '- **stateful (hand-written)**: {0} methods keep state and follow PVE\'s rules (see [How it works]'
        '(../how-it-works.md)).'.format(counts['stateful']),
        '- **generic (from the schema)**: {0} methods check parameters and permissions as the schema states them and '
        'answer with a value of the right shape. A write succeeds and changes nothing.'.format(counts['generic']),
        '- **routed to a hand-written handler that answers 501**: {0} methods whose route is claimed by a stateful '
        'family (VM `status/{{action}}`, guest `agent/{{command}}`) but whose action or command is not modelled.'
        .format(counts['unmodelled']),
        '',
        'For each method: **Access** is the permission rule from the schema (evaluated against `pve.grant`; root is '
        'always allowed), **Required** the parameters that must be sent (path parameters included), and **Errors** '
        'the names that `pve.fail(..., error=name)` accepts, from the [error catalogue](../errors.md). Errors marked '
        '"in the task" are raised in a PVE worker: the request succeeds and the task ends with the error.',
        '',
        'Besides the listed names, these cross-cutting errors apply, whatever the catalogue says: `invalid_ticket` '
        'and `authentication_failure` (401, any method that needs a login); `invalid_csrf`, `no_quorum` (writes); '
        '`config_lock_timeout` (writes to a QEMU or LXC guest); `not_implemented` (501); `no_route_to_host` (595) '
        'and `hostname_lookup_failed` (500) on paths with a `{node}`; `permission_denied` (403, methods that are not '
        'open to every user).',
        '',
        '## Contents',
        '',
    ]
    for area in sorted(areas):
        head.append('- [{0}](#{1}): {2} path{3}'.format(area, area.lower().replace('(', '').replace(')', ''),
                                                             len(areas[area]), '' if len(areas[area]) == 1 else 's'))
    body = []
    for area in sorted(areas):
        body += ['', '## {0}'.format(area)] + areas[area]
    return '\n'.join(head + body) + '\n'


# ------------------------------------------------------------------- signatures

def summary(obj):
    doc = inspect.getdoc(obj) or ''
    return doc.split('\n\n')[0].replace('\n', ' ').strip()


def sig(name, func):
    prefix = 'async ' if inspect.iscoroutinefunction(func) else ''
    return '{0}{1}{2}'.format(prefix, name, inspect.signature(func)).replace('(self, ', '(').replace('(self)', '()')


def members(cls):
    """Public functions, in source order, from the base classes up."""
    seen = {}
    for klass in reversed(cls.__mro__):
        if klass is object:
            continue
        for name, val in vars(klass).items():
            if name.startswith('_') or not (inspect.isfunction(val) or isinstance(val, property)):
                continue
            seen.pop(name, None)
            seen[name] = (klass, val)
    return seen


def short(value, limit=90):
    text = repr(value)
    return text if len(text) <= limit else text[:limit - 3] + '...'


def class_section(cls, instance, title):
    out = ['### {0}'.format(title), '', 'Constructor: `{0}{1}`'.format(cls.__name__, str(inspect.signature(cls))
                                                                   .replace('(self, ', '(')), '',
           '| Method | What it does |', '|---|---|']
    for name, (_, val) in members(cls).items():
        if isinstance(val, property):
            out.append('| `{0}` (property) | {1} |'.format(name, summary(val.fget)))
        else:
            out.append('| `{0}` | {1} |'.format(sig(name, val), summary(val)))
    out += ['', 'Attributes after construction:', '', '| Attribute | Initial value |', '|---|---|']
    for name, value in vars(instance).items():
        if not name.startswith('_'):
            out.append('| `{0}` | `{1}` |'.format(name, short(value).replace('|', '\\|')))
    return out


def module_section(title, module, names):
    out = ['### {0}'.format(title), '', '| Function | What it does |', '|---|---|']
    for name in names:
        out.append('| `{0}` | {1} |'.format(sig(name, getattr(module, name)), summary(getattr(module, name))))
    return out


def signatures_md():
    import fakepve
    out = ['## Signature index', '',
           'Generated by `tools/gen_docs.py` from the code. Do not edit between the markers; the explanations '
           'above and below are written by hand.', '',
           'Names exported by `fakepve`: ' + ', '.join('`{0}`'.format(n) for n in fakepve.__all__) + '.', '']
    out += class_section(FakePve, FakePve(host='127.0.0.2'), 'FakePve')
    out += [''] + class_section(FakeVm, FakeVm(100, 'vm'), 'FakeVm')
    out += ['', '### Exceptions', '', '| Class | Meaning |', '|---|---|']
    for cls in (fakepve.PveError, fakepve.TaskError):
        init = cls.__init__ if '__init__' in vars(cls) else None
        args = str(inspect.signature(init)).replace('(self, ', '(') if init else '(message)'
        out.append('| `{0}{1}` | {2} |'.format(cls.__name__, args, summary(cls)))
    out += [''] + module_section('fakepve (module functions)', fakepve, ['next_loopback', 'settle'])
    out += [''] + module_section('fakepve.certs', certs, ['make_cert'])
    out += [''] + module_section('fakepve.errors', errors, [n for n in errors.__all__])
    out += [''] + module_section('fakepve.schema', schema, ['load', 'validate', 'sample', 'is_task'])
    out += ['', '### fakepve.schema.Schema', '', '| Method | What it does |', '|---|---|']
    for name, (_, val) in members(schema.Schema).items():
        out.append('| `{0}` | {1} |'.format(sig(name, val), summary(val)))
    return '\n'.join(out) + '\n'


def python_api_text():
    with open(PYTHON_API, encoding='utf-8') as fh:
        text = fh.read()
    head, rest = text.split(BEGIN, 1)
    tail = rest.split(END, 1)[1]
    return head + BEGIN + '\n\n' + signatures_md() + '\n' + END + tail


# ------------------------------------------------------------------------ main

def main(argv=None):
    check = '--check' in (sys.argv[1:] if argv is None else argv)
    wanted = {ENDPOINTS: endpoints_md(), PYTHON_API: python_api_text()}
    stale = []
    for path, content in wanted.items():
        try:
            with open(path, encoding='utf-8') as fh:
                current = fh.read()
        except FileNotFoundError:
            current = None
        if current != content:
            stale.append(path)
            if not check:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'w', encoding='utf-8', newline='\n') as fh:
                    fh.write(content)
    for path in stale:
        print(('stale: ' if check else 'wrote: ') + os.path.relpath(path, ROOT))
    return 1 if check and stale else 0


if __name__ == '__main__':
    sys.exit(main())
