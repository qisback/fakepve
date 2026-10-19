"""The errors each PVE API method can return, selectable by name.

The catalogue (data/pve-errors.json.gz, built by tools/extract_errors.py)
holds the messages and status codes found in the PVE sources, per method.
Cross-cutting errors that apply to many methods (no ticket, no quorum, lock
timeout, ...) are added here. Messages are templates: `{vmid}`, `{node}`, ...
are filled from the request, or with a plausible value.
"""

import functools
import gzip
import json
import pkgutil
import re

from . import schema as pve_schema

API = '/api2/json'

__all__ = ['catalogue', 'errors_for', 'find', 'fill', 'listing', 'meta']

# Task type per last path segment, for the UPID of a failing task.
TASK_TYPES = {
    ('qemu', 'start'): 'qmstart', ('qemu', 'stop'): 'qmstop', ('qemu', 'shutdown'): 'qmshutdown',
    ('qemu', 'reset'): 'qmreset', ('qemu', 'reboot'): 'qmreboot', ('qemu', 'suspend'): 'qmsuspend',
    ('qemu', 'resume'): 'qmresume', ('qemu', 'clone'): 'qmclone', ('qemu', 'migrate'): 'qmigrate',
    ('qemu', 'snapshot'): 'qmsnapshot', ('qemu', 'rollback'): 'qmrollback', ('qemu', '{vmid}'): 'qmdestroy',
    ('lxc', 'start'): 'vzstart', ('lxc', 'stop'): 'vzstop', ('lxc', 'shutdown'): 'vzshutdown',
    ('lxc', 'reboot'): 'vzreboot', ('lxc', 'suspend'): 'vzsuspend', ('lxc', 'resume'): 'vzresume',
    ('lxc', 'clone'): 'vzclone', ('lxc', 'migrate'): 'vzmigrate', ('lxc', 'snapshot'): 'vzsnapshot',
    ('lxc', 'rollback'): 'vzrollback', ('lxc', '{vmid}'): 'vzdestroy',
}


@functools.lru_cache(maxsize=None)
def load():
    return json.loads(gzip.decompress(pkgutil.get_data('fakepve', 'data/pve-errors.json.gz')))


def catalogue():
    """{'<METHOD> <schema path>': [error, ...]} as extracted from the PVE sources."""
    return load()['errors']


def meta():
    """Where the catalogue came from: repositories with commits, date, counts."""
    return load()['meta']


def strip_prefix(path):
    path = path.split('?', 1)[0]
    if path.startswith(API):
        path = path[len(API):]
    return path


def task_type(template):
    segs = template.rstrip('/').split('/')
    kind = next((s for s in segs if s in ('qemu', 'lxc')), None)
    return TASK_TYPES.get((kind, segs[-1]), segs[-1].strip('{}'))


# ------------------------------------------------------------------ cross-cutting

def cross_cutting(method, template, info):
    """Errors that can happen to any (or any matching) method: from PVE's daemons, not its API modules."""
    out = []

    def add(name, status, message, errors=None):
        entry = {'name': name, 'status': status, 'message': message, 'in_task': False, 'source': 'cross-cutting'}
        if errors:
            entry['errors'] = errors
        out.append(entry)

    perms = (info or {}).get('permissions') or {}
    if perms.get('user') != 'world':
        add('invalid_ticket', 401, 'permission denied - invalid PVE ticket')
        add('authentication_failure', 401, 'authentication failure')
    if method != 'GET':
        add('invalid_csrf', 401, 'Permission denied - invalid csrf token')
        add('no_quorum', 500, 'cluster not ready - no quorum?')
        if '{vmid}' in template and '/qemu/' in template:
            add('config_lock_timeout', 500, "can't lock file '/var/lock/qemu-server/lock-{vmid}.conf' - got timeout")
        elif '{vmid}' in template and '/lxc/' in template:
            add('config_lock_timeout', 500, "can't lock file '/run/lock/lxc/pve-config-{vmid}.lock' - got timeout")
    add('not_implemented', 501, "Method '{method} {path}' not implemented")
    if '{node}' in template:
        add('no_route_to_host', 595, 'No route to host')
        add('hostname_lookup_failed', 500, "hostname lookup '{node}' failed - failed to get address info for: "
                                           "{node}: Name or service not known")
    if perms.get('user') not in ('all', 'world'):
        why = 'user != root@pam'
        check = perms.get('check')
        if check and check[0] == 'perm' and len(check) > 2 and check[2]:
            why = '{0}, {1}'.format(check[1], check[2][0])
        add('permission_denied', 403, 'Permission check failed ({0})'.format(why))
    return out


def listing(method, path):
    """Every error a method can return as templates: the catalogue's, then the cross-cutting ones.

    Returns [] for a path not in the schema. A name is unique within the list.
    """
    match = pve_schema.load().match(strip_prefix(path))
    if match is None:
        return []
    info = match.methods.get(method)
    entries = [dict(e) for e in catalogue().get('{0} {1}'.format(method, match.template), [])]
    taken = set(e['name'] for e in entries)
    for extra in cross_cutting(method, match.template, info):
        if extra['name'] in taken:
            extra['name'] += '_2'
        taken.add(extra['name'])
        entries.append(extra)
    return entries


def find(method, path, name):
    """The error called name for a method and path, or None."""
    for entry in listing(method, path):
        if entry['name'] == name:
            return entry
    return None


# ----------------------------------------------------------------------- filling

# Plausible values for placeholders the request does not give.
DEFAULTS = {
    'vmid': '100', 'newid': '101', 'node': 'pve1', 'target': 'pve2', 'storage': 'local', 'storeid': 'local',
    'snapname': 'snap1', 'lock': 'backup', 'guest_type': 'VM', 'type': 'qemu', 'err': 'unexpected error',
    'error': 'unexpected error', 'msg': 'unexpected error', 'volid': 'local:100/vm-100-disk-0.raw',
    'userid': 'root@pam', 'username': 'root@pam', 'user': 'root@pam', 'realm': 'pam', 'group': 'group1',
    'groupid': 'group1', 'roleid': 'role1', 'poolid': 'pool1', 'pool': 'pool1', 'path': '/', 'opt': 'scsi0',
    'key': 'scsi0', 'exitcode': '1', 'upid': 'UPID:pve1:00000000:00000000:00000000:task:100:root@pam:',
    'tokenid': 'root@pam!token', 'name': 'fake', 'id': '100', 'file': '/etc/pve/fake', 'len': '65',
    'iface': 'vmbr0', 'zone': 'zone1', 'vnet': 'vnet1', 'timeout': '30', 'status': 'stopped',
}


def default(name, ctx):
    if name == 'cfspath':
        kind = 'lxc' if ctx.get('_kind') == 'lxc' else 'qemu-server'
        return 'nodes/{0}/{1}/{2}.conf'.format(ctx.get('node', 'pve1'), kind, ctx.get('vmid', '100'))
    if name == 'guest_type':
        return 'CT' if ctx.get('_kind') == 'lxc' else 'VM'
    return DEFAULTS.get(name, 'fake')


def fill(template, ctx):
    """Replace {name} in a message template from ctx, else a plausible value."""
    def sub(m):
        name = m.group(1)
        if name in ctx and ctx[name] not in (None, ''):
            return str(ctx[name])
        return default(name, ctx)
    return re.sub(r'\{([A-Za-z_][\w-]*)\}', sub, template)


def render(entry, template, ctx, params=()):
    """The error entry with its placeholders filled: (status, message, errors or None)."""
    ctx = dict(ctx)
    ctx['_kind'] = 'lxc' if '/lxc/' in template else 'qemu'
    errors = None
    if entry.get('errors'):
        errors = {}
        spare = list(params)
        for key, text in entry['errors'].items():
            if re.fullmatch(r'\{[\w-]+\}', key) and (key[1:-1] not in ctx):
                # A parameter named at run time in PVE: pick one the method has.
                key = spare[0] if spare else 'param'
            else:
                key = fill(key, ctx)
            errors[key] = fill(text, ctx)
    return entry['status'], fill(entry['message'], ctx), errors


def errors_for(method, path, params=None):
    """The errors a method can return at a concrete path, as filled entries.

    path is e.g. '/nodes/pve1/qemu/100/status/start' (with or without /api2/json).
    Each entry has name, status, message, errors (or absent), in_task and source;
    placeholders come from the path and params, else plausible values.
    """
    match = pve_schema.load().match(strip_prefix(path))
    if match is None:
        return []
    ctx = dict(params or {})
    ctx.update(match.params)
    ctx.setdefault('method', method)
    ctx.setdefault('path', API + strip_prefix(path))
    names = [p for p in ((match.methods.get(method) or {}).get('parameters') or {}).get('properties', {})
             if p not in match.params]
    out = []
    for entry in listing(method, path):
        status, message, errors = render(entry, match.template, ctx, names)
        item = dict(entry, status=status, message=message)
        if errors:
            item['errors'] = errors
        out.append(item)
    return out
