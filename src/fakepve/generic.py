"""Every endpoint in the PVE API schema answers, whether or not it is modelled.

Requests the hand-written routes do not take land here. They are checked
against the schema (parameters, permissions) with PVE's errors, then answered
with a value built from the method's `returns`. Methods that start a worker
task return a real UPID. Nothing is stored.
"""

import re
import urllib.parse

from aiohttp import web

from . import schema as pve_schema
from . import shapes
from .model import PveError

# Methods that look like tasks by their result but return something else.
NOT_TASKS = {('POST', '/cluster/sdn/lock'), ('POST', '/nodes/{node}/qemu/{vmid}/monitor')}


# The URL prefixes the API answers under: PVE's JSON and ExtJS formats.
FORMAT_PREFIXES = ('/api2/json', '/api2/extjs')


def root_only(user):
    return user.split('!')[0] == 'root@pam'


class GenericApi(object):
    """Mixin for FakePve: the catch-all route and its schema checks."""

    def resolve(self, request, prefix):
        """The schema match of a request path, or None."""
        path = request.rel_url.raw_path
        for known in FORMAT_PREFIXES:
            if path.startswith(known + '/'):
                prefix = known
        raw = path[len(prefix):]
        path = '/'.join(urllib.parse.unquote(seg) for seg in raw.split('/'))
        return pve_schema.load().match(path)

    def is_world(self, match, method):
        """True if the method needs no login."""
        info = match and match.methods.get(method)
        return bool(info) and (info.get('permissions') or {}).get('user') == 'world'

    async def answer(self, request, match, params, user, call=None):
        """The data for a request: checked against the schema, then call(match, values) or a value from `returns`."""
        if match is None:
            raise web.HTTPNotFound()
        method = request.method
        info = match.methods.get(method)
        if info is None:
            raise PveError(501, "Method '{0} {1}' not implemented".format(method, request.path))
        values = dict(params)
        declared = (info.get('parameters') or {}).get('properties', {})
        self._check_acl_path(user, info.get('permissions'), dict(params, **match.params))
        # A few path parameters are missing from the schema; they are not checked.
        values.update((k, v) for k, v in match.params.items() if k in declared)
        values, errors = pve_schema.validate(info.get('parameters'), values)
        if errors:
            raise PveError(400, 'Parameter verification failed.', errors)
        values.update((k, v) for k, v in match.params.items() if k not in declared)
        if 'node' in match.params and match.params['node'] not in self.nodes:
            raise PveError(500, "hostname lookup '{0}' failed - failed to get address info for: {0}: "
                                "Name or service not known".format(match.params['node']))
        self.check_permissions(user, info.get('permissions'), values, declared)
        if call is not None:
            return await call(match, values)
        return await self.synthesise(match, method, info, user, values)

    # ---------------------------------------------------------- permissions

    @staticmethod
    def _check_acl_path(user, perms, values):
        """PVE checks permissions before the parameters: a path it cannot normalise (a name with a space) has
        no privileges for anyone but the root@pam login, and the error shows an empty path."""
        rule = (perms or {}).get('check')
        if user in (None, 'root@pam') or not rule or rule[0] != 'perm':
            return
        path = rule[1]
        for name in set(GenericApi._names(path)):
            if values.get(name) is None:
                return
            path = path.replace('{' + name + '}', str(values[name]))
        if not re.fullmatch(r'[A-Za-z0-9./_-]+', path):
            raise PveError(403, 'Permission check failed (, {0})'.format('|'.join(rule[2])))

    def check_permissions(self, user, perms, values, declared=None):
        """Raise a 403 PveError unless user satisfies the schema's permission rule."""
        if user is not None and (self.acl is None or root_only(user)):
            return
        if perms is None:
            ok, why = False, 'user != root@pam'
        elif 'check' in perms:
            ok, why = self._check(user, perms['check'], values, declared)
        elif perms.get('user') in ('all', 'world'):
            return
        else:
            ok, why = False, 'user != root@pam'
        if not ok:
            # A refusal by the "self" rule carries no reason in PVE.
            raise PveError(403, 'Permission check failed ({0})'.format(why) if why else 'Permission check failed')

    def _has(self, user, path, priv):
        try:
            return self.allowed(user, path, priv)
        except ValueError:  # '/vms/<not a number>'
            return False

    def _check(self, user, check, values, declared=None):
        """Evaluate one permission rule: (allowed, reason)."""
        form = check[0]
        if form == 'perm':
            path = check[1]
            opts = dict(zip(check[3::2], check[4::2], strict=False))
            for name in set(self._names(path)):
                if values.get(name) is None and declared is not None and name not in declared:
                    # The rule names a parameter the method does not take: PVE leaves it empty.
                    path = '/' + '/'.join(seg for seg in path.replace('{' + name + '}', '').split('/') if seg)
                    continue
                if values.get(name) is None:
                    return False, path
                path = path.replace('{' + name + '}', str(values[name]))
            if opts.get('require_param') and values.get(opts['require_param']) is None:
                return False, path
            privs = check[2]
            if opts.get('any'):
                return any(self._has(user, path, p) for p in privs), '{0}, {1}'.format(path, '|'.join(privs))
            for priv in privs:
                if not self._has(user, path, priv):
                    return False, '{0}, {1}'.format(path, priv)
            return True, ''
        if form in ('and', 'or'):
            why = ''
            for sub in check[1:]:
                ok, why = self._check(user, sub, values, declared)
                if ok == (form == 'or'):
                    return ok, why
            # PVE names no reason when none of several alternatives held.
            return form == 'and', why if form == 'and' else ''
        if form == 'userid-param' and check[1] == 'self':
            userid = values.get('userid')
            return userid is not None and userid == user.split('!')[0], ''
        if form == 'userid-param':
            realm = str(values.get('userid', '')).rpartition('@')[2]
            path = '/access/realm/' + realm
            return self._has(user, path, check[1]), '{0}, {1}'.format(path, check[1])
        if form == 'userid-group':
            privs = check[1]
            return any(self._has(user, '/access/groups', p) for p in privs), '/access/groups, ' + '|'.join(privs)
        if form == 'perm-modify':
            path = str(values.get('path', ''))
            return self._has(user, path, 'Permissions.Modify'), '{0}, Permissions.Modify'.format(path)
        # Unknown rule: root only.
        return False, 'user != root@pam'

    @staticmethod
    def _names(path):
        return [seg[1:-1] for seg in path.split('/') if seg.startswith('{') and seg.endswith('}')]

    # -------------------------------------------------------------- results

    def _sample_context(self, values=None):
        """The preferred values for names in a synthesised answer."""
        ctx = {'node': sorted(self.nodes)[0], 'storage': sorted(self.storages)[0], '_nodes': sorted(self.nodes)}
        if self.vms:
            ctx['vmid'] = self.vms[0].vmid
        ctx.update(values or {})
        return ctx

    def _complete(self, template, data, **values):
        """A hand-built answer for the GET method of `template`, with the keys PVE sends that it lacks."""
        returns = pve_schema.load().paths[template]['GET'].get('returns') or {}
        return shapes.complete(template, data, returns, self._sample_context(values))

    async def synthesise(self, match, method, info, user, values):
        """The answer for a generic method: a task UPID, or a value built from its `returns`."""
        returns = info.get('returns') or {}
        if pve_schema.is_task(method, info) and (method, match.template) not in NOT_TASKS:
            node = values.get('node')
            if node not in self.nodes:
                node = sorted(self.nodes)[0]
            ttype = match.template.rstrip('/').rsplit('/', 1)[-1].strip('{}')

            async def body():
                return None
            return await self.task(node, ttype, values.get('vmid', ''), user or 'root@pam', body)
        data = shapes.build(match.template, returns, self._sample_context(values), method)
        links = returns.get('links') or []
        if returns.get('type') == 'array' and not (returns.get('items') or {}).get('properties') and links:
            # A directory listing: one entry per named child.
            key = links[0].get('href', '').strip('{}')
            kids = pve_schema.load().children(match.template)
            if key and (returns.get('items') or {}).get('type') == 'object':
                data = [{key: kid} for kid in kids[:1]] or [{key: 'fake'}]
        return data
