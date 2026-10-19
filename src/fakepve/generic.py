"""Every endpoint in the PVE API schema answers, whether or not it is modelled.

Requests the hand-written routes do not take land here. They are checked
against the schema (parameters, permissions) with PVE's errors, then answered
with a value built from the method's `returns`. Methods that start a worker
task return a real UPID. Nothing is stored.
"""

import urllib.parse

from aiohttp import web

from . import schema as pve_schema
from .model import PveError

# Methods that look like tasks by their result but return something else.
NOT_TASKS = {('POST', '/cluster/sdn/lock'), ('POST', '/nodes/{node}/qemu/{vmid}/monitor')}


def root_only(user):
    return user is None or user.split('!')[0] == 'root@pam'


class GenericApi(object):
    """Mixin for FakePve: the catch-all route and its schema checks."""

    def resolve(self, request, prefix):
        """The schema match of a request path, or None."""
        raw = request.rel_url.raw_path[len(prefix):]
        path = '/'.join(urllib.parse.unquote(seg) for seg in raw.split('/'))
        return pve_schema.load().match(path)

    def is_world(self, match, method):
        """True if the method needs no login."""
        info = match and match.methods.get(method)
        return bool(info) and (info.get('permissions') or {}).get('user') == 'world'

    async def answer(self, request, match, params, user):
        """The data for a request the hand-written routes did not take."""
        if match is None:
            raise web.HTTPNotFound()
        method = request.method
        info = match.methods.get(method)
        if info is None:
            raise PveError(501, "Method '{0} {1}' not implemented".format(method, request.path))
        values = dict(params)
        values.update(match.params)
        values, errors = pve_schema.validate(info.get('parameters'), values)
        if errors:
            raise PveError(400, 'Parameter verification failed.', errors)
        if 'node' in match.params and match.params['node'] not in self.nodes:
            raise PveError(500, "hostname lookup '{0}' failed - failed to get address info for: {0}: "
                                "Name or service not known".format(match.params['node']))
        self.check_permissions(user, info.get('permissions'), values)
        return await self.synthesise(match, method, info, user, values)

    # ---------------------------------------------------------- permissions

    def check_permissions(self, user, perms, values):
        if perms is None:
            ok, why = (self.acl is None or root_only(user)), 'user != root@pam'
        elif 'check' in perms:
            ok, why = self._check(user, perms['check'], values)
        elif perms.get('user') in ('all', 'world'):
            return
        else:
            ok, why = self.acl is None or root_only(user), 'user != root@pam'
        if not ok:
            raise PveError(403, 'Permission check failed ({0})'.format(why))

    def _has(self, user, path, priv):
        try:
            return self.allowed(user, path, priv)
        except ValueError:  # '/vms/<not a number>'
            return False

    def _check(self, user, check, values):
        """Evaluate one permission rule: (allowed, reason)."""
        form = check[0]
        if form == 'perm':
            path = check[1]
            opts = dict(zip(check[3::2], check[4::2]))
            for name in set(self._names(path)):
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
                ok, why = self._check(user, sub, values)
                if ok == (form == 'or'):
                    return ok, why
            return form == 'and', why
        if form == 'userid-param' and check[1] == 'self':
            userid = values.get('userid')
            return userid is not None and userid == user.split('!')[0], 'user != self'
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
        return self.acl is None or root_only(user), 'user != root@pam'

    @staticmethod
    def _names(path):
        return [seg[1:-1] for seg in path.split('/') if seg.startswith('{') and seg.endswith('}')]

    # -------------------------------------------------------------- results

    async def synthesise(self, match, method, info, user, values):
        returns = info.get('returns') or {}
        if pve_schema.is_task(method, info) and (method, match.template) not in NOT_TASKS:
            node = values.get('node')
            if node not in self.nodes:
                node = sorted(self.nodes)[0]
            ttype = match.template.rstrip('/').rsplit('/', 1)[-1].strip('{}')

            async def body():
                return None
            return await self.task(node, ttype, values.get('vmid', ''), user or 'root@pam', body)
        ctx = {'node': sorted(self.nodes)[0], 'storage': sorted(self.storages)[0]}
        if self.vms:
            ctx['vmid'] = self.vms[0].vmid
        ctx.update(values)
        data = pve_schema.sample(returns, '', ctx)
        links = returns.get('links') or []
        if returns.get('type') == 'array' and not (returns.get('items') or {}).get('properties') and links:
            # A directory listing: one entry per named child.
            key = links[0].get('href', '').strip('{}')
            kids = pve_schema.load().children(match.template)
            if key and (returns.get('items') or {}).get('type') == 'object':
                data = [{key: kid} for kid in kids[:1]] or [{key: 'fake'}]
        return data
