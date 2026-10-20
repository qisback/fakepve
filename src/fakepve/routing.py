"""Shared plumbing for the stateful API areas (storage, pools, firewall).

An area is a mixin of FakePve with methods named `_routes_<area>` that list
`(method, schema path template, handler)`. FakePve._build_app registers them
in front of the catch-all route. A handler is `async def (self, values, user)`:
it runs after the schema's checks (parameters, permissions) and returns the
`data` of the answer, or raises PveError.
"""

import hashlib
import re

from aiohttp import web

from . import schema as pve_schema
from .model import PveError

DIGEST_CHANGED = 'detected modified configuration - file changed by other user? Try again.'


def ok(data=None):
    return web.json_response({'data': data})


def param_error(**fields):
    """PVE's raise_param_exc: a 400 with a message per field."""
    return PveError(400, 'Parameter verification failed.', fields)


def die(message):
    """A `die "...\\n"` inside an API handler: status 500 and the message."""
    return PveError(500, message)


def check_digest(current, given):
    """PVE::Tools::assert_if_modified."""
    if given and current and given != current:
        raise die(DIGEST_CHANGED)


def sha1(text):
    return hashlib.sha1(text.encode()).hexdigest()


def split_list(text):
    """PVE::Tools::split_list: items separated by commas, semicolons or white space."""
    return [item for item in re.split(r'[\s,;]+', str(text or '')) if item]


class StatefulRoutes(object):
    """Mixin of FakePve: registers the `_routes_*` tables."""

    def _register_stateful(self, router, prefixes):
        for name in sorted(dir(self)):
            if not name.startswith('_routes_'):
                continue
            for method, template, handler in getattr(self, name)():
                if method not in pve_schema.load().paths[template]:
                    raise KeyError('{0} {1} is not in the schema'.format(method, template))
                path = template.replace('{volume}', '{volume:.+}').replace('{cidr}', '{cidr:.+}') \
                    .replace('/pools/{poolid}', '/pools/{poolid:.+}')
                for prefix in prefixes:
                    router.add_route(method, prefix + path, self._stateful_handler(template, handler))

    def _stateful_handler(self, template, handler):
        async def serve(request):
            from .server import USER, params  # late: server imports this module
            match = pve_schema.Match(template, dict(request.match_info), pve_schema.load().paths[template])
            user = request[USER]

            async def call(_match, values):
                return await handler(values, user)
            return ok(await self.answer(request, match, await params(request), user, call))
        return serve
