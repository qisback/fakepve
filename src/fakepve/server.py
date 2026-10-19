"""A fake Proxmox VE API for testing Proxmox clients without a cluster.

Served over TLS with the behaviour PVE 8/9 shows: tickets with CSRF tokens
and expiry, API tokens, optional per-path permissions, tasks with UPIDs that
run, hold the VM config lock and log, pending config on running VMs, config
digests, and the termproxy and VNC websockets. Errors carry PVE's own status
codes and messages.

Every instance listens on its own loopback address (127.0.0.0/8 is all
local on Linux), so clients can use PVE's usual port, 8006. See model.Model
for the scenarios: delayed shutdowns, locked VMs, lost quorum, offline
nodes, migrations, network and Ceph trouble, and more.
"""

import asyncio
import hmac
import itertools
import json
import logging
import random
import re
import secrets
import time
import urllib.parse

import aiohttp
from aiohttp import web

from . import errors
from . import schema as pve_schema
from .generic import GenericApi
from .model import FakeVm, Model, PveError, TaskError

PORT = 8006  # PVE's API port; clients often assume it
_hostseq = itertools.count(2)
API = '/api2/json'
# Guest agent commands answered, and the key of vm.agent each reads.
AGENT_COMMANDS = {'get-osinfo': 'os', 'network-get-interfaces': 'interfaces', 'ping': None}
# Where the authenticated user is kept on the request.
USER = web.RequestKey('user', str) if hasattr(web, 'RequestKey') else 'user'
GENERIC = web.RequestKey('generic', object) if hasattr(web, 'RequestKey') else 'generic'

__all__ = ['PORT', 'FakePve', 'FakeVm', 'next_loopback', 'settle']


def next_loopback():
    """The next unused loopback address, so each instance can use port 8006."""
    n = next(_hostseq)
    return '127.0.{0}.{1}'.format(n // 250, n % 250 + 2)


def ok(data=None):
    return web.json_response({'data': data})


def error(status, message, errors=None):
    body = {'data': None, 'message': message + '\n'}
    if errors:
        body['errors'] = errors
    return web.json_response(body, status=status, reason=message.splitlines()[0][:200])


def bad_request(**fields):
    """PVE's 400 with a message per field."""
    return PveError(400, 'Parameter verification failed.', fields)


async def params(request):
    """Request parameters as PVE takes them: query string, form or JSON body."""
    out = dict(request.query)
    body = await request.read()
    if not body or request.content_type == 'multipart/form-data':
        return out
    try:
        if request.content_type == 'application/json':
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError('not an object')
            out.update(data)
        else:
            out.update(urllib.parse.parse_qsl(body.decode()))
    except RecursionError:
        raise bad_request(body='JSON nested too deeply') from None
    except UnicodeDecodeError:
        raise bad_request(body='request body is not valid UTF-8') from None
    except ValueError:
        raise bad_request(body='request body is not a JSON object' if request.content_type == 'application/json'
                          else 'malformed request body') from None
    return out


def int_param(values, name, default=None, minimum=None):
    """An integer parameter, or PVE's 400 for one that is not."""
    if values.get(name) is None:
        return default
    value, err = pve_schema.check_value({'type': 'integer', 'minimum': minimum} if minimum is not None
                                        else {'type': 'integer'}, values[name])
    if err:
        raise bad_request(**{name: err})
    return value


# Parameters whose values never reach pve.requests.
SECRET_KEYS = ('password', 'new-password', 'confirmation-password', 'ticket', 'vncticket', 'otp', 'tfa-challenge')
SECRET_FORM = re.compile(rb'(?<![^&])((?:' + b'|'.join(re.escape(k.encode()) for k in SECRET_KEYS) + rb')=)[^&]*')
# Recorded bodies are cut here, so a large upload does not sit in memory a second time.
RECORDED_BODY_MAX = 64 * 1024


def _redact_json(node):
    if isinstance(node, dict):
        return dict((k, '***' if k in SECRET_KEYS else _redact_json(v)) for k, v in node.items())
    if isinstance(node, list):
        return [_redact_json(v) for v in node]
    return node


def redact(body, content_type):
    """The body as recorded: secrets replaced by ***, long bodies cut."""
    if content_type == 'application/json':
        try:
            data = json.loads(body)
            clean = _redact_json(data)
            if clean != data:
                body = json.dumps(clean).encode()
        except (ValueError, RecursionError):
            body = b''  # unparseable, so it could hold anything
    elif content_type != 'multipart/form-data':
        body = SECRET_FORM.sub(rb'\g<1>***', body)
    return body[:RECORDED_BODY_MAX]


class BodyTimeout(Exception):
    """The client stopped sending its request body."""


class FakePve(GenericApi, Model):
    def __init__(self, user='root@pam', password='secret', host=None, port=PORT):
        super().__init__(user, password)
        self.host = host or next_loopback()
        self.port = port
        self.runner = None
        self.termdata = []
        self.monitor_allowed = True
        self.uploaded = None
        # Largest request body accepted, in bytes (PVE's own limit is similar for uploads).
        self.client_max_size = 64 * 1024 ** 2
        # Real seconds a client may take to send its request body; 0 waits for ever.
        self.body_timeout = 30.0
        self._random = random.Random()

    # ------------------------------------------------------------- lifecycle

    def _build_app(self):
        app = web.Application(middlewares=[self._middleware], client_max_size=self.client_max_size)
        r = app.router
        r.add_post(API + '/access/ticket', self._ticket)
        r.add_put(API + '/access/password', self._password)
        r.add_get(API + '/version', self._version)
        r.add_get(API + '/nodes', self._nodes)
        r.add_get(API + '/cluster/resources', self._resources)
        r.add_get(API + '/cluster/status', self._cluster_status)
        r.add_get(API + '/cluster/ceph/status', self._ceph_status)
        node = API + '/nodes/{node}'
        r.add_get(node + '/tasks', self._task_list)
        r.add_get(node + '/tasks/{upid}/status', self._task_status)
        r.add_get(node + '/tasks/{upid}/log', self._task_log)
        r.add_get(node + '/storage', self._storage_list)
        r.add_get(node + '/storage/{storage}/content', self._storage_content)
        r.add_post(node + '/storage/{storage}/download-url', self._download_url)
        r.add_post(node + '/storage/{storage}/upload', self._upload)
        qemu = node + '/qemu/{vmid}'
        r.add_get(qemu + '/status/current', self._status_current)
        r.add_post(qemu + '/status/{action}', self._status_action)
        r.add_get(qemu + '/config', self._config_get)
        r.add_put(qemu + '/config', self._config_put)
        r.add_post(qemu + '/config', self._config_post)
        r.add_get(qemu + '/pending', self._pending)
        r.add_post(qemu + '/termproxy', self._termproxy)
        r.add_post(qemu + '/vncproxy', self._vncproxy)
        r.add_get(qemu + '/vncwebsocket', self._vncwebsocket)
        r.add_get(qemu + '/agent/{command}', self._agent)
        r.add_post(qemu + '/agent/{command}', self._agent)
        r.add_post(qemu + '/monitor', self._monitor)
        # Last, so the routes above keep priority: the rest of the schema.
        r.add_route('*', API + '/{tail:.*}', self._generic)
        return app

    async def start(self, certfile, keyfile):
        """Listen on https://host:port with this certificate and key (PEM files)."""
        import ssl
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile, keyfile)
        if self.network.get('seed') is not None:
            self._random.seed(self.network['seed'])
        self.runner = web.AppRunner(self._build_app())
        await self.runner.setup()
        await web.TCPSite(self.runner, self.host, self.port, ssl_context=ctx).start()

    async def stop(self):
        """Stop listening."""
        if self.runner:
            await self.runner.cleanup()
            self.runner = None

    # ------------------------------------------------------------ middleware

    @web.middleware
    async def _middleware(self, request, handler):
        net = self.network
        generic = request[GENERIC] = self.resolve(request, API) if 'tail' in request.match_info else None
        path_node = request.match_info.get('node') or (generic and generic.params.get('node'))
        # Network trouble hits every client, logged in or not; injected failures only hit those who are.
        delay = net['latency'] + self._random.uniform(0, net['jitter']) + net['node_latency'].get(path_node, 0)
        await self.pause(delay)
        if net['drop_rate'] and self._random.random() < net['drop_rate']:
            request.transport.close()
            raise ConnectionResetError('fakepve: connection dropped')
        if net['hang_rate'] and self._random.random() < net['hang_rate']:
            await asyncio.sleep(net['hang_secs'] * (self.time_scale or 1))
        try:
            request[USER] = self._authenticate(request)
        except PveError as e:
            # Some generic endpoints (realm list, ...) need no login.
            if not (generic and self.is_world(generic, request.method)):
                self._record(request, b'')
                return error(e.status, e.message, e.errors)
            request[USER] = None
        try:
            body = await self._read_body(request)
        except BodyTimeout:
            self._record(request, b'')
            return self._closing(error(408, 'Request Timeout: the request body did not arrive in time'))
        except web.HTTPRequestEntityTooLarge:
            self._record(request, b'')
            return self._closing(error(413, 'Request body too large'))
        self._record(request, body)
        try:
            return await self._answer(request, handler, generic, path_node)
        except (PveError, web.HTTPException, asyncio.CancelledError):
            raise
        except Exception:  # noqa: BLE001 - nothing may reach the client as a traceback
            logging.getLogger('fakepve').exception('unhandled error in %s %s', request.method, request.path)
            return error(500, 'internal error')

    async def _answer(self, request, handler, generic, path_node):
        task_failure = None
        for key, rule in list(self.failures.items()):
            if request.method != key[0] or not self._failure_matches(request, generic, key[1]):
                continue
            if rule['times'] is not None:
                rule['times'] -= 1
                if rule['times'] <= 0:
                    del self.failures[key]
            if rule['error'] is None:
                if rule['html']:
                    return web.Response(status=rule['status'], text=rule['message'], content_type='text/html')
                return error(rule['status'], rule['message'])
            try:
                entry, status, message, errs, match = await self._named_failure(request, generic, rule['error'])
            except PveError as e:
                return error(e.status, e.message)
            if not entry['in_task']:
                return error(status, message, errs)
            task_failure = (message, match)
            break
        try:
            if path_node and path_node in self.nodes and not self.nodes[path_node].get('online', True):
                raise PveError(595, 'No route to host')
            if task_failure:
                return ok(await self._failed_task(request, path_node, *task_failure))
            return await handler(request)
        except PveError as e:
            return error(e.status, e.message, e.errors)

    async def _read_body(self, request):
        """The whole request body, within body_timeout real seconds."""
        try:
            return await asyncio.wait_for(request.read(), self.body_timeout or None)
        except asyncio.TimeoutError:
            raise BodyTimeout() from None

    @staticmethod
    def _closing(response):
        """Answer, then close the connection: the rest of the body will not be read."""
        response.force_close()
        return response

    def _record(self, request, body):
        """Add the request to pve.requests, secrets redacted, and drop the oldest beyond max_requests."""
        self.requests.append((request.method, request.path, redact(body, request.content_type)))
        excess = len(self.requests) - self.max_requests
        if excess > 0:
            del self.requests[:excess]

    def _failure_matches(self, request, generic, suffix):
        if '{' in suffix:  # a schema path template
            match = generic or self.resolve(request, API)
            return match is not None and match.template == suffix.rstrip('/')
        return request.path.endswith(suffix)

    async def _named_failure(self, request, generic, name):
        """A catalogue error for this request: (entry, status, message, errors, match) with placeholders filled."""
        match = generic or self.resolve(request, API)
        entry = errors.find(request.method, request.path, name) if match else None
        if entry is None:
            raise PveError(500, 'fakepve: no error {0!r} for {1} {2}'.format(name, request.method, request.path))
        values = dict(await params(request))
        values.update(match.params)
        values.setdefault('method', request.method)
        values.setdefault('path', request.path)
        names = [p for p in ((match.methods.get(request.method) or {}).get('parameters') or {}).get('properties', {})
                 if p not in match.params]
        status, message, errs = errors.render(entry, match.template, values, names)
        return entry, status, message, errs, match

    async def _failed_task(self, request, path_node, message, match):
        """The UPID of a task that ends with TASK ERROR: message."""
        node = path_node if path_node in self.nodes else sorted(self.nodes)[0]
        user = request[USER] or 'root@pam'

        async def body():
            raise TaskError(message)
        return await self.task(node, errors.task_type(match.template), match.params.get('vmid', ''), user, body)

    def _authenticate(self, request):
        if request.path == API + '/access/ticket':
            return None
        auth = request.headers.get('Authorization', '')
        if auth.startswith('PVEAPIToken='):
            tokenid, _, secret = auth[len('PVEAPIToken='):].partition('=')
            if self.apitokens.get(tokenid) != secret:
                raise PveError(401, 'authentication failure')
            return tokenid
        ticket = request.cookies.get('PVEAuthCookie')
        session = self.tickets.get(ticket)
        if session is None or session['expires'] < time.time():
            raise PveError(401, 'permission denied - invalid PVE ticket')
        if request.method not in ('GET', 'HEAD') and request.headers.get('CSRFPreventionToken') != session['csrf']:
            raise PveError(401, 'Permission denied - invalid csrf token')
        return session['user']

    async def _generic(self, request):
        data = await self.answer(request, request[GENERIC], await params(request), request[USER])
        return ok(data)

    # --------------------------------------------------------------- access

    async def _ticket(self, request):
        p = await params(request)
        user, password = str(p.get('username', '')), p.get('password', '')
        if '@' not in user:
            user += '@pam'
        if not self.check_password(user, password):
            raise PveError(401, 'authentication failure')
        if self.tfa:
            return ok({'ticket': 'PVE:!tfa!{0}'.format(secrets.token_hex(8)), 'username': user, 'NeedTFA': 1,
                       'CSRFPreventionToken': secrets.token_hex(8)})
        ticket, csrf = self.issue_ticket(user)
        return ok({'ticket': ticket, 'CSRFPreventionToken': csrf, 'username': user, 'cap': {}})

    async def _password(self, request):
        # PVE: allowtoken 0; anyone may change their own password, but only root without confirming the old one.
        user = request[USER]
        if '!' in user:
            raise PveError(403, 'Permission check failed (API token not allowed)')
        p = self._verify(request, await params(request))
        userid = p['userid']
        if userid != user and user != 'root@pam':
            raise PveError(403, 'Permission check failed (/access, User.Modify)')
        if user != 'root@pam':
            confirmation = p.get('confirmation-password')
            if confirmation is None:
                raise bad_request(**{'confirmation-password': 'password is required to modify user'})
            if not self.check_password(user, confirmation):
                raise PveError(500, 'authentication failure')
        if userid == self.user:
            self.password = p['password']
        else:
            self.users[userid] = p['password']
        return ok()

    async def _version(self, request):
        return ok({'version': self.version, 'release': self.release_version, 'repoid': 'fakepve'})

    # -------------------------------------------------------------- cluster

    async def _nodes(self, request):
        return ok([{'node': n, 'status': 'online' if s.get('online', True) else 'offline', 'type': 'node'}
                   for n, s in sorted(self.nodes.items())])

    async def _resources(self, request):
        kind = request.query.get('type')
        data = []
        for vm in self.vms:
            online = self.nodes.get(vm.node, {}).get('online', True)
            if kind not in (None, 'vm') or not self.allowed(request[USER], '/vms/{0}'.format(vm.vmid), 'VM.Audit'):
                continue
            item = {'id': vm.guest, 'type': 'qemu', 'node': vm.node, 'name': vm.name, 'vmid': vm.vmid,
                    'status': vm.status if online else 'unknown', 'template': 1 if vm.template else 0}
            if vm.lock:
                item['lock'] = vm.lock
            if vm.pool:
                item['pool'] = vm.pool
            if vm.ha_managed:
                item['hastate'] = vm.ha_state
            data.append(item)
        if kind in (None, 'node'):
            for name, state in sorted(self.nodes.items()):
                data.append({'id': 'node/' + name, 'type': 'node', 'node': name,
                             'status': 'online' if state.get('online', True) else 'offline'})
        if kind in (None, 'storage'):
            for node in sorted(self.nodes):
                for name, store in self.storages.items():
                    data.append({'id': 'storage/{0}/{1}'.format(node, name), 'type': 'storage', 'node': node,
                                 'storage': name, 'status': 'available' if store.get('active') else 'unknown'})
        return ok(data)

    async def _cluster_status(self, request):
        online = sum(1 for s in self.nodes.values() if s.get('online', True))
        data = [{'type': 'cluster', 'id': 'cluster', 'name': self.cluster_name, 'nodes': len(self.nodes),
                 'quorate': 1 if self.quorate else 0, 'version': 1}]
        for idx, (name, state) in enumerate(sorted(self.nodes.items()), 1):
            data.append({'type': 'node', 'id': 'node/' + name, 'name': name, 'nodeid': idx,
                         'online': 1 if state.get('online', True) else 0, 'local': 1 if idx == 1 else 0})
        data[0]['online'] = online
        return ok(data)

    async def _ceph_status(self, request):
        if self.ceph['down']:
            raise PveError(500, 'rados_connect failed - Connection timed out')
        return ok({'health': {'status': self.ceph['health']}, 'fsid': '00000000-fake-ceph'})

    # ---------------------------------------------------------------- tasks

    def _task_view(self, task):
        return dict((k, v) for k, v in task.items() if k != 'log')

    def _verify(self, request, values, drop=()):
        """The values checked against the method's schema, as the generic handler does: PVE's 400 on errors."""
        info = self.resolve(request, API).methods[request.method]
        values = dict((k, v) for k, v in values.items() if k not in drop)
        values.update(request.match_info)
        values, errs = pve_schema.validate(info.get('parameters'), values)
        if errs:
            raise PveError(400, 'Parameter verification failed.', errs)
        return values

    @staticmethod
    def _task_owner(user, task):
        """PVE: a user sees its own tasks and those of its tokens; a token only its own."""
        owner = task['user']
        return user == owner or user == owner.split('!')[0]

    async def _task_list(self, request):
        node = request.match_info['node']
        user = request[USER]
        p = self._verify(request, await params(request))
        vmid = p.get('vmid')
        audit = self.allowed(user, '/nodes/' + node, 'Sys.Audit')
        data = [self._task_view(t) for t in self.tasklog
                if t['node'] == node and (vmid is None or t['id'] == str(vmid))
                and (audit or self._task_owner(user, t))]
        data.sort(key=lambda t: -t['starttime'])
        start = p.get('start', 0)
        return ok(data[start:start + p.get('limit', 50)])

    def _get_task(self, request):
        """The task of the request's UPID; PVE lets its owner and Sys.Audit on the node see it."""
        task = self.tasks.get(request.match_info['upid'])
        if task is None or task['node'] != request.match_info['node']:
            raise PveError(500, "unable to parse worker upid '{0}'".format(request.match_info['upid']))
        user = request[USER]
        if not self._task_owner(user, task):
            self.require(user, '/nodes/' + task['node'], 'Sys.Audit')
        return task

    async def _task_status(self, request):
        self._verify(request, await params(request))
        return ok(self._task_view(self._get_task(request)))

    async def _task_log(self, request):
        p = self._verify(request, await params(request))
        lines = self._get_task(request)['log']
        start, limit = p.get('start', 0), p.get('limit', 50)
        return ok([{'n': n + 1, 't': t} for n, t in enumerate(lines)][start:start + limit])

    # -------------------------------------------------------------- storage

    async def _storage_list(self, request):
        user = request[USER]
        content = request.query.get('content')
        data = []
        for name, store in self.storages.items():
            if content and content not in store.get('content', ''):
                continue
            if not (self.allowed(user, '/storage/' + name, 'Datastore.Audit')
                    or self.allowed(user, '/storage/' + name, 'Datastore.AllocateSpace')):
                continue
            data.append({'storage': name, 'type': store.get('type', 'dir'), 'content': store.get('content', ''),
                         'active': store.get('active', 1), 'enabled': 1, 'shared': store.get('shared', 0)})
        return ok(data)

    def _storage(self, request):
        name = request.match_info['storage']
        if name not in self.storages:
            raise PveError(500, "storage '{0}' does not exist".format(name))
        store = self.storages[name]
        if store.get('type') == 'rbd' and self.ceph['down']:
            raise PveError(500, 'rbd error: rbd: listing images failed: (110) Connection timed out')
        if not store.get('active', 1):
            raise PveError(500, "storage '{0}' is not online".format(name))
        return name, store

    async def _storage_content(self, request):
        name, store = self._storage(request)
        self.require(request[USER], '/storage/' + name, 'Datastore.Audit')
        return ok([{'volid': '{0}:iso/{1}'.format(name, f), 'content': 'iso', 'format': 'iso'}
                   for f in sorted(store['files'])])

    async def _download_url(self, request):
        name, store = self._storage(request)
        user = request[USER]
        self.require(user, '/storage/' + name, 'Datastore.AllocateTemplate')
        self.require(user, '/', 'Sys.Audit')
        self.require(user, '/', 'Sys.Modify')
        p = await params(request)
        # size is the fake's own parameter: how large the download pretends to be.
        size = int_param(p, 'size', 1024 ** 2, minimum=0)
        p = self._verify(request, p, drop=('size',))

        async def body():
            await self.pause(5)
            self.store_file(name, p['filename'], size)
        return ok(await self.task(request.match_info['node'], 'download', name, user, body,
                                  log=['downloading {0} to {1}'.format(p.get('url'), p.get('filename'))]))

    async def _upload(self, request):
        name, store = self._storage(request)
        user = request[USER]
        self.require(user, '/storage/' + name, 'Datastore.AllocateTemplate')
        body = await request.read()
        try:
            boundary = request.content_type == 'multipart/form-data' and \
                request.headers['Content-Type'].split('boundary=', 1)[1]
            if not boundary or int(request.headers.get('Content-Length', -1)) != len(body):
                raise ValueError('not a complete multipart body')
            fields = {}
            for part in body.split(b'--' + boundary.encode())[1:-1]:
                head, _, data = part[2:-2].partition(b'\r\n\r\n')
                disposition = head.decode().split('\r\n')[0]
                field = disposition.split('name="', 1)[1].split('"', 1)[0]
                if 'filename="' in disposition:
                    fields['filename'] = disposition.split('filename="', 1)[1].split('"', 1)[0]
                    fields['data'] = data
                else:
                    fields[field] = data.decode()
        except (IndexError, ValueError):  # UnicodeDecodeError is one
            raise PveError(400, 'bad upload request') from None
        if fields.get('content') != 'iso':
            raise PveError(400, 'Parameter verification failed.', {'content': 'value not allowed'})
        self.uploaded = fields

        async def body_():
            self.store_file(name, fields['filename'], len(fields.get('data', b'')))
        return ok(await self.task(request.match_info['node'], 'imgcopy', '', user, body_))

    # ------------------------------------------------------------------ VMs

    def _vm(self, request, priv=None):
        vmid, err = pve_schema.check_value({'type': 'integer', 'minimum': 100}, request.match_info['vmid'])
        if err:
            raise bad_request(vmid=err)
        vm = self.find(request.match_info['node'], vmid)
        if priv:
            self.require(request[USER], '/vms/{0}'.format(vm.vmid), priv)
        return vm

    async def _status_current(self, request):
        vm = self._vm(request, 'VM.Audit')
        data = {'vmid': vm.vmid, 'name': vm.name, 'status': vm.status, 'qmpstatus': vm.qmpstatus,
                'cpus': int(vm.config.get('cores', 1)) * int(vm.config.get('sockets', 1)),
                'maxmem': int(str(vm.config.get('memory', 512)).split('=')[-1]) * 1048576,
                'cpu': 0.02 if vm.status == 'running' else 0,
                'mem': 67108864 if vm.status == 'running' else 0,
                'uptime': int(time.time() - vm.started_at) if vm.status == 'running' and vm.started_at else 0,
                'ha': {'managed': 1, 'state': vm.ha_state} if vm.ha_managed else {'managed': 0},
                'running-qemu': '10.0.2' if vm.status == 'running' else None}
        if vm.lock:
            data['lock'] = vm.lock
        if vm.template:
            data['template'] = 1
        data.update(vm.stats)
        return ok(dict((k, v) for k, v in data.items() if v is not None))

    def _check_lock(self, vm, allow=()):
        if vm.lock and vm.lock not in allow:
            raise PveError(500, 'VM is locked ({0})'.format(vm.lock))

    def _need_running(self, vm):
        if vm.status != 'running':
            raise PveError(500, 'VM {0} not running'.format(vm.vmid))

    async def _status_action(self, request):
        action = request.match_info['action']
        vm = self._vm(request, 'VM.PowerMgmt')
        user = request[USER]
        p = await params(request)
        int_param(p, 'timeout', minimum=0)
        handler = getattr(self, '_do_' + action, None)
        if handler is None:
            raise PveError(501, "Method 'POST /nodes/{0}/qemu/{1}/status/{2}' not implemented".format(
                vm.node, vm.vmid, action))
        self.need_quorum()
        return ok(await handler(vm, user, p))

    async def _ha_request(self, vm, user, state):
        async def body():
            async def later():
                await self.pause(self.ha_delay)
                if state == 'started':
                    vm.apply_pending()
                    vm.status = vm.qmpstatus = 'running'
                    vm.started_at = time.time()
                else:
                    vm.status = vm.qmpstatus = 'stopped'
                vm.ha_state = state
            if self.time_scale:
                asyncio.ensure_future(later())
            else:
                await later()
        verb = 'start' if state == 'started' else 'stop'
        return await self.task(vm.node, 'ha' + verb, vm.vmid, user, body, lock=False,
                               log=['Requesting HA {0} for VM {1}'.format(verb, vm.vmid)])

    async def _do_start(self, vm, user, p):
        if vm.template:
            raise PveError(500, "you can't start a vm if it's a template")
        if vm.status == 'running':
            raise PveError(500, 'VM {0} already running'.format(vm.vmid))
        self._check_lock(vm, allow=('suspended',))
        if vm.ha_managed:
            return await self._ha_request(vm, user, 'started')

        async def body():
            await self.ceph_io(vm)
            await self.pause(vm.start_secs)
            if vm.start_error:
                raise TaskError(vm.start_error)
            vm.apply_pending()
            if vm.lock == 'suspended':
                vm.lock = None
                vm.config.pop('lock', None)
            vm.status = vm.qmpstatus = 'running'
            vm.started_at = time.time()
        return await self.task(vm.node, 'qmstart', vm.vmid, user, body, vm=vm)

    async def _do_stop(self, vm, user, p):
        if not p.get('skiplock'):
            self._check_lock(vm)
        if vm.ha_managed:
            return await self._ha_request(vm, user, 'stopped')

        async def body():
            await self.pause(vm.stop_secs)
            vm.status = vm.qmpstatus = 'stopped'
        return await self.task(vm.node, 'qmstop', vm.vmid, user, body, vm=vm)

    async def _powerdown(self, vm, p):
        """Ask the guest to power off; PVE's task gives up at the timeout."""
        timeout = int(p.get('timeout') or self.shutdown_default_timeout)
        if vm.acpi and vm.shutdown_secs <= timeout:
            await self.pause(vm.shutdown_secs)
            vm.status = vm.qmpstatus = 'stopped'
            return None
        await self.pause(timeout)
        if str(p.get('forceStop', '0')) in ('1', 'true'):
            vm.status = vm.qmpstatus = 'stopped'
            return 'VM still running - terminating now with SIGTERM'
        raise TaskError('VM quit/powerdown failed - got timeout')

    async def _do_shutdown(self, vm, user, p):
        self._need_running(vm)
        self._check_lock(vm)
        if vm.ha_managed:
            return await self._ha_request(vm, user, 'stopped')
        return await self.task(vm.node, 'qmshutdown', vm.vmid, user, lambda: self._powerdown(vm, p), vm=vm)

    async def _do_reboot(self, vm, user, p):
        self._need_running(vm)
        self._check_lock(vm)

        async def body():
            await self._powerdown(vm, p)
            await self.ceph_io(vm)
            vm.apply_pending()
            vm.status = vm.qmpstatus = 'running'
            vm.started_at = time.time()
        return await self.task(vm.node, 'qmreboot', vm.vmid, user, body, vm=vm)

    async def _do_reset(self, vm, user, p):
        self._need_running(vm)
        self._check_lock(vm)

        async def body():
            vm.started_at = time.time()
        return await self.task(vm.node, 'qmreset', vm.vmid, user, body, vm=vm)

    async def _do_suspend(self, vm, user, p):
        self._need_running(vm)
        self._check_lock(vm)
        todisk = str(p.get('todisk', '0')) in ('1', 'true')

        async def body():
            if todisk:
                await self.ceph_io(vm)
                vm.status = vm.qmpstatus = 'stopped'
                vm.lock = 'suspended'
                vm.config['lock'] = 'suspended'
            else:
                vm.qmpstatus = 'paused'
        return await self.task(vm.node, 'qmsuspend', vm.vmid, user, body, vm=vm)

    async def _do_resume(self, vm, user, p):
        self._need_running(vm)

        async def body():
            vm.qmpstatus = 'running'
        return await self.task(vm.node, 'qmresume', vm.vmid, user, body, vm=vm)

    # --------------------------------------------------------------- config

    async def _config_get(self, request):
        # The current config; /pending shows what the next start will use.
        vm = self._vm(request, 'VM.Audit')
        cfg = dict(vm.config)
        cfg['digest'] = vm.digest()
        return ok(cfg)

    async def _pending(self, request):
        vm = self._vm(request, 'VM.Audit')
        data = []
        for key in sorted(set(vm.config) | set(vm.pending)):
            item = {'key': key}
            if key in vm.config:
                item['value'] = vm.config[key]
            if key in vm.pending:
                if vm.pending[key] is None:
                    item['delete'] = 1
                else:
                    item['pending'] = vm.pending[key]
            data.append(item)
        return ok(data)

    def _config_priv(self, key):
        if key == 'boot' or key.startswith(('scsi', 'virtio', 'sata', 'efidisk', 'tpmstate', 'unused')):
            return 'VM.Config.Disk'
        if key.startswith('ide'):
            return 'VM.Config.Disk'
        if key in ('cores', 'sockets', 'vcpus', 'cpu', 'cpulimit', 'cpuunits', 'numa'):
            return 'VM.Config.CPU'
        if key in ('memory', 'balloon', 'shares'):
            return 'VM.Config.Memory'
        if key.startswith('net'):
            return 'VM.Config.Network'
        if key in ('name', 'description', 'onboot', 'tags', 'protection', 'startup', 'agent'):
            return 'VM.Config.Options'
        if key == 'hookscript':
            return 'root'
        return 'VM.Config.HWType'

    async def _apply_config(self, vm, user, p):
        self.need_quorum()
        updates = dict(p)
        digest = updates.pop('digest', None)
        if digest and digest != vm.digest():
            raise PveError(500, 'detected modified configuration - file changed by other user? Try again.')
        deletes = [k for k in str(updates.pop('delete', '') or '').split(',') if k]
        updates.pop('skiplock', None)
        for key in list(updates) + deletes:
            priv = self._config_priv(key)
            if priv == 'root':
                if user != 'root@pam':
                    raise PveError(403, "only root can set '{0}' config".format(key))
            elif key.startswith('ide') and 'media=cdrom' in str(updates.get(key, '')):
                self.require(user, '/vms/{0}'.format(vm.vmid), 'VM.Config.CDROM')
            else:
                self.require(user, '/vms/{0}'.format(vm.vmid), priv)
        self._check_lock(vm)
        if 'boot' in updates:
            order = str(updates['boot'])
            if order.startswith('order='):
                known = set(vm.devices({**vm.config, **{k: v for k, v in vm.pending.items() if v}, **updates}))
                for dev in order[len('order='):].split(';'):
                    if dev and dev not in known:
                        raise PveError(400, 'Parameter verification failed.',
                                       {'boot': "invalid bootorder: device '{0}' does not exist'".format(dev)})
        try:
            await self.acquire(vm, 'config')
        except TaskError as e:
            raise PveError(500, str(e)) from e
        try:
            disks = [k for k in list(updates) + deletes if k.startswith(('ide', 'sata', 'scsi', 'virtio',
                                                                         'efidisk', 'tpmstate'))]
            if disks:
                try:
                    await self.ceph_io(vm, disks)
                except TaskError as e:
                    raise PveError(500, str(e)) from e
            running = vm.status == 'running'
            for key in deletes:
                if running and key not in ('description', 'tags', 'onboot', 'protection', 'hookscript', 'lock'):
                    vm.pending[key] = None
                else:
                    vm.config.pop(key, None)
            for key, val in updates.items():
                cdswap = 'media=cdrom' in str(val) and 'media=cdrom' in str(vm.config.get(key, ''))
                if running and key not in ('name', 'description', 'onboot', 'tags', 'protection', 'startup',
                                           'agent', 'hookscript') and not cdswap:
                    vm.pending[key] = val
                else:
                    vm.config[key] = val
                    vm.pending.pop(key, None)
        finally:
            self.release(vm, 'config')

    async def _config_put(self, request):
        vm = self._vm(request)
        await self._apply_config(vm, request[USER], await params(request))
        return ok()

    async def _config_post(self, request):
        # The asynchronous form: a qmconfig task.
        vm = self._vm(request)
        p = await params(request)
        user = request[USER]
        self.need_quorum()

        async def body():
            try:
                await self._apply_config(vm, user, p)
            except PveError as e:
                raise TaskError(e.message) from e
        return ok(await self.task(vm.node, 'qmconfig', vm.vmid, user, body))

    # --------------------------------------------------------- guest agent

    async def _agent(self, request):
        vm = self._vm(request, 'VM.GuestAgent.Audit')
        command = request.match_info['command']
        if vm.status != 'running' or vm.agent is None:
            raise PveError(500, 'QEMU guest agent is not running')
        if vm.agent_hangs:
            await self.pause(10)
            raise PveError(500, "VM {0} qmp command 'guest-ping' failed - got timeout".format(vm.vmid))
        if command not in AGENT_COMMANDS:
            raise PveError(501, "Method 'GET /nodes/{0}/qemu/{1}/agent/{2}' not implemented".format(
                vm.node, vm.vmid, command))
        key = AGENT_COMMANDS[command]
        return ok({'result': vm.agent.get(key) if key else {}})

    async def _monitor(self, request):
        vm = self._vm(request, 'VM.Monitor')
        command = (await params(request)).get('command')
        if command is None:
            raise bad_request(command='property is missing and it is not optional')
        command = str(command)
        if not command.strip():
            raise bad_request(command='value must be at least 1 characters long')
        user = request[USER]
        if not command.startswith('info'):
            self.require(user, '/', 'Sys.Modify')
            if command.split()[0] in ('nmi',) and user != 'root@pam':
                raise PveError(500, "root-only command '{0}'".format(command.split()[0]))
        if not self.monitor_allowed:
            raise PveError(403, 'Permission check failed (/, Sys.Modify)')
        self._need_running(vm)
        if command == 'nmi':
            vm.nmis += 1
        return ok('')

    # -------------------------------------------------------------- consoles

    def _issue_vnc_ticket(self, request, vm, rfb):
        """A console ticket for the requesting user, valid for vnc_ticket_ttl real seconds and one connection."""
        vm.rfb = rfb
        vm.vncticket = 'PVEVNC:{0}'.format(secrets.token_hex(8))
        vm.vncuser = request[USER]
        vm.vncissued = time.time()

    async def _termproxy(self, request):
        vm = self._vm(request, 'VM.Console')
        self._issue_vnc_ticket(request, vm, False)
        return ok({'ticket': vm.vncticket, 'port': '5900', 'user': vm.vncuser,
                   'upid': 'UPID:{0}:termproxy:{1}:'.format(vm.node, vm.vmid)})

    async def _vncproxy(self, request):
        vm = self._vm(request, 'VM.Console')
        p = await params(request)
        if not p.get('websocket'):
            return await self._termproxy(request)
        self._issue_vnc_ticket(request, vm, True)
        vm.vncpassword = secrets.token_hex(4) if p.get('generate-password') else None
        data = {'ticket': vm.vncticket, 'port': '5900', 'user': vm.vncuser,
                'upid': 'UPID:{0}:vncproxy:{1}:'.format(vm.node, vm.vmid)}
        if vm.vncpassword:
            data['password'] = vm.vncpassword
        return ok(data)

    def _take_vnc_ticket(self, request, vm):
        """Consume the ticket the request presents, as PVE checks it: user, age, and a match. Returns (user, ticket)."""
        ticket = getattr(vm, 'vncticket', None)
        given = request.query.get('vncticket') or ''
        fresh = time.time() - getattr(vm, 'vncissued', 0) < self.vnc_ticket_ttl
        if not (ticket and fresh and request[USER] == vm.vncuser
                and hmac.compare_digest(given.encode(), ticket.encode())):
            raise PveError(401, 'permission denied - invalid PVEVNC ticket')
        vm.vncticket = None  # one connection per ticket
        return vm.vncuser, ticket

    async def _vncwebsocket(self, request):
        vm = self._vm(request, 'VM.Console')
        user, ticket = self._take_vnc_ticket(request, vm)
        ws = web.WebSocketResponse(protocols=('binary',))
        await ws.prepare(request)
        if getattr(vm, 'rfb', False):
            try:
                await self._rfb(ws, vm, vm.vncpassword or ticket)
            except ConnectionError:
                pass
            await ws.close()
            return ws
        hello = await ws.receive()
        if self.refuse_terminal or hello.type != aiohttp.WSMsgType.TEXT or \
                hello.data != '{0}:{1}\n'.format(user, ticket):
            await ws.close()
            return ws
        await ws.send_bytes(b'OK')
        await ws.send_bytes(b'starting serial terminal on interface serial0\r\n')
        async for frame in ws:
            if frame.type != aiohttp.WSMsgType.TEXT:
                break
            self.termdata.append(frame.data)
            kind, _, rest = frame.data.partition(':')
            if kind == '0':
                _, _, payload = rest.partition(':')
                await ws.send_bytes(payload.encode())
        return ws

    async def _rfb(self, ws, vm, secret):
        """A VNC server: RFB 3.8, VNC authentication, raw encoding (needs cryptography)."""
        import struct
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:  # cryptography < 43
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        width, height, rgb = getattr(vm, 'screen', (4, 2, bytes(range(24))))
        stream = b''

        async def read(size):
            nonlocal stream
            while len(stream) < size:
                frame = await ws.receive()
                if frame.type != aiohttp.WSMsgType.BINARY:
                    raise ConnectionError('client went away')
                stream += frame.data
            data, stream = stream[:size], stream[size:]
            return data
        await ws.send_bytes(b'RFB 003.008\n')
        if await read(12) != b'RFB 003.008\n':
            return
        await ws.send_bytes(b'\x01\x02')
        if await read(1) != b'\x02':
            return
        challenge = secrets.token_bytes(16)
        await ws.send_bytes(challenge)
        key = (secret.encode() + b'\0' * 8)[:8]
        key = bytes(int('{:08b}'.format(b)[::-1], 2) for b in key)
        enc = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()
        if await read(16) != enc.update(challenge) + enc.finalize():
            await ws.send_bytes(struct.pack('>I', 1))
            return
        await ws.send_bytes(struct.pack('>I', 0))
        await read(1)  # ClientInit
        name = vm.name.encode()
        await ws.send_bytes(struct.pack('>HHBBBBHHHBBBxxxI', width, height, 16, 16, 0, 1, 31, 63, 31,
                                        11, 5, 0, len(name)) + name)
        await read(20)  # SetPixelFormat
        count = struct.unpack('>xxH', await read(4))[0]
        await read(4 * count)  # SetEncodings
        await read(10)  # FramebufferUpdateRequest
        vm.screenshots = getattr(vm, 'screenshots', 0) + 1

        def raw(rows):
            out = bytearray()
            for y in rows:
                for x in range(width):
                    r, g, b = rgb[(y * width + x) * 3:(y * width + x) * 3 + 3]
                    out += bytes((b, g, r, 0))
            return bytes(out)
        await ws.send_bytes(b'\x02')
        top = height // 2
        await ws.send_bytes(struct.pack('>BxH', 0, 2) + struct.pack('>HHHHi', 0, 0, width, top, 0)
                            + raw(range(top)) + struct.pack('>HHHHi', 0, top, width, height - top, 0))
        await ws.send_bytes(raw(range(top, height)))
        await ws.receive()


async def settle():
    """Let spawned tasks run."""
    for _ in range(3):
        await asyncio.sleep(0)
