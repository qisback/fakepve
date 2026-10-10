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
import itertools
import json
import random
import secrets
import time
import urllib.parse

import aiohttp
from aiohttp import web

from .model import FakeVm, Model, PveError, TaskError

PORT = 8006  # PVE's API port; clients often assume it
_hostseq = itertools.count(2)
API = '/api2/json'
# Where the authenticated user is kept on the request.
USER = web.RequestKey('user', str) if hasattr(web, 'RequestKey') else 'user'

__all__ = ['PORT', 'FakePve', 'FakeVm', 'next_loopback', 'settle']


def next_loopback():
    n = next(_hostseq)
    return '127.0.{0}.{1}'.format(n // 250, n % 250 + 2)


def ok(data=None):
    return web.json_response({'data': data})


def error(status, message, errors=None):
    body = {'data': None, 'message': message + '\n'}
    if errors:
        body['errors'] = errors
    return web.json_response(body, status=status, reason=message.splitlines()[0][:200])


async def params(request):
    """Request parameters as PVE takes them: query string, form or JSON body."""
    out = dict(request.query)
    body = await request.read()
    if body and request.content_type == 'application/json':
        out.update(json.loads(body))
    elif body and request.content_type != 'multipart/form-data':
        out.update(urllib.parse.parse_qsl(body.decode()))
    return out


class FakePve(Model):
    def __init__(self, user='root@pam', password='secret', host=None, port=PORT):
        super().__init__(user, password)
        self.host = host or next_loopback()
        self.port = port
        self.runner = None
        self.termdata = []
        self.monitor_allowed = True
        self.uploaded = None
        self._random = random.Random()

    # ------------------------------------------------------------- lifecycle

    async def start(self, certfile, keyfile):
        import ssl
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile, keyfile)
        if self.network.get('seed') is not None:
            self._random.seed(self.network['seed'])
        app = web.Application(middlewares=[self._middleware], client_max_size=1024 ** 4)
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
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        await web.TCPSite(self.runner, self.host, self.port, ssl_context=ctx).start()

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()
            self.runner = None

    # ------------------------------------------------------------ middleware

    @web.middleware
    async def _middleware(self, request, handler):
        body = await request.read()
        self.requests.append((request.method, request.path, body))
        net = self.network
        path_node = request.match_info.get('node')
        delay = net['latency'] + self._random.uniform(0, net['jitter']) + net['node_latency'].get(path_node, 0)
        await self.pause(delay)
        if net['drop_rate'] and self._random.random() < net['drop_rate']:
            request.transport.close()
            raise ConnectionResetError('fakepve: connection dropped')
        if net['hang_rate'] and self._random.random() < net['hang_rate']:
            await asyncio.sleep(net['hang_secs'] * (self.time_scale or 1))
        for (method, suffix), (status, message, html) in self.failures.items():
            if request.method == method and request.path.endswith(suffix):
                if html:
                    return web.Response(status=status, text=message, content_type='text/html')
                return error(status, message)
        try:
            request[USER] = self._authenticate(request)
            if path_node and path_node in self.nodes and not self.nodes[path_node].get('online', True):
                raise PveError(595, 'No route to host')
            return await handler(request)
        except PveError as e:
            return error(e.status, e.message, e.errors)

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

    # --------------------------------------------------------------- access

    async def _ticket(self, request):
        p = await params(request)
        user, password = p.get('username', ''), p.get('password', '')
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
        p = await params(request)
        user = request[USER]
        if p.get('userid') != user.split('!')[0] and user != 'root@pam':
            raise PveError(403, 'Permission check failed (/access, User.Modify)')
        current = self.password if p.get('userid') == self.user else self.users.get(p.get('userid'))
        if p.get('confirmation-password') is not None and p.get('confirmation-password') != current:
            raise PveError(401, 'confirmation password is wrong')
        if p.get('userid') == self.user:
            self.password = p['password']
        else:
            self.users[p['userid']] = p['password']
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

    async def _task_list(self, request):
        node = request.match_info['node']
        user = request[USER]
        vmid = request.query.get('vmid')
        audit = self.allowed(user, '/nodes/' + node, 'Sys.Audit')
        data = [self._task_view(t) for t in self.tasklog
                if t['node'] == node and (vmid is None or t['id'] == vmid) and (audit or t['user'] == user)]
        data.sort(key=lambda t: -t['starttime'])
        return ok(data[:int(request.query.get('limit', 50))])

    def _get_task(self, request):
        task = self.tasks.get(request.match_info['upid'])
        if task is None or task['node'] != request.match_info['node']:
            raise PveError(500, "unable to parse worker upid '{0}'".format(request.match_info['upid']))
        return task

    async def _task_status(self, request):
        return ok(self._task_view(self._get_task(request)))

    async def _task_log(self, request):
        lines = self._get_task(request)['log']
        start = int(request.query.get('start', 0))
        limit = int(request.query.get('limit', 50))
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
        size = int(p.get('size', 1024 ** 2))

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
        boundary = request.content_type == 'multipart/form-data' and \
            request.headers['Content-Type'].split('boundary=', 1)[1]
        if not boundary or int(request.headers.get('Content-Length', -1)) != len(body):
            raise PveError(400, 'bad upload request')
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
        if fields.get('content') != 'iso':
            raise PveError(400, 'Parameter verification failed.', {'content': 'value not allowed'})
        self.uploaded = fields

        async def body_():
            self.store_file(name, fields['filename'], len(fields.get('data', b'')))
        return ok(await self.task(request.match_info['node'], 'imgcopy', '', user, body_))

    # ------------------------------------------------------------------ VMs

    def _vm(self, request, priv=None):
        vm = self.find(request.match_info['node'], request.match_info['vmid'])
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
        key = {'get-osinfo': 'os', 'network-get-interfaces': 'interfaces', 'ping': None}.get(command, '?')
        if key == '?':
            raise PveError(501, "Method 'GET /nodes/{0}/qemu/{1}/agent/{2}' not implemented".format(
                vm.node, vm.vmid, command))
        return ok({'result': vm.agent.get(key) if key else {}})

    async def _monitor(self, request):
        vm = self._vm(request, 'VM.Monitor')
        command = (await params(request)).get('command', '')
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

    async def _termproxy(self, request):
        vm = self._vm(request, 'VM.Console')
        vm.rfb = False
        vm.vncticket = 'PVEVNC:{0}'.format(secrets.token_hex(8))
        vm.vncuser = request[USER]
        return ok({'ticket': vm.vncticket, 'port': '5900', 'user': vm.vncuser,
                   'upid': 'UPID:{0}:termproxy:{1}:'.format(vm.node, vm.vmid)})

    async def _vncproxy(self, request):
        vm = self._vm(request, 'VM.Console')
        p = await params(request)
        if not p.get('websocket'):
            return await self._termproxy(request)
        vm.rfb = True
        vm.vncticket = 'PVEVNC:{0}'.format(secrets.token_hex(8))
        vm.vncpassword = secrets.token_hex(4) if p.get('generate-password') else None
        data = {'ticket': vm.vncticket, 'port': '5900', 'user': request[USER],
                'upid': 'UPID:{0}:vncproxy:{1}:'.format(vm.node, vm.vmid)}
        if vm.vncpassword:
            data['password'] = vm.vncpassword
        return ok(data)

    async def _vncwebsocket(self, request):
        vm = self._vm(request)
        ws = web.WebSocketResponse(protocols=('binary',))
        await ws.prepare(request)
        if request.query.get('vncticket') != getattr(vm, 'vncticket', None):
            await ws.close()
            return ws
        if getattr(vm, 'rfb', False):
            try:
                await self._rfb(ws, vm)
            except ConnectionError:
                pass
            await ws.close()
            return ws
        hello = await ws.receive()
        if self.refuse_terminal or hello.type != aiohttp.WSMsgType.TEXT or \
                hello.data != '{0}:{1}\n'.format(vm.vncuser, vm.vncticket):
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

    async def _rfb(self, ws, vm):
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
        key = ((vm.vncpassword or vm.vncticket).encode() + b'\0' * 8)[:8]
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
