"""Guest agent answers: plausible results per command, and a record of what was asked.

Nothing runs and no file is read or written: exec and the file commands only
note the request on vm.agent_requests and answer with a result of the right
shape.
"""

import time

# Commands whose result vm.agent overrides under a key other than the command name.
KEYS = {'get-osinfo': 'os', 'network-get-interfaces': 'interfaces'}
SECRETS = ('password',)
# What `info` lists as supported.
SUPPORTED = ('guest-ping', 'guest-info', 'guest-get-osinfo', 'guest-get-host-name', 'guest-get-time',
             'guest-get-timezone', 'guest-get-users', 'guest-get-vcpus', 'guest-get-fsinfo',
             'guest-network-get-interfaces', 'guest-exec', 'guest-exec-status', 'guest-file-open',
             'guest-file-read', 'guest-file-write', 'guest-file-close', 'guest-fsfreeze-freeze',
             'guest-fsfreeze-status', 'guest-fsfreeze-thaw', 'guest-fstrim', 'guest-shutdown',
             'guest-set-user-password')


def record(vm, command, values):
    """Note the request on vm.agent_requests, secrets redacted."""
    asked = dict((k, '***' if k in SECRETS else v) for k, v in values.items() if k not in ('node', 'vmid'))
    vm.agent_requests.append((command, asked))


def default(vm, command):
    """The result of a command when vm.agent holds no answer for it."""
    cores = int(vm.config.get('cores', 1)) * int(vm.config.get('sockets', 1))
    if command == 'get-osinfo':
        return {'name': 'Debian GNU/Linux', 'id': 'debian', 'version': '13 (trixie)', 'version-id': '13',
                'pretty-name': 'Debian GNU/Linux 13 (trixie)', 'kernel-release': '6.12.0',
                'kernel-version': '#1 SMP', 'machine': 'x86_64'}
    if command == 'network-get-interfaces':
        return [{'name': 'lo', 'hardware-address': '00:00:00:00:00:00',
                 'ip-addresses': [{'ip-address': '127.0.0.1', 'ip-address-type': 'ipv4', 'prefix': 8}]},
                {'name': 'eth0', 'hardware-address': 'bc:24:11:00:00:01',
                 'ip-addresses': [{'ip-address': '192.0.2.10', 'ip-address-type': 'ipv4', 'prefix': 24}]}]
    return {
        'ping': {},
        'info': {'version': '9.0.0', 'supported_commands': [
            {'name': n, 'enabled': True, 'success-response': True} for n in SUPPORTED]},
        'get-host-name': {'host-name': vm.name},
        'get-time': time.time_ns(),
        'get-timezone': {'zone': 'UTC', 'offset': 0},
        'get-users': [{'user': 'root', 'login-time': time.time()}],
        'get-vcpus': [{'logical-id': n, 'online': True, 'can-offline': n > 0} for n in range(cores)],
        'get-fsinfo': [{'name': 'sda1', 'mountpoint': '/', 'type': 'ext4', 'used-bytes': 2147483648,
                        'total-bytes': 10737418240,
                        'disk': [{'bus-type': 'scsi', 'bus': 0, 'target': 0, 'unit': 0, 'serial': 'drive-scsi0'}]}],
        'get-memory-blocks': [{'phys-index': 0, 'online': True, 'can-offline': False}],
        'get-memory-block-info': {'size': 134217728},
        'fstrim': {'paths': [{'path': '/', 'trimmed': 0, 'minimum': 0}]},
    }.get(command)


def result(vm, command, values):
    """The data the API answers for an agent command that was accepted."""
    state = vm.agent
    if command == 'exec':
        vm.agent_pid += 1
        vm.agent_execs[vm.agent_pid] = list(values['command'])
        return {'pid': vm.agent_pid}
    if command == 'exec-status':
        argv = vm.agent_execs.get(values['pid'], [])
        known = (state.get('exec') or {}).get(' '.join(argv), {})
        return dict({'exited': True, 'exitcode': 0, 'out-data': '', 'err-data': ''}, **known)
    if command == 'file-read':
        return {'content': (state.get('files') or {}).get(values['file'], ''), 'truncated': False}
    if command == 'file-write':
        return None
    if command == 'fsfreeze-freeze':
        vm.agent_frozen = True
        return {'result': 1}
    if command == 'fsfreeze-thaw':
        was, vm.agent_frozen = vm.agent_frozen, False
        return {'result': 1 if was else 0}
    if command == 'fsfreeze-status':
        return {'result': 'frozen' if vm.agent_frozen else 'thawed'}
    if command in ('shutdown', 'suspend-disk', 'suspend-hybrid', 'suspend-ram', 'set-user-password'):
        return {'result': None}
    key = KEYS.get(command, command)
    return {'result': state[key] if key in state else default(vm, command)}
