"""A standalone fake with state the command line cannot set: users, grants, tokens, failures.

    python examples/custom_server.py [--host 127.0.0.2] [--port 8006]

Then point any Proxmox client at it (Terraform, Ansible, proxmoxer, curl, ...):

    root@pam / secret          everything allowed
    ops@pve / opspass          may look at VM 100, nothing else (403 on writes)
    root@pam!ci = s3cret       an API token:  Authorization: PVEAPIToken=root@pam!ci=s3cret

VM 101 cannot be destroyed (PVE's own error, by name), and VM 100 is mid-backup.
"""

import argparse
import asyncio
import tempfile

from fakepve import FakePve
from fakepve.certs import make_cert


def build(host=None, port=8006):
    pve = FakePve(user='root@pam', password='secret', host=host, port=port)
    pve.time_scale = 0.1                      # 60 PVE seconds take 6 real ones
    pve.add_node('pve2')
    pve.add_vm(100, 'web1', status='running', config={'scsi0': 'local-lvm:vm-100-disk-0,size=8G'})
    pve.add_vm(101, 'db1', status='running', node='pve2', config={'scsi0': 'local-lvm:vm-101-disk-0,size=32G'})
    pve.users['ops@pve'] = 'opspass'
    pve.grant('ops@pve', '/vms/100', 'VM.Audit')
    pve.apitokens['root@pam!ci'] = 's3cret'
    pve.fail('DELETE', '/nodes/pve2/qemu/101', error='running_destroy_failed')
    return pve


async def serve(args):
    pve = build(args.host, args.port)
    certfile, keyfile, _ = make_cert(tempfile.mkdtemp(prefix='fakepve-'))
    await pve.start(certfile, keyfile)
    await pve.backup(100, secs=3600)          # a backup that outlasts the session
    print('fakepve listening on https://{0}:{1}'.format(pve.host, pve.port), flush=True)
    await asyncio.Event().wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--host', default='127.0.0.2')
    parser.add_argument('--port', type=int, default=8006)
    try:
        asyncio.run(serve(parser.parse_args()))
    except KeyboardInterrupt:
        pass
