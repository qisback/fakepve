"""Serve a fake PVE with the guests from a JSON file.

    python -m fakepve examples/guests.json --host 127.0.0.2 --user root@pam --password secret
"""

import argparse
import asyncio
import json
import os
import tempfile

from .server import PORT, FakePve


async def serve(args):
    pve = FakePve(user=args.user, password=args.password, host=args.host, port=args.port)
    pve.time_scale = args.time_scale
    if args.latency:
        pve.slow_network(args.latency)
    with open(args.guests) as guestfile:
        guests = json.load(guestfile)['guests']
    for guest in guests:
        vm = pve.add_vm(guest['vmid'], guest['name'], node=guest.get('node', 'pve1'),
                        status=guest.get('status', 'stopped'), qmpstatus=guest.get('qmpstatus'),
                        config=guest.get('config', {}), template=guest.get('template', False),
                        lock=guest.get('lock'))
        vm.acpi = guest.get('acpi', True)
        for key in ('shutdown_secs', 'start_secs', 'stop_secs', 'start_error', 'ha_state', 'agent'):
            if key in guest:
                setattr(vm, key, guest[key])
    certfile, keyfile = args.cert, args.key
    if not certfile:
        from .certs import make_cert
        certfile, keyfile, _ = make_cert(tempfile.mkdtemp(prefix='fakepve-'))
    await pve.start(certfile, keyfile)
    print('fakepve listening on https://{0}:{1}'.format(pve.host, pve.port), flush=True)
    await asyncio.Event().wait()


def main():
    parser = argparse.ArgumentParser(prog='fakepve', description=__doc__.splitlines()[0])
    parser.add_argument('guests', help='JSON file: {"guests": [{"vmid", "name", "status", "config", ...}]}')
    parser.add_argument('--host', default='127.0.0.2')
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--user', default=os.environ.get('PVE_USER', 'root@pam'))
    parser.add_argument('--password', default=os.environ.get('PVE_PASS', 'secret'))
    parser.add_argument('--time-scale', type=float, default=1.0,
                        help='real seconds per PVE second; 0 finishes tasks instantly (default 1)')
    parser.add_argument('--latency', type=float, default=0.0, help='PVE seconds added to every response')
    parser.add_argument('--cert', help='PEM certificate; a self-signed one is made if omitted')
    parser.add_argument('--key', help='PEM key for --cert')
    try:
        asyncio.run(serve(parser.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
