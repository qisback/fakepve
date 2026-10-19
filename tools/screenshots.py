#!/usr/bin/env python3
"""Make the terminal screenshots in docs/img by running the real commands.

    pip install rich            # this tool only; fakepve itself does not need it
    python tools/screenshots.py [name ...]

Starts fakepve (and examples/custom_server.py) on loopback addresses, runs each
session's commands in a persistent shell, and renders the commands with their
actual output as an SVG terminal image. Nothing is typed in by hand: change the
code or the commands, run it again, and the images follow. Tickets and UPIDs
differ on every run, so the SVGs differ too.

Needs: sh, curl, python3 with aiohttp and cryptography, and a free port 8006
on 127.0.0.2 and 127.0.0.3.
"""

import os
import re
import subprocess
import sys
import time

from rich.console import Console
from rich.text import Text

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
IMG = os.path.join(ROOT, 'docs', 'img')
MAIN = '127.0.0.2'
CUSTOM = '127.0.0.3'
WIDTH = 100


def login(user='root@pam', password='secret'):
    return 'LOGIN=$(curl -sk -d username=%s -d password=%s $PVE/access/ticket)' % (user, password)


def pick(var, field):
    return ("%s=$(echo \"$LOGIN\" | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"data\"][\"%s\"])')"
            % (var, field))


def upid_of(call):
    return ("UPID=$(%s | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"data\"])')" % call)


EXPORT = 'export PVE=https://%s:8006/api2/json'
AUTH = '-b "PVEAuthCookie=$TICKET"'
WRITE = '-b "PVEAuthCookie=$TICKET" -H "CSRFPreventionToken: $CSRF"'

# name -> (title, server, [commands]). `server` says which fake the session needs.
SESSIONS = {
    'cli-help': ('fakepve --help', None, [
        'python -m fakepve --help',
    ]),
    'quick-start': ('Start the fake and log in', MAIN, [
        EXPORT % MAIN,
        'curl -sk -d username=root@pam -d password=secret $PVE/access/ticket | python3 -m json.tool',
    ]),
    'first-requests': ('Read a VM, then send a bad request', MAIN, [
        EXPORT % MAIN,
        login(), pick('TICKET', 'ticket'), pick('CSRF', 'CSRFPreventionToken'),
        'curl -sk %s $PVE/nodes/pve1/qemu/100/status/current | python3 -m json.tool' % AUTH,
        'curl -sk %s -X POST $PVE/nodes/pve1/lxc/50/status/start -w "\\nHTTP %%{http_code}\\n"' % WRITE,
    ]),
    'task-error': ('A start task that fails', MAIN, [
        EXPORT % MAIN,
        login(), pick('TICKET', 'ticket'), pick('CSRF', 'CSRFPreventionToken'),
        upid_of('curl -sk %s -X POST $PVE/nodes/pve1/qemu/103/status/start' % WRITE),
        'curl -sk %s $PVE/nodes/pve1/tasks/$UPID/status | python3 -m json.tool' % AUTH,
        'curl -sk %s $PVE/nodes/pve1/tasks/$UPID/log | python3 -m json.tool' % AUTH,
    ]),
    'errors': ('Permissions, a lock and an error by name', CUSTOM, [
        'python examples/custom_server.py --host %s > /dev/null 2>&1 &' % CUSTOM,
        EXPORT % CUSTOM,
        login('ops@pve', 'opspass'), pick('TICKET', 'ticket'), pick('CSRF', 'CSRFPreventionToken'),
        'curl -sk %s $PVE/nodes/pve1/qemu/100/status/current | head -c 60; echo' % AUTH,
        'curl -sk %s -X POST $PVE/nodes/pve1/qemu/100/status/start' % WRITE,
        'TOKEN="Authorization: PVEAPIToken=root@pam!ci=s3cret"',
        'curl -sk -H "$TOKEN" -X POST $PVE/nodes/pve1/qemu/100/status/shutdown',
        'curl -sk -H "$TOKEN" -X DELETE $PVE/nodes/pve2/qemu/101',
    ]),
    'tests': ('The test suite', None, [
        'python -m pytest -q -p no:cacheprovider',
    ]),
}


class Shell(object):
    """A persistent sh: commands share variables, output comes back per command."""

    def __init__(self, env):
        self.proc = subprocess.Popen(['sh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, cwd=ROOT, env=env, text=True, bufsize=1)

    def run(self, command):
        if os.environ.get('SCREENSHOT_DEBUG'):
            print('+', command, file=sys.stderr)
        self.proc.stdin.write(command + "\nprintf '\\n__DONE__%s\\n' $?\n")
        self.proc.stdin.flush()
        lines = []
        for line in self.proc.stdout:
            if line.startswith('__DONE__'):
                break
            lines.append(line.rstrip('\n'))
        # The marker follows a newline of its own, so an output with one ends in a blank line.
        if lines and lines[-1] == '':
            lines.pop()
        return lines

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        self.proc.terminate()
        self.proc.wait(10)


def wait_ready(host):
    for _ in range(50):
        probe = subprocess.run(['curl', '-ksf', 'https://%s:8006/api2/json/access/domains' % host],
                               stdout=subprocess.DEVNULL, check=False)
        if probe.returncode == 0:
            return
        time.sleep(0.2)
    raise SystemExit('fakepve did not start on ' + host)


def render(name, title, transcript):
    console = Console(record=True, width=WIDTH, file=open(os.devnull, 'w'), force_terminal=True,
                      color_system='truecolor')
    for command, output in transcript:
        prompt = Text()
        prompt.append('$ ', style='bold green')
        prompt.append(command, style='bold')
        console.print(prompt, soft_wrap=False)
        for line in output:
            console.print(Text(line), soft_wrap=False)
    os.makedirs(IMG, exist_ok=True)
    path = os.path.join(IMG, name + '.svg')
    svg = console.export_svg(title=title)
    # No trailing whitespace: the files are committed.
    svg = re.sub(r'[ \t]+\n', '\n', svg)
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(svg)
    print('wrote', os.path.relpath(path, ROOT))


def main(names):
    names = names or list(SESSIONS)
    env = dict(os.environ)
    env['PATH'] = os.path.dirname(sys.executable) + os.pathsep + env.get('PATH', '')
    env['PYTHONPATH'] = os.path.join(ROOT, 'src')
    env['COLUMNS'] = '88'
    servers = []
    try:
        needed = set(SESSIONS[n][1] for n in names)
        if MAIN in needed:
            servers.append(subprocess.Popen([sys.executable, '-m', 'fakepve', 'examples/guests.json',
                                             '--time-scale', '0', '--host', MAIN], cwd=ROOT, env=env,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            wait_ready(MAIN)
        for name in names:
            title, server, commands = SESSIONS[name]
            shell = Shell(env)
            transcript = []
            try:
                for command in commands:
                    output = shell.run(command)
                    if command.endswith('&'):
                        wait_ready(CUSTOM)
                    transcript.append((command, output))
            finally:
                shell.close()
            render(name, title, transcript)
    finally:
        subprocess.run(['pkill', '-f', 'examples/custom_server.py'], check=False)
        for proc in servers:
            proc.terminate()
            proc.wait(10)


if __name__ == '__main__':
    main(sys.argv[1:])
