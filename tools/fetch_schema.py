#!/usr/bin/env python3
"""Fetch the PVE API schema and store it, trimmed, as package data.

    python tools/fetch_schema.py [URL_OR_FILE]

The default is the schema the PVE API viewer is built from. The output is
src/fakepve/data/pve-api.json.gz ({"paths": {template: {METHOD: info}}}) and
a sidecar, pve-api.meta.json, recording where and when it came from.
"""

import argparse
import datetime
import gzip
import hashlib
import json
import os
import urllib.request

URL = 'https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js'
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'fakepve', 'data')

# Prose that is not needed to answer requests.
PROSE = ('description', 'verbose_description', 'typetext', 'format_description', 'title')
# Method keys kept; the rest (description, name, proxyto, ...) is not used.
METHOD_KEYS = ('parameters', 'returns', 'permissions', 'protected', 'allowtoken')


def schema_of(node):
    """A parameter or return schema without prose. Maps of schemas are kept whole."""
    out = {}
    for key, val in node.items():
        if key in PROSE and isinstance(val, str):
            continue
        if key == 'properties' or (key == 'format' and isinstance(val, dict)):
            out[key] = dict((name, schema_of(sub)) for name, sub in val.items())
        elif key == 'items' and isinstance(val, dict):
            out[key] = schema_of(val)
        elif key == 'oneOf':
            out[key] = [schema_of(sub) for sub in val]
        else:
            out[key] = val
    return out


def method_of(info):
    out = dict((k, info[k]) for k in METHOD_KEYS if k in info)
    if 'parameters' in out:
        out['parameters'] = schema_of(out['parameters'])
    if 'returns' in out:
        returns = schema_of(out['returns'])
        # The task and URL wording of a string result tells a UPID from a plain string.
        if isinstance(info['returns'].get('description'), str):
            returns['description'] = info['returns']['description']
        out['returns'] = returns
    perms = out.get('permissions')
    if isinstance(perms, dict):
        out['permissions'] = dict((k, v) for k, v in perms.items() if k != 'description')
    return out


def flatten(tree, paths):
    for node in tree:
        if node.get('info'):
            paths[node['path']] = dict((m, method_of(i)) for m, i in node['info'].items())
        flatten(node.get('children', []), paths)
    return paths


def read(source):
    if '://' in source:
        with urllib.request.urlopen(source, timeout=60) as rsp:
            return rsp.read()
    with open(source, 'rb') as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('source', nargs='?', default=URL, help='URL or file of apidoc.js (default: %(default)s)')
    ap.add_argument('--out', default=DATA, help='output directory (default: the package data)')
    args = ap.parse_args()
    raw = read(args.source)
    text = raw.decode('utf-8')
    tree, _ = json.JSONDecoder().raw_decode(text, text.index('['))
    paths = flatten(tree, {})
    methods = sum(len(m) for m in paths.values())
    body = json.dumps({'paths': paths}, sort_keys=True, separators=(',', ':')).encode()
    os.makedirs(args.out, exist_ok=True)
    # mtime=0 keeps the archive byte-identical for the same schema.
    with open(os.path.join(args.out, 'pve-api.json.gz'), 'wb') as f:
        f.write(gzip.compress(body, 9, mtime=0))
    meta = {'source': args.source, 'fetched': datetime.date.today().isoformat(),
            'sha256': hashlib.sha256(raw).hexdigest(), 'paths': len(paths), 'methods': methods}
    with open(os.path.join(args.out, 'pve-api.meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)
        f.write('\n')
    print('{0} paths, {1} methods, {2} bytes'.format(len(paths), methods, len(body)))


if __name__ == '__main__':
    main()
