#!/usr/bin/env python3
"""Compare the PVE API schema online with the one fakepve ships.

    python tools/check_schema.py [URL_OR_FILE] [--meta PATH]

Hashes the apidoc.js at the source (default: the source recorded in
src/fakepve/data/pve-api.meta.json) and compares it with the sha256 stored
there. Prints "old: <hash>" and "new: <hash>". Exit status: 0 same, 1 changed,
2 the source could not be read.

The weekly workflow .github/workflows/schema-check.yml runs this and opens an
issue on 1. To adopt a new schema, run tools/fetch_schema.py.
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request

META = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'fakepve', 'data',
                    'pve-api.meta.json')
# Larger than any apidoc.js so far (about 1 MB); a runaway response is cut here.
MAX_BYTES = 64 * 1024 ** 2


def read(source):
    if '://' in source:
        request = urllib.request.Request(source, headers={'User-Agent': 'fakepve-schema-check'})
        with urllib.request.urlopen(request, timeout=60) as rsp:
            return rsp.read(MAX_BYTES + 1)[:MAX_BYTES]
    with open(source, 'rb') as fh:
        return fh.read(MAX_BYTES)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('source', nargs='?', help="URL or file of apidoc.js (default: the meta file's source)")
    ap.add_argument('--meta', default=META, help='pve-api.meta.json to compare with (default: the package data)')
    args = ap.parse_args(argv)
    with open(args.meta, encoding='utf-8') as fh:
        meta = json.load(fh)
    try:
        raw = read(args.source or meta['source'])
    except (OSError, ValueError) as exc:
        print('cannot read the schema: {0}'.format(exc), file=sys.stderr)
        return 2
    new = hashlib.sha256(raw).hexdigest()
    print('old: {0}'.format(meta['sha256']))
    print('new: {0}'.format(new))
    return 0 if new == meta['sha256'] else 1


if __name__ == '__main__':
    sys.exit(main())
