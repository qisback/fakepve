#!/usr/bin/env python3
"""Run the code blocks in the docs, and keep their printed output in step.

    python tools/docs_runner.py [--fill] [FILE ...]

A ```python fence directly after a `<!-- run -->` line is executed. Blocks in
one file share a namespace, in order, and may use top-level `await`. A
```text fence directly after a `<!-- output -->` line holds what the preceding
run block prints; it is compared on every run, and rewritten with --fill.
"""

import ast
import asyncio
import contextlib
import io
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
FENCE = re.compile(r'^```(\w*)\s*$')


def blocks(text):
    """[(kind, first line number, source)] for run and output blocks, in order."""
    lines = text.split('\n')
    out = []
    i = 0
    while i < len(lines):
        marker = lines[i].strip()
        if marker in ('<!-- run -->', '<!-- output -->') and i + 1 < len(lines) and FENCE.match(lines[i + 1]):
            kind = marker[5:-4].strip()
            start = i + 2
            end = start
            while end < len(lines) and lines[end].rstrip() != '```':
                end += 1
            out.append((kind, start + 1, '\n'.join(lines[start:end])))
            i = end
        i += 1
    return out


def run_source(source, namespace, name):
    """Execute one block; returns what it printed."""
    code = compile(source, name, 'exec', flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = eval(code, namespace)  # noqa: S307 - our own docs
        if asyncio.iscoroutine(result):
            _run(result)
    return buf.getvalue()


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def run_file(path, fill=False):
    """Run every block in a file. Returns a list of problems; with fill, rewrites the output blocks."""
    with open(path, encoding='utf-8') as fh:
        text = fh.read()
    namespace = {'__name__': '__docs__'}
    # Blocks use paths relative to the repository and may start `python -m fakepve`.
    os.chdir(ROOT)
    src = os.path.join(ROOT, 'src')
    if src not in os.environ.get('PYTHONPATH', '').split(os.pathsep):
        os.environ['PYTHONPATH'] = src + os.pathsep + os.environ.get('PYTHONPATH', '')
    problems = []
    printed = None
    lines = text.split('\n')
    replacements = []
    for kind, line, source in blocks(text):
        name = '{0}:{1}'.format(os.path.relpath(path, ROOT), line)
        if kind == 'run':
            try:
                printed = run_source(source, namespace, name)
            except Exception as exc:  # noqa: BLE001 - reported with the location
                problems.append('{0}: {1}: {2}'.format(name, type(exc).__name__, exc))
                printed = None
        elif printed is not None:
            want = [x.rstrip() for x in source.split('\n')]
            got = [x.rstrip() for x in printed.rstrip('\n').split('\n')]
            if want != got:
                if fill:
                    replacements.append((line, source.count('\n') + 1, printed.rstrip('\n').split('\n')))
                else:
                    problems.append('{0}: output differs\n--- docs\n{1}\n--- run\n{2}'.format(
                        name, '\n'.join(want), '\n'.join(got)))
            printed = None
    for line, count, new in reversed(replacements):
        lines[line - 1:line - 1 + count] = new
    if replacements:
        with open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('\n'.join(lines))
    return problems


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    fill = '--fill' in args
    files = [a for a in args if a != '--fill']
    if not files:
        docs = os.path.join(ROOT, 'docs')
        files = [os.path.join(docs, f) for f in sorted(os.listdir(docs)) if f.endswith('.md')]
    bad = []
    for path in files:
        bad += run_file(path, fill)
    for problem in bad:
        print(problem)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.path.insert(0, os.path.join(ROOT, 'src'))
    sys.exit(main())
