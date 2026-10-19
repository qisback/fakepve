#!/usr/bin/env python3
"""Extract the errors each PVE API method can return from the PVE sources.

Run it on clones of the PVE repositories (pve-manager, qemu-server, ...):

    tools/extract_errors.py /path/to/clones

and it writes src/fakepve/data/pve-errors.json.gz: for every API method in
the vendored schema, the error messages and status codes PVE can answer with.

Only message strings, status codes and source references are taken from the
sources (AGPL); no code is ported. The reader is a small Perl tokenizer, not a
Perl parser, so the result is an approximation: errors raised in callees are
followed two levels deep, and a message built at run time is kept as a
template with {placeholders}.

Python 3, standard library only.
"""

import argparse
import bisect
import collections
import datetime
import gzip
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, '..', 'src', 'fakepve', 'data')

HTTP = {
    'BAD_REQUEST': 400, 'UNAUTHORIZED': 401, 'PAYMENT_REQUIRED': 402, 'FORBIDDEN': 403, 'NOT_FOUND': 404,
    'METHOD_NOT_ALLOWED': 405, 'NOT_ACCEPTABLE': 406, 'REQUEST_TIMEOUT': 408, 'CONFLICT': 409,
    'LENGTH_REQUIRED': 411, 'PRECONDITION_FAILED': 412, 'REQUEST_ENTITY_TOO_LARGE': 413,
    'UNPROCESSABLE_ENTITY': 422, 'LOCKED': 423, 'INTERNAL_SERVER_ERROR': 500, 'NOT_IMPLEMENTED': 501,
    'BAD_GATEWAY': 502, 'SERVICE_UNAVAILABLE': 503, 'GATEWAY_TIMEOUT': 504,
}

# Packages whose errors are generic plumbing, not about the method.
SKIP_PACKAGES = {
    'PVE::Tools', 'PVE::JSONSchema', 'PVE::RESTHandler', 'PVE::SafeSyslog', 'PVE::INotify',
    'PVE::RPCEnvironment', 'PVE::Exception', 'PVE::Cluster', 'PVE::CLIHandler', 'PVE::Daemon',
    'PVE::APIClient::LWP', 'PVE::PTY', 'PVE::ProcFSTools', 'PVE::CertHelpers', 'PVE::Certificate',
    'PVE::DataCenterConfig', 'PVE::SectionConfig', 'PVE::Syscall', 'PVE::CpuSet', 'PVE::LockedFile',
}
# Calls to these never lead anywhere useful.
SKIP_CALLS = {
    'die', 'warn', 'print', 'return', 'defined', 'exists', 'delete', 'keys', 'values', 'push', 'pop',
    'shift', 'unshift', 'join', 'split', 'map', 'grep', 'sort', 'reverse', 'sprintf', 'scalar',
    'ref', 'bless', 'eval', 'if', 'elsif', 'unless', 'while', 'foreach', 'for', 'my', 'our', 'local',
    'syslog', 'open', 'close', 'eof', 'length', 'substr', 'index', 'lc', 'uc', 'int', 'abs', 'wantarray',
}
MAX_DEPTH = 2
MAX_ERRORS = 60
STOPWORDS = set('a an the is are was be to of for and or in on at by with from vm ct container node it this '
                'that as not'.split()) - {'not'}
KEEP_WORDS = {'not'}

OPKW = set('return and or not if unless elsif while until foreach for split grep map join push unshift x eq '
           'ne lt gt le ge cmp print die warn when'.split())
QUOTE_OPS = {'q', 'qq', 'qw', 'qr', 'm', 's', 'tr', 'y'}
PAIRS = {'(': ')', '[': ']', '{': '}', '<': '>'}


# --------------------------------------------------------------------------- tokenizer

class Tok(object):
    __slots__ = ('kind', 'val', 'pos', 'interp', 'line')

    def __init__(self, kind, val, pos, interp=False):
        self.kind = kind
        self.val = val
        self.pos = pos
        self.interp = interp
        self.line = 0

    def __repr__(self):
        return '{0}:{1!r}'.format(self.kind, self.val)


def read_delim(src, i):
    """Text between the delimiter at src[i] and its closing mate; returns (text, index after)."""
    open_ = src[i]
    close = PAIRS.get(open_, open_)
    depth = 1
    j = i + 1
    n = len(src)
    while j < n:
        c = src[j]
        if c == '\\':
            j += 2
            continue
        if open_ != close and c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return src[i + 1:j], j + 1
        j += 1
    return src[i + 1:], n


def tokenize(src):
    toks = []
    i = 0
    n = len(src)
    pending = []  # heredocs waiting for the next line

    def prev_is_term():
        if not toks:
            return False
        p = toks[-1]
        if p.kind in ('var', 'str', 'num', 'regex', 'qw'):
            return True
        if p.kind == 'op':
            return p.val in (')', ']', '}')
        if p.kind == 'ident':
            return p.val not in OPKW
        return False

    while i < n:
        c = src[i]
        if c == '\n':
            i += 1
            for tok, tag, indent, interp in pending:
                lines = []
                while i < n:
                    e = src.find('\n', i)
                    e = n if e < 0 else e
                    line = src[i:e]
                    i = min(e + 1, n)
                    if (line.strip() if indent else line) == tag:
                        break
                    lines.append(line)
                if indent:
                    pad = min([len(x) - len(x.lstrip()) for x in lines if x.strip()] or [0])
                    lines = [x[pad:] for x in lines]
                tok.val = '\n'.join(lines) + '\n'
            pending = []
            if src.startswith('=', i) and re.match(r'=[a-zA-Z]', src[i:i + 2]):  # POD
                m = re.compile(r'^=cut\b.*$', re.M).search(src, i)
                i = m.end() if m else n
            continue
        if c in ' \t\r':
            i += 1
            continue
        if c == '#':
            e = src.find('\n', i)
            i = n if e < 0 else e
            continue
        if i == 0 and src.startswith('=') and re.match(r'=[a-zA-Z]', src):
            m = re.compile(r'^=cut\b.*$', re.M).search(src)
            i = m.end() if m else n
            continue
        start = i
        if c.isalpha() or c == '_':
            m = re.compile(r'[A-Za-z_]\w*(?:::\w+)*(?:::)?').match(src, i)
            word = m.group(0)
            i = m.end()
            if word in ('__END__', '__DATA__'):
                break
            nxt = src[i:i + 40].lstrip()
            quoted = (word in QUOTE_OPS and not (toks and toks[-1].val == '->') and nxt and
                      not nxt.startswith('=>') and not nxt.startswith(',') and nxt[0] not in ';)=' and
                      not (nxt[0] == '}' and toks and toks[-1].val == '{') and
                      (nxt == src[i:i + 40] or nxt[0] != '#') and
                      not (toks and toks[-1].val == 'sub'))
            if quoted:
                j = i
                while src[j] in ' \t':
                    j += 1
                delim = src[j]
                if delim.isalnum() or delim == '_' or delim.isspace():
                    quoted = False
            if quoted:
                text, i = read_delim(src, j)
                if word in ('s', 'tr', 'y'):
                    if src[j] in PAIRS:
                        while i < n and src[i] in ' \t\n':
                            i += 1
                        _, i = read_delim(src, i)
                    else:
                        e = i
                        while e < n and not (src[e] == src[j] and src[e - 1] != '\\'):
                            e += 1
                        i = e + 1
                m = re.compile(r'[a-z]*').match(src, i)
                i = m.end()
                if word in ('q', 'qq'):
                    toks.append(Tok('str', text, start, interp=(word == 'qq')))
                elif word == 'qw':
                    toks.append(Tok('qw', text.split(), start))
                else:
                    toks.append(Tok('regex', text, start))
            else:
                toks.append(Tok('ident', word, start))
            continue
        if c.isdigit():
            m = re.compile(r'0[xX][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?').match(src, i)
            toks.append(Tok('num', m.group(0), start))
            i = m.end()
            continue
        if c in '$@%&':
            nx = src[i + 1:i + 2]
            if c == '$' and nx == '#':
                nn = src[i + 2:i + 3]
                if nn in ('{', '$'):
                    toks.append(Tok('cast', '$#', start))
                    i += 2
                    continue
                m = re.compile(r'\$#(\w+(?:::\w+)*)').match(src, i)
                if m:
                    toks.append(Tok('var', '$#' + m.group(1), start))
                    i = m.end()
                    continue
            if c in '%&' and (prev_is_term() or nx == c):
                pass  # binary operator, handled below
            elif nx == '{' or (nx == '$' and re.match(r'\$[\w{$:]', src[i + 1:i + 3])):
                toks.append(Tok('cast', c, start))
                i += 1
                continue
            else:
                m = re.compile(r'(?:::)?[A-Za-z_]\w*(?:::\w+)*|\d+').match(src, i + 1)
                if m and not (c == '%' and m.group(0).isdigit()):
                    toks.append(Tok('var', c + m.group(0), start))
                    i = m.end()
                    continue
                if c == '$' and nx and nx in '@!_,;/\\&0.|"+-^<>[]':
                    if nx == '^':
                        toks.append(Tok('var', src[i:i + 3], start))
                        i += 3
                    else:
                        toks.append(Tok('var', '$' + nx, start))
                        i += 2
                    continue
                if c == '@' and nx == '_':
                    toks.append(Tok('var', '@_', start))
                    i += 2
                    continue
        if c == '"' or c == '`':
            text, i = read_delim(src, i)
            toks.append(Tok('str', text, start, interp=True))
            continue
        if c == "'":
            text, i = read_delim(src, i)
            toks.append(Tok('str', text, start, interp=False))
            continue
        if c == '/' and not prev_is_term():
            text, i = read_delim(src, i)
            i = re.compile(r'[a-z]*').match(src, i).end()
            toks.append(Tok('regex', text, start))
            continue
        if c == '<':
            m = re.compile(r'<<(~?)(?:"([^"\n]*)"|\'([^\'\n]*)\'|([A-Za-z_]\w*))').match(src, i)
            if m and (not prev_is_term() or m.group(2) is not None or m.group(3) is not None or
                      (m.group(4) or '').isupper()):
                tok = Tok('str', '', start, interp=m.group(3) is None)
                toks.append(tok)
                tag = m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4)
                pending.append((tok, tag, bool(m.group(1)), tok.interp))
                i = m.end()
                continue
            m = re.compile(r'<\$?\w*>').match(src, i)
            if m and not prev_is_term():
                toks.append(Tok('var', m.group(0), start))
                i = m.end()
                continue
        for op in ('<=>', '**=', '||=', '&&=', '//=', '...', '=>', '->', '=~', '!~', '&&', '||', '//', '==', '!=',
                   '<=', '>=', '..', '::', '+=', '-=', '.=', '*=', '|=', '&=', '++', '--', '<<', '>>'):
            if src.startswith(op, i):
                toks.append(Tok('op', op, start))
                i += len(op)
                break
        else:
            toks.append(Tok('op', c, start))
            i += 1
    return toks


# ----------------------------------------------------------------------- source files

class Func(object):
    """A body of tokens: a named sub, a closure or a registered method's code."""

    def __init__(self, sf, lo, hi, name, pkg):
        self.sf, self.lo, self.hi, self.name, self.pkg = sf, lo, hi, name, pkg
        self.scan = None


class SrcFile(object):
    def __init__(self, repo, rel, text):
        self.repo = repo
        self.rel = rel
        self.text = text
        self.toks = tokenize(text)
        self.starts = [m.start() for m in re.finditer(r'^', text, re.M)]
        for t in self.toks:
            t.line = bisect.bisect_right(self.starts, t.pos)
        self.match = {}
        stack = []
        for i, t in enumerate(self.toks):
            if t.kind == 'op' and t.val in '([{':
                stack.append(i)
            elif t.kind == 'op' and t.val in ')]}' and stack:
                j = stack.pop()
                self.match[j] = i
                self.match[i] = j
        self.subs = {}      # (pkg, name) -> Func
        self.locals = collections.defaultdict(list)  # variable name -> [Func] (my $x = sub {...})
        self.methods = []   # register_method hashes: (open index, close index, pkg)
        self.packages = []  # package names in order
        self.bases = collections.defaultdict(list)
        self.imports = {}   # function name -> package
        self.index()

    @property
    def ref(self):
        return '{0}/{1}'.format(self.repo, self.rel)

    def local(self, name, near):
        """The closure bound to a variable: the one inside `near` (a Func), else the nearest before it."""
        funcs = self.locals.get(name)
        if not funcs:
            return None
        inside = [f for f in funcs if near.lo <= f.lo and f.hi <= near.hi]
        if inside:
            return inside[-1]
        before = [f for f in funcs if f.hi < near.lo]
        return (before or funcs)[-1]

    def tv(self, i):
        return self.toks[i].val if 0 <= i < len(self.toks) else None

    def index(self):
        toks = self.toks
        pkg = 'main'
        for i, t in enumerate(toks):
            if t.kind != 'ident':
                continue
            v = t.val
            if v == 'package' and i + 1 < len(toks) and toks[i + 1].kind == 'ident':
                pkg = toks[i + 1].val
                self.packages.append(pkg)
            elif v == 'sub' and self.tv(i + 2) == '{' and toks[i + 1].kind == 'ident':
                self.subs[(pkg, toks[i + 1].val)] = Func(self, i + 2, self.match.get(i + 2, i + 2), toks[i + 1].val, pkg)
            elif v == 'sub' and self.tv(i + 1) == '{' and self.tv(i - 1) == '=' and toks[i - 2].kind == 'var':
                self.locals[toks[i - 2].val].append(Func(self, i + 1, self.match.get(i + 1, i + 1), toks[i - 2].val, pkg))
            elif v == 'register_method' and self.tv(i + 1) == '(' and self.tv(i + 2) == '{':
                self.methods.append((i + 2, self.match.get(i + 2, i + 2), pkg))
            elif v in ('base', 'parent') and self.tv(i - 1) == 'use':
                j = i + 1
                while j < len(toks) and toks[j].val != ';':
                    if toks[j].kind == 'str' and toks[j].val != '-norequire':
                        self.bases[pkg].append(toks[j].val)
                    elif toks[j].kind == 'qw':
                        self.bases[pkg].extend(w for w in toks[j].val if w != '-norequire')
                    j += 1
            elif v == 'use' and i + 1 < len(toks) and toks[i + 1].kind == 'ident':
                other = toks[i + 1].val
                j = i + 2
                while j < len(toks) and toks[j].val != ';':
                    if toks[j].kind == 'qw':
                        for w in toks[j].val:
                            self.imports[w] = other
                    elif toks[j].kind == 'str' and other not in ('base', 'parent'):
                        self.imports[toks[j].val] = other
                    j += 1
        for i, t in enumerate(toks):
            if t.kind == 'var' and t.val == '@ISA':
                j = i
                while j < len(toks) and toks[j].val != ';':
                    if toks[j].kind == 'str':
                        self.bases[self.packages[-1] if self.packages else 'main'].append(toks[j].val)
                    elif toks[j].kind == 'qw':
                        self.bases[self.packages[-1] if self.packages else 'main'].extend(toks[j].val)
                    j += 1

    def items(self, lo, hi):
        """Split the tokens in [lo, hi) at top-level commas: [(start, end)]."""
        out = []
        s = lo
        i = lo
        while i < hi:
            t = self.toks[i]
            if t.kind == 'op' and t.val in '([{' and i in self.match:
                i = self.match[i] + 1
                continue
            if t.kind == 'op' and t.val in (',', '=>') and t.val == ',':
                out.append((s, i))
                s = i + 1
            i += 1
        if s < hi:
            out.append((s, hi))
        return [(a, b) for a, b in out if b > a]

    def pairs(self, lo, hi):
        """key => value ranges of a hash body: {key: (start, end)}."""
        out = {}
        for a, b in self.items(lo, hi):
            if b - a >= 3 and self.toks[a + 1].val == '=>' and self.toks[a].kind in ('ident', 'str'):
                out[self.toks[a].val] = (a + 2, b)
        return out


# ------------------------------------------------------------------------- templates

def clean_name(name):
    name = re.sub(r'^[\$@%&]+', '', name)
    name = name.strip('\'" ')
    name = re.sub(r'[^\w-]', '', name)
    if not name or name.isdigit() or name == '_':
        return 'value'
    return name


def interpolate(s):
    """Template of a double-quoted Perl string: variables become {name}."""
    out = []
    i = 0
    n = len(s)
    esc = {'n': '\n', 't': '\t', 'r': '\r', '0': '\0', 'e': '\x1b'}
    while i < n:
        c = s[i]
        if c == '\\' and i + 1 < n:
            out.append(esc.get(s[i + 1], s[i + 1]))
            i += 2
            continue
        if c in '$@' and i + 1 < n:
            if s[i + 1] == '{':
                depth, j = 0, i + 1
                while j < n:
                    if s[j] == '{':
                        depth += 1
                    elif s[j] == '}':
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                inner = s[i + 2:j]
                m = re.fullmatch(r'\s*\^?(\w+)\s*', inner)
                if m and c == '$':
                    name = m.group(1)
                    i = j + 1
                    # ${name}->{key}
                    km = re.compile(r'(?:->)?\{([^}]*)\}|->\[[^\]]*\]').match(s, i)
                    while km:
                        if km.group(1) is not None:
                            name = clean_name(km.group(1))
                        i = km.end()
                        km = re.compile(r'(?:->)?\{([^}]*)\}|->\[[^\]]*\]').match(s, i)
                    out.append('{' + clean_name(name) + '}')
                    continue
                var = re.search(r'[\$@](\w+)', inner)
                out.append('{' + (clean_name(var.group(1)) if var else 'value') + '}')
                i = j + 1
                continue
            m = re.compile(r'[\$@](?:(?:::)?[A-Za-z_]\w*(?:::\w+)*|\d+|[@!&.,;])' if c == '$' else
                           r'@((?:::)?[A-Za-z_]\w*(?:::\w+)*)').match(s, i)
            if m is None and c == '$' and s[i + 1] == '$':
                m2 = re.compile(r'\$\$((?:::)?[A-Za-z_]\w*)').match(s, i)
                if m2:
                    out.append('{' + clean_name(m2.group(1)) + '}')
                    i = m2.end()
                    continue
            if m is None:
                out.append(c)
                i += 1
                continue
            raw = m.group(0)
            name = raw[1:]
            i = m.end()
            if name in '@!':
                name = 'error'
            elif name in ('&', '.', ',', ';'):
                out.append(c + name)
                continue
            if c == '$':
                while i < n:
                    km = re.compile(r'(?:->)?\{([^}]*)\}|(?:->)?\[[^\]]*\]').match(s, i)
                    if not km:
                        break
                    if km.group(1) is not None:
                        key = km.group(1)
                        name = clean_name(key)
                    i = km.end()
            out.append('{' + clean_name(name) + '}')
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def unquote_single(s):
    return re.sub(r"\\([\\'])", r'\1', s)


class Renderer(object):
    """Turns the tokens of a Perl expression into a message template."""

    def __init__(self, sf):
        self.sf = sf

    def parts(self, lo, hi):
        """Split [lo, hi) at top-level concatenation dots and commas."""
        sf = self.sf
        out = []
        s = lo
        i = lo
        while i < hi:
            t = sf.toks[i]
            if t.kind == 'op' and t.val in '([{' and i in sf.match:
                i = sf.match[i] + 1
                continue
            if t.kind == 'op' and t.val in ('.', ','):
                out.append((s, i))
                s = i + 1
            i += 1
        out.append((s, hi))
        return [(a, b) for a, b in out if b > a]

    def render(self, lo, hi):
        return ''.join(self.term(a, b) for a, b in self.parts(lo, hi))

    def term(self, a, b):
        sf = self.sf
        t = sf.toks[a]
        if b - a == 1:
            if t.kind == 'str':
                return interpolate(t.val) if t.interp else unquote_single(t.val)
            if t.kind == 'num':
                return t.val
            if t.kind == 'var':
                return '{' + clean_name('error' if t.val in ('$@', '$!') else t.val) + '}'
            if t.kind == 'qw':
                return ' '.join(t.val)
        if t.kind == 'op' and t.val == '(' and sf.match.get(a) == b - 1:
            return self.render(a + 1, b - 1)
        if t.kind == 'ident' and t.val in ('sprintf', 'PVE::Tools::sprintf') and a + 1 < b and sf.tv(a + 1) == '(':
            return self.sprintf(a + 2, sf.match.get(a + 1, b - 1))
        if t.kind == 'ident' and t.val == 'sprintf':
            return self.sprintf(a + 1, b)
        if t.kind == 'var':
            # $x->{key}->[0], $h{key}
            name = clean_name(t.val)
            i = a + 1
            while i < b:
                v = sf.tv(i)
                if v == '->' and sf.tv(i + 1) in ('{', '['):
                    i += 1
                    continue
                if v in ('{', '[') and i in sf.match:
                    if v == '{':
                        inner = sf.toks[i + 1:sf.match[i]]
                        if len(inner) == 1 and inner[0].kind in ('ident', 'str', 'var'):
                            name = clean_name(inner[0].val)
                    i = sf.match[i] + 1
                    continue
                if v == '->' and sf.toks[i + 1].kind == 'ident':
                    name = clean_name(sf.toks[i + 1].val)
                    break
                return '{value}'
            return '{' + name + '}'
        if t.kind == 'ident' or t.kind == 'cast':
            for j in range(a, b):
                if sf.toks[j].kind == 'var' and sf.toks[j].val[0] in '$@':
                    return '{' + clean_name(sf.toks[j].val) + '}'
            return '{' + clean_name(t.val) + '}'
        return '{value}'

    def sprintf(self, lo, hi):
        sf = self.sf
        items = self.parts_comma(lo, hi)
        if not items:
            return '{value}'
        fmt = self.render(*items[0])
        args = [self.term(a, b) for a, b in items[1:]]
        names = [x[1:-1] if re.fullmatch(r'\{[\w-]+\}', x) else 'value' for x in args]
        it = iter(names)

        def sub(m):
            if m.group(0) == '%%':
                return '%'
            return '{' + next(it, 'value') + '}'
        return re.sub(r'%%|%[-+ 0#]*\d*(?:\.\d+)?[sdifxXeEgGcub]', sub, fmt)

    def parts_comma(self, lo, hi):
        return self.sf.items(lo, hi)


def meaningful(template):
    text = re.sub(r'\{[\w-]+\}', '', template)
    if re.search(r'implement me|abstract method', text):
        return False
    return len(re.findall(r'[A-Za-z]{2,}', text)) >= 2


def slug(template, taken):
    text = re.sub(r'\{[\w-]+\}', ' ', template.lower())
    words = [w for w in re.findall(r'[a-z]+', text) if w not in STOPWORDS or w in KEEP_WORDS]
    base = '_'.join(words[:5])[:48].strip('_') or 'error'
    name, k = base, 2
    while name in taken:
        name = '{0}_{1}'.format(base, k)
        k += 1
    taken.add(name)
    return name


# ------------------------------------------------------------------------ scanning

class Error(object):
    def __init__(self, status, message, errors, in_task, sf, line, sprintf=False):
        self.status = status
        self.message = message
        self.errors = errors
        self.in_task = in_task
        self.source = '{0}:{1}'.format(sf.ref, line)
        self.sprintf = sprintf

    def key(self):
        return (self.status, self.message, json.dumps(self.errors, sort_keys=True))


class Scan(object):
    """Direct findings of one body: errors and calls, each flagged if inside a worker."""

    def __init__(self):
        self.errors = []  # (Error, in_worker)
        self.calls = []   # (Func, in_worker)


class Index(object):
    def __init__(self, files):
        self.files = files
        self.by_pkg = collections.defaultdict(dict)   # pkg -> name -> Func
        self.bases = collections.defaultdict(list)
        for sf in files:
            for (pkg, name), fn in sf.subs.items():
                self.by_pkg[pkg].setdefault(name, fn)
            for pkg, bs in sf.bases.items():
                self.bases[pkg].extend(bs)

    def find(self, pkg, name, seen=None):
        if pkg in SKIP_PACKAGES:
            return None
        seen = seen or set()
        if pkg in seen:
            return None
        seen.add(pkg)
        fn = self.by_pkg.get(pkg, {}).get(name)
        if fn:
            return fn
        for base in self.bases.get(pkg, []):
            fn = self.find(base, name, seen)
            if fn:
                return fn
        return None


STMT_END_WORDS = {'if', 'unless', 'for', 'foreach', 'while', 'until'}


def scan(index, fn):
    if fn.scan is not None:
        return fn.scan
    fn.scan = out = Scan()
    sf = fn.sf
    toks = sf.toks
    rend = Renderer(sf)
    lo, hi = fn.lo + 1, fn.hi

    # Worker bodies: closures handed to fork_worker, directly or through a variable.
    workers = []
    for i in range(lo, hi):
        t = toks[i]
        if t.kind == 'ident' and t.val.endswith('fork_worker') and sf.tv(i + 1) == '(' and (i + 1) in sf.match:
            end = sf.match[i + 1]
            j = i + 2
            while j < end:
                if toks[j].val == 'sub' and sf.tv(j + 1) == '{' and (j + 1) in sf.match:
                    workers.append((j + 1, sf.match[j + 1]))
                    j = sf.match[j + 1]
                elif toks[j].kind == 'var' and toks[j].val in sf.locals:
                    w = sf.local(toks[j].val, fn)
                    workers.append((w.lo, w.hi))
                elif toks[j].val == '\\' and sf.tv(j + 1) and toks[j + 1].kind == 'var' and toks[j + 1].val.startswith('&'):
                    w = index.find(fn.pkg, toks[j + 1].val[1:])
                    if w and w.sf is sf:
                        workers.append((w.lo, w.hi))
                j += 1
    for name in ('$realcmd', '$worker', '$workercmd'):
        w = sf.local(name, fn)
        if w and fn.lo <= w.lo and w.hi <= fn.hi:
            workers.append((w.lo, w.hi))

    def in_worker(i):
        return any(a < i < b for a, b in workers)

    def stmt_end(i):
        """End (exclusive) of the arguments that start at token i."""
        j = i
        while j < hi:
            t = toks[j]
            if t.kind == 'op' and t.val in '([{' and j in sf.match:
                j = sf.match[j] + 1
                continue
            if t.kind == 'op' and t.val in (';', '}', ')', ']'):
                return j
            if t.kind == 'ident' and t.val in STMT_END_WORDS or (t.kind == 'ident' and t.val in ('or', 'and')):
                return j
            j += 1
        return j

    def add(status, message, errors, i, sprintf=False):
        message = re.sub(r'\s+$', '', message) if message.endswith('\n') else message
        if not meaningful(message):
            return
        out.errors.append((Error(status, message, errors, False, sf, toks[i].line, sprintf), in_worker(i)))

    i = lo
    while i < hi:
        t = toks[i]
        if t.kind == 'ident' and t.val == 'eval' and sf.tv(i + 1) == '{' and (i + 1) in sf.match:
            # Errors inside an eval block are caught there.
            i = sf.match[i + 1] + 1
            continue
        if t.kind == 'ident':
            v = t.val
            prev = sf.tv(i - 1)
            nxt = sf.tv(i + 1)
            if v == 'die' and prev != '->' and nxt != '=>':
                a = i + 1
                if sf.tv(a) == '(' and a in sf.match and stmt_end(a) >= sf.match[a]:
                    e = sf.match[a]
                    a += 1
                else:
                    e = stmt_end(a)
                if a < e and toks[a].val != 'PVE::Exception' and not (e - a == 1 and toks[a].kind == 'var'):
                    msg = rend.render(a, e)
                    spf = toks[a].val == 'sprintf'
                    add(500, msg, None, i, spf)
            elif v in ('raise_param_exc', 'PVE::Exception::raise_param_exc') and nxt == '(':
                e = sf.match.get(i + 1, i + 1)
                a = i + 2
                if sf.tv(a) == '{' and a in sf.match:
                    pairs = sf.pairs(a + 1, sf.match[a])
                    errors = {}
                    for key, (x, y) in pairs.items():
                        kt = sf.toks[x - 2]
                        errors[interpolate(key) if kt.kind == 'str' and kt.interp else key] = rend.render(x, y)
                    if errors:
                        add(400, 'Parameter verification failed.', errors, i)
                    else:
                        add(400, 'Parameter verification failed.', None, i)
                elif a < e:
                    add(400, 'Parameter verification failed.', {'{value}': rend.render(a, e)}, i)
            elif v in ('raise_perm_exc', 'PVE::Exception::raise_perm_exc') and nxt in ('(', ';'):
                e = sf.match.get(i + 1, i + 1) if nxt == '(' else i + 1
                what = rend.render(i + 2, e) if e > i + 2 else ''
                add(403, 'Permission check failed' + (' ({0})'.format(what) if what else ''), None, i)
            elif v in ('raise', 'PVE::Exception::raise') and nxt == '(' and prev != '->':
                self_raise(sf, rend, i + 1, i, add)
            elif v == 'PVE::Exception' and nxt == '->' and sf.tv(i + 2) in ('new', 'raise') and sf.tv(i + 3) == '(':
                self_raise(sf, rend, i + 3, i, add)
            else:
                callee = resolve(index, sf, fn, i)
                if callee is not None and callee is not fn:
                    out.calls.append((callee, in_worker(i)))
        elif (t.kind == 'var' and t.val in ('$class', '$self') and sf.tv(i + 1) == '->' and
              sf.tv(i + 2) and toks[i + 2].kind == 'ident' and sf.tv(i + 3) == '('):
            callee = index.find(fn.pkg, toks[i + 2].val)
            if callee is not None and callee is not fn:
                out.calls.append((callee, in_worker(i)))
        elif t.kind == 'var' and t.val in sf.locals and sf.tv(i + 1) == '->' and sf.tv(i + 2) == '(':
            w = sf.local(t.val, fn)
            if not (fn.lo <= w.lo and w.hi <= fn.hi) and w is not fn:
                out.calls.append((w, in_worker(i)))
        elif t.kind == 'var' and t.val.startswith('&') and t.val.replace('&', '$', 1) not in sf.locals:
            callee = index.find(fn.pkg, t.val[1:])
            if callee is not None and callee is not fn:
                out.calls.append((callee, in_worker(i)))
        elif t.kind == 'cast' and t.val == '&' and sf.tv(i + 1) and toks[i + 1].kind == 'var' and toks[i + 1].val in sf.locals:
            w = sf.local(toks[i + 1].val, fn)
            if not (fn.lo <= w.lo and w.hi <= fn.hi) and w is not fn:
                out.calls.append((w, in_worker(i)))
        i += 1
    return out


def self_raise(sf, rend, paren, at, add):
    """raise("msg", code => HTTP_X, errors => {...}) with the paren at index paren."""
    end = sf.match.get(paren, paren)
    items = sf.items(paren + 1, end)
    if not items:
        return
    msg = rend.render(*items[0])
    status = 500
    errors = None
    for a, b in items[1:]:
        if sf.toks[a].val == 'code' and sf.tv(a + 1) == '=>' and a + 2 < b:
            v = sf.toks[a + 2].val
            if v.isdigit():
                status = int(v)
            elif v.startswith('HTTP_'):
                status = HTTP.get(v[5:], 500)
    # errors => { k => "v" } spans several comma items; look for the key by scanning
    for j in range(paren + 1, end):
        if sf.toks[j].val == 'errors' and sf.tv(j + 1) == '=>' and sf.tv(j + 2) == '{' and (j + 2) in sf.match:
            pairs = sf.pairs(j + 3, sf.match[j + 2])
            errors = {k: rend.render(x, y) for k, (x, y) in pairs.items()} or None
    if sf.toks[items[0][0]].val == 'code':
        return
    if msg.endswith('\n'):
        msg = msg.rstrip('\n')
    add(status, msg, errors, at)


def resolve(index, sf, fn, i):
    """The Func an identifier at token i calls, or None."""
    toks = sf.toks
    t = toks[i]
    name = t.val
    nxt = sf.tv(i + 1)
    prev = sf.tv(i - 1)
    if prev == '->' or name in SKIP_CALLS:
        return None
    if nxt == '->' and sf.tv(i + 2) and toks[i + 2].kind == 'ident' and sf.tv(i + 3) == '(':
        # Class->method(...)
        method = toks[i + 2].val
        if name == '__PACKAGE__' or name in ('PVE::API2',):
            return index.find(fn.pkg, method)
        if '::' in name or name[:1].isupper():
            return index.find(name, method)
        return None
    if nxt == '(' or (nxt == ';' and False):
        if '::' in name:
            pkg, _, func = name.rpartition('::')
            return index.find(pkg, func)
        local = sf.subs.get((fn.pkg, name))
        if local:
            return local
        if name in sf.imports:
            return index.find(sf.imports[name], name)
    return None


def method_errors(index, fn):
    foreign = fn.sf.repo != 'pve-access-control'
    """All errors of one API method, nearest first."""
    found = collections.OrderedDict()
    queue = [(fn, 0, False)]
    visited = set()
    while queue:
        cur, depth, task = queue.pop(0)
        key = (id(cur), task)
        if key in visited:
            continue
        visited.add(key)
        s = scan(index, cur)
        for err, worker in s.errors:
            e = Error.__new__(Error)
            e.__dict__.update(err.__dict__)
            e.in_task = task or worker
            k = (e.key(), e.in_task)
            if k not in found:
                found[k] = (depth, e)
        if depth < MAX_DEPTH:
            for callee, worker in s.calls:
                if foreign and callee.sf.repo == 'pve-access-control' and callee.pkg == 'PVE::AccessControl':
                    continue
                queue.append((callee, depth + 1, task or worker))
    ordered = sorted(found.values(), key=lambda x: x[0])
    # The same error seen in and out of a task keeps the outer one.
    res, seen = [], set()
    for _, e in ordered:
        if e.key() in seen:
            continue
        seen.add(e.key())
        res.append(e)
    return res[:MAX_ERRORS]


# --------------------------------------------------------------------------- mapping

def load_files(root):
    files = []
    for repo in sorted(os.listdir(root)):
        base = os.path.join(root, repo)
        if not os.path.isdir(os.path.join(base, '.git')) and not os.path.isdir(base):
            continue
        for dirpath, dirs, names in os.walk(base):
            dirs[:] = [d for d in dirs if d not in ('.git', 'test', 'tests', 't', 'debian', 'bin')]
            for name in names:
                if name.endswith('.pm'):
                    path = os.path.join(dirpath, name)
                    with open(path, encoding='utf-8', errors='replace') as fh:
                        files.append(SrcFile(repo, os.path.relpath(path, base).replace(os.sep, '/'), fh.read()))
    return files


def norm(path):
    return '/' + '/'.join(s for s in path.split('/') if s)


def mounts(files):
    """pkg -> [(parent pkg, path)] from subclass registrations."""
    out = collections.defaultdict(list)
    for sf in files:
        for lo, hi, pkg in sf.methods:
            pairs = sf.pairs(lo + 1, hi)
            if 'subclass' in pairs and 'path' in pairs:
                a, b = pairs['subclass']
                c, d = pairs['path']
                out[sf.toks[a].val].append((pkg, sf.toks[c].val if sf.toks[c].kind == 'str' else ''))
    return out


def prefixes(mnt, derived, pkg, depth=0, seen=()):
    if pkg == 'PVE::API2':
        return ['']
    if depth > 12 or pkg in seen:
        return []
    res = []
    # Methods of a base class are served wherever a subclass is mounted.
    for sub in derived.get(pkg, []):
        res.extend(prefixes(mnt, derived, sub, depth + 1, seen + (pkg,)))
    for parent, path in mnt.get(pkg, []):
        for pre in prefixes(mnt, derived, parent, depth + 1, seen + (pkg,)):
            res.append(pre + '/' + path.strip('/') if path.strip('/') else pre)
    return sorted(set(res))


def build(root, schema_path, out_path):
    files = load_files(root)
    index = Index(files)
    mnt = mounts(files)
    derived = collections.defaultdict(list)
    for pkg, bases in index.bases.items():
        for base in bases:
            derived[base].append(pkg)
    with gzip.open(schema_path) as fh:
        schema = json.load(fh)['paths']
    by_name = collections.defaultdict(list)
    for path, methods in schema.items():
        for method, info in methods.items():
            if info.get('name'):
                by_name[(info['name'], method)].append(path)

    catalogue = collections.defaultdict(list)
    unmapped = []
    registered = 0
    for sf in files:
        if '/API2/' not in '/' + sf.rel and 'API2/' not in sf.rel:
            continue
        for lo, hi, pkg in sf.methods:
            pairs = sf.pairs(lo + 1, hi)
            if 'subclass' in pairs or 'method' not in pairs or 'code' not in pairs:
                continue
            registered += 1
            method = sf.toks[pairs['method'][0]].val
            name = sf.toks[pairs['name'][0]].val if 'name' in pairs else ''
            rel = sf.toks[pairs['path'][0]].val if 'path' in pairs and sf.toks[pairs['path'][0]].kind == 'str' else ''
            a, b = pairs['code']
            if sf.toks[a].val == 'sub' and sf.tv(a + 1) == '{':
                fn = Func(sf, a + 1, sf.match.get(a + 1, a + 1), name, pkg)
            elif sf.toks[a].kind == 'var' and sf.toks[a].val in sf.locals:
                fn = sf.local(sf.toks[a].val, Func(sf, a, a, '', pkg))
            else:
                unmapped.append('{0} {1} ({2}:{3}) code is not an inline sub'.format(method, rel, sf.ref, sf.toks[a].line))
                continue
            full = [p for p in (norm(pre + '/' + rel) for pre in prefixes(mnt, derived, pkg))
                    if p in schema and method in schema[p]]
            if not full and name:
                cands = by_name.get((name, method), [])
                tail = norm(rel)
                narrowed = [p for p in cands if p.endswith(tail)] if rel else cands
                full = narrowed or (cands if len(cands) == 1 else [])
            if not full:
                unmapped.append('{0} {1} {2} ({3}:{4})'.format(method, rel, name, sf.ref, sf.toks[pairs['method'][0]].line))
                continue
            errors = method_errors(index, fn)
            if not errors:
                for path in full:
                    catalogue['{0} {1}'.format(method, path)]
                continue
            for path in full:
                taken = set()
                entries = []
                for e in errors:
                    entry = {'name': slug_for(e, taken), 'status': e.status, 'message': e.message}
                    if e.errors:
                        entry['errors'] = e.errors
                    if e.sprintf:
                        entry['sprintf'] = True
                    entry['in_task'] = e.in_task
                    entry['source'] = e.source
                    entries.append(entry)
                catalogue['{0} {1}'.format(method, path)] = entries

    total = sum(len(v) for v in catalogue.values())
    meta = {
        'date': datetime.date.today().isoformat(),
        'repos': repo_commits(root),
        'registered_methods': registered,
        'unmapped': len(unmapped),
        'methods_with_errors': sum(1 for v in catalogue.values() if v),
        'errors': total,
        'in_task': sum(1 for v in catalogue.values() for e in v if e['in_task']),
    }
    with gzip.GzipFile(out_path, 'wb', mtime=0) as fh:
        fh.write(json.dumps({'meta': meta, 'errors': dict(sorted(catalogue.items()))},
                            indent=None, sort_keys=False, separators=(',', ':')).encode())
    return meta, unmapped, catalogue, schema


def slug_for(e, taken):
    if e.status == 400 and e.errors:
        key = next(iter(e.errors))
        return slug('param ' + re.sub(r'\W+', ' ', key) + ' ' + next(iter(e.errors.values())), taken)
    return slug(e.message, taken)


def repo_commits(root):
    out = {}
    for repo in sorted(os.listdir(root)):
        try:
            out[repo] = subprocess.check_output(['git', '-C', os.path.join(root, repo), 'rev-parse', 'HEAD'],
                                                stderr=subprocess.DEVNULL).decode().strip()
        except (OSError, subprocess.CalledProcessError):
            pass
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('root', help='directory holding the cloned PVE repositories')
    ap.add_argument('--schema', default=os.path.join(DATA, 'pve-api.json.gz'))
    ap.add_argument('--out', default=os.path.join(DATA, 'pve-errors.json.gz'))
    args = ap.parse_args()
    meta, unmapped, catalogue, schema = build(args.root, args.schema, args.out)
    total = sum(len(m) for m in schema.values())
    covered = sum(1 for k in catalogue)
    print(json.dumps(meta, indent=1))
    print('schema methods', total, 'catalogue entries', covered)
    for line in unmapped[:40]:
        print('unmapped:', line)
    return 0


if __name__ == '__main__':
    sys.exit(main())
