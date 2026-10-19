"""Hardening: hostile input must not hang, exhaust memory, leak secrets or crash the server."""

import time
import urllib.parse

from fakepve import schema

OCI_PATTERN = schema.load().paths['/nodes/{node}/query-oci-repo-tags']['GET']['parameters']['properties'][
    'reference']['pattern']


# ------------------------------------------------------- F2: pattern matching

async def test_crafted_oci_reference_is_refused_quickly(pve, api):
    start = time.monotonic()
    for hostile in ('a' * 40 + '!', 'a' * 64 + '!', 'a-' * 30 + '!'):
        status, body = await api.call('GET', '/nodes/pve1/query-oci-repo-tags?reference=' +
                                      urllib.parse.quote(hostile))
        assert status == 400 and body['errors'] == {'reference': 'value does not match the regex pattern'}
    assert time.monotonic() - start < 0.5


async def test_valid_oci_references_still_pass(pve, api):
    for ref in ('alpine', 'docker.io/library/nginx', 'registry.example.org:5000/team/app-v2_x.y', 'a--b/c__d'):
        status, body = await api.call('GET', '/nodes/pve1/query-oci-repo-tags?reference=' +
                                      urllib.parse.quote(ref))
        assert status == 200, (ref, body)


def test_linear_oci_pattern_accepts_what_the_original_did():
    import re
    old = re.compile('^(?:' + OCI_PATTERN + ')$', re.S)
    new = schema._pattern(OCI_PATTERN)
    for text in ('a', 'a-b', 'a--b', 'a_b', 'a__b', 'a___b', 'a.b', 'a-', '-a', 'a-_b', 'A', 'a/b', 'a//b', 'a:b',
                 'ab--cd/ef_gh.ij', 'host:5000/a', '', '/', 'a b'):
        assert bool(old.match(text)) == bool(new.match(text)), text


def test_no_pattern_in_the_schema_is_exponential():
    patterns = set()

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get('pattern'), str):
                patterns.add(node['pattern'])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(schema.load().paths)
    start = time.monotonic()
    for pattern in patterns:
        rx = schema._pattern(pattern)
        if rx is None:
            continue
        for char in 'a1-_.,= ;:':
            rx.match(char * 200 + '!')
    assert time.monotonic() - start < 2


def test_values_over_the_cap_fail_patterns_without_matching():
    sch = {'type': 'string', 'pattern': '[a-z]+'}
    assert schema.check_value(sch, 'a' * schema.MAX_PATTERN_VALUE)[1] is None
    assert schema.check_value(sch, 'a' * (schema.MAX_PATTERN_VALUE + 1))[1] == 'value does not match the regex pattern'
