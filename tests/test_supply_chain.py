"""Dependency floors, pinned CI actions and the pinned base image."""

import glob
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def version(text):
    return tuple(int(n) for n in text.split('.'))


def test_dependency_floors_exclude_versions_with_advisories():
    pyproject = read('pyproject.toml')
    aiohttp = re.search(r'"aiohttp>=([\d.]+)"', pyproject).group(1)
    assert version(aiohttp) >= (3, 14, 3)
    floors = re.findall(r'"cryptography>=([\d.]+)"', pyproject)
    assert floors and all(version(f) >= (50, 0, 0) for f in floors)


def test_python_support_matches_the_ci_matrix():
    minimum = re.search(r'requires-python = ">=(\d+\.\d+)"', read('pyproject.toml')).group(1)
    matrix = re.search(r"python: \[([^\]]+)\]", read('.github', 'workflows', 'ci.yml')).group(1)
    versions = re.findall(r"'(\d+\.\d+)'", matrix)
    assert versions and minimum in versions
    assert all(version(v) >= version(minimum) for v in versions)
    assert version(minimum) >= (3, 10)  # aiohttp 3.14 needs it; 3.9 is end of life


def test_ci_tools_are_pinned_exactly():
    pins = read('.github', 'ci-constraints.txt')
    names = [line.split('==')[0] for line in pins.splitlines() if line and not line.startswith('#')]
    assert {'ruff', 'pytest', 'pytest-asyncio', 'requests', 'PyYAML', 'aiohttp', 'cryptography'} <= set(names)
    assert all('==' in line for line in pins.splitlines() if line and not line.startswith('#'))
    for workflow in ("ci.yml", "pages.yml", "release.yml"):
        text = read('.github', 'workflows', workflow)
        for line in re.findall(r'^\s*run: .*pip install.*$', text, flags=re.M):
            assert '-c .github/ci-constraints.txt' in line, line


def test_actions_are_pinned_to_commits():
    files = glob.glob(os.path.join(ROOT, 'examples', 'ci', '*.yml')) + \
        glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml'))
    assert files
    for path in files:
        for ref in re.findall(r'uses:\s*(\S+)', open(path, encoding='utf-8').read()):
            assert re.match(r'^[\w./-]+@[0-9a-f]{40}$', ref), (path, ref)
        text = open(path, encoding='utf-8').read()
        assert all('#' in line for line in text.splitlines() if 'uses:' in line), path


def test_base_image_is_pinned_by_digest():
    froms = re.findall(r'^FROM\s+(\S+)', read('Dockerfile'), flags=re.M)
    assert froms and all(re.search(r'@sha256:[0-9a-f]{64}$', f) for f in froms)


def test_release_workflow_is_least_privilege_and_ordered():
    import yaml
    flow = yaml.safe_load(read('.github', 'workflows', 'release.yml'))
    assert flow[True] == {'push': {'tags': ['v*']}}  # YAML reads the key "on" as True
    assert flow['permissions'] == {'contents': 'read'}
    jobs = flow['jobs']
    assert set(jobs) == {'build', 'pypi', 'image', 'release'}
    assert jobs['pypi']['needs'] == 'build' and jobs['pypi']['environment'] == 'pypi'
    assert jobs['pypi']['permissions'] == {'id-token': 'write'}
    assert jobs['image']['permissions'] == {'contents': 'read', 'packages': 'write'}
    assert set(jobs['release']['needs']) == {'build', 'image'}
    assert jobs['release']['permissions'] == {'contents': 'write'}
    for job in jobs.values():
        for step in job['steps']:
            # Event data reaches scripts through env, never by expansion into the script.
            assert '${{' not in step.get('run', ''), step
            if step.get('uses', '').startswith('actions/checkout'):
                assert step['with']['persist-credentials'] is False


def test_ci_builds_the_image_and_tests_release_branches():
    text = read('.github', 'workflows', 'ci.yml')
    assert "'release/**'" in text
    assert 'tools/smoke_image.sh' in text and 'tools/smoke_image.sh' in read('.github', 'workflows', 'release.yml')
