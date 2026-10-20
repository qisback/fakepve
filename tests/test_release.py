"""Versioning: one version, a parseable changelog, and tools/release.py."""

import importlib.util
import os
import re
import subprocess
import sys

import pytest

import fakepve

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def load_release():
    spec = importlib.util.spec_from_file_location('release', os.path.join(ROOT, 'tools', 'release.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load_release()


def read(name):
    with open(os.path.join(ROOT, name), encoding='utf-8') as fh:
        return fh.read()


def test_version_in_pyproject_is_the_package_version():
    declared = re.search(r'^version = "([^"]+)"', read('pyproject.toml'), re.M).group(1)
    assert re.match(r'^\d+\.\d+\.\d+$', declared)
    assert fakepve.__version__ == declared
    assert declared not in read('src/fakepve/__init__.py')  # single-sourced


def test_cli_prints_the_version():
    result = subprocess.run([sys.executable, '-m', 'fakepve', '--version'], capture_output=True, text=True,
                            env=dict(os.environ, PYTHONPATH=os.path.join(ROOT, 'src')))
    assert result.returncode == 0
    assert result.stdout.strip() == 'fakepve ' + fakepve.__version__


def test_changelog_parses_and_its_newest_section_is_the_current_version_or_unreleased():
    preamble, sections, links = release.parse(read('CHANGELOG.md'))
    names = [name for name, _, _ in sections]
    assert 'Keep a Changelog' in '\n'.join(preamble) and 'Semantic Versioning' in '\n'.join(preamble)
    assert names and names[0] in ('Unreleased', fakepve.__version__)
    assert all(re.match(r'^\d+\.\d+\.\d+$', n) for n in names if n != 'Unreleased')
    for name, date, _ in sections:
        assert (name == 'Unreleased' and date is None) or re.match(r'^\d{4}-\d\d-\d\d$', date)
    assert set(links) <= set(names)
    assert not re.search('[–—]', read('CHANGELOG.md'))


def test_current_version_notes_are_not_empty():
    # [Unreleased] is legitimately empty straight after a release; the current version's section is not.
    notes = release.section_notes(read('CHANGELOG.md'), fakepve.__version__)
    assert notes is not None and notes.strip()


SAMPLE = '''# Changelog

Keep a Changelog, Semantic Versioning.

## [Unreleased]

### Added

- Something new.

## [0.1.0] - 2026-01-01

- First.

[Unreleased]: https://github.com/qisback/fakepve/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/qisback/fakepve/releases/tag/v0.1.0
'''
PYPROJECT = '[project]\nname = "fakepve"\nversion = "0.1.0"\n'


def test_release_renames_unreleased_bumps_and_links():
    changelog, pyproject = release.release('0.2.0', '2026-02-03', SAMPLE, PYPROJECT)
    assert 'version = "0.2.0"' in pyproject
    _, sections, links = release.parse(changelog)
    assert [(n, d) for n, d, _ in sections] == [('Unreleased', None), ('0.2.0', '2026-02-03'), ('0.1.0', '2026-01-01')]
    assert links['Unreleased'].endswith('/compare/v0.2.0...HEAD')
    assert links['0.2.0'].endswith('/compare/v0.1.0...v0.2.0')
    assert links['0.1.0'].endswith('/releases/tag/v0.1.0')
    assert release.section_notes(changelog, '0.2.0').strip() == '### Added\n\n- Something new.'
    assert release.section_notes(changelog, 'Unreleased').strip() == ''
    # Nothing new since: a second release has to be refused.
    with pytest.raises(SystemExit, match='empty'):
        release.release('0.2.1', '2026-02-04', changelog, pyproject)


def test_first_release_links_to_the_tag():
    text = '# Changelog\n\n## [Unreleased]\n\n- All of it.\n'
    changelog, _ = release.release('0.1.0', '2026-01-01', text, PYPROJECT)
    assert '[0.1.0]: https://github.com/qisback/fakepve/releases/tag/v0.1.0' in changelog


@pytest.mark.parametrize('version', ['1.0', 'v1.0.0', '1.0.0rc1'])
def test_release_rejects_a_bad_version(version):
    with pytest.raises(SystemExit):
        release.release(version, '2026-01-01', SAMPLE, PYPROJECT)


def test_release_refuses_an_existing_version():
    with pytest.raises(SystemExit, match='already'):
        release.release('0.1.0', '2026-01-01', SAMPLE, PYPROJECT)


def test_check_tag_needs_matching_version_and_a_section():
    assert release.check_tag('v0.1.0', SAMPLE, PYPROJECT) == []
    assert 'pyproject.toml says 0.1.0' in release.check_tag('v0.2.0', SAMPLE, PYPROJECT)[0]
    assert any('no section' in p for p in release.check_tag('v0.2.0', SAMPLE, PYPROJECT.replace('0.1.0', '0.2.0')))
    assert 'not vX.Y.Z' in release.check_tag('0.1.0', SAMPLE, PYPROJECT)[0]


def test_notes_command_prints_a_version(capsys):
    changelog = read('CHANGELOG.md')
    name = release.parse(changelog)[1][0][0]
    assert release.main(['--notes', name]) == 0
    assert capsys.readouterr().out.strip() == release.section_notes(changelog, name).strip()
    assert release.main(['--notes', '9.9.9']) == 1
    assert 'no section' in capsys.readouterr().err
