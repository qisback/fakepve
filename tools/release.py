#!/usr/bin/env python3
"""Cut a release: move [Unreleased] in CHANGELOG.md to a version and bump pyproject.toml.

    python tools/release.py X.Y.Z [--date YYYY-MM-DD]   # rename [Unreleased], bump, add links, print the notes
    python tools/release.py --notes X.Y.Z               # print the notes of an existing version
    python tools/release.py --check vX.Y.Z              # exit 1 unless the tag matches pyproject and the changelog
"""

import argparse
import datetime
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
CHANGELOG = os.path.join(ROOT, 'CHANGELOG.md')
PYPROJECT = os.path.join(ROOT, 'pyproject.toml')
REPO = 'https://github.com/qisback/fakepve'
SEMVER = re.compile(r'^\d+\.\d+\.\d+$')
HEADING = re.compile(r'^## \[([^\]]+)\](?: - (\S+))?\s*$')
LINK = re.compile(r'^\[([^\]]+)\]: (\S+)\s*$')


def parse(text):
    """(preamble, [(name, date, body lines)], {name: url}) from a Keep a Changelog file."""
    preamble, sections, links = [], [], {}
    for line in text.split('\n'):
        match = HEADING.match(line)
        link = LINK.match(line)
        if match:
            sections.append([match.group(1), match.group(2), []])
        elif link:
            links[link.group(1)] = link.group(2)
        elif sections:
            sections[-1][2].append(line)
        else:
            preamble.append(line)
    return preamble, [(n, d, body) for n, d, body in sections], links


def render(preamble, sections, links):
    out = list(preamble)
    for name, date, body in sections:
        out.append('## [{0}]{1}'.format(name, ' - ' + date if date else ''))
        out += body
    text = '\n'.join(out).rstrip('\n') + '\n\n'
    order = [n for n, _, _ in sections]
    text += '\n'.join('[{0}]: {1}'.format(n, links[n]) for n in order if n in links) + '\n'
    return text


def section_notes(text, version):
    """The body of one version's section, or None."""
    for name, _, body in parse(text)[1]:
        if name == version:
            return '\n'.join(body).strip('\n') + '\n'
    return None


def pyproject_version(text):
    return re.search(r'^version = "([^"]+)"', text, re.M).group(1)


def check_tag(tag, changelog_text, pyproject_text):
    """Problems (a list of strings) with releasing this tag."""
    version = tag[1:] if tag.startswith('v') else None
    if version is None or not SEMVER.match(version):
        return ['tag {0!r} is not vX.Y.Z'.format(tag)]
    problems = []
    if pyproject_version(pyproject_text) != version:
        problems.append('tag {0} but pyproject.toml says {1}'.format(tag, pyproject_version(pyproject_text)))
    notes = section_notes(changelog_text, version)
    if not notes or not notes.strip():
        problems.append('CHANGELOG.md has no section for [{0}]'.format(version))
    return problems


def release(version, date, changelog_text, pyproject_text):
    """(new changelog, new pyproject) with [Unreleased] released as version."""
    if not SEMVER.match(version):
        raise SystemExit('version must be X.Y.Z, not {0!r}'.format(version))
    preamble, sections, links = parse(changelog_text)
    names = [n for n, _, _ in sections]
    if version in names:
        raise SystemExit('CHANGELOG.md already has [{0}]'.format(version))
    if not names or names[0] != 'Unreleased':
        raise SystemExit('CHANGELOG.md has no [Unreleased] section first')
    if not ''.join(sections[0][2]).strip():
        raise SystemExit('[Unreleased] is empty: nothing to release')
    previous = names[1] if len(names) > 1 else None
    sections[0] = (version, date, sections[0][2])
    sections.insert(0, ('Unreleased', None, ['']))
    links['Unreleased'] = '{0}/compare/v{1}...HEAD'.format(REPO, version)
    links[version] = ('{0}/compare/v{1}...v{2}'.format(REPO, previous, version) if previous
                      else '{0}/releases/tag/v{1}'.format(REPO, version))
    bumped = re.sub(r'^version = "[^"]+"', 'version = "{0}"'.format(version), pyproject_text, count=1, flags=re.M)
    return render(preamble, sections, links), bumped


def read(path):
    with open(path, encoding='utf-8', newline='') as fh:
        return fh.read().replace('\r\n', '\n')


def write(path, text):
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('version', nargs='?', help='X.Y.Z to release (with --notes: to print; with --check: vX.Y.Z)')
    parser.add_argument('--date', default=datetime.date.today().isoformat(), help='release date (default today)')
    parser.add_argument('--notes', action='store_true', help='print the notes of an existing version and exit')
    parser.add_argument('--check', action='store_true', help='check a tag against pyproject.toml and the changelog')
    args = parser.parse_args(argv)
    if not args.version:
        parser.error('a version is required')
    changelog, pyproject = read(CHANGELOG), read(PYPROJECT)
    if args.check:
        problems = check_tag(args.version, changelog, pyproject)
        for problem in problems:
            print('release: ' + problem, file=sys.stderr)
        return 1 if problems else 0
    if args.notes:
        notes = section_notes(changelog, args.version)
        if notes is None:
            print('release: no section [{0}] in CHANGELOG.md'.format(args.version), file=sys.stderr)
            return 1
        sys.stdout.write(notes)
        return 0
    new_changelog, new_pyproject = release(args.version, args.date, changelog, pyproject)
    write(CHANGELOG, new_changelog)
    write(PYPROJECT, new_pyproject)
    sys.stdout.write(section_notes(new_changelog, args.version))
    return 0


if __name__ == '__main__':
    sys.exit(main())
