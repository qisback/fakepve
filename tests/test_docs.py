"""The documentation cannot go stale: links resolve, generated files are current, code blocks run."""

import importlib.util
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DOCS = os.path.join(ROOT, 'docs')
sys.path.insert(0, os.path.join(ROOT, 'tools'))


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, 'tools', name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen_docs = load_tool('gen_docs')
docs_runner = load_tool('docs_runner')


def markdown_files():
    out = [os.path.join(ROOT, 'README.md')]
    for base, _, names in os.walk(DOCS):
        out += [os.path.join(base, n) for n in sorted(names) if n.endswith('.md')]
    return sorted(out)


def read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def rel(path):
    return os.path.relpath(path, ROOT).replace(os.sep, '/')


def slug(heading):
    """GitHub's anchor for a heading."""
    text = re.sub(r'`', '', heading).strip().lower()
    text = re.sub(r'[^\w\- ]', '', text)
    return text.replace(' ', '-')


def anchors(path):
    out = set()
    in_code = False
    for line in read(path).split('\n'):
        if line.startswith('```'):
            in_code = not in_code
        elif not in_code and line.startswith('#'):
            out.add(slug(line.lstrip('#')))
    return out


# ------------------------------------------------------------------------ links

# Pages link to files outside docs/ by the repository's address; the file must exist.
REPO_BLOB = 'https://github.com/qisback/fakepve/blob/main/'
LINK = re.compile(r'!?\[[^\]]*\]\(([^)\s]+)\)')


@pytest.mark.parametrize('path', markdown_files(), ids=rel)
def test_relative_links_resolve(path):
    text = re.sub(r'```.*?```', '', read(path), flags=re.S)
    text = re.sub(r'`[^`\n]*`', '', text)
    bad = []
    for target in LINK.findall(text):
        if target.startswith(REPO_BLOB):
            if not os.path.exists(os.path.join(ROOT, target[len(REPO_BLOB):].split('#')[0])):
                bad.append(target)
            continue
        if re.match(r'^[a-z][a-z0-9+.-]*:', target) or target.startswith('<'):
            continue
        name, _, fragment = target.partition('#')
        dest = os.path.normpath(os.path.join(os.path.dirname(path), name)) if name else path
        if not os.path.exists(dest):
            bad.append(target)
        elif fragment and dest.endswith('.md') and fragment not in anchors(dest):
            bad.append(target + ' (no such heading)')
    assert not bad, bad


def test_images_are_valid_svg_and_used():
    images = os.path.join(DOCS, 'img')
    names = sorted(n for n in os.listdir(images) if n.endswith('.svg'))
    assert names
    used = ''.join(read(p) for p in markdown_files())
    for name in names:
        ET.parse(os.path.join(images, name))
        assert 'img/' + name in used, name + ' is not used by any page'


# ----------------------------------------------------------------- style rules

def test_no_em_or_en_dashes():
    paths = markdown_files()
    paths += [os.path.join(ROOT, 'examples', n) for n in os.listdir(os.path.join(ROOT, 'examples'))
              if os.path.isfile(os.path.join(ROOT, 'examples', n))]
    paths += [os.path.join(ROOT, 'examples', 'ci', n) for n in os.listdir(os.path.join(ROOT, 'examples', 'ci'))]
    paths.append(os.path.join(ROOT, 'Dockerfile'))
    found = [rel(p) for p in paths if re.search('[–—]', read(p))]
    assert not found, found


# ---------------------------------------------------------------- generated files

def test_endpoint_reference_is_current():
    assert read(gen_docs.ENDPOINTS) == gen_docs.endpoints_md(), 'run: python tools/gen_docs.py'


def test_signature_index_is_current():
    assert read(gen_docs.PYTHON_API) == gen_docs.python_api_text(), 'run: python tools/gen_docs.py'


def test_endpoint_reference_covers_every_method():
    from fakepve import schema
    text = read(gen_docs.ENDPOINTS)
    paths = schema.load().paths
    assert text.count('\n### `') == len(paths)
    assert sum(text.count('- **' + m + '**') for m in ('GET', 'POST', 'PUT', 'DELETE')) == \
        sum(len(methods) for methods in paths.values())


def public_names():
    from fakepve import FakePve, FakeVm
    names = set()
    for cls, instance in ((FakePve, FakePve(host='127.0.0.2')), (FakeVm, FakeVm(100, 'vm'))):
        names |= set(gen_docs.members(cls))
        names |= set(n for n in vars(instance) if not n.startswith('_'))
    return names


def test_python_api_explains_every_public_name():
    text = read(gen_docs.PYTHON_API)
    hand_written = text.split(gen_docs.BEGIN)[0]
    spans = ' '.join(re.findall(r'`[^`\n]+`', hand_written))
    missing = sorted(n for n in public_names() if not re.search(r'(?<![\w])' + re.escape(n) + r'(?![\w])', spans))
    assert not missing, missing


# ------------------------------------------------------------------- code blocks

def runnable():
    return [p for p in markdown_files() if any(kind == 'run' for kind, _, _ in docs_runner.blocks(read(p)))]


@pytest.mark.parametrize('path', runnable(), ids=rel)
def test_code_blocks_run_and_print_what_the_docs_say(path):
    cwd = os.getcwd()
    environ = dict(os.environ)
    try:
        problems = docs_runner.run_file(path)
    finally:
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(environ)
    assert not problems, '\n'.join(problems)


def test_every_run_block_has_an_output_or_prints_nothing():
    # An output block must follow a run block; a stray one would never be checked.
    for path in runnable():
        previous = None
        for kind, line, _ in docs_runner.blocks(read(path)):
            assert not (kind == 'output' and previous != 'run'), '{0}:{1}'.format(rel(path), line)
            previous = kind


# -------------------------------------------------------------------- the site

@pytest.mark.skipif(importlib.util.find_spec('properdocs') is None or importlib.util.find_spec('material') is None,
                    reason='needs properdocs and mkdocs-material (docs/requirements.txt)')
def test_site_builds_in_strict_mode(tmp_path):
    command = [sys.executable, '-m', 'properdocs', 'build', '--strict', '-q', '-d', str(tmp_path / 'site')]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    assert 'WARNING' not in result.stdout + result.stderr
    assert (tmp_path / 'site' / 'img' / 'quick-start.svg').exists()
    assert (tmp_path / 'site' / 'index.html').exists()
