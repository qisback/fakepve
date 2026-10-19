# Contributing

## Checks before a change

```console
pip install ruff pytest pytest-asyncio aiohttp cryptography
ruff check .
PYTHONPATH=src python -m pytest -q
```

The tests include the documentation checks: relative links, the generated reference files, the code blocks in the pages and, when ProperDocs is installed, a strict build of the site. After changing code that the docs show, regenerate what is derived:

```console
python tools/gen_docs.py                      # endpoint reference and signature index
python tools/docs_runner.py --fill            # the printed output of the runnable blocks
pip install rich && python tools/screenshots.py   # the terminal screenshots
```

How these fit together is in [How it works](how-it-works.md#documentation-tooling).

## Building the site locally

The site is built with [ProperDocs](https://properdocs.org), the maintained continuation of MkDocs 1.6, and the Material theme. Its configuration is `properdocs.yml` at the repository root. The versions are pinned in `docs/requirements.txt`.

```console
python -m venv .venv-docs
.venv-docs/bin/pip install -r docs/requirements.txt
.venv-docs/bin/properdocs build --strict      # writes site/
.venv-docs/bin/properdocs serve               # preview at http://127.0.0.1:8000
```

`--strict` turns every warning (a broken link or anchor, a page missing from the navigation) into an error, so a clean strict build is the bar. `site/` is generated and not committed.

!!! note
    `mkdocs-material` depends on the original `mkdocs` package, so both are installed. Use the `properdocs` command to build; it reads `properdocs.yml`.

Pages in `docs/` link to the examples with the repository's address (`https://github.com/qisback/fakepve/blob/main/...`), because the site cannot reach files outside `docs/`. When the repository moves, change that prefix, `repo_url` in `properdocs.yml`, and the one in `tests/test_docs.py`.

## Publishing the site

The build is plain static files in `site/`, so any static host works. There is deliberately no publishing workflow in the repository.

- **GitHub Pages:** copy `site/` to a `gh-pages` branch (`properdocs gh-deploy` does this from a checkout with push access), or upload it as a Pages artifact from a workflow of your own, and enable Pages for that branch.
- **Forgejo or Gitea Pages:** push the contents of `site/` to the branch or repository your Pages setup serves.
- **Any static host:** copy `site/` to the web root, for example `rsync -a --delete site/ host:/var/www/fakepve/`.

If the site is served from a sub-path, set `site_url` in `properdocs.yml` to its address, so that links and the search index resolve.
