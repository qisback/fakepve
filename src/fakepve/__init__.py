"""A lightweight fake Proxmox VE API for testing Proxmox clients."""

import os
import re
from importlib import metadata

from .lxc import FakeCt
from .model import FakeVm, PveError, TaskError
from .server import PORT, FakePve, next_loopback, settle

__all__ = ['PORT', 'FakeCt', 'FakePve', 'FakeVm', 'PveError', 'TaskError', 'next_loopback', 'settle']


def _version():
    """The installed version; from pyproject.toml when run from an uninstalled source tree."""
    try:
        return metadata.version('fakepve')
    except metadata.PackageNotFoundError:
        pass
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'pyproject.toml')
        with open(path, encoding='utf-8') as fh:
            return re.search(r'^version = "([^"]+)"', fh.read(), re.M).group(1)
    except (OSError, AttributeError):
        return '0+unknown'


__version__ = _version()
