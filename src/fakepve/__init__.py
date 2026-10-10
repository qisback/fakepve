"""A lightweight fake Proxmox VE API for testing Proxmox clients."""

from .model import FakeVm, PveError, TaskError
from .server import PORT, FakePve, next_loopback, settle

__all__ = ['PORT', 'FakePve', 'FakeVm', 'PveError', 'TaskError', 'next_loopback', 'settle']
__version__ = '0.1.0'
