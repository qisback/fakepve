### Added

- LXC containers keep state. `pve.add_ct()` and `FakeCt` add one; a client can create one with `POST /nodes/{node}/lxc`. Containers appear in `/cluster/resources` (type `lxc`) and `/nodes/{node}/lxc`, and share the VM id space (`VM 100 already exists on node 'pve1'`, `CT 100 already exists ...`). Create, destroy, `status/current`, `status/{start,stop,shutdown,reboot,suspend,resume}`, `config` (GET and PUT, with `digest`, `delete`, `revert`, `current` and `snapshot`), `pending`, `clone`, `template`, `migrate` (GET and POST), `resize`, `interfaces` and `snapshot` (list, create, delete, rollback, snapshot config) read and write that state, with PVE's messages, task types (`vzcreate`, `vzstart`, `vzstop`, `vzshutdown`, `vzreboot`, `vzdestroy`, `vzclone`, `vzsnapshot`, ...), locks and privileges.
- A running container takes cores, memory, swap, network changes, new mount points, names and tags at once and keeps the rest pending until the next start or reboot; a stopped one takes everything. Removed mount points become `unused` volumes.
- Container scenarios: `ct.start_secs`, `ct.stop_secs`, `ct.shutdown_secs`, `ct.start_error`, `ct.ha_state`, and `pve.ct_secs` for the other tasks. `lose_quorum`, `set_node_offline`, `hold_config_lock`, `backup`, `migrate`, `snapshot_lock`, `unlock` and `pve.fail(..., error=name)` work on containers.
- The guests file takes `"type": "lxc"` for a container.

### Changed

- The `lxc` routes above no longer answer from the schema alone: a request for a container that does not exist fails as PVE's does (`Configuration file 'nodes/pve1/lxc/100.conf' does not exist`, or a start task that ends with it).
