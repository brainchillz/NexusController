"""Hypervisor metric collectors for virtualization host adapters.

Each collector exposes:
  * collect_metrics(host, user, password, port, verify_ssl) -> dict  (does I/O)
  * build_metrics(...)                                       -> dict  (pure, tested)

The returned metric dict is normalized across collectors (see the fields in
build_metrics) so app.py's virt adapter can map any of them into one fan-out
envelope. Heavy client libs (proxmoxer, pyVmomi) are imported inside the
collector modules, so importing this package pulls them in only when used.
"""
