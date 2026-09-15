"""Hypervisor metric collectors for virtualization host adapters.

Each collector exposes:
  * collect_metrics(host, user, password, port, verify_ssl) -> dict  (does I/O)
  * build_metrics(...)                                       -> dict  (pure, tested)

The returned metric dict is normalized across collectors (see the fields in
build_metrics) so app.py's virt adapter can map any of them into one fan-out
envelope. Heavy client libs (proxmoxer, pyVmomi) are imported inside the
collector modules, so importing this package pulls them in only when used.
"""
import hashlib


def session_key(base, username, password):
    """Cache key for a collector's per-host session. It carries the
    CREDENTIALS, not just the URL: keyed by URL alone, an Edit that changed
    the password re-used the old, still-valid session — so the "test
    connection" probe passed with a WRONG password, the bad password was
    stored, and the host only failed once the appliance expired the session.
    The password rides as a digest so the key never holds it in clear."""
    return (base, username or '',
            hashlib.sha256((password or '').encode('utf-8')).hexdigest())
