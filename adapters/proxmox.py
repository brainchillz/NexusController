"""Proxmox VE host adapter (collector: collectors/proxmox.py, lazy proxmoxer)."""
import re

from .virt import VirtAdapter
from .base import NodeError

# Guest ids are minted by the collector as "<kind>-<node>-<vmid>" (a node name
# may itself contain hyphens; the vmid is always the trailing integer).
_GUEST_ID = re.compile(r'^(qemu|lxc)-(.+)-(\d+)$')
_NODE_NAME = re.compile(r'^[A-Za-z0-9._-]+$')


class ProxmoxAdapter(VirtAdapter):
    kind = 'proxmox'
    label = 'Proxmox VE'
    default_port = 8006
    url_placeholder = 'https://192.168.2.107:8006'
    username_placeholder = 'root@pam'
    verify_tls = True
    supports_write = True

    def _collect_metrics(self, host, port, user, password, verify_ssl):
        from collectors import proxmox
        return proxmox.collect_metrics(host, user, password, port=port, verify_ssl=verify_ssl)

    def _vm_action(self, host, port, user, pw, verify_ssl, vm_id, action):
        from collectors import proxmox
        m = _GUEST_ID.match(str(vm_id))
        if not m:
            raise NodeError('unrecognized guest id: %s' % vm_id)
        kind, node_name, vmid = m.group(1), m.group(2), m.group(3)
        if not _NODE_NAME.match(node_name):
            raise NodeError('invalid node name in guest id: %s' % vm_id)
        return proxmox.vm_action(host, user, pw, node_name, kind, vmid, action,
                                 port=port, verify_ssl=verify_ssl)
