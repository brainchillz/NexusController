"""VMware adapters (collector: collectors/vmware.py, lazy pyVmomi). vCenter
aggregates all managed ESXi hosts + VMs; a standalone ESXi host reports just
itself. Same collector for both — the subclasses differ only in kind/label."""
from .virt import VirtAdapter


class VMwareAdapter(VirtAdapter):
    default_port = 443
    verify_tls = True
    supports_write = True

    def _collect_metrics(self, host, port, user, password, verify_ssl):
        from collectors import vmware
        return vmware.collect_metrics(host, user, password, port=port, verify_ssl=verify_ssl)

    def _vm_action(self, host, port, user, pw, verify_ssl, vm_id, action):
        from collectors import vmware
        return vmware.vm_action(host, user, pw, str(vm_id), action,
                                port=port, verify_ssl=verify_ssl)

    def native_url(self, node):
        return node['base_url'] + '/ui'   # vSphere / ESXi HTML5 client


class VCenterAdapter(VMwareAdapter):
    kind = 'vcenter'
    label = 'VMware vCenter'
    url_placeholder = 'https://vcenter.local'
    username_placeholder = 'administrator@vsphere.local'


class ESXiAdapter(VMwareAdapter):
    kind = 'esxi'
    label = 'VMware ESXi (standalone)'
    url_placeholder = 'https://esxi-host.local'
    username_placeholder = 'root'
