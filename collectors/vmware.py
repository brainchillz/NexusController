"""VMware collector — lifted from the virtualization-dashboard project.

Handles both vCenter (aggregates all managed ESXi hosts + VMs) and a standalone
ESXi host via pyVmomi. Returns the normalized metric dict consumed by app.py's
VMware adapters. pyVmomi is imported lazily inside the I/O functions so
build_metrics() (pure) is unit-testable without the heavy dependency installed.
"""
import ssl
import socket
from contextlib import contextmanager

# Bound how long a hung/unreachable host can block a poller thread. pyVmomi uses
# blocking http.client sockets, so a default socket timeout caps both the connect
# and each subsequent SOAP call.
CONNECT_TIMEOUT = 30


@contextmanager
def _socket_timeout(seconds):
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(seconds)
    try:
        yield
    finally:
        socket.setdefaulttimeout(previous)


def _connect(host, user, password, port, verify_ssl):
    from pyVim.connect import SmartConnect
    ssl_context = ssl.create_default_context()
    if not verify_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    return SmartConnect(host=host, user=user, pwd=password, port=port, sslContext=ssl_context)


def collect_metrics(host, user, password, port=443, verify_ssl=False):
    from pyVim.connect import Disconnect
    from pyVmomi import vim
    with _socket_timeout(CONNECT_TIMEOUT):
        si = _connect(host, user, password, port, verify_ssl)
        try:
            content = si.RetrieveContent()
            hosts = _collect(content, vim.HostSystem, [
                "name",
                "hardware.cpuInfo.numCpuCores",
                "hardware.cpuInfo.hz",
                "hardware.memorySize",
                "summary.quickStats.overallCpuUsage",
                "summary.quickStats.overallMemoryUsage",
            ])
            vms = _collect(content, vim.VirtualMachine, [
                "name",
                "config.hardware.numCPU",
                "config.hardware.memoryMB",
                "config.guestFullName",
                "runtime.powerState",
                "runtime.host",
            ])
            datastores = _collect(content, vim.Datastore, [
                "summary.capacity",
                "summary.freeSpace",
            ])
        finally:
            Disconnect(si)

    host_names = {ref["_obj"]._moId: ref.get("name") for ref in hosts}
    return build_metrics(hosts, vms, datastores, host_names)


def _collect(content, obj_type, path_set):
    """Batch-fetch the requested properties for every object of obj_type in a
    single RetrievePropertiesEx call instead of one round-trip per attribute."""
    from pyVmomi import vim, vmodl
    view = content.viewManager.CreateContainerView(content.rootFolder, [obj_type], True)
    try:
        trav = vmodl.query.PropertyCollector.TraversalSpec(
            name="view", type=vim.view.ContainerView, path="view", skip=False
        )
        obj_spec = vmodl.query.PropertyCollector.ObjectSpec(obj=view, skip=True, selectSet=[trav])
        prop_spec = vmodl.query.PropertyCollector.PropertySpec(
            type=obj_type, all=False, pathSet=path_set
        )
        filter_spec = vmodl.query.PropertyCollector.FilterSpec(
            objectSet=[obj_spec], propSet=[prop_spec]
        )
        options = vmodl.query.PropertyCollector.RetrieveOptions()
        result = content.propertyCollector.RetrievePropertiesEx([filter_spec], options)

        out = []
        while result is not None:
            for obj in result.objects:
                row = {"_obj": obj.obj}
                for prop in obj.propSet:
                    row[prop.name] = prop.val
                out.append(row)
            token = result.token
            if not token:
                break
            result = content.propertyCollector.ContinueRetrievePropertiesEx(token)
        return out
    finally:
        view.Destroy()


def build_metrics(hosts, vms, datastores, host_names):
    """Pure transform from collected property dicts to the metric payload.

    Kept free of pyVmomi calls so it can be unit-tested with plain dicts.
    """
    total_cpu_mhz = 0.0
    used_cpu_mhz = 0.0
    for h in hosts:
        cores = h.get("hardware.cpuInfo.numCpuCores") or 0
        hz = h.get("hardware.cpuInfo.hz") or 0
        total_cpu_mhz += cores * hz / 1_000_000
        used_cpu_mhz += h.get("summary.quickStats.overallCpuUsage") or 0

    total_mem_bytes = sum(h.get("hardware.memorySize") or 0 for h in hosts)
    used_mem_bytes = sum((h.get("summary.quickStats.overallMemoryUsage") or 0) * 1024 * 1024 for h in hosts)

    total_storage_bytes = sum(d.get("summary.capacity") or 0 for d in datastores)
    free_storage_bytes = sum(d.get("summary.freeSpace") or 0 for d in datastores)
    used_storage_bytes = total_storage_bytes - free_storage_bytes

    running = sum(1 for v in vms if str(v.get("runtime.powerState")) == "poweredOn")

    vm_list = []
    for v in vms:
        host_ref = v.get("runtime.host")
        host_name = host_names.get(host_ref._moId) if host_ref is not None else None
        vm_list.append({
            "vm_id": str(v["_obj"]._moId),
            "name": v.get("name"),
            "power_state": str(v.get("runtime.powerState")),
            "cpu_count": v.get("config.hardware.numCPU"),
            "memory_mb": v.get("config.hardware.memoryMB"),
            "guest_os": v.get("config.guestFullName"),
            "host_name": host_name,
        })

    return {
        "cpu_usage_percent": (used_cpu_mhz / total_cpu_mhz * 100) if total_cpu_mhz else None,
        "memory_used_gb": used_mem_bytes / (1024 ** 3),
        "memory_total_gb": total_mem_bytes / (1024 ** 3),
        "memory_usage_percent": (used_mem_bytes / total_mem_bytes * 100) if total_mem_bytes else None,
        "storage_used_gb": used_storage_bytes / (1024 ** 3),
        "storage_total_gb": total_storage_bytes / (1024 ** 3),
        "storage_usage_percent": (used_storage_bytes / total_storage_bytes * 100) if total_storage_bytes else None,
        "vm_count": len(vms),
        "vm_running_count": running,
        "host_count": len(hosts),
        "vms": vm_list,
    }


VM_ACTIONS = {"start", "stop", "shutdown", "reboot"}


def _find_vm_by_moid(content, moid):
    from pyVmomi import vim
    view = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.VirtualMachine], True)
    try:
        for vm in view.view:
            if vm._moId == moid:
                return vm
    finally:
        view.Destroy()
    return None


def vm_action(host, user, password, moid, action, port=443, verify_ssl=False):
    """Perform one lifecycle action on a VMware guest identified by its managed
    object id. `start`/`stop` are hard power ops; `shutdown`/`reboot` are the
    graceful guest ops (require VMware Tools). Returns a short task/op label.
    Raises on unknown action or a vSphere failure."""
    if action not in VM_ACTIONS:
        raise ValueError("unsupported action: %s" % action)
    from pyVim.connect import Disconnect
    with _socket_timeout(CONNECT_TIMEOUT):
        si = _connect(host, user, password, port, verify_ssl)
        try:
            content = si.RetrieveContent()
            vm = _find_vm_by_moid(content, moid)
            if vm is None:
                raise ValueError("VM %s not found" % moid)
            if action == "start":
                return vm.PowerOnVM_Task()._moId
            if action == "stop":
                return vm.PowerOffVM_Task()._moId
            if action == "reboot":
                vm.RebootGuest()
                return "RebootGuest"
            vm.ShutdownGuest()           # action == "shutdown"
            return "ShutdownGuest"
        finally:
            Disconnect(si)
