"""Proxmox VE collector — lifted from the virtualization-dashboard project.

Talks to a Proxmox node/cluster over its REST API (proxmoxer, HTTPS on :8006)
with username/password auth, and returns the normalized metric dict consumed by
app.py's ProxmoxAdapter. build_metrics() is a pure transform (unit-tested).
"""
CONNECT_TIMEOUT = 30


def collect_metrics(host, user, password, port=8006, verify_ssl=False):
    # Imported lazily so the controller (and build_metrics unit tests) don't need
    # proxmoxer installed unless a Proxmox host is actually enrolled/polled.
    import urllib3
    from proxmoxer import ProxmoxAPI
    # Homelab Proxmox nodes almost always use self-signed certs; the controller
    # pins the cert fingerprint itself before each poll, so silence the noisy
    # per-request warning when verify_ssl is False.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    px = ProxmoxAPI(host, user=user, password=password, port=port,
                    verify_ssl=verify_ssl, timeout=CONNECT_TIMEOUT)

    blobs = []
    for node in px.nodes.get():
        node_name = node["node"]
        blob = {"node": node_name, "status": {}, "storages": [], "qemus": [], "containers": []}
        try:
            blob["status"] = px.nodes(node_name).status.get()
        except Exception:
            pass
        try:
            blob["storages"] = px.nodes(node_name).storage.get(content="images")
        except Exception:
            pass
        try:
            blob["qemus"] = px.nodes(node_name).qemu.get()
        except Exception:
            pass
        try:
            blob["containers"] = px.nodes(node_name).lxc.get()
        except Exception:
            pass
        blobs.append(blob)

    return build_metrics(blobs)


def build_metrics(blobs):
    """Pure transform from per-node API blobs to the metric payload."""
    total_cpu_pct = 0.0
    total_mem_used = 0
    total_mem_total = 0
    total_storage_used = 0
    total_storage_total = 0
    vm_list = []
    vm_running = 0

    for blob in blobs:
        node_name = blob["node"]
        status = blob.get("status") or {}

        total_cpu_pct += status.get("cpu", 0) * 100
        total_mem_used += status.get("memory", {}).get("used", 0)
        total_mem_total += status.get("memory", {}).get("total", 0)

        for s in blob.get("storages") or []:
            total_storage_used += s.get("used", 0)
            total_storage_total += s.get("total", 0)

        for vm in blob.get("qemus") or []:
            state = vm.get("status", "unknown")
            if state == "running":
                vm_running += 1
            vm_list.append({
                "vm_id": f"qemu-{node_name}-{vm['vmid']}",
                "name": vm.get("name", f"VM {vm['vmid']}"),
                "power_state": state,
                "cpu_count": vm.get("cpus"),
                "memory_mb": vm.get("maxmem", 0) // (1024 * 1024),
                "guest_os": None,
                "host_name": node_name,
            })

        for ct in blob.get("containers") or []:
            state = ct.get("status", "unknown")
            if state == "running":
                vm_running += 1
            vm_list.append({
                "vm_id": f"lxc-{node_name}-{ct['vmid']}",
                "name": ct.get("name", f"CT {ct['vmid']}"),
                "power_state": state,
                "cpu_count": ct.get("cpus"),
                "memory_mb": ct.get("maxmem", 0) // (1024 * 1024),
                "guest_os": "LXC",
                "host_name": node_name,
            })

    host_count = len(blobs)
    avg_cpu = (total_cpu_pct / host_count) if host_count else None

    return {
        "cpu_usage_percent": avg_cpu,
        "memory_used_gb": total_mem_used / (1024 ** 3),
        "memory_total_gb": total_mem_total / (1024 ** 3),
        "memory_usage_percent": (total_mem_used / total_mem_total * 100) if total_mem_total else None,
        "storage_used_gb": total_storage_used / (1024 ** 3),
        "storage_total_gb": total_storage_total / (1024 ** 3),
        "storage_usage_percent": (total_storage_used / total_storage_total * 100) if total_storage_total else None,
        "vm_count": len(vm_list),
        "vm_running_count": vm_running,
        "host_count": host_count,
        "vms": vm_list,
    }


# Guest lifecycle actions the Proxmox status endpoint accepts (qemu + lxc both
# expose all four). Kept small on purpose — no destroy/delete from the console.
VM_ACTIONS = {"start", "stop", "shutdown", "reboot"}


def vm_action(host, user, password, node_name, kind, vmid, action,
              port=8006, verify_ssl=False):
    """Perform one lifecycle action on a single Proxmox guest. `kind` is
    'qemu' (VM) or 'lxc' (container). Returns the Proxmox task UPID. Raises on
    an unknown action or an API failure."""
    if action not in VM_ACTIONS:
        raise ValueError("unsupported action: %s" % action)
    if kind not in ("qemu", "lxc"):
        raise ValueError("unknown guest kind: %s" % kind)
    import urllib3
    from proxmoxer import ProxmoxAPI
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    px = ProxmoxAPI(host, user=user, password=password, port=port,
                    verify_ssl=verify_ssl, timeout=CONNECT_TIMEOUT)
    node = px.nodes(node_name)
    guest = node.qemu(vmid) if kind == "qemu" else node.lxc(vmid)
    upid = getattr(guest.status, action).post()
    _wait_task(node, upid)
    return upid


def _wait_task(node, upid, timeout=10.0):
    """Briefly poll a submitted task so an immediately-failing action (locked
    guest, missing config, …) surfaces its error instead of the controller
    reporting success-at-submission. A task still running when `timeout`
    expires is fine — long operations keep reporting success-at-accept."""
    import time
    deadline = time.time() + timeout
    while True:
        st = node.tasks(upid).status.get() or {}
        if (st.get("status") or "") != "running":
            exit_ = st.get("exitstatus") or ""
            if exit_ not in ("", "OK"):
                raise RuntimeError("task failed: %s" % exit_)
            return
        if time.time() >= deadline:
            return
        time.sleep(0.5)
