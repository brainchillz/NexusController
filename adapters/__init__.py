"""Host-adapter registry. Each host type is one self-contained module that
declares its own UI descriptor (label, auth model, placeholders) — the enroll
modal and credential fields are built from descriptors(), so ADDING A HOST
TYPE = adding a module here + registering it below. No app.py or SPA edits.

app.py must call configure() (from .base) once at import to inject the secret
decryptor + registry loader."""
from .base import (configure, NodeError, NodeClient, HostAdapter, base_envelope,
                   cert_fingerprint, pinned_request, _split_host_port,
                   NODE_TIMEOUT, PROXY_TIMEOUT, FANOUT_WORKERS, VIRT_POLL_INTERVAL)
from .virt import (VirtAdapter, build_virt_envelope, seed_cache, evict_cache,
                   start_virt_poller, _is_virt)
from .nexus import (NexusAdapter, probe_node, classify_node, parse_human_bytes,
                    _serves_ai)
from .proxmox import ProxmoxAdapter
from .vmware import VMwareAdapter, VCenterAdapter, ESXiAdapter
from .truenas import TrueNasAdapter, build_nas_envelope
from .synology import SynologyAdapter
from .zimaos import ZimaOSAdapter
from .unraid import UnraidAdapter
from .omv import OmvAdapter
from .sparkdash import SparkDashAdapter, build_spark_envelope
from .agent import AgentAdapter, build_agent_envelope

# Registration order = the order host types appear in the Add-Host dropdown.
ADAPTERS = {a.kind: a for a in
            (NexusAdapter(), ProxmoxAdapter(), VCenterAdapter(), ESXiAdapter(),
             TrueNasAdapter(), SynologyAdapter(), ZimaOSAdapter(), UnraidAdapter(),
             OmvAdapter(), SparkDashAdapter(), AgentAdapter())}


def adapter_for(node):
    """Resolve a host's adapter; records without a host_type are nexus nodes."""
    return ADAPTERS.get(node.get('host_type') or 'nexus', ADAPTERS['nexus'])


def probe_host(host_type, base_url, creds):
    """Adapter-aware enroll/test probe. Raises NodeError on unknown type."""
    adapter = ADAPTERS.get(host_type or 'nexus')
    if not adapter:
        raise NodeError('unknown host type: %s' % host_type)
    return adapter.probe(base_url, creds)


def descriptors():
    """UI descriptors for every registered host type (→ /api/host-types)."""
    return [a.descriptor() for a in ADAPTERS.values()]
