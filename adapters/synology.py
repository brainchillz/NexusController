"""Synology DSM (NAS) adapter — username/password of a LOCAL no-2FA account in
the administrators group (DSM has no read-only admin role; all calls are
read-only — see collectors/synology.py). Reuses the VirtAdapter machinery
(userpass probe, background poller, pre-poll cert pin) and the TrueNAS `nas`
envelope, so the NAS row chips / amber-on-degraded dot / storage rollup work
unchanged. DSM "volumes" appear as the envelope's "pools"."""
from .virt import VirtAdapter
from .truenas import build_nas_envelope


class SynologyAdapter(VirtAdapter):
    kind = 'synology'
    label = 'Synology DSM (NAS)'
    default_port = 5001
    default_type = 'Storage'
    url_placeholder = 'https://synology.local:5001'
    username_placeholder = 'local admin account (no 2FA)'
    verify_tls = True

    def envelope(self, node, metrics):
        return build_nas_envelope(node, metrics)

    def _collect_metrics(self, host, port, user, password, verify_ssl):
        from collectors import synology
        return synology.collect_metrics(host, user, password, port=port,
                                        verify_ssl=verify_ssl)
