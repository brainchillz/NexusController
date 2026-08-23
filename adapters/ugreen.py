"""UGREEN UGOS Pro (NAS) adapter — username/password of a LOCAL UGOS account
without 2FA (UGREEN has no official API or API keys; the collector speaks the
community-reverse-engineered UGOS web-GUI API, RSA login and all — see
collectors/ugreen.py). Reuses the VirtAdapter machinery (userpass probe,
background poller, pre-poll cert pin) and the TrueNAS `nas` envelope, so the
NAS row chips / amber-on-degraded dot / storage rollup work unchanged. UGOS
"storage pools" map straight onto the envelope's pools."""
from .virt import VirtAdapter
from .truenas import build_nas_envelope


class UgreenAdapter(VirtAdapter):
    kind = 'ugreen'
    label = 'UGREEN UGOS Pro (NAS)'
    default_port = 9443
    default_type = 'Storage'
    url_placeholder = 'https://ugreen-nas:9443'
    username_placeholder = 'local UGOS account (no 2FA)'
    verify_tls = True

    def envelope(self, node, metrics):
        return build_nas_envelope(node, metrics)

    def _collect_metrics(self, host, port, user, password, verify_ssl):
        from collectors import ugreen
        return ugreen.collect_metrics(host, user, password, port=port,
                                      verify_ssl=verify_ssl)
