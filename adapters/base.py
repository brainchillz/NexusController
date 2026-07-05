"""Shared host-adapter machinery: node HTTP client with in-handshake cert
pinning, the common fan-out envelope, and the HostAdapter contract.

Dependency direction: app.py imports adapters; adapters NEVER import app.
The two app-owned services adapters need (secret decryption, the node
registry) are injected once at startup via configure().
"""
import os
import ssl
import socket
import hashlib

import requests

# Per-node call timeout (connect, read) seconds; short so a slow node never
# blocks the fleet view.
NODE_TIMEOUT = (4, 8)
# The reverse-proxy carries user-initiated actions (incl. writes like disk
# format/mkfs) that can legitimately run far longer than a fleet poll, so it
# gets its own generous read timeout rather than the short fan-out one.
PROXY_TIMEOUT = (4, 300)
FANOUT_WORKERS = 8
# Virtualization/NAS hosts are polled by a background thread rather than live
# in the fan-out: a hypervisor API call (esp. pyVmomi) can take many seconds,
# which must never block the fleet view.
VIRT_POLL_INTERVAL = int(os.environ.get('CONTROLLER_VIRT_POLL', '60'))

# App-injected services (see configure()).
_runtime = {'decrypt_secret': None, 'load_nodes': None}


def configure(decrypt_secret, load_nodes):
    """Called once by app.py at import: inject the Fernet decryptor and the
    registry loader so adapters stay import-independent of the app module."""
    _runtime['decrypt_secret'] = decrypt_secret
    _runtime['load_nodes'] = load_nodes


def decrypt_secret(ciphertext):
    return _runtime['decrypt_secret'](ciphertext)


def load_nodes():
    return _runtime['load_nodes']()


class NodeError(Exception):
    pass


def _split_host_port(base_url):
    from urllib.parse import urlparse
    u = urlparse(base_url)
    return u.hostname, (u.port or (443 if u.scheme == 'https' else 80))


def cert_fingerprint(host, port):
    """SHA-256 of the host's leaf certificate (DER), captured over a raw TLS
    socket. Used for the TOFU capture at enroll, and as a pre-check by the
    polled adapters whose collector libraries own their own connections."""
    ctx = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=NODE_TIMEOUT[0]) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


class _FingerprintAdapter(requests.adapters.HTTPAdapter):
    """Pin the TLS certificate in-handshake: urllib3 compares the peer cert's
    SHA-256 against the enrolled fingerprint on the SAME connection that
    carries the request. (The old scheme checked the pin over a separate
    socket and then sent the request unverified — a TOCTOU gap.)"""

    def __init__(self, fingerprint):
        self._fp = fingerprint
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **kw):
        kw['assert_fingerprint'] = self._fp
        kw['cert_reqs'] = ssl.CERT_NONE   # pin replaces CA verification
        return super().init_poolmanager(connections, maxsize, block, **kw)


def pinned_request(method, url, fingerprint, **kwargs):
    """One HTTPS request with in-handshake fingerprint pinning. A None
    fingerprint means not-yet-pinned (the enroll TOFU path captures it first).
    Raises NodeError on any transport/pin failure."""
    with requests.Session() as s:
        s.verify = False
        if fingerprint:
            s.mount('https://', _FingerprintAdapter(fingerprint))
        try:
            return s.request(method, url, **kwargs)
        except requests.exceptions.SSLError as e:
            if 'fingerprint' in str(e).lower():
                raise NodeError('certificate fingerprint changed for %s '
                                '(pinned %s…)' % (url.split('/api/')[0], fingerprint[:16]))
            raise NodeError(str(e))
        except requests.RequestException as e:
            raise NodeError(str(e))


class NodeClient:
    """One node's API surface: bearer auth + per-node cert pinning + timeout."""

    def __init__(self, node):
        self.node = node
        self.base_url = node['base_url'].rstrip('/')
        self.token = decrypt_secret(node.get('token_enc', '')) if node.get('token_enc') else None
        self.cert_fp = node.get('cert_fp')

    def request(self, method, path, timeout=NODE_TIMEOUT, **kwargs):
        url = f"{self.base_url}/api/{path.lstrip('/')}"
        headers = kwargs.pop('headers', {})
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return pinned_request(method, url, self.cert_fp,
                              headers=headers, timeout=timeout, **kwargs)

    def get_json(self, path):
        r = self.request('GET', path)
        if r.status_code != 200:
            raise NodeError(f'HTTP {r.status_code}')
        return r.json()

    def raw_get(self, path):
        """GET an arbitrary (non-/api) path on the node — drill-in HTML/assets.
        Unauthenticated but still pinned."""
        return pinned_request('GET', self.base_url + path, self.cert_fp,
                              timeout=NODE_TIMEOUT)


def base_envelope(node):
    """Fields common to every host type's fan-out envelope."""
    return {'id': node['id'], 'name': node['name'], 'base_url': node['base_url'],
            'host_type': node.get('host_type', 'nexus'),
            'type': node.get('type', 'Unknown'), 'type_pinned': node.get('type_pinned', False),
            'tags': node.get('tags', []),
            'capabilities': node.get('capabilities', []),
            'token_role': node.get('role'),  # enrolled token's role (gates writes)
            'version': node.get('version'), 'ok': False, 'error': None,
            'summary': None, 'resources': None, 'used_bytes': 0, 'size_bytes': 0}


class HostAdapter:
    """Per-host-type strategy: how to probe at enroll, fetch for the fan-out,
    and where the row's drill-in points. Subclasses normalize into
    base_envelope(). Class attributes double as the UI descriptor — the enroll
    modal builds its host-type list and credential fields from descriptor(),
    so adding a host type means adding an adapter module, not editing the SPA.
    """
    kind = 'nexus'
    label = 'Nexus Dashboard node'
    auth = 'token'            # credential model: 'token' (API token/key) or 'userpass'
    secret_label = 'API token'
    secret_placeholder = ''
    url_placeholder = 'https://host'
    username_placeholder = 'username'
    verify_tls = False        # show the verify-TLS toggle (pin-only types hide it)
    default_type = 'Unknown'  # fallback classification for polled hosts
    polled = False            # background-polled (virt/NAS) vs live fan-out

    def probe(self, base_url, creds):
        """Enroll/test-connection: validate credentials + capture the cert
        fingerprint; return identity (role/version/capabilities). Raises NodeError."""
        raise NotImplementedError

    def fetch(self, node):
        """Fan-out: pull one host's status into an envelope. MUST NOT raise —
        a single unreachable host must never crash the whole fleet view."""
        raise NotImplementedError

    def native_url(self, node):
        """Where the row's 'Open' link points."""
        return '/nodes/%s/' % node['id']

    def descriptor(self):
        """UI-facing description of this host type (served by /api/host-types)."""
        return {'kind': self.kind, 'label': self.label, 'auth': self.auth,
                'secret_label': self.secret_label,
                'secret_placeholder': self.secret_placeholder,
                'url_placeholder': self.url_placeholder,
                'username_placeholder': self.username_placeholder,
                'verify_tls': self.verify_tls, 'default_type': self.default_type,
                'polled': self.polled}
