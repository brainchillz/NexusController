#!/usr/bin/env python3
"""Nexus Fleet Controller — an unprivileged console that enrolls single-host
Nexus Dashboard nodes and monitors/controls them over their existing token-authed
REST API.

Design (see the cluster_dashboard_proposal in the node repo):
  * NO root, NO sudo, NO shell-outs. The controller only ever speaks HTTPS to
    nodes; all privileged work stays on the node behind its own auth/RBAC/audit.
  * Conventions mirror the node app: one Flask app + vanilla-JS SPA, no build
    step, atomic JSON writes, central RBAC guard, session+token auth.

Phase 1 scope: enrollment + NodeClient + controller auth/RBAC skeleton, plus a
basic fleet-summary fan-out (Phase 2 will add caching + richer rollups).
"""
import os
import ssl
import re
import json
import time
import socket
import secrets
import hashlib
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from flask import Flask, jsonify, request, session, send_from_directory, g, Response
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Nodes use self-signed certs by default; we pin their fingerprint ourselves
# (TOFU, accept-new), so requests' own CA verification is intentionally off and
# its warning is noise here.
urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__, static_url_path='')

APP_DIR = os.path.dirname(os.path.abspath(__file__))
APP_VERSION = '0.1.1'


def env_bool(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.lower() in ('1', 'true', 'yes', 'on')


# ─── Files & TLS ──────────────────────────────────────────────────────
# All persistent state lives under DATA_DIR (default: next to app.py). In a
# container, set CONTROLLER_DATA_DIR=/data and mount a volume there so the
# encrypted registry, credentials, audit log, and TLS cert survive restarts.
# Individual paths can still be overridden one-by-one.
DATA_DIR = os.environ.get('CONTROLLER_DATA_DIR', APP_DIR)
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except OSError:
    pass

AUTH_FILE = os.environ.get('CONTROLLER_AUTH_FILE', os.path.join(DATA_DIR, 'controller-auth.json'))
NODES_FILE = os.environ.get('CONTROLLER_NODES_FILE', os.path.join(DATA_DIR, 'nodes.json'))
AUDIT_FILE = os.environ.get('CONTROLLER_AUDIT_FILE', os.path.join(DATA_DIR, 'audit.log'))

TLS_ENABLED = env_bool('CONTROLLER_TLS', True)
TLS_DIR = os.environ.get('CONTROLLER_TLS_DIR', os.path.join(DATA_DIR, 'certs'))
TLS_CERT = os.environ.get('CONTROLLER_TLS_CERT', os.path.join(TLS_DIR, 'controller.crt'))
TLS_KEY = os.environ.get('CONTROLLER_TLS_KEY', os.path.join(TLS_DIR, 'controller.key'))
PORT = int(os.environ.get('CONTROLLER_PORT', '9443' if TLS_ENABLED else '9080'))

# Per-node call timeout (connect, read) seconds; short so a slow node never
# blocks the fleet view.
NODE_TIMEOUT = (4, 8)
# The reverse-proxy carries user-initiated actions (incl. writes like disk
# format/mkfs) that can legitimately run far longer than a fleet poll, so it
# gets its own generous read timeout rather than the short fan-out one.
PROXY_TIMEOUT = (4, 300)
FANOUT_WORKERS = 8
# Brief fleet-summary cache so the SPA's auto-refresh doesn't hammer the nodes.
# A manual refresh passes ?fresh=1 to bypass it.
FLEET_CACHE_TTL = 12
# Virtualization hosts (proxmox/vmware) are polled by a background thread rather
# than live in the fan-out: a hypervisor API call (esp. pyVmomi) can take many
# seconds, which must never block the fleet view. The fan-out serves each virt
# host's last polled result from _virt_cache.
VIRT_POLL_INTERVAL = int(os.environ.get('CONTROLLER_VIRT_POLL', '60'))

MIN_PASSWORD_LEN = 8
# Controller roles, most→least privilege. admin manages nodes + full control;
# operator controls existing nodes but can't enroll/remove; viewer is read-only.
ROLES = ('admin', 'operator', 'viewer')

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=env_bool('CONTROLLER_COOKIE_SECURE', TLS_ENABLED),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


# ─── Atomic JSON I/O (mirrors the node's write_json_atomic) ───────────
def write_json_atomic(path, data, mode=0o600):
    """Temp file + fsync + os.replace so a crash/full disk can't truncate a
    config (a corrupt controller-auth.json would lock everyone out)."""
    tmp = f'{path}.tmp.{os.getpid()}'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default


def err(msg, code=400):
    return jsonify({'success': False, 'error': msg}), code


# Nodes report ZFS used/size as human strings (e.g. "1.2T") from the node's
# _human_bytes (suffixes B/K/M/G/T/P). Parse them back to bytes so the
# controller can sum fleet-wide storage.
_UNIT_MULT = {'B': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3,
              'T': 1024 ** 4, 'P': 1024 ** 5}


def parse_human_bytes(s):
    if not s:
        return 0
    m = re.match(r'^\s*([\d.]+)\s*([BKMGTP])?\s*$', str(s))
    if not m:
        return 0
    return int(float(m.group(1)) * _UNIT_MULT.get(m.group(2) or 'B', 1))


# ─── Config / auth bootstrap ──────────────────────────────────────────
def load_config():
    return load_json(AUTH_FILE, {})


def save_config(cfg):
    write_json_atomic(AUTH_FILE, cfg, 0o600)


def _fernet():
    """Fernet for encrypting node tokens at rest. The key lives in the (0600)
    auth file; a node token is admin-equivalent on that node, so the registry is
    a high-value secret store."""
    cfg = load_config()
    key = cfg.get('fernet_key')
    if not key:
        key = Fernet.generate_key().decode()
        cfg['fernet_key'] = key
        save_config(cfg)
    return Fernet(key.encode())


def encrypt_secret(plaintext):
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext):
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, AttributeError):
        return None


def ensure_bootstrap():
    cfg = load_config()
    changed = False
    if not cfg.get('secret_key'):
        cfg['secret_key'] = secrets.token_hex(32)
        changed = True
    if not cfg.get('fernet_key'):
        cfg['fernet_key'] = Fernet.generate_key().decode()
        changed = True
    if not cfg.get('users'):
        pw = os.environ.get('CONTROLLER_ADMIN_PASSWORD')
        generated = not pw
        if not pw:
            pw = secrets.token_urlsafe(12)
        cfg.setdefault('users', {})['admin'] = {
            'password': generate_password_hash(pw), 'role': 'admin', 'must_change': True}
        changed = True
        if generated:
            print('=' * 64, flush=True)
            print('Nexus Controller: created initial admin account', flush=True)
            print('  username: admin', flush=True)
            print(f'  password: {pw}', flush=True)
            print('=' * 64, flush=True)
    if changed:
        save_config(cfg)
    return cfg


def _users():
    return load_config().get('users', {})


def _user_role(rec):
    if isinstance(rec, dict):
        return rec.get('role', 'viewer')
    return 'viewer'


# ─── AuthN / AuthZ ────────────────────────────────────────────────────
PUBLIC_ENDPOINTS = {'api_login', 'api_me', 'index', 'static'}
# Writes a non-admin role may still issue (sign out / change own password).
RBAC_EXEMPT = {'api_logout', 'change_password'}
# Endpoints that require the top (admin) role regardless of method — enrolling
# or removing a node, and managing controller users.
ADMIN_ONLY = {'nodes_add', 'node_delete', 'node_update', 'tls_regenerate', 'tls_upload_cert'}


def _resolve_identity():
    user = session.get('user')
    if user:
        return user, _user_role(_users().get(user))
    return None, None


@app.before_request
def require_login():
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    name, role = _resolve_identity()
    if not name:
        return err('Authentication required', 401)
    g.identity_name = name
    g.identity_role = role
    if request.endpoint in ADMIN_ONLY and role != 'admin':
        return err('Admin role required', 403)
    # viewer is read-only: no state-changing methods.
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH') and request.endpoint not in RBAC_EXEMPT:
        if role == 'viewer':
            return err('Read-only account: action not permitted', 403)
    return None


def _is_admin():
    return getattr(g, 'identity_role', None) == 'admin'


# ─── Audit (controller-side, mirrors the node) ────────────────────────
def audit_line(method, path, target, status):
    try:
        entry = {
            'ts': datetime.now().astimezone().isoformat(timespec='seconds'),
            'user': getattr(g, 'identity_name', '-'),
            'ip': request.headers.get('X-Forwarded-For', request.remote_addr) or '-',
            'method': method, 'path': path, 'target': target or '-', 'status': status,
        }
        with open(os.open(AUDIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception:
        pass  # auditing must never break a request


@app.after_request
def _audit(resp):
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH') and request.endpoint not in PUBLIC_ENDPOINTS:
        audit_line(request.method, request.path, getattr(g, 'audit_target', None), resp.status_code)
    return resp


# ─── Node registry ────────────────────────────────────────────────────
def load_nodes():
    return load_json(NODES_FILE, {'nodes': []})


def save_nodes(data):
    write_json_atomic(NODES_FILE, data, 0o600)


def _public_node(n):
    """Registry record minus secrets — never return the node token or a virt
    host's password via the API."""
    return {k: v for k, v in n.items() if k not in ('token_enc', 'password_enc')}


def _find_node(node_id):
    for n in load_nodes().get('nodes', []):
        if n.get('id') == node_id:
            return n
    return None


# ─── NodeClient — authenticated, cert-pinned calls to one node ────────
def cert_fingerprint(host, port):
    """SHA-256 of the node's leaf certificate (DER), captured over a raw TLS
    socket. Used for TOFU pinning — accept-new at enroll, compare every call."""
    ctx = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=NODE_TIMEOUT[0]) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


def _split_host_port(base_url):
    from urllib.parse import urlparse
    u = urlparse(base_url)
    return u.hostname, (u.port or (443 if u.scheme == 'https' else 80))


class NodeError(Exception):
    pass


class NodeClient:
    """One node's API surface: bearer auth + per-node cert pinning + timeout."""

    def __init__(self, node):
        self.node = node
        self.base_url = node['base_url'].rstrip('/')
        self.token = decrypt_secret(node.get('token_enc', '')) if node.get('token_enc') else None
        self.cert_fp = node.get('cert_fp')

    def _verify_pin(self):
        if not self.cert_fp:
            return  # not pinned yet (enroll path captures it)
        host, port = _split_host_port(self.base_url)
        try:
            live = cert_fingerprint(host, port)
        except (socket.error, ssl.SSLError, OSError) as e:
            # Offline/unreachable node: surface as NodeError so the fan-out
            # records this node as down instead of crashing the whole summary.
            raise NodeError(f'cannot reach {host}:{port} ({e})')
        if live != self.cert_fp:
            raise NodeError(f'certificate fingerprint changed for {host} '
                            f'(pinned {self.cert_fp[:16]}…, saw {live[:16]}…)')

    def request(self, method, path, **kwargs):
        self._verify_pin()
        url = f"{self.base_url}/api/{path.lstrip('/')}"
        headers = kwargs.pop('headers', {})
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        try:
            return requests.request(method, url, headers=headers, verify=False,
                                    timeout=NODE_TIMEOUT, **kwargs)
        except requests.RequestException as e:
            raise NodeError(str(e))

    def get_json(self, path):
        r = self.request('GET', path)
        if r.status_code != 200:
            raise NodeError(f'HTTP {r.status_code}')
        return r.json()


def probe_node(base_url, token):
    """Test-connection at enroll: capture cert fingerprint, validate the token
    via /api/me, return role + version + capabilities. Raises NodeError."""
    host, port = _split_host_port(base_url)
    if not host:
        raise NodeError('invalid base URL')
    try:
        fp = cert_fingerprint(host, port)
    except (socket.error, ssl.SSLError, OSError) as e:
        raise NodeError(f'cannot reach {host}:{port} ({e})')
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    try:
        r = requests.get(f"{base_url.rstrip('/')}/api/me", headers=headers,
                         verify=False, timeout=NODE_TIMEOUT)
    except requests.RequestException as e:
        raise NodeError(str(e))
    if r.status_code == 401:
        raise NodeError('token rejected (401) — check the token and that it is admin/readonly')
    if r.status_code != 200:
        raise NodeError(f'unexpected response (HTTP {r.status_code})')
    data = r.json()
    return {
        'cert_fp': fp,
        'role': data.get('role'),
        'version': data.get('version'),
        'fqdn': data.get('fqdn'),
        'capabilities': data.get('capabilities', []),
    }


def _serves_ai(llama):
    """A node is serving AI if its llama-server is healthy, or the service is
    active with a model loaded. `llama` is the node's /api/llama (+ embedded
    health), which the node's /api/summary does NOT include — the controller
    fetches it separately for llamacpp-capable nodes."""
    if not isinstance(llama, dict):
        return False
    health = llama.get('health') or {}
    if health.get('ok'):
        return True
    svc = llama.get('service') or {}
    return svc.get('active') == 'active' and bool(llama.get('model'))


def classify_node(summary, capabilities, llama=None):
    """Suggest a node type (Storage / AI / Mixed / Unknown) from a node's
    /api/summary + (separately fetched) llama status + capabilities. Heuristic
    per proposal §6.7; manual override lives in the registry."""
    serves_storage = False
    serves_ai = _serves_ai(llama)
    if isinstance(summary, dict):
        zfs = summary.get('zfs') or {}
        nfs = summary.get('nfs') or {}
        smb = summary.get('smb') or {}
        iscsi = summary.get('iscsi') or {}
        pools = len(zfs.get('pools', []) or []) if isinstance(zfs.get('pools'), list) else zfs.get('pools', 0)
        serves_storage = bool(pools or smb.get('shares') or nfs.get('exports') or iscsi.get('targets'))
    if not (serves_storage or serves_ai):
        # idle — fall back to enabled capabilities
        caps = set(capabilities or [])
        # Node module ids (see node app MODULES): AI = 'llamacpp'; storage feature
        # areas. 'disks' alone is weak evidence but counts toward storage.
        has_ai = bool(caps & {'llamacpp', 'llama', 'ai'})
        has_storage = bool(caps & {'zfs', 'iscsi', 'nfs', 'smb', 'lvm', 'mdraid', 'disks'})
        if has_ai and has_storage:
            return 'Mixed'
        if has_ai:
            return 'AI'
        if has_storage:
            return 'Storage'
        return 'Unknown'
    if serves_storage and serves_ai:
        return 'Mixed'
    return 'Storage' if serves_storage else 'AI'


# ─── Routes: SPA + auth ───────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory(APP_DIR, 'templates/index.html')


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    user = (data.get('username') or '').strip()
    pw = data.get('password') or ''
    rec = _users().get(user)
    if not rec or not check_password_hash(rec.get('password', ''), pw):
        return err('Invalid credentials', 401)
    session.permanent = True
    session['user'] = user
    return jsonify({'success': True, 'user': user, 'role': _user_role(rec),
                    'must_change': bool(rec.get('must_change'))})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/me')
def api_me():
    name, role = _resolve_identity()
    if not name:
        return jsonify({'authenticated': False}), 401
    rec = _users().get(name)
    return jsonify({'authenticated': True, 'user': name, 'role': role,
                    'must_change': bool(isinstance(rec, dict) and rec.get('must_change')),
                    'version': APP_VERSION})


@app.route('/api/account/password', methods=['POST'])
def change_password():
    data = request.get_json() or {}
    user = session.get('user')
    if not user:
        return err('Only an interactive session can change a password', 401)
    cfg = load_config()
    rec = cfg.get('users', {}).get(user)
    if not rec or not check_password_hash(rec.get('password', ''), data.get('old_password') or ''):
        return err('Current password is incorrect')
    new = data.get('new_password') or ''
    if len(new) < MIN_PASSWORD_LEN:
        return err(f'New password must be at least {MIN_PASSWORD_LEN} characters')
    rec['password'] = generate_password_hash(new)
    rec.pop('must_change', None)
    cfg['users'][user] = rec
    save_config(cfg)
    return jsonify({'success': True})


# ─── Routes: node registry (enrollment) ───────────────────────────────
@app.route('/api/nodes')
def nodes_list():
    return jsonify({'nodes': [_public_node(n) for n in load_nodes().get('nodes', [])]})


@app.route('/api/nodes/test', methods=['POST'])
def nodes_test():
    """Test-connection without enrolling. operator+ (not viewer)."""
    data = request.get_json() or {}
    base_url = (data.get('base_url') or '').strip()
    host_type = (data.get('host_type') or 'nexus').strip()
    if not base_url:
        return err('base_url is required')
    creds = {'token': (data.get('token') or '').strip(),
             'username': (data.get('username') or '').strip(),
             'password': data.get('password') or '',
             'verify_ssl': bool(data.get('verify_ssl'))}
    try:
        info = _probe_host(host_type, base_url, creds)
    except NodeError as e:
        return err(str(e), 502)
    m = info.pop('metrics', None)  # don't ship the full inventory in a test
    resp = {'success': True, 'host_type': host_type, **info}
    if m:  # a polled probe — surface a quick count instead of role/version
        if 'pool_count' in m:  # NAS probe
            resp['metrics'] = {'pool_count': m.get('pool_count'),
                               'pools_degraded': m.get('pools_degraded'),
                               'disk_count': m.get('disk_count')}
        else:                  # virt probe
            resp['metrics'] = {'host_count': m.get('host_count'), 'vm_count': m.get('vm_count'),
                               'vm_running_count': m.get('vm_running_count')}
    return jsonify(resp)


@app.route('/api/nodes', methods=['POST'])
def nodes_add():
    """Enroll a node. Admin-only (ADMIN_ONLY)."""
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    base_url = (data.get('base_url') or '').strip()
    host_type = (data.get('host_type') or 'nexus').strip()
    token = (data.get('token') or '').strip()
    tags = data.get('tags') or []
    if not name or not base_url:
        return err('name and base_url are required')
    if host_type not in ADAPTERS:
        return err('unknown host type: %s' % host_type)
    creds = {'token': token,
             'username': (data.get('username') or '').strip(),
             'password': data.get('password') or '',
             'verify_ssl': bool(data.get('verify_ssl'))}
    try:
        info = _probe_host(host_type, base_url, creds)
    except NodeError as e:
        return err(f'connection test failed: {e}', 502)
    reg = load_nodes()
    nid = secrets.token_hex(8)
    node = {
        'id': nid, 'name': name, 'base_url': base_url.rstrip('/'),
        'host_type': host_type,
        'cert_fp': info['cert_fp'], 'role': info.get('role'),
        'version': info.get('version'), 'capabilities': info.get('capabilities', []),
        'tags': [str(t) for t in tags if isinstance(t, (str, int, float))],
        'added_at': datetime.now().astimezone().isoformat(timespec='seconds'),
        'last_seen': None,
    }
    adapter = ADAPTERS[host_type]
    if adapter.auth == 'token':
        node['token_enc'] = encrypt_secret(token) if token else ''
        if host_type != 'nexus':   # token-authed non-nexus (truenas) still pins/verifies TLS
            node['verify_ssl'] = creds['verify_ssl']
    else:
        node['username'] = creds['username']
        node['password_enc'] = encrypt_secret(creds['password']) if creds['password'] else ''
        node['verify_ssl'] = creds['verify_ssl']
    # Classify immediately (best-effort) so the node isn't 'Unknown'/'awaiting'
    # until the first fleet refresh. A manual `type` pins it; else it tracks
    # type_auto. Polled hosts fall back to their adapter's default type
    # (virt → Virtualization, truenas → Storage).
    if host_type == 'nexus':
        type_auto = 'Unknown'
        try:
            client = NodeClient(node)
            summ = client.get_json('summary')
            la = None
            if 'llamacpp' in (info.get('capabilities') or []):
                try:
                    la = client.get_json('llama')
                    la['health'] = client.get_json('llama/health')
                except NodeError:
                    la = None
            type_auto = classify_node(summ, info.get('capabilities'), la)
        except NodeError:
            pass
    else:
        type_auto = adapter.default_type
    pinned = bool(data.get('type'))
    node['type'] = data.get('type') if pinned else type_auto
    node['type_auto'] = type_auto
    node['type_pinned'] = pinned
    if host_type != 'nexus' and info.get('metrics'):
        _virt_seed_cache(node, info['metrics'])  # so the card renders immediately
    reg.setdefault('nodes', []).append(node)
    save_nodes(reg)
    g.audit_target = name
    return jsonify({'success': True, 'node': _public_node(node)})


@app.route('/api/nodes/<node_id>', methods=['PUT'])
def node_update(node_id):
    """Edit a node in place: name, tags, manual type override, base_url, and/or
    token. Admin-only. Changing the base_url or token triggers a re-probe (so a
    new URL's cert is re-pinned and role/version/capabilities are refreshed) —
    no need to delete and re-enroll."""
    data = request.get_json() or {}
    reg = load_nodes()
    for n in reg.get('nodes', []):
        if n.get('id') != node_id:
            continue
        if 'name' in data:
            n['name'] = (data['name'] or '').strip() or n['name']
        if 'tags' in data and isinstance(data['tags'], list):
            n['tags'] = [str(t) for t in data['tags']]
        if 'type' in data:
            # 'auto' un-pins (effective type reverts to type_auto); a concrete
            # type pins the manual override.
            if data['type'] == 'auto':
                n['type_pinned'] = False
                n['type'] = n.get('type_auto', 'Unknown')
            elif data['type'] in ('Storage', 'AI', 'Mixed', 'Virtualization', 'Unknown'):
                n['type'] = data['type']
                n['type_pinned'] = True

        # A base_url/credential change → re-probe to validate and refresh the
        # pinned cert (+ role/version/caps for nexus). Probe with the new secret
        # if supplied, else the host's existing (decrypted) one.
        host_type = n.get('host_type', 'nexus')
        adapter = ADAPTERS.get(host_type) or ADAPTERS['nexus']
        new_url = (data.get('base_url') or '').strip()
        url_changed = bool(new_url) and new_url.rstrip('/') != n['base_url']
        if adapter.auth == 'token':
            new_token = (data.get('token') or '').strip()
            verify_changed = host_type != 'nexus' and 'verify_ssl' in data
            if url_changed or new_token or verify_changed:
                base_url = (new_url or n['base_url']).rstrip('/')
                token = new_token or (decrypt_secret(n.get('token_enc', '')) if n.get('token_enc') else '')
                verify_ssl = bool(data['verify_ssl']) if 'verify_ssl' in data else bool(n.get('verify_ssl'))
                try:
                    info = _probe_host(host_type, base_url, {'token': token, 'verify_ssl': verify_ssl})
                except NodeError as e:
                    return err('connection test failed: %s' % e, 502)
                n['base_url'] = base_url
                n['cert_fp'] = info['cert_fp']
                n['role'] = info.get('role')
                n['version'] = info.get('version')
                n['capabilities'] = info.get('capabilities', [])
                if new_token:
                    n['token_enc'] = encrypt_secret(new_token)
                if host_type != 'nexus':   # truenas: refresh verify flag + reseed the card
                    n['verify_ssl'] = verify_ssl
                    if info.get('metrics'):
                        _virt_seed_cache(n, info['metrics'])
        else:
            new_pw = data.get('password') or ''
            new_user = (data.get('username') or '').strip()
            user_changed = bool(new_user) and new_user != n.get('username')
            if url_changed or new_pw or user_changed or 'verify_ssl' in data:
                base_url = (new_url or n['base_url']).rstrip('/')
                username = new_user or n.get('username', '')
                password = new_pw or (decrypt_secret(n.get('password_enc', '')) or '')
                verify_ssl = bool(data['verify_ssl']) if 'verify_ssl' in data else bool(n.get('verify_ssl'))
                try:
                    info = _probe_host(host_type, base_url,
                                       {'username': username, 'password': password, 'verify_ssl': verify_ssl})
                except NodeError as e:
                    return err('connection test failed: %s' % e, 502)
                n['base_url'] = base_url
                n['cert_fp'] = info['cert_fp']
                n['username'] = username
                n['verify_ssl'] = verify_ssl
                if new_pw:
                    n['password_enc'] = encrypt_secret(new_pw)
                if info.get('metrics'):
                    _virt_seed_cache(n, info['metrics'])

        save_nodes(reg)
        with _fleet_lock:   # reflect edits on the next fleet view
            _fleet_cache['ts'] = 0.0
        g.audit_target = n['name']
        return jsonify({'success': True, 'node': _public_node(n)})
    return err('node not found', 404)


@app.route('/api/nodes/<node_id>', methods=['DELETE'])
def node_delete(node_id):
    """Remove a node from the registry. Admin-only."""
    reg = load_nodes()
    before = len(reg.get('nodes', []))
    target = next((n['name'] for n in reg.get('nodes', []) if n.get('id') == node_id), None)
    reg['nodes'] = [n for n in reg.get('nodes', []) if n.get('id') != node_id]
    if len(reg['nodes']) == before:
        return err('node not found', 404)
    save_nodes(reg)
    g.audit_target = target
    return jsonify({'success': True})


# ─── Fleet aggregation ────────────────────────────────────────────────
_fleet_cache = {'ts': 0.0, 'data': None}
_fleet_lock = threading.Lock()


# ─── Host adapters — per-type probe / fetch / drill-in ────────────────
# Every enrolled host has a `host_type`. The default 'nexus' adapter speaks the
# Nexus Dashboard REST API (Bearer token + /api/*, systemd services, ZFS pools)
# and proxies the node's own SPA for drill-in. Virtualization adapters
# (proxmox/vmware) talk to a hypervisor API and normalize their metrics into the
# SAME per-node envelope, so the fleet rollup, cards, and storage view work
# across host types with little special-casing.
def _base_envelope(node):
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
    """Per-host-type strategy: how to probe at enroll, fetch for the fan-out, and
    where the card's drill-in points. Subclasses normalize into `_base_envelope`."""
    kind = 'nexus'
    auth = 'token'   # credential model: 'token' (API token/key) or 'userpass'

    def probe(self, base_url, creds):
        """Enroll/test-connection: validate credentials + capture the cert
        fingerprint; return identity (role/version/capabilities). Raises NodeError."""
        raise NotImplementedError

    def fetch(self, node):
        """Fan-out: pull one host's status into an envelope. MUST NOT raise —
        a single unreachable host must never crash the whole fleet view."""
        raise NotImplementedError

    def native_url(self, node):
        """Where the card's 'Open dashboard' link points."""
        return '/nodes/%s/' % node['id']


class NexusAdapter(HostAdapter):
    """A single-host Nexus Dashboard node, over its token-authed REST API."""
    kind = 'nexus'

    def probe(self, base_url, creds):
        return probe_node(base_url, (creds or {}).get('token'))

    def fetch(self, node):
        """Pull one node's summary + resources. Never raises — returns an
        envelope. Adds parsed storage bytes so the rollup can sum capacity."""
        out = _base_envelope(node)
        try:
            client = NodeClient(node)
            out['summary'] = client.get_json('summary')
            try:
                out['resources'] = client.get_json('system/resources')
            except NodeError:
                pass  # resources are best-effort
            zfs = (out['summary'] or {}).get('zfs') or {}
            out['used_bytes'] = parse_human_bytes(zfs.get('used'))
            out['size_bytes'] = parse_human_bytes(zfs.get('size'))
            # AI nodes: pull llama config + health (not in /api/summary) for the
            # card and for AI/Mixed classification. Best-effort.
            if 'llamacpp' in (node.get('capabilities') or []):
                try:
                    li = client.get_json('llama')
                    try:
                        li['health'] = client.get_json('llama/health')
                    except NodeError:
                        li['health'] = {'ok': False}
                    # Only surface llama on nodes that actually run/serve it — a
                    # storage node with the module merely toggled on (no model
                    # configured) shouldn't show a 'down' AI card.
                    if li.get('configured') or _serves_ai(li):
                        out['llama'] = li
                except NodeError:
                    pass
            out['ok'] = True
            # Refresh version + capabilities straight from the node so the
            # registry self-heals — no manual "test connection" / token re-entry
            # to update the version column after a node upgrade. Best-effort.
            try:
                me = client.get_json('me')
                if me.get('version'):
                    out['version'] = me['version']
                if isinstance(me.get('capabilities'), list):
                    out['capabilities'] = me['capabilities']
            except NodeError:
                pass
            out['type_auto'] = classify_node(out['summary'], out.get('capabilities'), out.get('llama'))
        except NodeError as e:
            out['error'] = str(e)
        except Exception as e:
            # Defense in depth: one node must never crash the whole fan-out.
            out['error'] = str(e)
        return out


def build_virt_envelope(node, metrics):
    """Map a collector metric dict (see collectors/*.build_metrics) into the
    fan-out envelope. Pure → unit-tested. Splits LXC containers out of the VM
    list (Proxmox tags them 'lxc-…'); VMware has none. Populates `resources`
    and used/size bytes so the existing CPU/Mem meters + storage rollup light up
    for virt hosts unchanged."""
    out = _base_envelope(node)
    vms = metrics.get('vms') or []
    is_ct = lambda v: str(v.get('vm_id', '')).startswith('lxc-')
    running = lambda v: v.get('power_state') in ('running', 'poweredOn')
    containers = [v for v in vms if is_ct(v)]
    guests = [v for v in vms if not is_ct(v)]
    out['ok'] = True
    out['resources'] = {'cpu_pct': metrics.get('cpu_usage_percent'),
                        'memory': {'pct': metrics.get('memory_usage_percent')}}
    out['used_bytes'] = int((metrics.get('storage_used_gb') or 0) * 1024 ** 3)
    out['size_bytes'] = int((metrics.get('storage_total_gb') or 0) * 1024 ** 3)
    out['virt'] = {
        'kind': node.get('host_type'),
        'hosts': metrics.get('host_count') or 0,
        'vms': len(guests), 'vms_running': sum(1 for v in guests if running(v)),
        'containers': len(containers), 'containers_running': sum(1 for v in containers if running(v)),
        'mem_used_gb': round(metrics.get('memory_used_gb') or 0, 1),
        'mem_total_gb': round(metrics.get('memory_total_gb') or 0, 1),
        'storage_used_gb': round(metrics.get('storage_used_gb') or 0, 1),
        'storage_total_gb': round(metrics.get('storage_total_gb') or 0, 1),
        'vm_list': vms,
    }
    out['type_auto'] = 'Virtualization'
    return out


def build_nas_envelope(node, metrics):
    """Map a NAS collector metric dict (collectors/truenas.build_metrics) into the
    fan-out envelope. Pure → unit-tested. Adds a `nas` block + `resources` +
    used/size bytes so the CPU/Mem meters, storage rollup, and overview rows all
    light up for a NAS the same way they do for nexus/virt hosts."""
    out = _base_envelope(node)
    out['ok'] = True
    out['resources'] = {'cpu_pct': metrics.get('cpu_usage_percent'),
                        'memory': {'pct': metrics.get('memory_usage_percent')}}
    out['used_bytes'] = int((metrics.get('storage_used_gb') or 0) * 1024 ** 3)
    out['size_bytes'] = int((metrics.get('storage_total_gb') or 0) * 1024 ** 3)
    out['nas'] = {
        'kind': node.get('host_type'),
        'hostname': metrics.get('hostname'),
        'model': metrics.get('model'),
        'version': metrics.get('version'),
        'pools': metrics.get('pool_count') or 0,
        'pools_healthy': metrics.get('pools_healthy') or 0,
        'pools_degraded': metrics.get('pools_degraded') or 0,
        'disks': metrics.get('disk_count') or 0,
        'alerts': metrics.get('alert_count') or 0,
        'alert_list': metrics.get('alerts') or [],
        'pool_list': metrics.get('pools') or [],
        'storage_used_gb': round(metrics.get('storage_used_gb') or 0, 1),
        'storage_total_gb': round(metrics.get('storage_total_gb') or 0, 1),
    }
    out['type_auto'] = 'Storage'
    return out


class VirtAdapter(HostAdapter):
    """Base for hypervisor hosts (proxmox/vmware): username+password auth, cert
    pinning, background polling into _virt_cache. Subclasses supply the collector
    and the native-UI link. `fetch` (fan-out) reads the cache; `collect` (poller)
    does the real hypervisor call."""
    default_port = 443
    auth = 'userpass'
    default_type = 'Virtualization'   # fallback classification (see envelope)

    def envelope(self, node, metrics):
        """Collector metric dict → fan-out envelope (per host-type)."""
        return build_virt_envelope(node, metrics)

    def _collect_metrics(self, host, port, user, password, verify_ssl):
        raise NotImplementedError

    def probe(self, base_url, creds):
        """Validate credentials by doing a real collect + capture the cert
        fingerprint for pinning. Returns identity incl. the initial metrics so
        the caller can seed the cache (no second connect)."""
        creds = creds or {}
        if not creds.get('username') or not creds.get('password'):
            raise NodeError('username and password are required')
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        try:
            fp = cert_fingerprint(host, port)
        except (socket.error, ssl.SSLError, OSError) as e:
            raise NodeError(f'cannot reach {host}:{port} ({e})')
        try:
            metrics = self._collect_metrics(host, port, creds['username'],
                                             creds['password'], bool(creds.get('verify_ssl')))
        except Exception as e:
            raise NodeError(f'connection/credentials rejected: {e}')
        return {'cert_fp': fp, 'role': None, 'version': None, 'fqdn': None,
                'capabilities': [self.kind], 'metrics': metrics}

    def collect(self, node):
        """Poller entry point: verify the pinned cert, decrypt creds, poll the
        hypervisor, and return an envelope. Never raises."""
        try:
            host, port = _split_host_port(node['base_url'])
            if node.get('cert_fp'):
                live = cert_fingerprint(host, port)
                if live != node['cert_fp']:
                    raise NodeError('certificate fingerprint changed for %s:%s '
                                    '(pinned %s…, saw %s…)'
                                    % (host, port, node['cert_fp'][:16], live[:16]))
            pw = decrypt_secret(node.get('password_enc', '')) or ''
            metrics = self._collect_metrics(host, port, node.get('username', ''),
                                            pw, bool(node.get('verify_ssl')))
            return self.envelope(node, metrics)
        except Exception as e:
            out = _base_envelope(node)
            out['error'] = str(e)
            out['type_auto'] = self.default_type
            return out

    def fetch(self, node):
        """Fan-out: serve this host's last polled envelope from the cache."""
        with _virt_lock:
            entry = _virt_cache.get(node['id'])
        if not entry:
            out = _base_envelope(node)
            out['error'] = 'awaiting first poll'
            out['type_auto'] = self.default_type
            return out
        env = dict(entry['env'])
        # Reflect live registry metadata (type/tags edits shouldn't wait a poll).
        env['type'] = node.get('type', 'Virtualization')
        env['type_pinned'] = node.get('type_pinned', False)
        env['tags'] = node.get('tags', [])
        env['stale'] = (time.time() - entry['ts']) > VIRT_POLL_INTERVAL * 3
        return env

    def native_url(self, node):
        # Virt hosts serve their own native UI; the browser reaches it directly.
        return node['base_url'] + '/'


class ProxmoxAdapter(VirtAdapter):
    kind = 'proxmox'
    default_port = 8006

    def _collect_metrics(self, host, port, user, password, verify_ssl):
        from collectors import proxmox
        return proxmox.collect_metrics(host, user, password, port=port, verify_ssl=verify_ssl)


class VMwareAdapter(VirtAdapter):
    """vSphere over pyVmomi. vCenter aggregates all managed ESXi hosts + VMs;
    a standalone ESXi host reports just itself. Same collector for both — the
    subclasses differ only in `kind` (host-type label)."""
    default_port = 443

    def _collect_metrics(self, host, port, user, password, verify_ssl):
        from collectors import vmware
        return vmware.collect_metrics(host, user, password, port=port, verify_ssl=verify_ssl)

    def native_url(self, node):
        return node['base_url'] + '/ui'   # vSphere / ESXi HTML5 client


class VCenterAdapter(VMwareAdapter):
    kind = 'vcenter'


class ESXiAdapter(VMwareAdapter):
    kind = 'esxi'


class TrueNasAdapter(VirtAdapter):
    """TrueNAS SCALE/CORE over the JSON-RPC 2.0 WebSocket API (REST v2.0 is removed
    in TrueNAS 26.04). Reuses the virt background-poller + cert-pinning machinery,
    but authenticates with an API key via ``auth.login_with_api_key`` (not
    username/password), classifies as Storage, and normalizes into the `nas`
    envelope. Read-only — the poller only ever calls read methods (+ one reporting
    read)."""
    kind = 'truenas'
    default_port = 443
    auth = 'token'
    default_type = 'Storage'

    def envelope(self, node, metrics):
        return build_nas_envelope(node, metrics)

    def probe(self, base_url, creds):
        creds = creds or {}
        token = (creds.get('token') or '').strip()
        if not token:
            raise NodeError('an API key is required')
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        try:
            fp = cert_fingerprint(host, port)
        except (socket.error, ssl.SSLError, OSError) as e:
            raise NodeError(f'cannot reach {host}:{port} ({e})')
        from collectors import truenas
        try:
            metrics = truenas.collect_metrics(host, token, port=port,
                                              verify_ssl=bool(creds.get('verify_ssl')))
        except Exception as e:
            raise NodeError(f'connection/API key rejected: {e}')
        return {'cert_fp': fp, 'role': None, 'version': metrics.get('version'),
                'fqdn': metrics.get('hostname'), 'capabilities': [self.kind],
                'metrics': metrics}

    def collect(self, node):
        try:
            host, port = _split_host_port(node['base_url'])
            if node.get('cert_fp'):
                live = cert_fingerprint(host, port)
                if live != node['cert_fp']:
                    raise NodeError('certificate fingerprint changed for %s:%s '
                                    '(pinned %s…, saw %s…)'
                                    % (host, port, node['cert_fp'][:16], live[:16]))
            from collectors import truenas
            tok = decrypt_secret(node.get('token_enc', '')) or ''
            metrics = truenas.collect_metrics(host, tok, port=port,
                                              verify_ssl=bool(node.get('verify_ssl')))
            return build_nas_envelope(node, metrics)
        except Exception as e:
            out = _base_envelope(node)
            out['error'] = str(e)
            out['type_auto'] = self.default_type
            return out

    def native_url(self, node):
        return node['base_url'] + '/ui/dashboard'   # TrueNAS SCALE web UI


ADAPTERS = {a.kind: a for a in
            (NexusAdapter(), ProxmoxAdapter(), VCenterAdapter(), ESXiAdapter(),
             TrueNasAdapter())}


def _adapter_for(node):
    """Resolve a host's adapter; records without a host_type are nexus nodes."""
    return ADAPTERS.get(node.get('host_type') or 'nexus', ADAPTERS['nexus'])


def _probe_host(host_type, base_url, creds):
    """Adapter-aware enroll/test probe. Raises NodeError on unknown type."""
    adapter = ADAPTERS.get(host_type or 'nexus')
    if not adapter:
        raise NodeError('unknown host type: %s' % host_type)
    return adapter.probe(base_url, creds)


# ─── Virtualization host polling (background) ─────────────────────────
_virt_cache = {}          # node_id -> {'env': envelope, 'ts': float}
_virt_lock = threading.Lock()


def _virt_seed_cache(node, metrics):
    """Prime the cache from an enroll/edit probe's metrics so the card doesn't
    show 'awaiting first poll' until the next background cycle."""
    env = _adapter_for(node).envelope(node, metrics)
    with _virt_lock:
        _virt_cache[node['id']] = {'env': env, 'ts': time.time()}


def _is_virt(node):
    return (node.get('host_type') or 'nexus') != 'nexus'


def _virt_poll_once():
    nodes = [n for n in load_nodes().get('nodes', []) if _is_virt(n)]
    ids = {n['id'] for n in nodes}
    if nodes:
        with ThreadPoolExecutor(max_workers=FANOUT_WORKERS) as pool:
            futs = {pool.submit(_adapter_for(n).collect, n): n for n in nodes}
            for fut in as_completed(futs):
                n = futs[fut]
                with _virt_lock:
                    _virt_cache[n['id']] = {'env': fut.result(), 'ts': time.time()}
    with _virt_lock:  # drop cache entries for removed hosts
        for k in [k for k in _virt_cache if k not in ids]:
            del _virt_cache[k]


def _virt_poller_loop():
    while True:
        try:
            _virt_poll_once()
        except Exception:
            pass  # a poll cycle must never kill the poller thread
        time.sleep(VIRT_POLL_INTERVAL)


def start_virt_poller():
    threading.Thread(target=_virt_poller_loop, daemon=True, name='virt-poller').start()


def _fetch_one(node):
    """Fan-out one host through its host-type adapter (nexus is the default)."""
    return _adapter_for(node).fetch(node)


def _services_down(summary):
    """Count services that should be running (enabled) but aren't active. A
    deliberately-disabled service is not 'down'."""
    svcs = (summary or {}).get('services') or {}
    return sum(1 for sv in svcs.values()
               if sv.get('enabled') == 'enabled' and sv.get('active') != 'active')


def compute_rollup(results):
    """Pure fleet rollup from per-node envelopes (nexus + virt) — unit-tested."""
    healthy = unreachable = alerts = degraded = svc_down = 0
    used = size = 0
    vms = containers = 0
    for r in results:
        if not r.get('ok'):
            unreachable += 1
            continue
        healthy += 1
        s = r.get('summary') or {}
        n_alerts = len(s.get('alerts') or [])
        alerts += n_alerts
        used += r.get('used_bytes', 0)
        size += r.get('size_bytes', 0)
        down = _services_down(s)
        svc_down += down
        zfs = s.get('zfs') or {}
        zfs_bad = bool(zfs.get('pools')) and not zfs.get('online', True)
        v = r.get('virt') or {}          # virt hosts: fold VM/CT counts into the rollup
        vms += (v.get('vms') or 0) + (v.get('containers') or 0)
        containers += v.get('containers') or 0
        if n_alerts or down or zfs_bad or r.get('stale'):
            degraded += 1
    return {'total': len(results), 'healthy': healthy, 'unreachable': unreachable,
            'alerts': alerts, 'degraded': degraded, 'services_down': svc_down,
            'storage_used': used, 'storage_size': size,
            'vms': vms, 'containers': containers}


def _build_fleet():
    nodes = load_nodes().get('nodes', [])
    results = []
    if nodes:
        with ThreadPoolExecutor(max_workers=FANOUT_WORKERS) as pool:
            futures = [pool.submit(_fetch_one, n) for n in nodes]
            for fut in as_completed(futures):
                results.append(fut.result())
    # Refresh last_seen + type_auto for reachable nodes (best-effort).
    seen = {r['id']: r for r in results}
    reg = load_nodes()
    dirty = False
    for n in reg.get('nodes', []):
        r = seen.get(n['id'])
        if r and r['ok']:
            n['last_seen'] = datetime.now().astimezone().isoformat(timespec='seconds')
            ta = r.get('type_auto')
            if ta and ta != 'Unknown':
                n['type_auto'] = ta
                if not n.get('type_pinned'):
                    n['type'] = ta   # effective type tracks the suggestion
                    r['type'] = ta   # reflect in THIS response (no one-poll lag)
            # Self-heal the stored version/capabilities from the live probe.
            if r.get('version'):
                n['version'] = r['version']
            caps = r.get('capabilities')
            if isinstance(caps, list) and caps:
                n['capabilities'] = caps
            dirty = True
    if dirty:
        save_nodes(reg)
    results.sort(key=lambda r: r['name'].lower())
    return {'nodes': results, 'rollup': compute_rollup(results),
            'generated_at': datetime.now().astimezone().isoformat(timespec='seconds')}


@app.route('/api/fleet/summary')
def fleet_summary():
    fresh = request.args.get('fresh') in ('1', 'true', 'yes')
    with _fleet_lock:
        age = time.time() - _fleet_cache['ts']
        if not fresh and _fleet_cache['data'] is not None and age < FLEET_CACHE_TTL:
            return jsonify({**_fleet_cache['data'], 'cached': True, 'cache_age': round(age, 1)})
        data = _build_fleet()
        _fleet_cache['data'] = data
        _fleet_cache['ts'] = time.time()
    return jsonify({**data, 'cached': False, 'cache_age': 0})


FLEET_ACTIONS = {'start', 'stop', 'restart', 'enable', 'disable'}
RE_SERVICE = re.compile(r'^[A-Za-z0-9_.@-]+$')


def _proxy_service_action(node, service, action):
    """Best-effort single proxied service action → result envelope. Never raises."""
    out = {'id': node['id'], 'name': node['name'], 'ok': False, 'status': None, 'error': None}
    try:
        r = NodeClient(node).request('POST', 'service/%s/%s' % (service, action))
        out['status'] = r.status_code
        out['ok'] = r.status_code == 200
        if not out['ok']:
            try:
                out['error'] = (r.json() or {}).get('error') or 'HTTP %d' % r.status_code
            except ValueError:
                out['error'] = 'HTTP %d' % r.status_code
    except NodeError as e:
        out['error'] = str(e)
    except Exception as e:
        # Defense in depth: one node must never crash the fleet action.
        out['error'] = str(e)
    return out


@app.route('/api/fleet/action', methods=['POST'])
def fleet_action():
    """Fan out a systemd service action to many nodes at once. Best-effort:
    returns a per-node success/failure list (proposal §10). Controller RBAC
    (require_login) already blocked viewer; each node still enforces its own
    token role (a readonly-token node will 403)."""
    data = request.get_json() or {}
    service = (data.get('service') or '').strip()
    action = (data.get('action') or '').strip()
    node_ids = data.get('node_ids')
    if action not in FLEET_ACTIONS:
        return err('invalid action (start/stop/restart/enable/disable)')
    if not RE_SERVICE.match(service):
        return err('invalid service name')
    nodes = load_nodes().get('nodes', [])
    if isinstance(node_ids, list) and node_ids:
        wanted = set(node_ids)
        nodes = [n for n in nodes if n['id'] in wanted]
    if not nodes:
        return err('no matching nodes', 404)
    g.audit_target = 'fleet %s/%s [%d node(s)]' % (service, action, len(nodes))
    results = []
    with ThreadPoolExecutor(max_workers=FANOUT_WORKERS) as pool:
        futs = [pool.submit(_proxy_service_action, n, service, action) for n in nodes]
        for f in as_completed(futs):
            results.append(f.result())
    with _fleet_lock:  # force a fresh poll next time so the matrix reflects the change
        _fleet_cache['ts'] = 0.0
    results.sort(key=lambda r: r['name'].lower())
    ok = sum(1 for r in results if r['ok'])
    return jsonify({'service': service, 'action': action, 'ok': ok,
                    'failed': len(results) - ok, 'results': results})


# ─── Drill-in: reverse-proxy a node's own SPA + API ───────────────────
# Headers we must not pass straight through (the WSGI layer re-computes them).
_HOP_HEADERS = {'content-encoding', 'transfer-encoding', 'connection',
                'content-length', 'keep-alive', 'te', 'trailer', 'upgrade'}


def render_drillin_html(html, node_id):
    """Retarget the node's own index.html to run through the controller:
    inject a fetch-shim rewriting /api/* to the proxy, and point the one static
    asset reference at the controller's node-static proxy. Pure → unit-tested."""
    base = '/nodes/%s' % node_id
    html = html.replace('href="/static/', 'href="%s/static/' % base)
    html = html.replace('src="/static/', 'src="%s/static/' % base)
    shim = ('<script>(function(){var P="/api/nodes/%s/proxy/";'
            'var f=window.fetch;window.fetch=function(u,o){'
            'if(typeof u==="string"&&u.indexOf("/api/")===0){u=P+u.slice(5);}'
            'return f.call(this,u,o);};})();</script>') % node_id
    if '<head>' in html:
        return html.replace('<head>', '<head>' + shim, 1)
    return shim + html


def _node_raw_get(node, path):
    """GET an arbitrary (non-/api) path on a node, cert-pin enforced."""
    client = NodeClient(node)
    client._verify_pin()
    return requests.get(client.base_url + path, verify=False, timeout=NODE_TIMEOUT)


@app.route('/nodes/<node_id>/')
def node_drillin(node_id):
    """Serve the node's own dashboard SPA, retargeted through this controller."""
    node = _find_node(node_id)
    if not node:
        return err('node not found', 404)
    try:
        r = _node_raw_get(node, '/')
    except (NodeError, requests.RequestException) as e:
        return Response('<h2>Drill-in unavailable</h2><p>%s</p>'
                        '<p><a href="/">&larr; back to fleet</a></p>' % str(e), status=502,
                        content_type='text/html')
    return Response(render_drillin_html(r.text, node_id), content_type='text/html')


@app.route('/nodes/<node_id>/static/<path:subpath>')
def node_static(node_id, subpath):
    """Proxy the node's static assets (CSS/JS/img) for drill-in."""
    node = _find_node(node_id)
    if not node:
        return err('node not found', 404)
    try:
        r = _node_raw_get(node, '/static/' + subpath)
    except (NodeError, requests.RequestException) as e:
        return err(str(e), 502)
    return Response(r.content, status=r.status_code,
                    content_type=r.headers.get('Content-Type', 'application/octet-stream'))


@app.route('/api/nodes/<node_id>/proxy/<path:subpath>',
           methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def node_proxy(node_id, subpath):
    """Forward an API call to a node with its token. Controller RBAC already
    blocked viewer writes (require_login); the after_request hook audits
    mutations. The node's own auth/RBAC/validation still applies on its end."""
    node = _find_node(node_id)
    if not node:
        return err('node not found', 404)
    g.audit_target = '%s:/api/%s' % (node['name'], subpath)
    client = NodeClient(node)
    try:
        client._verify_pin()
    except NodeError as e:
        return err(str(e), 502)
    qs = request.query_string.decode()
    url = '%s/api/%s%s' % (client.base_url, subpath, ('?' + qs if qs else ''))
    headers = {}
    if client.token:
        headers['Authorization'] = 'Bearer ' + client.token
    ct = request.headers.get('Content-Type')
    if ct:
        headers['Content-Type'] = ct
    body = request.get_data()
    try:
        resp = requests.request(request.method, url, headers=headers,
                                data=body if body else None, verify=False, timeout=PROXY_TIMEOUT)
    except requests.RequestException as e:
        return err('proxy to node failed: %s' % e, 502)
    out = [(k, v) for k, v in resp.headers.items() if k.lower() not in _HOP_HEADERS]
    return Response(resp.content, status=resp.status_code, headers=out)


# ─── TLS certificate management (cryptography lib — no openssl) ────────
def _cert_expiry(cert):
    try:
        return cert.not_valid_after_utc            # cryptography >= 42
    except AttributeError:
        return cert.not_valid_after                 # older (naive UTC)


def cert_info(cert_path=None):
    """Metadata for the serving certificate (mirrors the node's /api/tls/info)."""
    cert_path = cert_path or TLS_CERT
    if not os.path.exists(cert_path):
        return {'present': False}
    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
    except Exception:
        return {'present': True, 'error': 'unreadable certificate'}
    fp = cert.fingerprint(hashes.SHA256()).hex()
    exp = _cert_expiry(cert)
    return {
        'present': True, 'path': cert_path,
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'expires': exp.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'self_signed': cert.subject == cert.issuer,
        'fingerprint_sha256': ':'.join(fp[i:i + 2] for i in range(0, len(fp), 2)),
    }


def generate_self_signed():
    """Create a self-signed cert+key (cryptography lib) and write them to the
    serving paths. Returns (ok, error)."""
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cn = socket.gethostname()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
                .sign(key, hashes.SHA256()))
        os.makedirs(TLS_DIR, exist_ok=True)
        with open(TLS_CERT, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        fd = os.open(TLS_KEY, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        return True, ''
    except Exception as e:
        return False, str(e)


def ensure_tls_cert():
    """Ensure a usable cert+key exist. Generate a self-signed pair only when BOTH
    are missing — never overwrite an operator-supplied certificate."""
    have_cert, have_key = os.path.exists(TLS_CERT), os.path.exists(TLS_KEY)
    if have_cert and have_key:
        return
    if have_cert or have_key:
        raise RuntimeError(f'TLS cert/key mismatch: one of {TLS_CERT} / {TLS_KEY} is missing')
    ok, e = generate_self_signed()
    if not ok:
        raise RuntimeError(f'Failed to generate self-signed certificate: {e}')


def validate_and_install_cert(cert_pem, key_pem):
    """Validate a PEM cert+key pair (well-formed + key matches cert) and install
    them to the serving paths. Pure cryptography — no openssl. Returns (ok, err)."""
    cert_pem = (cert_pem or '').strip()
    key_pem = (key_pem or '').strip()
    if 'BEGIN CERTIFICATE' not in cert_pem:
        return False, 'Certificate must be PEM (-----BEGIN CERTIFICATE-----)'
    if 'PRIVATE KEY' not in key_pem:
        return False, 'Key must be a PEM private key'
    if len(cert_pem) > 100_000 or len(key_pem) > 100_000:
        return False, 'Certificate or key too large'
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        return False, 'Invalid certificate'
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except Exception:
        return False, 'Invalid private key'
    try:
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        cpub = cert.public_key().public_bytes(serialization.Encoding.PEM, spki)
        kpub = key.public_key().public_bytes(serialization.Encoding.PEM, spki)
    except Exception:
        return False, 'Could not compare certificate and key'
    if cpub != kpub:
        return False, 'Certificate and private key do not match'
    os.makedirs(TLS_DIR, exist_ok=True)
    tmp_cert, tmp_key = TLS_CERT + '.upload', TLS_KEY + '.upload'
    try:
        with open(tmp_cert, 'w') as f:
            f.write(cert_pem + '\n')
        fd = os.open(tmp_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(key_pem + '\n')
        os.replace(tmp_cert, TLS_CERT)
        os.replace(tmp_key, TLS_KEY)
        os.chmod(TLS_KEY, 0o600)
    finally:
        for p in (tmp_cert, tmp_key):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
    return True, ''


@app.route('/api/tls/info')
def tls_info():
    info = cert_info()
    info['tls_enabled'] = TLS_ENABLED
    return jsonify(info)


@app.route('/api/tls/regenerate', methods=['POST'])
def tls_regenerate():
    """Regenerate the self-signed cert (admin). Restart to apply."""
    ok, e = generate_self_signed()
    if not ok:
        return err('Failed to generate certificate: %s' % e, 500)
    g.audit_target = 'tls-regenerate'
    return jsonify({'success': True, 'restart_required': True})


@app.route('/api/tls/cert', methods=['POST'])
def tls_upload_cert():
    """Replace the serving cert with an operator-supplied PEM pair (admin)."""
    data = request.get_json() or {}
    ok, e = validate_and_install_cert(data.get('cert'), data.get('key'))
    if not ok:
        return err(e)
    g.audit_target = 'tls-cert'
    return jsonify({'success': True, 'restart_required': True})


def cli_set_password(argv):
    """`app.py set-password [user]` — set a controller login password without the
    web UI. Reads CONTROLLER_ADMIN_PASSWORD if set (non-interactive, used by
    install.sh), else prompts. Creates the user (role admin) if absent."""
    import getpass
    user = argv[2] if len(argv) > 2 else 'admin'
    if not re.match(r'^[A-Za-z0-9._-]{1,32}$', user):
        print('Invalid username')
        return 1
    pw = os.environ.get('CONTROLLER_ADMIN_PASSWORD')
    if not pw:
        pw = getpass.getpass(f'New password for {user}: ')
        if pw != getpass.getpass('Confirm password: '):
            print('Passwords do not match')
            return 1
    if len(pw) < MIN_PASSWORD_LEN:
        print(f'Password must be at least {MIN_PASSWORD_LEN} characters')
        return 1
    cfg = ensure_bootstrap()
    users = cfg.setdefault('users', {})
    rec = users[user] if isinstance(users.get(user), dict) else {'role': 'admin'}
    rec['password'] = generate_password_hash(pw)
    rec.pop('must_change', None)
    users[user] = rec
    save_config(cfg)
    print(f'Password updated for {user}')
    return 0


def main():
    cfg = ensure_bootstrap()
    app.secret_key = cfg['secret_key']
    ssl_ctx = None
    if TLS_ENABLED:
        ensure_tls_cert()
        ssl_ctx = (TLS_CERT, TLS_KEY)
    start_virt_poller()  # background polling for any enrolled proxmox/vmware hosts
    print(f'Nexus Controller v{APP_VERSION} on {"https" if TLS_ENABLED else "http"}://0.0.0.0:{PORT}', flush=True)
    app.run(host='0.0.0.0', port=PORT, ssl_context=ssl_ctx, threaded=True)


def cli_install_cert(argv):
    """`app.py install-cert <cert.pem> <key.pem>` — replace the serving cert with
    a real one (e.g. from Let's Encrypt). Restart the controller to apply."""
    if len(argv) < 4:
        print('usage: app.py install-cert <cert.pem> <key.pem>')
        return 1
    try:
        cert_pem = open(argv[2]).read()
        key_pem = open(argv[3]).read()
    except OSError as e:
        print(f'cannot read file: {e}')
        return 1
    ok, e = validate_and_install_cert(cert_pem, key_pem)
    if not ok:
        print(f'error: {e}')
        return 1
    print(f'Certificate installed to {TLS_CERT}. Restart the controller to apply:')
    print('  sudo systemctl restart nexus-controller   (or: docker restart <container>)')
    return 0


def cli_cert_info(argv):
    print(json.dumps(cert_info(), indent=2))
    return 0


if __name__ == '__main__':
    import sys
    _cmds = {'set-password': cli_set_password, 'install-cert': cli_install_cert,
             'cert-info': cli_cert_info}
    if len(sys.argv) > 1 and sys.argv[1] in _cmds:
        sys.exit(_cmds[sys.argv[1]](sys.argv))
    main()
