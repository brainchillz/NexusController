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
import re
import json
import time
import socket
import secrets
import threading
from collections import deque
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from urllib3.exceptions import InsecureRequestWarning
import urllib3
from flask import Flask, jsonify, request, session, send_from_directory, g, Response
from flask_sock import Sock
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import requests
import adapters
import monitoring
import history
from adapters import (   # host-type seam — see adapters/__init__.py
    NodeError, NodeClient, classify_node, parse_human_bytes, _serves_ai,
    probe_node, build_virt_envelope, build_nas_envelope, build_spark_envelope,
    build_agent_envelope, build_dnsmaq_envelope,
    cert_fingerprint, _split_host_port, start_virt_poller, ADAPTERS,
    NODE_TIMEOUT, PROXY_TIMEOUT, FANOUT_WORKERS, VIRT_POLL_INTERVAL)
from adapters import adapter_for as _adapter_for, probe_host as _probe_host

# Nodes use self-signed certs by default; we pin their fingerprint ourselves
# (TOFU, in-handshake — see adapters.base), so requests' own CA verification is
# intentionally off and its warning is noise here.
urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__, static_url_path='')

APP_DIR = os.path.dirname(os.path.abspath(__file__))
APP_VERSION = '0.7.5'


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
HISTORY_FILE = os.environ.get('CONTROLLER_HISTORY_FILE', os.path.join(DATA_DIR, 'history.db'))
HISTORY_DAYS = int(os.environ.get('CONTROLLER_HISTORY_DAYS', '30'))

TLS_ENABLED = env_bool('CONTROLLER_TLS', True)
TLS_DIR = os.environ.get('CONTROLLER_TLS_DIR', os.path.join(DATA_DIR, 'certs'))
TLS_CERT = os.environ.get('CONTROLLER_TLS_CERT', os.path.join(TLS_DIR, 'controller.crt'))
TLS_KEY = os.environ.get('CONTROLLER_TLS_KEY', os.path.join(TLS_DIR, 'controller.key'))
PORT = int(os.environ.get('CONTROLLER_PORT', '9443' if TLS_ENABLED else '9080'))

# (Per-node timeouts, fan-out workers, and the virt poll interval live in
# adapters.base — imported above.)
# Brief fleet-summary cache so the SPA's auto-refresh doesn't hammer the nodes.
# A manual refresh passes ?fresh=1 to bypass it.
FLEET_CACHE_TTL = 12

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


# ─── Tag-scoped RBAC (pure helpers — unit-tested) ─────────────────────
def clean_scope_tags(v):
    """Normalize a user-supplied scope tag list: strings, trimmed, deduped."""
    if not isinstance(v, list):
        return []
    out = []
    for t in v:
        t = str(t).strip()[:64]
        if t and t not in out:
            out.append(t)
    return out[:32]


def clean_type(v):
    """Validate a manual host type: a short printable label. Built-ins
    (Storage/AI/…) and custom labels alike — a custom label becomes its own
    overview category. Returns the cleaned label, or None if unusable
    ('auto' is the un-pin sentinel, never a stored type)."""
    if not isinstance(v, str):
        return None
    v = ' '.join(v.split())
    if not v or len(v) > 24 or v.lower() == 'auto':
        return None
    return v


def user_scope(rec, role, presets=None):
    """Tag scope for an account. None = unscoped (sees the whole fleet):
    admins are always unscoped — someone has to manage enrollment — and an
    operator/viewer with no scope keeps fleet-wide behavior. A record may
    reference a named **scope preset** (`scope_preset`) instead of literal
    tags — presets resolve live, so editing one re-scopes every login bound
    to it. A dangling preset reference resolves to an EMPTY scope (matches no
    host — fail closed; deleting an in-use preset is blocked upstream)."""
    if role == 'admin' or not isinstance(rec, dict):
        return None
    preset = rec.get('scope_preset')
    if preset:
        tags = (presets or {}).get(preset)
        if tags is None:
            return set()   # dangling reference: deny rather than open up
        return set(clean_scope_tags(tags)) or None
    tags = clean_scope_tags(rec.get('tags') or [])
    return set(tags) or None


def scope_allows(scope, node):
    """May this tag scope (None or a set) see/touch this host? OR semantics,
    matching the overview tag filter and tag-targeted fleet actions."""
    return scope is None or bool(scope & set(node.get('tags') or []))


def scoped_fleet(data, scope):
    """Filter a fleet payload to a scope and recompute the rollup so a scoped
    account's header pill reflects only the hosts it can see."""
    if scope is None or not data:
        return data
    nodes = [r for r in data.get('nodes', []) if scope_allows(scope, r)]
    return {**data, 'nodes': nodes, 'rollup': compute_rollup(nodes)}


def _scope():
    """The current request's tag scope (None when unscoped, or outside a
    request — background threads, CLI paths, and direct test calls are always
    unscoped). `g` raises RuntimeError outside an app context, which getattr's
    default does not cover — hence the try."""
    try:
        return getattr(g, 'identity_scope', None)
    except RuntimeError:
        return None


def _scope_presets():
    """Named scope presets ("roles"): {name: [tags]}, stored in the auth file."""
    p = load_config().get('scope_presets')
    return p if isinstance(p, dict) else {}


# ─── AuthN / AuthZ ────────────────────────────────────────────────────
PUBLIC_ENDPOINTS = {'api_login', 'api_me', 'index', 'static'}
# Writes a non-admin role may still issue (sign out / change own password).
RBAC_EXEMPT = {'api_logout', 'change_password'}
# Endpoints that require the top (admin) role regardless of method — enrolling
# or removing a node, and managing controller users.
ADMIN_ONLY = {'nodes_add', 'node_delete', 'node_update', 'node_cert', 'node_repin',
              'tls_regenerate', 'tls_upload_cert',
              'notifications_save', 'notifications_test', 'notifications_events',
              'users_list', 'users_add', 'users_update', 'users_delete',
              'audit_list',
              'scope_presets_list', 'scope_presets_save', 'scope_presets_delete'}


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
    g.identity_scope = user_scope(_users().get(name), role, _scope_presets())
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


def audit_matches(entry, q):
    """Case-insensitive substring match across an audit entry's visible fields
    (pure — unit-tested)."""
    hay = ' '.join(str(entry.get(k, '')) for k in
                   ('ts', 'user', 'ip', 'method', 'path', 'target', 'status')).lower()
    return q in hay


@app.route('/api/audit')
def audit_list():
    """Tail of the controller audit trail, newest first (admin). `q` filters by
    substring across all fields; `limit` caps the result (default 200)."""
    limit = min(1000, max(1, int(request.args.get('limit', 200) or 200)))
    q = (request.args.get('q') or '').strip().lower()
    entries = []
    try:
        with open(AUDIT_FILE, 'r') as f:
            lines = deque(f, maxlen=5000)   # bounded read of an unrotated file
        for ln in lines:
            try:
                entries.append(json.loads(ln))
            except ValueError:
                pass
    except FileNotFoundError:
        pass
    if q:
        entries = [e for e in entries if audit_matches(e, q)]
    return jsonify({'entries': entries[-limit:][::-1]})


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
    """Resolve a node id for the current request. Every per-node route (proxy,
    drill-in, ws bridge, guest/cert actions, history detail) goes through here,
    so the tag-scope check lives in this one spot: an out-of-scope host is
    simply not found (404) — invisible, not merely forbidden."""
    for n in load_nodes().get('nodes', []):
        if n.get('id') == node_id:
            return n if scope_allows(_scope(), n) else None
    return None


# Inject the app-owned services the adapters package needs (it never imports
# app — see adapters/base.configure).
adapters.configure(decrypt_secret=decrypt_secret, load_nodes=load_nodes)


# ─── Routes: SPA + auth ───────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory(APP_DIR, 'templates/index.html')


# ─── Login throttling (in-memory sliding window) ─────────────────────
LOGIN_WINDOW = int(os.environ.get('CONTROLLER_LOGIN_WINDOW', '900'))
LOGIN_MAX_PER_USER = int(os.environ.get('CONTROLLER_LOGIN_MAX_USER', '5'))
LOGIN_MAX_PER_IP = int(os.environ.get('CONTROLLER_LOGIN_MAX_IP', '20'))
_login_fails = {}          # key tuple → [fail timestamps]
_login_lock = threading.Lock()


def _prune_fails(key, now):
    ts = [t for t in _login_fails.get(key, ()) if now - t < LOGIN_WINDOW]
    if ts:
        _login_fails[key] = ts
    else:
        _login_fails.pop(key, None)
    return ts


def login_throttled(ip, user, now=None):
    """True when this (ip, user) has burned its failed-attempt budget: per-user
    (defends one account against one IP) or per-IP (defends every account
    against one IP spraying usernames). Pure given `now` — unit-tested."""
    now = time.time() if now is None else now
    with _login_lock:
        return (len(_prune_fails(('ip', ip), now)) >= LOGIN_MAX_PER_IP
                or len(_prune_fails(('user', ip, user), now)) >= LOGIN_MAX_PER_USER)


def login_failed(ip, user, now=None):
    now = time.time() if now is None else now
    with _login_lock:
        _login_fails.setdefault(('ip', ip), []).append(now)
        _login_fails.setdefault(('user', ip, user), []).append(now)


def login_succeeded(ip, user):
    with _login_lock:
        _login_fails.pop(('user', ip, user), None)


def _client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr) or '-'


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    user = (data.get('username') or '').strip()
    pw = data.get('password') or ''
    ip = _client_ip()
    if login_throttled(ip, user):
        return err('Too many failed attempts — try again in a few minutes', 429)
    rec = _users().get(user)
    if not rec or not check_password_hash(rec.get('password', ''), pw):
        login_failed(ip, user)
        return err('Invalid credentials', 401)
    login_succeeded(ip, user)
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
    scope = user_scope(rec, role, _scope_presets())
    return jsonify({'authenticated': True, 'user': name, 'role': role,
                    'scope_tags': sorted(scope) if scope else None,
                    'scope_preset': rec.get('scope_preset') if isinstance(rec, dict) else None,
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


# ─── Controller user management (admin) ───────────────────────────────
RE_USERNAME = re.compile(r'^[A-Za-z0-9._-]{1,32}$')


@app.route('/api/users')
def users_list():
    """List controller logins (no password hashes). Admin-only."""
    out = [{'username': u, 'role': _user_role(r),
            'tags': clean_scope_tags(r.get('tags') or []) if isinstance(r, dict) else [],
            'scope_preset': r.get('scope_preset') if isinstance(r, dict) else None,
            'must_change': bool(isinstance(r, dict) and r.get('must_change'))}
           for u, r in _users().items()]
    out.sort(key=lambda u: u['username'].lower())
    return jsonify({'users': out})


@app.route('/api/users', methods=['POST'])
def users_add():
    """Create a controller login (admin)."""
    data = request.get_json() or {}
    user = (data.get('username') or '').strip()
    role = data.get('role')
    pw = data.get('password') or ''
    if not RE_USERNAME.match(user):
        return err('username must be 1–32 chars: letters, digits, . _ -')
    if role not in ROLES:
        return err('role must be one of: %s' % ', '.join(ROLES))
    if len(pw) < MIN_PASSWORD_LEN:
        return err(f'password must be at least {MIN_PASSWORD_LEN} characters')
    cfg = load_config()
    if user in cfg.get('users', {}):
        return err('user already exists')
    # Optional scope: a named preset ("role") OR literal tags — the preset
    # wins when both arrive. Admins are always fleet-wide — no dead scope.
    preset = (data.get('scope_preset') or '').strip() if role != 'admin' else ''
    if preset and preset not in _scope_presets():
        return err('unknown scope preset: %s' % preset)
    tags = clean_scope_tags(data.get('tags')) if (role != 'admin' and not preset) else []
    rec = {'password': generate_password_hash(pw), 'role': role, 'must_change': True,
           'tags': tags}
    if preset:
        rec['scope_preset'] = preset
    cfg.setdefault('users', {})[user] = rec
    save_config(cfg)
    g.audit_target = 'user:%s (%s%s)' % (user, role,
                                         ' @' + (preset or ','.join(tags)) if (preset or tags) else '')
    return jsonify({'success': True})


@app.route('/api/users/<user>', methods=['PUT'])
def users_update(user):
    """Change a user's role and/or reset their password (admin)."""
    data = request.get_json() or {}
    cfg = load_config()
    rec = cfg.get('users', {}).get(user)
    if not isinstance(rec, dict):
        return err('user not found', 404)
    if 'role' in data:
        if data['role'] not in ROLES:
            return err('role must be one of: %s' % ', '.join(ROLES))
        # Don't let the last admin demote themselves out of admin access.
        if user == g.identity_name and data['role'] != 'admin':
            return err('cannot remove your own admin role')
        rec['role'] = data['role']
    if data.get('password'):
        if len(data['password']) < MIN_PASSWORD_LEN:
            return err(f'password must be at least {MIN_PASSWORD_LEN} characters')
        rec['password'] = generate_password_hash(data['password'])
        rec['must_change'] = True   # operator-set password → force a change on first login
    # Scope: a named preset and literal tags are mutually exclusive — setting
    # one clears the other; scope_preset:'' or tags:[] clears the scope.
    if 'scope_preset' in data or 'tags' in data:
        preset = (data.get('scope_preset') or '').strip()
        if preset and preset not in (cfg.get('scope_presets') or {}):
            return err('unknown scope preset: %s' % preset)
        if rec.get('role') == 'admin':
            preset = ''
        if preset:
            rec['scope_preset'] = preset
            rec['tags'] = []
        else:
            rec.pop('scope_preset', None)
            rec['tags'] = clean_scope_tags(data.get('tags')) if rec.get('role') != 'admin' else []
    cfg['users'][user] = rec
    save_config(cfg)
    g.audit_target = 'user:%s' % user
    return jsonify({'success': True})


@app.route('/api/users/<user>', methods=['DELETE'])
def users_delete(user):
    """Remove a controller login (admin). Can't delete yourself or the last admin."""
    cfg = load_config()
    users = cfg.get('users', {})
    if user not in users:
        return err('user not found', 404)
    if user == g.identity_name:
        return err('cannot delete your own account')
    admins = [u for u, r in users.items() if _user_role(r) == 'admin']
    if _user_role(users[user]) == 'admin' and len(admins) <= 1:
        return err('cannot delete the last admin')
    del users[user]
    save_config(cfg)
    g.audit_target = 'user:%s (deleted)' % user
    return jsonify({'success': True})


# ─── Scope presets: named tag groupings ("roles") for user scoping ────
@app.route('/api/scope-presets')
def scope_presets_list():
    return jsonify({'presets': _scope_presets()})


@app.route('/api/scope-presets', methods=['POST'])
def scope_presets_save():
    """Create or update one named preset (admin). Users referencing it by
    name re-scope immediately — presets resolve at request time."""
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not RE_USERNAME.match(name):
        return err('preset name must be 1–32 chars: letters, digits, . _ -')
    tags = clean_scope_tags(data.get('tags'))
    if not tags:
        return err('a preset needs at least one tag')
    cfg = load_config()
    cfg.setdefault('scope_presets', {})[name] = tags
    save_config(cfg)
    g.audit_target = 'scope-preset:%s = %s' % (name, ','.join(tags))
    return jsonify({'success': True})


@app.route('/api/scope-presets/<name>', methods=['DELETE'])
def scope_presets_delete(name):
    """Remove a preset (admin) — refused while any login references it, so a
    scoped account can never silently lose (or gain) access."""
    cfg = load_config()
    presets = cfg.get('scope_presets') or {}
    if name not in presets:
        return err('preset not found', 404)
    holders = [u for u, r in cfg.get('users', {}).items()
               if isinstance(r, dict) and r.get('scope_preset') == name]
    if holders:
        return err('preset is in use by: %s' % ', '.join(sorted(holders)))
    del presets[name]
    save_config(cfg)
    g.audit_target = 'scope-preset:%s (deleted)' % name
    return jsonify({'success': True})


# ─── Routes: node registry (enrollment) ───────────────────────────────
@app.route('/api/nodes')
def nodes_list():
    return jsonify({'nodes': [_public_node(n) for n in load_nodes().get('nodes', [])
                              if scope_allows(_scope(), n)]})


@app.route('/api/host-types')
def host_types():
    """UI descriptors for every registered host type — the Add/Edit modals
    build their type dropdown + credential fields from this, so a new adapter
    module shows up in the UI with zero SPA changes."""
    return jsonify({'types': adapters.descriptors()})


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
        if 'pool_count' in m:          # NAS probe
            resp['metrics'] = {'pool_count': m.get('pool_count'),
                               'pools_degraded': m.get('pools_degraded'),
                               'disk_count': m.get('disk_count')}
        elif 'cluster_healthy' in m:   # sparkdash probe (snapshot)
            resp['metrics'] = {'node_count': m.get('node_count'),
                               'cluster_healthy': bool(m.get('cluster_healthy')),
                               'model': (m.get('vllm') or {}).get('model')}
        elif m.get('agent') == 'nexus-agent':   # bare-host agent probe
            resp['metrics'] = {'mount_count': len(m.get('mounts') or []),
                               'hostname': m.get('hostname'), 'os': m.get('os')}
        else:                          # virt probe
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
    manual_type = None
    if data.get('type') and data['type'] != 'auto':
        manual_type = clean_type(data['type'])
        if not manual_type:
            return err('invalid type')
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
    node['type'] = manual_type or type_auto
    node['type_auto'] = type_auto
    node['type_pinned'] = bool(manual_type)
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
            # 'auto' un-pins (effective type reverts to type_auto); any other
            # cleaned label pins the manual override — a custom label becomes
            # its own overview category.
            if data['type'] == 'auto':
                n['type_pinned'] = False
                n['type'] = n.get('type_auto', 'Unknown')
            else:
                label = clean_type(data['type'])
                if not label:
                    return err('invalid type')
                n['type'] = label
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


@app.route('/api/nodes/<node_id>/cert', methods=['GET'])
def node_cert(node_id):
    """Compare a node's pinned TLS fingerprint against the certificate it is
    serving *right now*. Admin-only. Lets an operator review a cert change
    out-of-band before deciding whether to re-pin. An http:// host has no
    certificate to pin."""
    n = _find_node(node_id)
    if not n:
        return err('node not found', 404)
    pinned = n.get('cert_fp')
    if not (n.get('base_url') or '').lower().startswith('https'):
        return jsonify({'scheme': 'http', 'pinned': pinned, 'observed': None,
                        'match': None, 'note': 'plain HTTP — no certificate to pin'})
    host, port = _split_host_port(n['base_url'])
    observed = error = None
    try:
        observed = cert_fingerprint(host, port)
    except Exception as e:
        error = str(e)
    return jsonify({
        'scheme': 'https', 'host': host, 'port': port,
        'pinned': pinned, 'observed': observed,
        'match': (observed == pinned) if (observed and pinned) else None,
        'error': error,
    })


@app.route('/api/nodes/<node_id>/repin', methods=['POST'])
def node_repin(node_id):
    """Accept a node's *current* TLS certificate as the new pin (TOFU re-trust).
    Admin-only. The client echoes back the fingerprint it just reviewed as
    `expected`; we re-capture the live cert and re-pin only if it still matches
    what the admin saw — so a certificate that flips again between review and
    click is rejected rather than blindly trusted."""
    data = request.get_json() or {}
    expected = (data.get('expected') or '').strip().lower().replace(':', '')
    reg = load_nodes()
    n = next((x for x in reg.get('nodes', []) if x.get('id') == node_id), None)
    if not n:
        return err('node not found', 404)
    if not (n.get('base_url') or '').lower().startswith('https'):
        return err('node uses plain HTTP — there is no certificate to pin', 400)
    host, port = _split_host_port(n['base_url'])
    try:
        observed = cert_fingerprint(host, port)
    except Exception as e:
        return err('cannot reach %s:%s to read its certificate (%s)' % (host, port, e), 502)
    if expected and observed != expected:
        return err('the certificate changed again since you reviewed it '
                   '(reviewed %s…, now serving %s…) — re-open and verify before re-pinning'
                   % (expected[:16], observed[:16]), 409)
    old = n.get('cert_fp')
    if observed == old:
        return jsonify({'success': True, 'cert_fp': observed, 'previous': old,
                        'unchanged': True, 'node': _public_node(n)})
    n['cert_fp'] = observed
    save_nodes(reg)
    with _fleet_lock:   # drop the cached error envelope so the row recovers now
        _fleet_cache['ts'] = 0.0
    adapters.evict_cache(node_id)  # clear any stale polled error envelope
    g.audit_target = '%s cert re-pin %s… → %s…' % (n['name'], (old or 'none')[:16], observed[:16])
    return jsonify({'success': True, 'cert_fp': observed, 'previous': old,
                    'node': _public_node(n)})


# ─── Fleet aggregation ────────────────────────────────────────────────
_fleet_cache = {'ts': 0.0, 'data': None}
_fleet_lock = threading.Lock()


# ─── Host adapters ────────────────────────────────────────────────────
# Per-host-type probe/fetch/drill-in lives in the adapters/ package — one
# self-describing module per host type (see adapters/__init__.py). Adding a
# host type = adding a module there; the enroll modal builds itself from
# /api/host-types.
def _virt_seed_cache(node, metrics):
    """Prime the poll cache from an enroll/edit probe's metrics so the row
    doesn't show 'awaiting first poll' until the next background cycle.
    No-op for live-fetched types (e.g. the bare-host agent) — they have no
    poll cache (and no envelope() on their adapter)."""
    adapter = _adapter_for(node)
    if not adapter.polled:
        return
    adapters.seed_cache(node['id'], adapter.envelope(node, metrics))


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
        nas = r.get('nas') or {}         # NAS hosts report alerts/pool health here
        n_alerts = len(s.get('alerts') or []) + (nas.get('alerts') or 0)
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
        i = r.get('instances') or {}     # nexus nodes running LXD (v2 Containers)
        vms += (i.get('vms') or 0) + (i.get('containers') or 0)
        containers += i.get('containers') or 0
        if n_alerts or down or zfs_bad or nas.get('pools_degraded') or r.get('stale'):
            degraded += 1
    return {'total': len(results), 'healthy': healthy, 'unreachable': unreachable,
            'alerts': alerts, 'degraded': degraded, 'services_down': svc_down,
            'storage_used': used, 'storage_size': size,
            'vms': vms, 'containers': containers}


def _version_tuple(v):
    """'2.0.0' → (2, 0, 0); tolerant of prefixes/suffixes; unknown → (0,)."""
    parts = re.findall(r'\d+', str(v or ''))
    return tuple(int(p) for p in parts[:3]) or (0,)


def flag_version_skew(results):
    """Mark nexus envelopes whose dashboard version trails the fleet's newest
    with version_lag = the newest version string. Pure → unit-tested. Virt/NAS
    hosts have vendor versions and are ignored."""
    nexus = [r for r in results
             if r.get('ok') and (r.get('host_type') or 'nexus') == 'nexus' and r.get('version')]
    if len(nexus) < 2:
        return results
    newest = max(nexus, key=lambda r: _version_tuple(r.get('version')))
    top = _version_tuple(newest.get('version'))
    for r in nexus:
        if _version_tuple(r.get('version')) < top:
            r['version_lag'] = newest.get('version')
    return results


# First-seen timestamps for active health conditions: (host_id, key) → iso ts.
_health_since = {}
_health_lock = threading.Lock()


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
    flag_version_skew(results)
    # Fold each host's warning+ conditions (failed services, degraded pools,
    # stale polls, alerts, unreachable — same set the notifier fires on) into
    # the envelope, with a first-seen timestamp per (host, condition) so the
    # Alerts tab can say "since when". The since-map is in-memory (resets on
    # restart) and shared with the monitor thread — guard it.
    now_iso = datetime.now().astimezone().isoformat(timespec='seconds')
    with _health_lock:
        live = set()
        for r in results:
            entries = monitoring.health_entries(r)
            for e in entries:
                k = (r['id'], e['key'])
                live.add(k)
                e['since'] = _health_since.setdefault(k, now_iso)
            if entries:
                r['health'] = entries
        ids = {r['id'] for r in results}
        for k in [k for k in _health_since if k[0] in ids and k not in live]:
            del _health_since[k]   # cleared → a re-fire gets a fresh timestamp
    results.sort(key=lambda r: r['name'].lower())
    return {'nodes': results, 'rollup': compute_rollup(results),
            'generated_at': datetime.now().astimezone().isoformat(timespec='seconds')}


def _refresh_fleet():
    """Build the fleet and store it in the shared cache. Used by the HTTP
    endpoint and the background monitor so both share one recent snapshot."""
    data = _build_fleet()
    with _fleet_lock:
        _fleet_cache['data'] = data
        _fleet_cache['ts'] = time.time()
    return data


@app.route('/api/fleet/summary')
def fleet_summary():
    fresh = request.args.get('fresh') in ('1', 'true', 'yes')
    # The cache is shared across users — filter a per-request copy to the
    # caller's tag scope (scoped accounts get their own rollup), never the
    # cache itself.
    with _fleet_lock:
        age = time.time() - _fleet_cache['ts']
        if not fresh and _fleet_cache['data'] is not None and age < FLEET_CACHE_TTL:
            return jsonify({**scoped_fleet(_fleet_cache['data'], _scope()),
                            'cached': True, 'cache_age': round(age, 1)})
    data = _refresh_fleet()
    return jsonify({**scoped_fleet(data, _scope()), 'cached': False, 'cache_age': 0})


# ─── Notifications: monitor state transitions, POST to webhooks ────────
# A background thread rebuilds the fleet every MONITOR_INTERVAL, diffs each
# host's alertable conditions (monitoring.host_conditions) against the last
# cycle, and posts state-transition events to the configured webhooks. Config
# (incl. webhook URLs, which carry tokens) lives in the 0600 auth file.
MONITOR_INTERVAL = int(os.environ.get('CONTROLLER_MONITOR_INTERVAL', '60'))
# A condition must persist this many cycles before it fires (rides out a single
# dropped poll); recovery notifies immediately.
FLAP_CYCLES = int(os.environ.get('CONTROLLER_FLAP_CYCLES', '2'))
# Don't re-fire the same (host, condition) within this window (flap guard).
NOTIFY_COOLDOWN = int(os.environ.get('CONTROLLER_NOTIFY_COOLDOWN', '1800'))
WEBHOOK_TIMEOUT = (5, 10)

_mon = {'present_streak': {}, 'active': set(), 'last_fire': {}, 'seeded': False}
_mon_lock = threading.Lock()


def notify_config():
    return load_config().get('notifications') or {'enabled': False, 'webhooks': []}


def _mask_url(url):
    """Show scheme://host/…path (hide query/tokens) for the config API."""
    try:
        from urllib.parse import urlparse
        u = urlparse(url)
        tail = u.path if len(u.path) <= 24 else u.path[:23] + '…'
        return f'{u.scheme}://{u.hostname}{tail}' + ('?…' if u.query else '')
    except Exception:
        return '(hidden)'


def _public_notify_config():
    cfg = notify_config()
    hooks = []
    for h in cfg.get('webhooks', []):
        hooks.append({'id': h.get('id'), 'name': h.get('name'),
                      'format': h.get('format', 'gchat'),
                      'min_severity': h.get('min_severity', 'warning'),
                      'url_display': _mask_url(h.get('url', ''))})
    return {'enabled': bool(cfg.get('enabled')), 'webhooks': hooks,
            'interval': MONITOR_INTERVAL}


def send_webhook(hook, title, text):
    """POST one event/digest to one webhook. Returns (ok, error)."""
    try:
        kw = monitoring.webhook_payload(hook.get('format'), title, text)
        r = requests.post(hook['url'], timeout=WEBHOOK_TIMEOUT, **kw)
        if r.status_code >= 300:
            return False, 'HTTP %d' % r.status_code
        return True, None
    except requests.RequestException as e:
        return False, str(e)


# Recent state-transition events (fired OR recovered, whether or not any
# webhook is configured) — answers "did anything happen overnight?" from the
# 🔔 Notify modal. In-memory ring: resets on controller restart.
_notify_events = deque(maxlen=100)


def _record_events(events):
    ts = datetime.now().astimezone().isoformat(timespec='seconds')
    for e in events:
        _notify_events.append({**e, 'ts': ts})


@app.route('/api/notifications/events')
def notifications_events():
    """Last ~100 monitor state transitions, newest first (admin)."""
    return jsonify({'events': list(_notify_events)[::-1],
                    'since_restart': True, 'interval': MONITOR_INTERVAL})


def _dispatch(events):
    """Send a batch of events to every enabled webhook that wants their
    severity. Grouped into one message per webhook."""
    cfg = notify_config()
    if not cfg.get('enabled') or not events:
        return
    for hook in cfg.get('webhooks', []):
        floor = monitoring.SEVERITY.get(hook.get('min_severity', 'warning'), 1)
        # recoveries always pass (so an all-clear isn't filtered out)
        want = [e for e in events
                if e['kind'] == 'recovered'
                or monitoring.SEVERITY.get(e['severity'], 3) <= floor]
        if not want:
            continue
        title, text = monitoring.format_digest(want)
        ok, err = send_webhook(hook, title, text)
        if not ok:
            print('notify: webhook %s failed: %s' % (hook.get('name'), err), flush=True)


def _monitor_cycle(results):
    """Diff this fan-out against the running state and dispatch transitions.
    Debounced: FLAP_CYCLES to fire, immediate recovery, per-key cooldown."""
    snap = monitoring.snapshot_conditions(results)
    present = {(hid, key) for hid, e in snap.items() for key in e['conditions']}
    now = time.time()
    fire, recover = [], []
    with _mon_lock:
        streak = _mon['present_streak']
        # advance streaks
        for pk in present:
            streak[pk] = streak.get(pk, 0) + 1
        for pk in list(streak):
            if pk not in present:
                del streak[pk]
        if not _mon['seeded']:
            # first cycle after (re)start: adopt current state silently
            _mon['active'] = set(present)
            for pk in present:
                _mon['last_fire'][pk] = now
            _mon['seeded'] = True
            return
        # fire: present, stable, not already active, cooldown elapsed
        for pk in present:
            if pk in _mon['active'] or streak.get(pk, 0) < FLAP_CYCLES:
                continue
            if now - _mon['last_fire'].get(pk, 0) < NOTIFY_COOLDOWN:
                continue
            hid, key = pk
            meta = snap[hid]['conditions'][key]
            fire.append({'host_id': hid, 'host': snap[hid]['name'], 'key': key,
                         'kind': 'firing', 'severity': meta['severity'], 'detail': meta['detail']})
            _mon['active'].add(pk)
            _mon['last_fire'][pk] = now
        # recover: was active, now absent
        for pk in list(_mon['active']):
            if pk not in present:
                hid, key = pk
                name = (snap.get(hid) or {}).get('name', hid)
                recover.append({'host_id': hid, 'host': name, 'key': key,
                                'kind': 'recovered', 'severity': 'info',
                                'detail': _COND_LABEL.get(key, key)})
                _mon['active'].discard(pk)
    _record_events(fire + recover)
    _dispatch(fire + recover)


_COND_LABEL = {'unreachable': 'reachable again', 'cert_changed': 'certificate re-pinned',
               'alerts': 'alerts cleared', 'pool_degraded': 'pools healthy',
               'cluster_unhealthy': 'cluster healthy', 'services_down': 'services back up',
               'stale': 'polling again', 'version_lag': 'version in sync'}


# ─── History store (lazy: importing app must not create a stray DB) ───
_history = None
_history_lock = threading.Lock()


def get_history():
    global _history
    if _history is None:
        with _history_lock:
            if _history is None:
                _history = history.HistoryStore(HISTORY_FILE, HISTORY_DAYS)
    return _history


def _monitor_loop():
    while True:
        try:
            data = _refresh_fleet()
            _monitor_cycle(data['nodes'])
            try:
                get_history().record(data['nodes'])
            except Exception as e:
                print('history: record failed: %s' % e, flush=True)
        except Exception as e:
            print('monitor: cycle failed: %s' % e, flush=True)
        time.sleep(MONITOR_INTERVAL)


@app.route('/api/history/spark')
def history_spark():
    """Compact recent CPU series per host for the Overview sparklines. One call
    returns every host: {host_id: [v, …]} downsampled to `buckets` points over
    the last `hours`."""
    hours = min(168, max(1, float(request.args.get('hours', 6))))
    buckets = min(60, max(4, int(request.args.get('buckets', 24))))
    metric = request.args.get('metric', 'cpu')
    hist = get_history()
    out = {}
    for n in load_nodes().get('nodes', []):
        if not scope_allows(_scope(), n):
            continue
        pts = hist.series(n['id'], hours, buckets, metric)
        if pts:
            out[n['id']] = [round(v, 1) if v is not None else None for _, v in pts]
    return jsonify({'hours': hours, 'metric': metric, 'spark': out})


@app.route('/api/history/summary')
def history_summary():
    """Per-host availability% + storage capacity forecast over `hours` (default
    7 days), plus a fleet storage forecast. Feeds the Storage tab."""
    hours = min(720, max(1, float(request.args.get('hours', 168))))
    hist = get_history()
    reg = load_nodes().get('nodes', [])
    seen = {}
    with _fleet_lock:
        data = _fleet_cache['data']
    for r in (data or {}).get('nodes', []):
        seen[r['id']] = r
    hosts = {}
    fleet_pts, fleet_size, fleet_used = {}, 0, 0
    for n in reg:
        if not scope_allows(_scope(), n):
            continue   # scoped accounts: their "fleet" forecast = their hosts
        hid = n['id']
        avail, nsamp = hist.availability(hid, hours)
        r = seen.get(hid) or {}
        size = int(r.get('size_bytes') or 0)
        used = int(r.get('used_bytes') or 0)
        fc = history.forecast_capacity(hist.storage_points(hid, hours), size, used) if size else None
        hosts[hid] = {'availability': avail, 'samples': nsamp, 'forecast': fc}
        for ts, u in hist.storage_points(hid, hours):
            fleet_pts[ts] = fleet_pts.get(ts, 0) + u
        fleet_size += size
        fleet_used += used
    fleet_fc = history.forecast_capacity(sorted(fleet_pts.items()), fleet_size, fleet_used) \
        if fleet_size else None
    return jsonify({'hours': hours, 'hosts': hosts, 'fleet': fleet_fc})


@app.route('/api/history/<host_id>')
def history_host(host_id):
    """Full CPU+mem series for one host (detail view)."""
    if not _find_node(host_id):
        return err('node not found', 404)
    hours = min(720, max(1, float(request.args.get('hours', 24))))
    buckets = min(200, max(4, int(request.args.get('buckets', 96))))
    hist = get_history()
    return jsonify({
        'host_id': host_id, 'hours': hours,
        'cpu': [{'ts': ts, 'v': v} for ts, v in hist.series(host_id, hours, buckets, 'cpu')],
        'mem': [{'ts': ts, 'v': v} for ts, v in hist.series(host_id, hours, buckets, 'mem')],
        'availability': hist.availability(host_id, hours)[0],
    })


def start_monitor():
    threading.Thread(target=_monitor_loop, daemon=True, name='monitor').start()


@app.route('/api/notifications')
def notifications_get():
    return jsonify(_public_notify_config())


@app.route('/api/notifications', methods=['POST'])
def notifications_save():
    """Replace notification config (admin). A webhook with a blank url keeps its
    stored URL (so the masked display can be re-saved without re-entering the
    token)."""
    data = request.get_json() or {}
    cfg = load_config()
    existing = {h.get('id'): h for h in (cfg.get('notifications') or {}).get('webhooks', [])}
    hooks = []
    for h in data.get('webhooks', []):
        hid = h.get('id') or secrets.token_hex(6)
        url = (h.get('url') or '').strip()
        if not url and hid in existing:
            url = existing[hid]['url']   # keep stored token
        if not url:
            continue
        fmt = h.get('format', 'gchat')
        sev = h.get('min_severity', 'warning')
        if sev not in monitoring.SEVERITY:
            sev = 'warning'
        hooks.append({'id': hid, 'name': (h.get('name') or 'webhook').strip(),
                      'url': url, 'format': fmt, 'min_severity': sev})
    cfg['notifications'] = {'enabled': bool(data.get('enabled')), 'webhooks': hooks}
    save_config(cfg)
    g.audit_target = 'notifications (%d webhook(s))' % len(hooks)
    return jsonify({'success': True, **_public_notify_config()})


@app.route('/api/notifications/test', methods=['POST'])
def notifications_test():
    """Send a test message to every configured webhook (admin)."""
    cfg = notify_config()
    hooks = cfg.get('webhooks', [])
    if not hooks:
        return err('no webhooks configured')
    results = []
    for h in hooks:
        ok, e = send_webhook(h, 'Nexus Controller',
                             '✅ Test notification — webhook *%s* is working.' % h.get('name'))
        results.append({'name': h.get('name'), 'ok': ok, 'error': e})
    g.audit_target = 'notifications-test'
    return jsonify({'success': True, 'results': results})


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
    tags = data.get('tags')
    if action not in FLEET_ACTIONS:
        return err('invalid action (start/stop/restart/enable/disable)')
    if not RE_SERVICE.match(service):
        return err('invalid service name')
    # A tag-scoped account can only ever reach its own hosts, whatever the
    # selector below says (explicit ids included).
    nodes = [n for n in load_nodes().get('nodes', []) if scope_allows(_scope(), n)]
    scope = 'all nodes'
    # Explicit node_ids win; else an optional tag set narrows the fan-out to
    # hosts bearing ANY of the given tags ("restart smbd on everything tagged
    # prod"). No selector = every node that has the service.
    if isinstance(node_ids, list) and node_ids:
        wanted = set(node_ids)
        nodes = [n for n in nodes if n['id'] in wanted]
        scope = '%d node(s)' % len(nodes)
    elif isinstance(tags, list) and tags:
        want = {str(t) for t in tags}
        nodes = [n for n in nodes if want & set(n.get('tags') or [])]
        scope = 'tag(s) ' + ','.join(sorted(want))
    if not nodes:
        return err('no matching nodes', 404)
    g.audit_target = 'fleet %s/%s [%s → %d node(s)]' % (service, action, scope, len(nodes))
    results = []
    with ThreadPoolExecutor(max_workers=FANOUT_WORKERS) as pool:
        futs = [pool.submit(_proxy_service_action, n, service, action) for n in nodes]
        for f in as_completed(futs):
            results.append(f.result())
    with _fleet_lock:  # force a fresh poll next time so the matrix reflects the change
        _fleet_cache['ts'] = 0.0
    results.sort(key=lambda r: r['name'].lower())
    ok = sum(1 for r in results if r['ok'])
    return jsonify({'service': service, 'action': action, 'scope': scope, 'ok': ok,
                    'failed': len(results) - ok, 'results': results})


VM_ACTIONS = {'start', 'stop', 'shutdown', 'reboot'}


@app.route('/api/nodes/<node_id>/vm/<vm_id>/<action>', methods=['POST'])
def vm_action(node_id, vm_id, action):
    """Guest (VM/CT) lifecycle action on a virtualization host — start / stop /
    shutdown / reboot. Operator+ (viewer is blocked upstream). Delegates to the
    host adapter (Proxmox/VMware), which re-verifies the pinned cert before the
    write. Best-effort power ops only; no create/destroy from the console."""
    if action not in VM_ACTIONS:
        return err('invalid action (start/stop/shutdown/reboot)')
    node = _find_node(node_id)
    if not node:
        return err('node not found', 404)
    adapter = _adapter_for(node)
    if not getattr(adapter, 'supports_write', False):
        return err('host type %r does not support guest actions' % node.get('host_type'), 400)
    try:
        task = adapter.vm_action(node, vm_id, action)
    except NodeError as e:
        return err(str(e), 502)
    except Exception as e:   # defense in depth: never 500 on a hypervisor hiccup
        return err('action failed: %s' % e, 502)
    with _fleet_lock:        # next poll reflects the new power state
        _fleet_cache['ts'] = 0.0
    adapters.evict_cache(node_id)
    g.audit_target = '%s guest %s → %s' % (node['name'], vm_id, action)
    return jsonify({'success': True, 'task': str(task), 'action': action})


# ─── Drill-in: reverse-proxy a node's own SPA + API ───────────────────
# Headers we must not pass straight through (the WSGI layer re-computes them).
_HOP_HEADERS = {'content-encoding', 'transfer-encoding', 'connection',
                'content-length', 'keep-alive', 'te', 'trailer', 'upgrade'}


def render_drillin_html(html, node_id):
    """Retarget the node's own index.html to run through the controller:
    inject a fetch-shim rewriting /api/* to the proxy, a WebSocket-shim
    rewriting /ws/* to the controller's ws bridge (the v2 node's Containers
    console is a websocket), and point static asset references at the
    controller's node-static proxy. Pure → unit-tested."""
    base = '/nodes/%s' % node_id
    html = html.replace('href="/static/', 'href="%s/static/' % base)
    html = html.replace('src="/static/', 'src="%s/static/' % base)
    shim = ('<script>(function(){var P="/api/nodes/%s/proxy/";'
            'var f=window.fetch;window.fetch=function(u,o){'
            'if(typeof u==="string"&&u.indexOf("/api/")===0){u=P+u.slice(5);}'
            'return f.call(this,u,o);};'
            # The node SPA builds ws URLs as (ws|wss)://<location.host>/ws/…,
            # which lands on the CONTROLLER's host — rewrite the path to the
            # per-node bridge. Also handle a bare "/ws/…" path.
            'var W=window.WebSocket,B="/nodes/%s/ws/";'
            'function r(u){if(typeof u!=="string")return u;'
            'var m=u.match(/^(wss?:\\/\\/[^\\/]+)\\/ws\\/(.*)$/);'
            'if(m)return m[1]+B+m[2];'
            'if(u.indexOf("/ws/")===0)return B+u.slice(4);return u;}'
            'window.WebSocket=function(u,p){return p===undefined?new W(r(u)):new W(r(u),p);};'
            'window.WebSocket.prototype=W.prototype;'
            '})();</script>') % (node_id, node_id)
    if '<head>' in html:
        return html.replace('<head>', '<head>' + shim, 1)
    return shim + html


@app.route('/nodes/<node_id>/')
def node_drillin(node_id):
    """Serve the node's own dashboard SPA, retargeted through this controller."""
    node = _find_node(node_id)
    if not node:
        return err('node not found', 404)
    try:
        r = NodeClient(node).raw_get('/')
    except NodeError as e:
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
        r = NodeClient(node).raw_get('/static/' + subpath)
    except NodeError as e:
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
    qs = request.query_string.decode()
    path = subpath + ('?' + qs if qs else '')
    headers = {}
    ct = request.headers.get('Content-Type')
    if ct:
        headers['Content-Type'] = ct
    body = request.get_data()
    try:
        resp = NodeClient(node).request(request.method, path, headers=headers,
                                        data=body if body else None,
                                        timeout=PROXY_TIMEOUT)
    except NodeError as e:
        return err('proxy to node failed: %s' % e, 502)
    out = [(k, v) for k, v in resp.headers.items() if k.lower() not in _HOP_HEADERS]
    return Response(resp.content, status=resp.status_code, headers=out)


# ─── Drill-in websocket bridge (node Containers console) ───────────────
sock = Sock(app)


def _pinned_ws_connect(node, path):
    """Open a websocket to the node with the enrolled bearer token, pinning the
    TLS cert in-handshake: we establish TLS ourselves, verify the fingerprint
    BEFORE any HTTP bytes (incl. the Authorization header) are sent, then hand
    the socket to websocket-client for the upgrade (ws:// skips its own wrap)."""
    import ssl as _ssl
    import hashlib as _hashlib
    import websocket as wsclient
    host, port = _split_host_port(node['base_url'])
    ctx = _ssl._create_unverified_context()
    raw = socket.create_connection((host, port), timeout=NODE_TIMEOUT[0])
    try:
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except OSError:
        raw.close()
        raise
    try:
        fp = _hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        if node.get('cert_fp') and fp != node['cert_fp']:
            raise NodeError('certificate fingerprint changed for %s:%s '
                            '(pinned %s…, saw %s…)'
                            % (host, port, node['cert_fp'][:16], fp[:16]))
        tls.settimeout(15)
        token = decrypt_secret(node.get('token_enc', '')) or ''
        ws = wsclient.create_connection(
            'ws://%s:%s%s' % (host, port, path), socket=tls,
            header=['Authorization: Bearer ' + token],
            enable_multithread=True, timeout=None)
    except Exception:
        tls.close()
        raise
    return ws


@sock.route('/nodes/<node_id>/ws/<path:subpath>')
def node_ws(ws, node_id, subpath):
    """Bridge a browser websocket (drill-in) to the node's websocket with the
    node's token attached server-side — the browser never sees it. The node
    still enforces its own auth/role on the connection (its console requires an
    admin token). require_login already authenticated the controller session."""
    node = _find_node(node_id)
    if not node:
        try:
            ws.send(json.dumps({'type': 'error', 'error': 'node not found'}))
        finally:
            ws.close()
        return
    qs = request.query_string.decode()
    path = '/ws/' + subpath + ('?' + qs if qs else '')
    try:
        upstream = _pinned_ws_connect(node, path)
    except Exception as e:
        try:
            ws.send(json.dumps({'type': 'error', 'error': 'bridge: %s' % e}))
        finally:
            ws.close()
        return
    audit_line('WS', request.path, '%s:%s' % (node['name'], path.split('?')[0]), 101)
    stop = threading.Event()

    def pump_node_to_browser():
        try:
            while not stop.is_set():
                data = upstream.recv()
                if data is None or data == '' or data == b'':
                    break
                ws.send(data)
        except Exception:
            pass
        finally:
            stop.set()
            try:
                ws.close()
            except Exception:
                pass

    t = threading.Thread(target=pump_node_to_browser, daemon=True)
    t.start()
    try:
        while not stop.is_set():
            msg = ws.receive(timeout=30)
            if msg is None:
                continue
            if isinstance(msg, str):
                upstream.send(msg)          # JSON control/stdin frames
            else:
                upstream.send_binary(msg)
    except Exception:
        pass
    finally:
        stop.set()
        for c in (upstream,):
            try:
                c.close()
            except Exception:
                pass
        try:
            ws.close()
        except Exception:
            pass


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
    if TLS_ENABLED:
        ensure_tls_cert()
    print(f'Nexus Controller v{APP_VERSION} on {"https" if TLS_ENABLED else "http"}://0.0.0.0:{PORT}', flush=True)
    try:
        from gunicorn.app.base import BaseApplication
    except ImportError:
        # Dev fallback: werkzeug's threaded server (fine locally; the container
        # and installer always have gunicorn from requirements.txt).
        start_virt_poller()
        start_monitor()
        app.run(host='0.0.0.0', port=PORT, threaded=True,
                ssl_context=(TLS_CERT, TLS_KEY) if TLS_ENABLED else None)
        return

    class Controller(BaseApplication):
        """Embedded gunicorn so `python app.py` stays the one entrypoint (the
        Dockerfile, systemd unit, and CLI subcommands are unchanged).
        MUST stay a single worker: the fleet/virt caches and the poller are
        in-process state. gthread worker = websocket-capable (flask-sock)."""

        def load_config(self):
            self.cfg.set('bind', '0.0.0.0:%d' % PORT)
            self.cfg.set('workers', 1)
            self.cfg.set('worker_class', 'gthread')
            self.cfg.set('threads', int(os.environ.get('CONTROLLER_THREADS', '16')))
            self.cfg.set('timeout', 120)
            self.cfg.set('accesslog', None)
            if TLS_ENABLED:
                self.cfg.set('certfile', TLS_CERT)
                self.cfg.set('keyfile', TLS_KEY)
            # Background threads must live in the WORKER process, not the master.
            def _post_fork(server, worker):
                start_virt_poller()
                start_monitor()
            self.cfg.set('post_fork', _post_fork)

        def load(self):
            return app

    Controller().run()


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
