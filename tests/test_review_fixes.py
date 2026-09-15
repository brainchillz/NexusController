"""Pins for the v0.13.1 full-codebase review (2026-09-15). One test per defect
found; each names the failure it guards against, so a regression reads as a
sentence rather than a stack trace."""
import os
import re
import json
import threading

import pytest

import app as A
import adapters
from adapters.base import NodeError

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def as_role(client, monkeypatch):
    """Log the test client in as a given role without touching the store."""
    def _as(role, name='tester'):
        monkeypatch.setattr(A, '_resolve_identity', lambda: (name, role))
        monkeypatch.setattr(A, '_users', lambda: {name: {'role': role}})
        return client
    return _as


# ── unhandled exceptions answer JSON ──────────────────────────────────

def test_unhandled_exception_is_json_500(as_role, monkeypatch):
    c = as_role('admin')

    def boom():
        raise RuntimeError('kaboom')
    monkeypatch.setitem(A.app.view_functions, 'host_types', boom)
    r = c.get('/api/host-types')
    assert r.status_code == 500
    assert r.get_json() == {'success': False, 'error': 'Internal error: RuntimeError: kaboom'}


def test_http_exceptions_keep_their_own_body(as_role):
    r = as_role('admin').get('/no/such/route')
    assert r.status_code == 404


def test_junk_query_numbers_do_not_500(as_role):
    c = as_role('admin')
    assert c.get('/api/audit?limit=lots').status_code == 200
    assert c.get('/api/history/spark?hours=abc&buckets=-3').status_code == 200
    assert c.get('/api/history/summary?hours=%00').status_code == 200


# ── RBAC: the console bridge is a write ──────────────────────────────

def test_ws_bridge_endpoint_name_is_what_the_guard_checks():
    assert 'node_ws' in A.app.view_functions


# The bridge's URL rule is websocket-only (werkzeug matches it solely for an
# Upgrade: websocket request), so a plain GET 404s before the guard ever runs.
_WS = {'Upgrade': 'websocket', 'Connection': 'Upgrade'}


def test_viewer_cannot_open_the_console_bridge(as_role):
    r = as_role('viewer').get('/nodes/abc/ws/console/x', headers=_WS)
    assert r.status_code == 403
    assert 'console' in r.get_json()['error']


def test_operator_passes_the_bridge_guard(as_role):
    # There is no real socket under the test client, so the route itself
    # fails (a JSON 500 now) — anything but the guard's 403 proves the request
    # was let through to it.
    r = as_role('operator').get('/nodes/abc/ws/console/x', headers=_WS)
    assert r.status_code != 403


# ── registry read-modify-write is serialized ─────────────────────────

def test_registry_lock_covers_monitor_refresh_vs_enroll(monkeypatch):
    """The monitor's last_seen refresh reloads+saves the registry; an enroll
    landing between its load and save used to vanish. Both paths take
    _REG_LOCK now — prove the lock is real by holding it and watching the
    refresh block."""
    A.save_nodes({'nodes': [{'id': 'n1', 'name': 'one', 'base_url': 'https://x'}]})
    got = threading.Event()

    def refresh():
        with A._REG_LOCK:
            A._refresh_registry_from_results({'n1': {'ok': True, 'type_auto': 'Storage'}})
        got.set()
    with A._REG_LOCK:
        t = threading.Thread(target=refresh, daemon=True)
        t.start()
        assert not got.wait(0.3)          # blocked behind our lock
        # meanwhile an "enroll" lands under the same lock — never lost
        reg = A.load_nodes()
        reg['nodes'].append({'id': 'n2', 'name': 'two', 'base_url': 'https://y'})
        A.save_nodes(reg)
    assert got.wait(2)
    ids = [n['id'] for n in A.load_nodes()['nodes']]
    assert ids == ['n1', 'n2']
    assert A.load_nodes()['nodes'][0]['type'] == 'Storage'


def test_reg_and_cfg_locks_are_reentrant():
    with A._REG_LOCK:
        with A._REG_LOCK:
            pass
    with A._CFG_LOCK:
        with A._CFG_LOCK:
            pass


# ── delete cleans up everything the host owned ───────────────────────

def test_node_delete_evicts_cache_and_health_since(as_role):
    c = as_role('admin', 'admin')
    A.save_nodes({'nodes': [{'id': 'dead', 'name': 'gone', 'base_url': 'https://x',
                             'host_type': 'proxmox'}]})
    adapters.seed_cache('dead', {'id': 'dead'})
    with A._health_lock:
        A._health_since[('dead', 'unreachable')] = 'ts'
    with A._fleet_lock:
        A._fleet_cache['ts'] = 1e12
    r = c.delete('/api/nodes/dead')
    assert r.status_code == 200
    from adapters import virt
    assert 'dead' not in virt._cache
    assert ('dead', 'unreachable') not in A._health_since
    assert A._fleet_cache['ts'] == 0.0


def test_monitor_cycle_drops_a_deleted_host_without_a_recovery_event(monkeypatch):
    sent = []
    monkeypatch.setattr(A, '_dispatch', lambda evs: sent.extend(evs))
    monkeypatch.setattr(A, '_record_events', lambda evs: None)
    monkeypatch.setattr(A, 'tuning', lambda: {'flap_cycles': 1, 'monitor_interval': 60,
                                              'check_timeout': 5})
    with A._mon_lock:
        A._mon['active'] = {('h1', 'unreachable')}
        A._mon['detail'] = {('h1', 'unreachable'): 'no route to host'}
        A._mon['present_streak'] = {('h1', 'unreachable'): 3}
        A._mon['last_fire'] = {('h1', 'unreachable'): 0}
        A._mon['seeded'] = True
    # h1 is no longer in the fan-out at all (deleted) — not paused, not up
    A._monitor_cycle([{'id': 'h2', 'name': 'other', 'ok': True, 'summary': {}}])
    assert sent == []
    assert ('h1', 'unreachable') not in A._mon['active']
    assert ('h1', 'unreachable') not in A._mon['present_streak']


def test_health_since_forgets_a_removed_host(monkeypatch):
    monkeypatch.setattr(A, 'load_nodes', lambda: {'nodes': []})
    monkeypatch.setattr(A, '_attach_svc_checks', lambda r: None)
    with A._health_lock:
        A._health_since[('ghost', 'unreachable')] = 'ts'
    with A._REG_LOCK:
        A._build_fleet()
    assert ('ghost', 'unreachable') not in A._health_since


# ── fan-out never sinks the whole fleet ──────────────────────────────

def test_fetch_one_turns_a_raising_adapter_into_an_error_envelope(monkeypatch):
    class Bad:
        polled = False

        def fetch(self, node):
            raise KeyError('resources')
    monkeypatch.setattr(A, '_adapter_for', lambda n: Bad())
    env = A._fetch_one({'id': 'x', 'name': 'x', 'base_url': 'https://x'})
    assert env['ok'] is False and 'resources' in env['error']


def test_rollup_tolerates_null_byte_counts():
    r = A.compute_rollup([{'ok': True, 'used_bytes': None, 'size_bytes': None, 'summary': {}}])
    assert r['storage_used'] == 0 and r['storage_size'] == 0


def test_refresh_fleet_serves_a_fresh_snapshot_instead_of_rebuilding(monkeypatch):
    calls = []
    monkeypatch.setattr(A, '_build_fleet', lambda: (calls.append(1) or {'nodes': [], 'rollup': {}}))
    data, built = A._refresh_fleet()
    assert built and calls == [1]
    data2, built2 = A._refresh_fleet(max_age=60)
    assert not built2 and data2 is data and calls == [1]
    A._refresh_fleet(max_age=0)          # 0 = always stale
    assert calls == [1, 1]


# ── input handling ───────────────────────────────────────────────────

@pytest.mark.parametrize('rx,good,bad', [
    (A.RE_USERNAME, 'bob', 'bob\n'),
    (A.RE_SERVICE, 'smbd', 'smbd\n'),
])
def test_validators_reject_a_trailing_newline(rx, good, bad):
    assert rx.match(good) and not rx.match(bad)


def test_checks_target_rejects_trailing_newline():
    import checks
    assert checks._TARGET.match('10.0.0.1') and not checks._TARGET.match('10.0.0.1\n')


def test_proxmox_guest_id_rejects_trailing_newline():
    from adapters.proxmox import _GUEST_ID
    assert _GUEST_ID.match('qemu-pve-100') and not _GUEST_ID.match('qemu-pve-100\n')


def test_login_survives_non_string_fields(client):
    r = client.post('/api/login', json={'username': 12345, 'password': ['x']})
    assert r.status_code == 401     # not 500


def test_login_attempts_are_audited(client, tmp_path, monkeypatch):
    log = tmp_path / 'audit.log'
    monkeypatch.setattr(A, 'AUDIT_FILE', str(log))
    A._login_fails.clear()
    client.post('/api/login', json={'username': 'ghost', 'password': 'x'})
    entries = [json.loads(l) for l in log.read_text().splitlines()]
    assert entries and entries[-1]['target'] == 'login:ghost (failed)'
    assert entries[-1]['status'] == 401


def test_login_throttle_table_is_swept_when_large(monkeypatch):
    A._login_fails.clear()
    monkeypatch.setattr(A, 'LOGIN_WINDOW', 1)
    for i in range(5001):
        A._login_fails[('user', '10.0.0.%d' % (i % 250), 'u%d' % i)] = [0.0]
    A.login_failed('1.2.3.4', 'x', now=1000.0)
    assert len(A._login_fails) <= 2


def test_nodes_add_tags_string_is_not_split_into_characters(as_role, monkeypatch):
    c = as_role('admin', 'admin')
    monkeypatch.setattr(A, '_probe_host', lambda t, u, cr: {'cert_fp': 'ab' * 32, 'role': 'admin',
                                                            'version': '3.4.3', 'capabilities': []})
    monkeypatch.setattr(A, 'NodeClient', lambda n: (_ for _ in ()).throw(NodeError('no')))
    A.save_nodes({'nodes': []})
    r = c.post('/api/nodes', json={'name': 'n', 'base_url': 'https://h', 'token': 't',
                                   'tags': 'prod'})
    assert r.status_code == 200
    assert A.load_nodes()['nodes'][0]['tags'] == []
    r = c.post('/api/nodes', json={'name': 'n2', 'base_url': 'https://h2', 'token': 't',
                                   'tags': [' prod ', 'prod', 3]})
    assert A.load_nodes()['nodes'][1]['tags'] == ['prod', '3']


def test_node_update_probes_before_locking_and_keeps_edits(as_role, monkeypatch):
    c = as_role('admin', 'admin')
    A.save_nodes({'nodes': [{'id': 'e1', 'name': 'old', 'base_url': 'https://h', 'host_type': 'nexus',
                             'token_enc': '', 'type_auto': 'Storage', 'type': 'Storage'}]})
    probed = []

    def probe(t, u, cr):
        assert not A._REG_LOCK._is_owned()   # network I/O outside the lock
        probed.append(u)
        return {'cert_fp': 'cd' * 32, 'role': 'admin', 'version': '9', 'capabilities': ['zfs']}
    monkeypatch.setattr(A, '_probe_host', probe)
    r = c.put('/api/nodes/e1', json={'name': 'new', 'tags': ['a'], 'base_url': 'https://h2/',
                                     'type': 'auto', 'disabled': True})
    assert r.status_code == 200 and probed == ['https://h2']
    n = A.load_nodes()['nodes'][0]
    assert (n['name'], n['tags'], n['base_url'], n['disabled'], n['version'], n['type_pinned']) == \
        ('new', ['a'], 'https://h2', True, '9', False)


def test_users_add_duplicate_is_409(as_role):
    c = as_role('admin', 'admin')
    cfg = A.load_config(); cfg['users'] = {'admin': {'role': 'admin', 'password': 'x'}}
    A.save_config(cfg)
    r = c.post('/api/users', json={'username': 'admin', 'role': 'viewer', 'password': 'longenough'})
    assert r.status_code == 409


def test_notifications_save_ignores_malformed_hooks(as_role):
    c = as_role('admin', 'admin')
    r = c.post('/api/notifications', json={'enabled': True,
                                           'webhooks': ['junk', {'url': 'ftp://x'}, {'url': 7},
                                                        {'url': 'https://ok/hook', 'name': 5}]})
    assert r.status_code == 200
    hooks = A.load_config()['notifications']['webhooks']
    assert [h['url'] for h in hooks] == ['https://ok/hook'] and hooks[0]['name'] == '5'


# ── nodes that answer 200 with something other than JSON ─────────────

class _Resp:
    def __init__(self, code, text):
        self.status_code, self.text = code, text

    def json(self):
        return json.loads(self.text)


def test_probe_node_non_json_is_a_node_error(monkeypatch):
    from adapters import nexus
    monkeypatch.setattr(nexus, 'cert_fingerprint', lambda h, p: 'ab' * 32)
    monkeypatch.setattr(nexus, 'pinned_request', lambda *a, **k: _Resp(200, '<html>portal</html>'))
    with pytest.raises(NodeError, match='non-JSON'):
        nexus.probe_node('https://h', 't')
    monkeypatch.setattr(nexus, 'pinned_request', lambda *a, **k: _Resp(200, '[1,2]'))
    with pytest.raises(NodeError, match='shape'):
        nexus.probe_node('https://h', 't')


def test_get_json_non_json_is_a_node_error(monkeypatch):
    from adapters import base
    monkeypatch.setattr(base, 'pinned_request', lambda *a, **k: _Resp(200, 'nope'))
    client = base.NodeClient({'base_url': 'https://h', 'cert_fp': None})
    with pytest.raises(NodeError, match='non-JSON'):
        client.get_json('summary')


# ── collector session caches are keyed by credential ─────────────────

def test_collector_session_key_changes_with_the_password():
    from collectors import session_key
    a = session_key('https://nas', 'admin', 'old')
    b = session_key('https://nas', 'admin', 'new')
    assert a != b and a[0] == b[0] and 'old' not in repr(a)


def test_every_caching_collector_uses_the_credential_key():
    for name in ('synology', 'ugreen', 'omv', 'unraid'):
        src = open(os.path.join(REPO, 'collectors', name + '.py')).read()
        assert 'session_key(base, username, password)' in src, name
        assert '_sessions.get(base)' not in src and '_sessions[base]' not in src, name


# ── checks: UDP probes pick the address family ───────────────────────

def test_udp_socket_family_follows_the_target():
    import socket
    import checks
    s = checks._udp_socket('127.0.0.1', 53, 1)
    assert s.family == socket.AF_INET
    s.close()
    try:
        s6 = checks._udp_socket('::1', 53, 1)
    except OSError:
        pytest.skip('no IPv6 loopback here')
    assert s6.family == socket.AF_INET6
    s6.close()


# ── websocket bridge and plain-http nodes ────────────────────────────

def test_ws_bridge_only_wraps_tls_for_https_nodes():
    assert A._ws_is_tls({'base_url': 'https://h:8443'})
    assert not A._ws_is_tls({'base_url': 'http://agent:9143'})


# ── deploy files ship every module app.py imports ────────────────────

def _local_modules():
    """Top-level local modules reachable from app.py, transitively (sso.py
    pulls in ed25519.py)."""
    seen, todo = set(), ['app']
    while todo:
        m = todo.pop()
        src = open(os.path.join(REPO, m + '.py')).read()
        names = set(re.findall(r'^import (\w+)$', src, re.M)) | set(re.findall(r'^from (\w+) import', src, re.M))
        for n in names:
            if n not in seen and os.path.exists(os.path.join(REPO, n + '.py')):
                seen.add(n)
                todo.append(n)
    return sorted(seen)


def test_dockerfile_and_installer_ship_every_local_module():
    """sso.py shipped in the image but not the systemd installer — the
    installer's copy list is by hand and had drifted, so `import sso`
    failed on a fresh systemd install."""
    mods = _local_modules()
    assert 'sso' in mods and 'ed25519' in mods
    docker = open(os.path.join(REPO, 'Dockerfile')).read()
    installer = open(os.path.join(REPO, 'install.sh')).read()
    for m in mods:
        assert m + '.py' in docker, 'Dockerfile does not COPY %s.py' % m
        assert m + '.py' in installer, 'install.sh does not cp %s.py' % m


# ── SPA: no esc() inside a single-quoted JS string for free text ─────

def test_spa_uses_jsarg_for_names_in_onclick_handlers():
    html = open(os.path.join(REPO, 'templates', 'index.html')).read()
    assert 'function jsArg(v)' in html
    # names / service keys never go through the esc()-in-quotes construct
    leaks = re.findall(r"\\''\+esc\((?:n|c)\.name\)|\\''\+esc\(k\)\+'\\'", html)
    assert leaks == [], leaks
    for site in ('openRepin(', 'removeNode(', 'delCheck(', 'openSvc('):
        assert re.search(re.escape(site) + r"'\+jsArg\(", html), site
    assert 'hgroup-h">\'+esc(c)+' in html
