"""v0.21.0 certificate expiry warnings: pure condition math, the sweep with a
stub fetcher, the fold into envelopes, the controller's own cert entity."""
from datetime import datetime, timezone, timedelta

import app as A
import monitoring as M

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def _iso(days):
    return (NOW + timedelta(days=days)).isoformat()


def test_cert_days_left():
    assert M.cert_days_left(_iso(10), NOW) == 10
    assert M.cert_days_left(_iso(-3), NOW) == -3
    assert M.cert_days_left('2026-10-01T00:00:00Z', NOW) == 13
    assert M.cert_days_left('2026-10-01T00:00:00', NOW) == 13      # naive → UTC
    assert M.cert_days_left(None, NOW) is None and M.cert_days_left('nope', NOW) is None


def test_cert_condition_thresholds():
    assert M.cert_condition(_iso(60), NOW) is None
    assert M.cert_condition(_iso(30), NOW)['severity'] == 'info'
    assert M.cert_condition(_iso(15), NOW)['severity'] == 'info'
    c = M.cert_condition(_iso(14), NOW)
    assert c['severity'] == 'warning' and c['detail'].startswith('TLS certificate expires in 14 day(s) (2026-10-01)')
    c = M.cert_condition(_iso(-2), NOW)
    assert c['severity'] == 'warning' and 'expired 2 day(s) ago' in c['detail']
    assert M.cert_condition(None, NOW) is None


def test_host_conditions_carry_cert_expiring():
    env = {'ok': True, 'summary': {}, 'cert_not_after': _iso(5), '_now': NOW}
    c = M.host_conditions(env)
    assert c['cert_expiring']['severity'] == 'warning'
    assert [e['key'] for e in M.health_entries(env)] == ['cert_expiring']      # warning → dot
    env['cert_not_after'] = _iso(20)
    assert M.host_conditions(env)['cert_expiring']['severity'] == 'info'
    assert M.health_entries(env) == []                                            # info → no dot
    env['ok'] = False; env['error'] = 'down'
    assert 'cert_expiring' not in M.host_conditions(env)                          # a down host: outage only


def test_sweep_uses_the_fetcher_keeps_last_value_and_forgets_removed(monkeypatch):
    calls = []
    def fetch(host, port):
        calls.append((host, port))
        if host == 'bad':
            raise OSError('refused')
        return _iso(100)
    nodes = [{'id': 'a', 'base_url': 'https://a:8443'}, {'id': 'b', 'base_url': 'https://bad:443'},
             {'id': 'c', 'base_url': 'http://plain'}, {'id': 'd', 'base_url': 'https://d', 'disabled': True}]
    with A._cert_expiry_lock:
        A._cert_expiry_cache.clear()
        A._cert_expiry_cache['b'] = {'not_after': _iso(3), 'checked': 1}
        A._cert_expiry_cache['ghost'] = {'not_after': _iso(3), 'checked': 1}
    done = A._sweep_cert_expiry(nodes, fetch=fetch, now=123)
    assert done == ['a']
    assert sorted(calls) == [('a', 8443), ('bad', 443)]       # http + paused hosts skipped
    assert A._cert_expiry_cache['a'] == {'not_after': _iso(100), 'checked': 123}
    assert A._cert_expiry_cache['b']['not_after'] == _iso(3)         # unreadable → last value kept
    assert 'ghost' not in A._cert_expiry_cache


def test_fleet_build_stamps_cert_not_after(monkeypatch):
    monkeypatch.setattr(A, '_attach_svc_checks', lambda r: None)
    with A._cert_expiry_lock:
        A._cert_expiry_cache.clear()
        A._cert_expiry_cache['h1'] = {'not_after': _iso(5), 'checked': 1}
        A._cert_expiry_cache['h2'] = {'not_after': _iso(5), 'checked': 1}
    envs = [{'id': 'h1', 'name': 'a', 'ok': True, 'resources': {}, 'summary': {}},
            {'id': 'h2', 'name': 'b', 'ok': False, 'disabled': True, 'error': 'monitoring disabled'}]
    data = A._build_fleet_finish(envs)
    by = {n['id']: n for n in data['nodes']}
    assert by['h1']['cert_not_after'] == _iso(5)
    assert [e['key'] for e in by['h1']['health']] == ['cert_expiring']
    assert 'cert_not_after' not in by['h2'] and 'health' not in by['h2']   # paused: nothing
    with A._cert_expiry_lock:
        A._cert_expiry_cache.clear()


def test_leaf_not_after_reads_a_real_cert(tmp_path, monkeypatch):
    """Round-trip against the controller's own generated cert."""
    import ssl, socket, threading
    monkeypatch.setattr(A, 'TLS_DIR', str(tmp_path)); monkeypatch.setattr(A, 'TLS_CERT', str(tmp_path / 'c.crt'))
    monkeypatch.setattr(A, 'TLS_KEY', str(tmp_path / 'c.key'))
    A.generate_self_signed()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(str(tmp_path / 'c.crt'), str(tmp_path / 'c.key'))
    srv = socket.socket(); srv.bind(('127.0.0.1', 0)); srv.listen(1); port = srv.getsockname()[1]
    def serve():
        try:
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as ss:
                ss.recv(1)
        except Exception:
            pass
    t = threading.Thread(target=serve, daemon=True); t.start()
    got = A._leaf_not_after('127.0.0.1', port)
    srv.close()
    assert got == A.cert_info(str(tmp_path / 'c.crt'))['not_after']
    assert A.cert_info(str(tmp_path / 'c.crt'))['days_left'] > 300


def test_controller_cert_entity(monkeypatch):
    monkeypatch.setattr(A, 'TLS_ENABLED', True)
    monkeypatch.setattr(A, 'cert_info', lambda cert_path=None: {'present': True, 'not_after': _iso(7)})
    envs = A._controller_cert_env()
    assert envs[0]['id'] == 'controller'
    assert M.host_conditions(envs[0])['cert_expiring']['severity'] == 'warning'
    monkeypatch.setattr(A, 'TLS_ENABLED', False)
    assert A._controller_cert_env() == []
    assert A._COND_LABEL['cert_expiring'] == 'certificate renewed'
