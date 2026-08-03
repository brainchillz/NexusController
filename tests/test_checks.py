"""Service checks: catalog integrity, definition validation, the prober
against live local sockets, and the app-side envelope folding."""
import socket
import threading

import checks
import monitoring
import app


# ── catalog ──────────────────────────────────────────────────────────
def test_catalog_integrity():
    ids = [s['id'] for s in checks.SERVICES]
    assert len(ids) == len(set(ids))
    for s in checks.SERVICES:
        assert s['kind'] in ('tcp', 'tls', 'http', 'https', 'dns', 'ntp')
        assert s['port'] is None or 1 <= s['port'] <= 65535
        assert s['label']
    assert checks.SERVICE_MAP['ssh']['port'] == 22


# ── clean_check validation ───────────────────────────────────────────
def test_clean_check_defaults_port_and_name():
    rec, e = checks.clean_check({'service': 'ssh', 'target': '192.168.1.5'})
    assert e is None
    assert rec['port'] == 22
    assert rec['name'] == 'SSH @ 192.168.1.5'
    assert rec['node_id'] is None


def test_clean_check_custom_port_pin_and_name():
    rec, e = checks.clean_check({'service': 'https', 'target': 'h.example.com',
                                 'port': '8443', 'node_id': 'abc', 'name': 'my web'})
    assert e is None
    assert rec['port'] == 8443 and rec['node_id'] == 'abc' and rec['name'] == 'my web'


def test_clean_check_rejects_bad_input():
    assert checks.clean_check({'service': 'nope', 'target': 'x'})[1]
    assert checks.clean_check({'service': 'ssh', 'target': ''})[1]
    assert checks.clean_check({'service': 'ssh', 'target': 'bad host!'})[1]
    assert checks.clean_check({'service': 'ssh', 'target': 'x', 'port': '0'})[1]
    assert checks.clean_check({'service': 'ssh', 'target': 'x', 'port': '70000'})[1]
    assert checks.clean_check({'service': 'ssh', 'target': 'x', 'port': 'abc'})[1]
    # the custom-TCP entry has no default port — one must be supplied
    assert checks.clean_check({'service': 'tcp', 'target': 'x'})[1]


# ── run_check against real local sockets ─────────────────────────────
def _banner_listener(banner):
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)

    def serve():
        try:
            c, _ = srv.accept()
            c.sendall(banner)
            c.close()
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_run_check_banner_match():
    srv, port = _banner_listener(b'SSH-2.0-TestServer\r\n')
    r = checks.run_check({'service': 'ssh', 'target': '127.0.0.1', 'port': port},
                         timeout=3)
    srv.close()
    assert r['ok'] is True
    assert 'SSH-2.0-TestServer' in r['detail']
    assert r['latency_ms'] >= 0


def test_run_check_banner_mismatch_is_down():
    srv, port = _banner_listener(b'HTTP/1.0 200 OK\r\n')
    r = checks.run_check({'service': 'ssh', 'target': '127.0.0.1', 'port': port},
                         timeout=3)
    srv.close()
    assert r['ok'] is False and 'unexpected reply' in r['detail']


def test_run_check_plain_tcp_open():
    srv, port = _banner_listener(b'')
    r = checks.run_check({'service': 'smb', 'target': '127.0.0.1', 'port': port},
                         timeout=3)
    srv.close()
    assert r['ok'] is True and r['detail'] == 'port open'


def test_run_check_connection_refused():
    # A fresh bound-then-closed port is reliably refused.
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    r = checks.run_check({'service': 'smb', 'target': '127.0.0.1', 'port': port},
                         timeout=3)
    assert r['ok'] is False and r['detail'] == 'connection refused'


def test_dns_query_wire_format():
    q = checks._dns_query()
    assert q[:2] == b'\x4e\x43'          # our query id
    assert b'\x07example\x03com\x00' in q


# ── monitoring: pinned-check failure is a host condition ─────────────
def test_host_conditions_check_failed():
    env = {'ok': True, 'summary': {}, 'svc_checks': [
        {'name': 'HTTP @ web', 'ok': False, 'detail': 'connection refused'},
        {'name': 'SSH @ web', 'ok': True},
        {'name': 'DNS @ web', 'ok': None}]}   # pending — not a failure
    c = monitoring.host_conditions(env)
    assert 'check_failed' in c and c['check_failed']['severity'] == 'warning'
    assert 'HTTP @ web' in c['check_failed']['detail']
    assert 'SSH' not in c['check_failed']['detail']


def test_host_conditions_no_checks_no_condition():
    assert 'check_failed' not in monitoring.host_conditions(
        {'ok': True, 'summary': {}, 'svc_checks': [{'name': 'x', 'ok': True}]})


# ── app-side folding ─────────────────────────────────────────────────
def test_attach_svc_checks_folds_into_envelope(monkeypatch):
    monkeypatch.setattr(app, 'load_checks', lambda: {'checks': [
        {'id': 'c1', 'name': 'Web', 'service': 'http', 'target': 'x', 'port': 80,
         'node_id': 'n1'}]})
    with app._check_lock:
        app._check_results['c1'] = {'ok': False, 'detail': 'connection refused',
                                    'latency_ms': 5, 'ts': 't'}
    try:
        envs = [{'id': 'n1', 'ok': True}, {'id': 'n2', 'ok': True}]
        app._attach_svc_checks(envs)
        assert envs[0]['svc_checks'][0]['ok'] is False
        assert 'svc_checks' not in envs[1]
        # a disabled host's pinned checks stay hidden with it
        denv = [{'id': 'n1', 'ok': False, 'disabled': True}]
        app._attach_svc_checks(denv)
        assert 'svc_checks' not in denv[0]
    finally:
        with app._check_lock:
            app._check_results.clear()


def test_check_monitor_envs_unpinned_only(monkeypatch):
    monkeypatch.setattr(app, 'load_checks', lambda: {'checks': [
        {'id': 'c1', 'name': 'Web', 'service': 'http', 'target': 'x', 'port': 80,
         'node_id': 'n1'},
        {'id': 'c2', 'name': 'DNS @ y', 'service': 'dns', 'target': 'y', 'port': 53,
         'node_id': None},
        {'id': 'c3', 'name': 'New', 'service': 'ssh', 'target': 'z', 'port': 22,
         'node_id': None}]})   # c3 has no result yet → excluded
    with app._check_lock:
        app._check_results.update({
            'c1': {'ok': False, 'detail': 'x', 'ts': 't'},
            'c2': {'ok': False, 'detail': 'timed out', 'ts': 't'}})
    try:
        envs = app._check_monitor_envs()
        assert [e['id'] for e in envs] == ['check:c2']
        assert envs[0]['ok'] is False and envs[0]['error'] == 'timed out'
        # its failure rides the standard unreachable condition
        assert 'unreachable' in monitoring.host_conditions(envs[0])
    finally:
        with app._check_lock:
            app._check_results.clear()


# ── public status endpoint ───────────────────────────────────────────
def test_api_status_is_public_and_minimal(client, monkeypatch):
    monkeypatch.setattr(app, 'load_checks', lambda: {'checks': [
        {'id': 'c9', 'name': 'DNS @ ns', 'service': 'dns', 'target': 'x',
         'port': 53, 'node_id': None}]})
    with app._check_lock:
        app._check_results['c9'] = {'ok': False, 'detail': 'timed out', 'ts': 't'}
    with app._fleet_lock:
        saved = app._fleet_cache['data']
        app._fleet_cache['data'] = {'nodes': [
            {'id': 'n1', 'name': 'node1', 'type': 'Storage', 'ok': True,
             'base_url': 'https://secret:9', 'summary': {}},
            {'id': 'n2', 'name': 'node2', 'ok': False, 'error': 'connection refused'}],
            'generated_at': 'T'}
    try:
        r = client.get('/api/status')   # NO login — must still be 200
        assert r.status_code == 200
        d = r.get_json()
        assert {h['name']: h['state'] for h in d['hosts']} == \
            {'node1': 'green', 'node2': 'red'}
        red = next(h for h in d['hosts'] if h['name'] == 'node2')
        assert red['issues'] == ['connection refused']
        assert d['checks'][0]['state'] == 'red' and d['checks'][0]['detail'] == 'timed out'
        # nothing sensitive leaks: no urls/ids/versions in the payload
        body = r.get_data(as_text=True)
        assert 'base_url' not in body and 'secret' not in body
    finally:
        with app._fleet_lock:
            app._fleet_cache['data'] = saved
        with app._check_lock:
            app._check_results.clear()
