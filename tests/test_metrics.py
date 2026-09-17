"""v0.17.0 Prometheus exposition (metrics.py is pure) + the /metrics route."""
import app as A
import metrics as M
from tests.conftest import USER_PASSWORDS


def _env(**kw):
    base = {'id': 'n1', 'name': 'node1', 'host_type': 'nexus', 'type': 'Storage', 'ok': True,
            'resources': {'cpu_pct': 12.5, 'memory': {'pct': 40}}, 'used_bytes': 10, 'size_bytes': 100,
            'summary': {'alerts': ['x'], 'updates': {'available': 3, 'security': 1, 'reboot_required': True}},
            'health': [{'key': 'services_down', 'severity': 'warning', 'detail': 'd'}],
            'instances': {'total': 4, 'running': 3, 'vms': 1, 'containers': 3}}
    base.update(kw)
    return base


FLEET = {'generated_at': '2026-09-17T12:00:00+00:00',
         'rollup': {'healthy': 2, 'unreachable': 1, 'disabled': 1, 'degraded': 1,
                    'storage_used': 10, 'storage_size': 100},
         'nodes': [_env(),
                   _env(id='n2', name='vm "host"\\x', host_type='proxmox', type='Virtualization',
                        summary=None, health=[], instances=None,
                        virt={'vms': 5, 'vms_running': 4, 'containers': 2, 'containers_running': 2}),
                   _env(id='n3', name='down', ok=False, error='timed out', resources=None,
                        summary=None, health=[]),
                   _env(id='n4', name='paused', disabled=True, ok=False)]}


def _lines(text):
    return [l for l in text.splitlines() if l and not l.startswith('#')]


def test_label_escaping_and_number_formatting():
    assert M.line('m', {'a': 'q"b\\c\nd'}, 1) == 'm{a="q\\"b\\\\c\\nd"} 1'
    assert M.line('m', {}, 12.0) == 'm 12'
    assert M.line('m', {}, 12.5) == 'm 12.5'
    assert M.line('m', {}, True) == 'm 1'


def test_render_covers_fleet_hosts_and_shapes():
    text = M.render(FLEET, [], {}, {}, '9.9.9')
    L = _lines(text)
    assert 'nexus_controller_info{version="9.9.9"} 1' in L
    assert 'nexus_fleet_generated_timestamp_seconds 1789646400' in L
    assert 'nexus_fleet_hosts{state="paused"} 1' in L
    assert 'nexus_fleet_storage_bytes{kind="size"} 100' in L
    n1 = 'host="n1",name="node1",host_type="nexus",category="Storage"'
    assert 'nexus_host_up{%s} 1' % n1 in L
    assert 'nexus_host_cpu_percent{%s} 12.5' % n1 in L
    assert 'nexus_host_memory_percent{%s} 40' % n1 in L
    assert 'nexus_host_storage_bytes{%s,kind="used"} 10' % n1 in L
    assert 'nexus_host_alerts{%s} 1' % n1 in L
    assert 'nexus_host_health_issues{%s} 1' % n1 in L
    assert 'nexus_host_health_issue{%s,key="services_down",severity="warning"} 1' % n1 in L
    assert 'nexus_host_guests{%s,kind="container",state="total"} 3' % n1 in L
    assert 'nexus_host_guests{%s,kind="vm",state="running"} 3' % n1 in L   # LXD: one running total
    assert 'nexus_host_security_updates_pending{%s} 1' % n1 in L
    assert 'nexus_host_reboot_required{%s} 1' % n1 in L
    # proxmox: per-kind running counts; name with quote/backslash escaped
    n2 = 'host="n2",name="vm \\"host\\"\\\\x",host_type="proxmox",category="Virtualization"'
    assert 'nexus_host_guests{%s,kind="vm",state="running"} 4' % n2 in L
    assert 'nexus_host_guests{%s,kind="container",state="running"} 2' % n2 in L
    # a down host: up 0, no resource series, no health series
    n3 = 'host="n3",name="down",host_type="nexus",category="Storage"'
    assert 'nexus_host_up{%s} 0' % n3 in L
    assert not any(l.startswith('nexus_host_cpu_percent{%s}' % n3) for l in L)
    assert not any(l.startswith('nexus_host_health_issues{%s}' % n3) for l in L)
    # a paused host: paused 1 and NOTHING else (no up=0 to alert on)
    n4 = 'host="n4",name="paused",host_type="nexus",category="Storage"'
    assert 'nexus_host_paused{%s} 1' % n4 in L
    assert [l for l in L if n4 in l] == ['nexus_host_paused{%s} 1' % n4]
    assert text.endswith('\n')


def test_checks_are_exposed_only_once_probed():
    checks = [{'id': 'c1', 'name': 'ssh', 'service': 'ssh', 'target': '10.0.0.1', 'node_id': 'n1'},
              {'id': 'c2', 'name': 'dns', 'service': 'dns', 'target': 'ns1'},
              {'id': 'c3', 'name': 'pend', 'service': 'http', 'target': 'x'}]
    res = {'c1': {'ok': True, 'latency_ms': 12}, 'c2': {'ok': False, 'latency_ms': 2000, 'detail': 'refused'},
           'c3': {'ok': None}}
    L = _lines(M.render(None, checks, res, {'n1': 'node1'}, '1'))
    assert 'nexus_check_up{check="c1",name="ssh",service="ssh",target="10.0.0.1",host="node1"} 1' in L
    assert 'nexus_check_latency_seconds{check="c1",name="ssh",service="ssh",target="10.0.0.1",host="node1"} 0.012' in L
    assert 'nexus_check_up{check="c2",name="dns",service="dns",target="ns1",host=""} 0' in L
    assert not any('c3' in l for l in L)
    assert not any(l.startswith('nexus_fleet') for l in L)   # warming: no fleet series


def test_route_requires_a_login_and_serves_the_cache_only(real_users, monkeypatch):
    c = A.app.test_client()
    assert c.get('/metrics').status_code == 401
    calls = []
    monkeypatch.setattr(A, '_build_fleet', lambda: calls.append(1))
    c.post('/api/login', json={'username': 'op1', 'password': USER_PASSWORDS['op1']})
    r = c.get('/metrics')
    assert r.status_code == 200
    assert r.content_type.startswith('text/plain; version=0.0.4')
    assert r.headers['Cache-Control'] == 'no-store'
    assert 'nexus_controller_info{version="%s"} 1' % A.APP_VERSION in r.get_data(as_text=True)
    assert calls == [], 'a scrape must never trigger a fan-out'


def test_route_works_with_an_api_token_and_scopes_the_fleet(real_users, monkeypatch):
    c = A.app.test_client()
    c.post('/api/login', json={'username': 'view1', 'password': USER_PASSWORDS['view1']})
    tok = c.post('/api/tokens', json={'name': 'prometheus'}).get_json()['token']
    cfg = A.load_config(); cfg['users']['view1']['tags'] = ['lab']; A.save_config(cfg)
    monkeypatch.setattr(A, 'load_nodes', lambda: {'nodes': [
        {'id': 'n1', 'name': 'node1', 'tags': ['lab']}, {'id': 'n2', 'name': 'other', 'tags': ['prod']}]})
    with A._fleet_lock:
        A._fleet_cache['data'] = {'generated_at': FLEET['generated_at'],
                                  'rollup': FLEET['rollup'],
                                  'nodes': [_env(tags=['lab']), _env(id='n2', name='other', tags=['prod'])]}
        A._fleet_cache['ts'] = 0.0
    try:
        body = A.app.test_client().get('/metrics', headers={'Authorization': 'Bearer ' + tok}).get_data(as_text=True)
    finally:
        with A._fleet_lock:
            A._fleet_cache['data'] = None
    assert 'name="node1"' in body and 'name="other"' not in body
