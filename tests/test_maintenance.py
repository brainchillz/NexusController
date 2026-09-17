"""v0.20.0 scheduled maintenance windows: disabled_until on the host record,
validated on edit, expired by the fleet build so the host resumes itself."""
from datetime import datetime, timezone, timedelta

import app as A
from tests.conftest import USER_PASSWORDS

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def test_clean_until():
    ok, e = A.clean_until('2026-09-18T12:00:00Z', now=NOW)
    assert e is None and ok == '2026-09-18T12:00:00+00:00'
    ok, e = A.clean_until('2026-09-17T14:00:00', now=NOW)          # naive → UTC
    assert ok == '2026-09-17T14:00:00+00:00'
    ok, e = A.clean_until('2026-09-17T09:00:00-04:00', now=NOW)    # 13:00Z, future
    assert ok == '2026-09-17T13:00:00+00:00'
    assert A.clean_until('2026-09-17T11:00:00Z', now=NOW)[1] == 'disabled_until must be in the future'
    assert 'within' in A.clean_until('2027-01-01T00:00:00Z', now=NOW)[1]
    for bad in ('', None, 'tomorrow', 5):
        assert A.clean_until(bad, now=NOW)[1].startswith('disabled_until must be an ISO')


def test_expire_pauses():
    nodes = [{'id': 'a', 'name': 'a', 'disabled': True, 'disabled_until': '2026-09-17T11:59:00+00:00'},
             {'id': 'b', 'name': 'b', 'disabled': True, 'disabled_until': '2026-09-17T12:01:00+00:00'},
             {'id': 'c', 'name': 'c', 'disabled': True},                       # manual pause: never auto-resumes
             {'id': 'd', 'name': 'd', 'disabled': True, 'disabled_until': 'garbage'},
             {'id': 'e', 'name': 'e', 'disabled': False, 'disabled_until': '2026-09-17T11:00:00+00:00'}]
    assert A.expire_pauses(nodes, now=NOW) == ['a']
    assert nodes[0] == {'id': 'a', 'name': 'a', 'disabled': False, 'disabled_until': None}
    assert nodes[1]['disabled'] is True and nodes[2]['disabled'] is True and nodes[3]['disabled'] is True


def _login(c, user):
    assert c.post('/api/login', json={'username': user, 'password': USER_PASSWORDS[user]}).status_code == 200
    return c


def _reg(monkeypatch, nodes):
    store = {'nodes': nodes}
    monkeypatch.setattr(A, 'load_nodes', lambda: {'nodes': [dict(n) for n in store['nodes']]})
    monkeypatch.setattr(A, 'save_nodes', lambda d: store.update(d))
    return store


def test_edit_sets_and_clears_the_window(real_users, monkeypatch):
    store = _reg(monkeypatch, [{'id': 'h1', 'name': 'node1', 'base_url': 'https://x', 'tags': []}])
    c = _login(A.app.test_client(), 'op1')
    future = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
    r = c.put('/api/nodes/h1', json={'disabled': True, 'disabled_until': future})
    assert r.status_code == 200, r.get_json()
    n = store['nodes'][0]
    assert n['disabled'] is True and n['disabled_until'].endswith('+00:00')
    assert c.get('/api/nodes').get_json()['nodes'][0]['disabled_until'] == n['disabled_until']
    # a bad window is refused, the record untouched
    assert c.put('/api/nodes/h1', json={'disabled': True, 'disabled_until': 'yesterday'}).status_code == 400
    assert store['nodes'][0]['disabled_until'] == n['disabled_until']
    # a plain pause (no window) clears a previous window; resume clears it too
    assert c.put('/api/nodes/h1', json={'disabled': True}).status_code == 200
    assert store['nodes'][0]['disabled_until'] is None
    c.put('/api/nodes/h1', json={'disabled': True, 'disabled_until': future})
    assert c.put('/api/nodes/h1', json={'disabled': False}).status_code == 200
    assert store['nodes'][0] .get('disabled') is False and store['nodes'][0]['disabled_until'] is None
    # a window on a resume request is ignored (only meaningful when pausing)
    assert c.put('/api/nodes/h1', json={'disabled': False, 'disabled_until': future}).status_code == 200
    assert store['nodes'][0]['disabled_until'] is None


def test_fleet_build_resumes_an_expired_window_and_audits(monkeypatch, tmp_path):
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    store = _reg(monkeypatch, [
        {'id': 'h1', 'name': 'node1', 'base_url': 'https://x', 'disabled': True, 'disabled_until': past},
        {'id': 'h2', 'name': 'node2', 'base_url': 'https://y', 'disabled': True, 'disabled_until': future}])
    log = tmp_path / 'audit.log'; monkeypatch.setattr(A, 'AUDIT_FILE', str(log))
    monkeypatch.setattr(A, '_attach_svc_checks', lambda r: None)
    polled = []
    monkeypatch.setattr(A, '_fetch_one', lambda n: (polled.append(n['id']), {**A.adapters.base_envelope(n), 'ok': True})[1])
    data = A._build_fleet()
    assert polled == ['h1'], 'the resumed host is polled in the same cycle'
    assert store['nodes'][0]['disabled'] is False and store['nodes'][0]['disabled_until'] is None
    assert store['nodes'][1]['disabled'] is True
    by = {n['id']: n for n in data['nodes']}
    assert by['h1']['ok'] is True and by['h2']['disabled'] is True
    assert by['h2']['disabled_until'] == future
    assert 'node1 resumed (maintenance window ended)' in log.read_text()
