"""v0.19.0 acknowledge / snooze: quiet ONE condition on ONE host without
pausing the host. Pure helpers in monitoring.py; the fold into the fleet
build, the rollup, the notifier and the routes are exercised here."""
import time
import pytest

import app as A
import monitoring as M
from tests.conftest import USER_PASSWORDS

E = [{'key': 'alerts', 'severity': 'warning', 'detail': '1 active alert'},
     {'key': 'services_down', 'severity': 'warning', 'detail': '1 enabled service(s) not running'}]


@pytest.fixture(autouse=True)
def _clean_acks():
    A.save_acks({})
    yield
    A.save_acks({})


# ── pure ────────────────────────────────────────────────────────────────

def test_clean_ack_until_clears_or_snooze():
    rec, e = M.clean_ack({}, 'dave', now=1000)
    assert e is None and rec == {'by': 'dave', 'note': '', 'ts': 1000, 'until': None}
    rec, _ = M.clean_ack({'hours': '4', 'note': ' disk  on order '}, 'dave', now=1000)
    assert rec['until'] == 1000 + 4 * 3600 and rec['note'] == 'disk on order'
    assert M.clean_ack({'hours': 'soon'}, 'd')[1] == 'hours must be a number'
    assert 'between' in M.clean_ack({'hours': 99999}, 'd')[1]
    assert 'between' in M.clean_ack({'hours': -1}, 'd')[1]
    assert M.clean_ack({'hours': 0}, 'd')[0]['until'] is None


def test_split_acked_and_expiry():
    acks = {M.ack_key('h1', 'alerts'): {'by': 'd', 'until': None},
            M.ack_key('h1', 'services_down'): {'by': 'd', 'until': 500}}
    live, acked = M.split_acked(E, acks, 'h1', now=1000)
    assert [x['key'] for x in live] == ['services_down']      # snooze lapsed → live again
    assert [x['key'] for x in acked] == ['alerts'] and acked[0]['ack']['by'] == 'd'
    live, acked = M.split_acked(E, acks, 'h2', now=1000)      # another host: untouched
    assert len(live) == 2 and acked == []


def test_prune_acks_drops_resolved_and_expired():
    acks = {'h1|alerts': {'until': None}, 'h1|services_down': {'until': 500},
            'h2|unreachable': {'until': None}}
    gone = M.prune_acks(acks, {'h1|alerts', 'h1|services_down'}, now=1000)
    assert sorted(gone) == ['h1|services_down', 'h2|unreachable']
    assert list(acks) == ['h1|alerts']


def test_board_state_acked_outage_is_amber_not_red():
    env = {'ok': False, 'error': 'no route to host', 'health_acked': [{'key': 'unreachable'}]}
    assert M.board_state(env) == ('amber', ['acknowledged: no route to host'])
    env = {'ok': True, 'health_acked': [{'key': 'alerts'}], 'resources': {}}
    assert M.board_state(env)[0] == 'green'


# ── fleet build: acked entries leave health, ride as health_acked ───────

def _fleet_with(env, acks):
    A.save_acks(acks)
    return A._build_fleet_finish([env])


def test_build_folds_acks_and_rollup_follows(monkeypatch):
    monkeypatch.setattr(A, '_attach_svc_checks', lambda r: None)
    env = {'id': 'h1', 'name': 'node1', 'ok': True, 'resources': {},
           'summary': {'alerts': ['disk warm'], 'services': {'smb': {'enabled': 'enabled', 'active': 'inactive'}}}}
    data = _fleet_with(dict(env), {})
    r = data['nodes'][0]
    assert sorted(x['key'] for x in r['health']) == ['alerts', 'services_down']
    assert data['rollup']['degraded'] == 1
    data = _fleet_with(dict(env), {'h1|alerts': {'by': 'd', 'until': None}})
    r = data['nodes'][0]
    assert [x['key'] for x in r['health']] == ['services_down']
    assert [x['key'] for x in r['health_acked']] == ['alerts'] and r['health_acked'][0]['ack']['by'] == 'd'
    assert data['rollup']['degraded'] == 1
    data = _fleet_with(dict(env), {'h1|alerts': {'until': None}, 'h1|services_down': {'until': None}})
    r = data['nodes'][0]
    assert 'health' not in r and len(r['health_acked']) == 2
    assert data['rollup']['degraded'] == 0, 'everything acked → not degraded'


def test_rollup_legacy_envelopes_still_use_raw_signals():
    """compute_rollup on raw (pre-build) envelopes keeps the old logic."""
    assert A.compute_rollup([{'ok': True, 'summary': {'alerts': ['x']}}])['degraded'] == 1


# ── notifier: acking never fires 'recovered'; recurrence after clear fires ──

def _mon(monkeypatch, sent):
    monkeypatch.setattr(A, '_dispatch', lambda evs, *a: sent.extend(evs))
    monkeypatch.setattr(A, '_record_events', lambda evs: None)
    monkeypatch.setattr(A, 'tuning', lambda: {'flap_cycles': 1, 'monitor_interval': 60, 'check_timeout': 5})


def test_ack_is_silent_and_recurrence_alerts_again(monkeypatch):
    sent = []; _mon(monkeypatch, sent)
    with A._mon_lock:
        A._mon['active'] = {('h1', 'alerts')}
        A._mon['detail'] = {('h1', 'alerts'): 'disk warm'}
        A._mon['present_streak'] = {('h1', 'alerts'): 3}
        A._mon['last_fire'] = {('h1', 'alerts'): 0}
        A._mon['seeded'] = True
    firing = [{'id': 'h1', 'name': 'node1', 'ok': True, 'summary': {'alerts': ['disk warm']}}]
    A.save_acks({'h1|alerts': {'by': 'd', 'until': None, 'ts': 1}})
    A._monitor_cycle(firing)
    assert sent == [], 'acking must not fire recovered'
    assert ('h1', 'alerts') not in A._mon['active']
    A._monitor_cycle(firing)
    assert sent == [], 'still acked, still quiet'
    # the condition clears → the ack is pruned
    A._monitor_cycle([{'id': 'h1', 'name': 'node1', 'ok': True, 'summary': {'alerts': []}}])
    assert A.load_acks() == {}
    # …so a recurrence fires like new
    A._monitor_cycle(firing)
    assert [e['kind'] for e in sent] == ['firing']


def test_expired_snooze_fires_again(monkeypatch):
    sent = []; _mon(monkeypatch, sent)
    with A._mon_lock:
        A._mon['active'] = set(); A._mon['detail'] = {}; A._mon['present_streak'] = {}
        A._mon['last_fire'] = {}; A._mon['seeded'] = True
    firing = [{'id': 'h1', 'name': 'node1', 'ok': True, 'summary': {'alerts': ['disk warm']}}]
    A.save_acks({'h1|alerts': {'by': 'd', 'until': int(time.time()) - 1, 'ts': 1}})
    A._monitor_cycle(firing)
    assert A.load_acks() == {}
    assert [e['kind'] for e in sent] == ['firing']


# ── routes ───────────────────────────────────────────────────────────────

def _login(c, user):
    assert c.post('/api/login', json={'username': user, 'password': USER_PASSWORDS[user]}).status_code == 200
    return c


REG = {'nodes': [{'id': 'h1', 'name': 'node1', 'base_url': 'https://x', 'tags': ['lab']},
                 {'id': 'h2', 'name': 'node2', 'base_url': 'https://y', 'tags': ['prod']}]}


def test_ack_routes(real_users, monkeypatch, tmp_path):
    monkeypatch.setattr(A, 'load_nodes', lambda: REG)
    log = tmp_path / 'audit.log'; monkeypatch.setattr(A, 'AUDIT_FILE', str(log))
    v = _login(A.app.test_client(), 'view1')
    assert v.post('/api/acks', json={'host_id': 'h1', 'key': 'alerts'}).status_code == 403
    c = _login(A.app.test_client(), 'admin')   # operator
    assert c.post('/api/acks', json={'host_id': 'nope', 'key': 'alerts'}).status_code == 404
    assert c.post('/api/acks', json={'host_id': 'h1', 'key': 'Bad Key!'}).status_code == 400
    assert c.post('/api/acks', json={'host_id': 'h1', 'key': 'alerts', 'hours': 'x'}).status_code == 400
    r = c.post('/api/acks', json={'host_id': 'h1', 'key': 'alerts', 'hours': 4, 'note': 'disk on order'})
    assert r.status_code == 200 and r.get_json()['by'] == 'admin' and r.get_json()['until']
    lst = c.get('/api/acks').get_json()['acks']
    assert len(lst) == 1 and lst[0]['host'] == 'node1' and lst[0]['note'] == 'disk on order'
    assert 'node1 ack alerts for 4h' in log.read_text()
    assert v.get('/api/acks').status_code == 200   # viewers can read
    assert c.delete('/api/acks/h1/services_down').status_code == 404
    assert c.delete('/api/acks/h1/alerts').status_code == 200
    assert c.get('/api/acks').get_json()['acks'] == []
    assert 'node1 unack alerts' in log.read_text()


def test_acks_respect_tag_scope(real_users, monkeypatch):
    monkeypatch.setattr(A, 'load_nodes', lambda: REG)
    A.save_acks({'h1|alerts': {'by': 'x', 'until': None}, 'h2|alerts': {'by': 'x', 'until': None}})
    cfg = A.load_config(); cfg['users']['admin']['tags'] = ['lab']; A.save_config(cfg)
    c = _login(A.app.test_client(), 'admin')
    assert [a['host_id'] for a in c.get('/api/acks').get_json()['acks']] == ['h1']
    assert c.post('/api/acks', json={'host_id': 'h2', 'key': 'alerts'}).status_code == 404   # invisible
    assert c.delete('/api/acks/h2/alerts').status_code == 404


def test_deleting_a_host_drops_its_acks(real_users, monkeypatch):
    A.save_acks({'h1|alerts': {'until': None}, 'h2|alerts': {'until': None}})
    monkeypatch.setattr(A, 'load_nodes', lambda: {'nodes': [dict(n) for n in REG['nodes']]})
    monkeypatch.setattr(A, 'save_nodes', lambda d: None)
    c = _login(A.app.test_client(), 'op1')
    assert c.delete('/api/nodes/h1').status_code == 200
    assert list(A.load_acks()) == ['h2|alerts']
