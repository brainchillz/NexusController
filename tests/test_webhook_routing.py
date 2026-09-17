"""v0.22.0 per-webhook host-tag routing (monitoring.hook_wants is pure; the
dispatcher, the save route and the public config are exercised)."""
import app as A
import monitoring as M
from tests.conftest import USER_PASSWORDS

TAGS = {'h1': ['prod', 'nas'], 'h2': ['lab']}


def ev(host_id, sev='warning', kind='firing'):
    return {'host_id': host_id, 'host': host_id, 'key': 'alerts', 'kind': kind, 'severity': sev, 'detail': 'd'}


def test_hook_wants_severity_then_tags():
    untagged = {'min_severity': 'warning'}
    prod = {'min_severity': 'warning', 'tags': ['prod']}
    assert M.hook_wants(untagged, ev('h1'), TAGS) and M.hook_wants(untagged, ev('h2'), TAGS)
    assert M.hook_wants(prod, ev('h1'), TAGS) and not M.hook_wants(prod, ev('h2'), TAGS)
    assert M.hook_wants({'tags': ['nas', 'lab']}, ev('h2'), TAGS)              # any-of
    assert not M.hook_wants(prod, ev('h1', sev='info'), TAGS)                  # floor first
    assert M.hook_wants(prod, ev('h1', sev='info', kind='recovered'), TAGS)    # recoveries pass the floor…
    assert not M.hook_wants(prod, ev('h2', kind='recovered'), TAGS)            # …but not the tag filter
    # entities without host tags (checks, the controller's cert) → untagged hooks only
    assert M.hook_wants(untagged, ev('check:x'), TAGS) and not M.hook_wants(prod, ev('check:x'), TAGS)
    assert M.hook_wants(prod, ev('h1'), None) is False and M.hook_wants({'tags': []}, ev('h1'), None)


def test_dispatch_routes_per_hook(monkeypatch):
    sent = []
    monkeypatch.setattr(A, 'notify_config', lambda: {'enabled': True, 'webhooks': [
        {'name': 'all', 'url': 'https://a', 'min_severity': 'warning', 'tags': []},
        {'name': 'prod-only', 'url': 'https://p', 'min_severity': 'warning', 'tags': ['prod']}]})
    monkeypatch.setattr(A, 'send_webhook', lambda hook, title, text: (sent.append((hook['name'], text)), (True, None))[1])
    A._dispatch([ev('h1'), ev('h2'), ev('check:c1')], TAGS)
    by = dict(sent)
    assert by['all'].count('*') == 6 and 'h2' in by['all'] and 'check:c1' in by['all']
    assert 'h1' in by['prod-only'] and 'h2' not in by['prod-only'] and 'check' not in by['prod-only']


def test_monitor_cycle_hands_host_tags_to_dispatch(monkeypatch):
    got = {}
    monkeypatch.setattr(A, '_dispatch', lambda evs, tags=None: got.update({'tags': tags}))
    monkeypatch.setattr(A, '_record_events', lambda evs: None)
    monkeypatch.setattr(A, 'tuning', lambda: {'flap_cycles': 1, 'monitor_interval': 60, 'check_timeout': 5})
    with A._mon_lock:
        A._mon['active'] = set(); A._mon['detail'] = {}; A._mon['present_streak'] = {}
        A._mon['last_fire'] = {}; A._mon['seeded'] = True
    A._monitor_cycle([{'id': 'h1', 'name': 'a', 'ok': False, 'error': 'down', 'tags': ['prod']},
                      {'id': 'check:c', 'name': 'check c', 'ok': True, 'summary': {}}])
    assert got['tags'] == {'h1': ['prod'], 'check:c': []}


def test_save_stores_cleaned_tags_and_config_returns_them(real_users):
    c = A.app.test_client()
    c.post('/api/login', json={'username': 'op1', 'password': USER_PASSWORDS['op1']})
    r = c.post('/api/notifications', json={'enabled': True, 'webhooks': [
        {'name': 'prod', 'url': 'https://hooks.example/x', 'format': 'slack', 'min_severity': 'warning',
         'tags': [' Prod ', 'nas', 'nas', '']},
        {'name': 'all', 'url': 'https://hooks.example/y', 'format': 'ntfy', 'tags': 'notalist'}]})
    assert r.status_code == 200, r.get_json()
    hooks = {h['name']: h for h in r.get_json()['webhooks']}
    assert hooks['prod']['tags'] == ['Prod', 'nas']          # case-sensitive, like scopes
    assert hooks['all']['tags'] == []
    assert 'url' not in hooks['prod']                        # masked as before
    stored = {h['name']: h for h in A.load_config()['notifications']['webhooks']}
    assert stored['prod']['tags'] == ['Prod', 'nas'] and stored['all']['tags'] == []
