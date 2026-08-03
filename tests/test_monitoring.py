"""Pure monitoring logic: condition extraction, snapshot diffing, formatting,
and webhook payload shaping."""
import monitoring


def test_host_conditions_healthy_is_empty():
    assert monitoring.host_conditions({'ok': True, 'summary': {}}) == {}


def test_host_conditions_unreachable():
    c = monitoring.host_conditions({'ok': False, 'error': 'Connection refused'})
    assert 'unreachable' in c and c['unreachable']['severity'] == 'critical'


def test_host_conditions_cert_change_distinct():
    c = monitoring.host_conditions({'ok': False, 'error': 'certificate fingerprint changed for x'})
    assert 'cert_changed' in c and 'unreachable' not in c


def test_host_conditions_awaiting_is_silent():
    assert monitoring.host_conditions({'ok': False, 'error': 'awaiting first poll'}) == {}


def test_host_conditions_nas_degraded_and_alerts():
    env = {'ok': True, 'summary': {}, 'nas': {'pools_degraded': 1, 'alerts': 2}}
    c = monitoring.host_conditions(env)
    assert c['pool_degraded']['severity'] == 'critical'
    assert c['alerts']['detail'].startswith('2')


def test_host_conditions_spark_unhealthy_and_version_lag():
    assert 'cluster_unhealthy' in monitoring.host_conditions(
        {'ok': True, 'spark': {'healthy': False}})
    assert 'version_lag' in monitoring.host_conditions(
        {'ok': True, 'version_lag': '2.0.0'})


def test_host_conditions_services_down():
    env = {'ok': True, 'summary': {'services': {
        'a': {'enabled': 'enabled', 'active': 'active'},
        'b': {'enabled': 'enabled', 'active': 'dead'}}}}
    assert monitoring.host_conditions(env)['services_down']['detail'].startswith('1')


def test_diff_fires_and_recovers():
    down = {'ok': False, 'id': 'n1', 'name': 'node1', 'error': 'refused'}
    up = {'ok': True, 'id': 'n1', 'name': 'node1', 'summary': {}}
    prev = monitoring.snapshot_conditions([up])
    cur = monitoring.snapshot_conditions([down])
    ev = monitoring.diff_snapshots(prev, cur)
    assert len(ev) == 1 and ev[0]['kind'] == 'firing' and ev[0]['host'] == 'node1'
    ev2 = monitoring.diff_snapshots(cur, prev)
    assert ev2[0]['kind'] == 'recovered'


def test_diff_ignores_vanished_hosts():
    prev = monitoring.snapshot_conditions([{'ok': False, 'id': 'gone', 'name': 'x', 'error': 'e'}])
    assert monitoring.diff_snapshots(prev, {}) == []


def test_format_event():
    ev = {'host': 'node1', 'key': 'unreachable', 'kind': 'firing',
          'severity': 'critical', 'detail': 'host unreachable'}
    assert 'node1' in monitoring.format_event(ev) and 'unreachable' in monitoring.format_event(ev)


def test_webhook_payload_gchat_and_ntfy():
    p = monitoring.webhook_payload('gchat', 'T', 'body')
    assert p['json']['text'].startswith('*T*') and 'body' in p['json']['text']
    n = monitoring.webhook_payload('ntfy', 'T', 'body')
    assert n['data'] == b'body' and n['headers']['Title'] == 'T'
    g = monitoring.webhook_payload('gotify', 'T', 'body')
    assert g['json'] == {'title': 'T', 'message': 'body'}


# ── health_entries (drives the overview status dot + Alerts tab) ─────
def test_health_entries_folds_services_and_pools():
    env = {'ok': True, 'summary': {
        'services': {'smbd': {'enabled': 'enabled', 'active': 'inactive'}},
        'zfs': {'pools': 2, 'online': False}}}
    entries = monitoring.health_entries(env)
    keys = {e['key'] for e in entries}
    assert 'services_down' in keys and 'pool_degraded' in keys
    assert all(e['severity'] in ('warning', 'critical') and e['detail'] for e in entries)


def test_health_entries_excludes_info_level():
    # version_lag is info — it tints the version text, not the dot.
    env = {'ok': True, 'summary': {}, 'version_lag': '2.1.0'}
    assert monitoring.health_entries(env) == []


def test_health_entries_healthy_is_empty():
    env = {'ok': True, 'summary': {
        'services': {'smbd': {'enabled': 'enabled', 'active': 'active'}},
        'zfs': {'pools': 1, 'online': True}}}
    assert monitoring.health_entries(env) == []


def test_health_entries_covers_unreachable_hosts():
    entries = monitoring.health_entries({'ok': False, 'error': 'Connection refused'})
    assert entries and entries[0]['key'] == 'unreachable'


def test_host_conditions_disabled_is_silent():
    # A paused (monitoring-disabled) host reports NOTHING — even unreachable
    # or degraded states are suppressed until it's re-enabled.
    assert monitoring.host_conditions(
        {'ok': False, 'disabled': True, 'error': 'monitoring disabled'}) == {}
    env = {'ok': True, 'disabled': True, 'summary': {'alerts': ['a']},
           'nas': {'pools_degraded': 1}}
    assert monitoring.host_conditions(env) == {}
    assert monitoring.health_entries(env) == []


# ── public wallboard state ───────────────────────────────────────────
def test_board_state_grey_red_green():
    assert monitoring.board_state({'disabled': True, 'ok': False}) == ('grey', [])
    s, issues = monitoring.board_state({'ok': False, 'error': 'no route to host'})
    assert s == 'red' and issues == ['no route to host']
    s, issues = monitoring.board_state(
        {'ok': True, 'health': [{'key': 'alerts', 'severity': 'warning', 'detail': '2 active alert(s)'}]})
    assert s == 'red' and issues == ['2 active alert(s)']
    assert monitoring.board_state({'ok': True, 'summary': {}})[0] == 'green'


def test_board_state_amber_resources():
    env = {'ok': True, 'summary': {}, 'resources': {'cpu_pct': 97, 'memory': {'pct': 50}}}
    s, issues = monitoring.board_state(env)
    assert s == 'amber' and 'high CPU (97%)' in issues
    env = {'ok': True, 'summary': {}, 'resources': {'memory': {'pct': 95}}}
    assert monitoring.board_state(env)[0] == 'amber'
    env = {'ok': True, 'summary': {}, 'used_bytes': 95, 'size_bytes': 100}
    s, issues = monitoring.board_state(env)
    assert s == 'amber' and issues == ['storage 95% full']


def test_board_state_memory_exemptions():
    # AI hosts, ZFS hosts, and TrueNAS keep memory pinned by design — high
    # memory alone must not amber them.
    mem = {'resources': {'memory': {'pct': 95}}}
    assert monitoring.board_state({'ok': True, 'type': 'AI', 'summary': {}, **mem})[0] == 'green'
    assert monitoring.board_state(
        {'ok': True, 'summary': {'zfs': {'pools': 2}}, **mem})[0] == 'green'
    assert monitoring.board_state(
        {'ok': True, 'host_type': 'truenas', 'summary': {}, **mem})[0] == 'green'
    # …but CPU still ambers them
    env = {'ok': True, 'type': 'AI', 'summary': {},
           'resources': {'cpu_pct': 99, 'memory': {'pct': 95}}}
    s, issues = monitoring.board_state(env)
    assert s == 'amber' and issues == ['high CPU (99%)']


def test_board_state_warmup_is_amber_not_red():
    s, issues = monitoring.board_state({'ok': False, 'error': 'awaiting first poll'})
    assert s == 'amber' and issues == ['awaiting first poll']
