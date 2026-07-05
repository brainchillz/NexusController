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
    down = {'ok': False, 'id': 'n1', 'name': 'silo', 'error': 'refused'}
    up = {'ok': True, 'id': 'n1', 'name': 'silo', 'summary': {}}
    prev = monitoring.snapshot_conditions([up])
    cur = monitoring.snapshot_conditions([down])
    ev = monitoring.diff_snapshots(prev, cur)
    assert len(ev) == 1 and ev[0]['kind'] == 'firing' and ev[0]['host'] == 'silo'
    ev2 = monitoring.diff_snapshots(cur, prev)
    assert ev2[0]['kind'] == 'recovered'


def test_diff_ignores_vanished_hosts():
    prev = monitoring.snapshot_conditions([{'ok': False, 'id': 'gone', 'name': 'x', 'error': 'e'}])
    assert monitoring.diff_snapshots(prev, {}) == []


def test_format_event():
    ev = {'host': 'silo', 'key': 'unreachable', 'kind': 'firing',
          'severity': 'critical', 'detail': 'host unreachable'}
    assert 'silo' in monitoring.format_event(ev) and 'unreachable' in monitoring.format_event(ev)


def test_webhook_payload_gchat_and_ntfy():
    p = monitoring.webhook_payload('gchat', 'T', 'body')
    assert p['json']['text'].startswith('*T*') and 'body' in p['json']['text']
    n = monitoring.webhook_payload('ntfy', 'T', 'body')
    assert n['data'] == b'body' and n['headers']['Title'] == 'T'
    g = monitoring.webhook_payload('gotify', 'T', 'body')
    assert g['json'] == {'title': 'T', 'message': 'body'}
