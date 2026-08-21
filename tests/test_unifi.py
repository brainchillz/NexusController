"""The unifi host type: /api/overview → a network envelope.

Fixture values are synthetic — this ships publicly, so it must not carry a
snapshot of anyone's real network."""
import pytest

from adapters import ADAPTERS
from adapters.base import NodeError
from adapters.unifi import build_unifi_envelope

NODE = {'id': 'n1', 'name': 'UniFi Network', 'base_url': 'https://unifi.example.com',
        'host_type': 'unifi', 'type': 'Network'}

SNAP = {
    'generatedAt': 1786867127,
    'counts': {'clients': 40, 'wireless': 25, 'wired': 15,
               'devicesOnline': 5, 'devicesTotal': 6},
    'throughput': {'wanRxBps': 20_000_000, 'wanTxBps': 500_000,
                   'lanRxBps': 40_000_000, 'lanTxBps': 30_000_000},
    'wan': {'status': 'ok', 'latencyMs': 6, 'isp': 'Example ISP'},
    'subsystems': [{'name': 'wan', 'status': 'ok'}, {'name': 'lan', 'status': 'error'}],
    'issues': [
        {'severity': 'warning', 'kind': 'port_flapping', 'subject': 'aa:bb',
         'subjectName': 'Switch port 3', 'message': 'dropped link 209 times',
         'active': True, 'ackedAt': None, 'occurrences': 2},
        {'severity': 'critical', 'kind': 'gateway_down', 'subject': 'gw',
         'subjectName': 'Gateway', 'message': 'WAN down',
         'active': True, 'ackedAt': None, 'occurrences': 1},
        {'severity': 'info', 'kind': 'noise', 'subject': 'x', 'subjectName': 'X',
         'message': 'informational', 'active': True, 'ackedAt': None},
        # Must be filtered out: acknowledged, resolved/inactive, and muted.
        {'severity': 'critical', 'kind': 'old', 'subject': 'y', 'subjectName': 'Y',
         'message': 'already looked at', 'active': True, 'ackedAt': 123},
        {'severity': 'critical', 'kind': 'gone', 'subject': 'z', 'subjectName': 'Z',
         'message': 'resolved', 'active': False, 'ackedAt': None},
        {'severity': 'critical', 'kind': 'very_weak_signal', 'subject': 'w',
         'subjectName': 'W', 'message': 'muted at the source',
         'active': True, 'ackedAt': None, 'muted': True},
    ],
}


@pytest.fixture
def env():
    return build_unifi_envelope(dict(NODE), SNAP)


def test_boxes_the_overview_needs(env):
    n = env['network']
    assert (n['wan_rx_bps'], n['wan_tx_bps']) == (20_000_000, 500_000)
    assert (n['lan_rx_bps'], n['lan_tx_bps']) == (40_000_000, 30_000_000)
    assert (n['clients'], n['wireless'], n['wired']) == (40, 25, 15)
    assert n['latency_ms'] == 6
    assert env['ok'] is True
    assert env['type_auto'] == 'Network'


def test_only_active_unacknowledged_issues_count():
    """An acknowledged issue is one someone has already looked at, and a
    resolved one is history — neither should light up the box."""
    n = build_unifi_envelope(dict(NODE), SNAP)['network']
    assert n['critical'] == 1      # not 3: one acked, one inactive
    assert n['warning'] == 1
    assert n['info'] == 1
    msgs = [i['message'] for i in n['issues']]
    assert 'already looked at' not in msgs and 'resolved' not in msgs


def test_muted_issues_do_not_light_up_the_box():
    """Muting is per-kind in UnifiDash and gates its notifier. If a muted kind
    still became a node condition here, silencing it at the source would only
    move the noise onto our webhooks."""
    n = build_unifi_envelope(dict(NODE), SNAP)['network']
    assert n['critical'] == 1      # not 2: the muted one does not count
    assert 'muted at the source' not in [i['message'] for i in n['issues']]
    assert 'W: muted at the source' not in \
        (build_unifi_envelope(dict(NODE), SNAP).get('summary') or {}).get('alerts', [])


def test_muted_absent_means_not_muted():
    """UnifiDash builds older than the flag omit it entirely."""
    issues = [{'severity': 'critical', 'kind': 'device_offline', 'subject': 'd',
               'subjectName': 'Switch', 'message': 'offline',
               'active': True, 'ackedAt': None}]
    n = build_unifi_envelope(dict(NODE), dict(SNAP, issues=issues))['network']
    assert n['critical'] == 1


def test_issues_are_worst_first(env):
    """The tooltip shows the top of this list, so ordering is what decides
    whether the important one is visible."""
    assert [i['severity'] for i in env['network']['issues']] == \
        ['critical', 'warning', 'info']


def test_critical_issues_reach_the_fleet_rollup(env):
    alerts = (env['summary'] or {}).get('alerts') or []
    assert any('WAN down' in a for a in alerts)


def test_rollup_names_the_subject_not_its_mac():
    """`subject` is the detector's key — a MAC for a client. The rollup line is
    what lands in a webhook, and a MAC there has to be looked up before anyone
    can act on it."""
    issues = [{'severity': 'critical', 'kind': 'device_offline',
               'subject': 'aa:bb:cc:dd:ee:ff', 'subjectName': 'Workbench switch',
               'message': 'Offline', 'active': True, 'ackedAt': None}]
    env = build_unifi_envelope(dict(NODE), dict(SNAP, issues=issues))
    assert env['summary']['alerts'] == ['Workbench switch: Offline']


def test_rollup_falls_back_to_the_subject_when_unnamed():
    issues = [{'severity': 'critical', 'kind': 'device_offline',
               'subject': 'aa:bb:cc:dd:ee:ff', 'subjectName': None,
               'message': 'Offline', 'active': True, 'ackedAt': None}]
    env = build_unifi_envelope(dict(NODE), dict(SNAP, issues=issues))
    assert env['summary']['alerts'] == ['aa:bb:cc:dd:ee:ff: Offline']


def test_warnings_alone_do_not_raise_a_fleet_alert():
    """Warnings are shown in the box but must not make the host look unhealthy
    fleet-wide, or the overview cries wolf."""
    snap = dict(SNAP, issues=[i for i in SNAP['issues'] if i['severity'] != 'critical'])
    env = build_unifi_envelope(dict(NODE), snap)
    assert env['network']['warning'] == 1
    assert env['summary'] is None


def test_missing_sections_do_not_explode():
    env = build_unifi_envelope(dict(NODE), {})
    n = env['network']
    assert n['clients'] == 0 and n['wan_rx_bps'] == 0
    assert n['latency_ms'] is None and n['issues'] == []


def test_tooltip_payload_is_bounded():
    """The tooltip is a title attribute — it must not carry 200 issues."""
    many = [{'severity': 'warning', 'kind': 'k', 'subject': str(i),
             'subjectName': f'S{i}', 'message': 'm', 'active': True,
             'ackedAt': None} for i in range(200)]
    n = build_unifi_envelope(dict(NODE), dict(SNAP, issues=many))['network']
    assert len(n['issues']) == 12
    assert n['warning'] == 200          # the count is still the true total


def test_plain_http_is_refused():
    """Pinning is the trust model for this host type and there is nothing to
    pin over http — refuse rather than poll an unencrypted endpoint."""
    with pytest.raises(NodeError) as e:
        ADAPTERS['unifi'].probe('http://unifi.example.com:8088', {})
    assert 'https' in str(e.value).lower()


def test_native_url_points_at_unifidash():
    assert ADAPTERS['unifi'].native_url(NODE) == NODE['base_url']


def test_descriptor_is_ui_ready():
    d = ADAPTERS['unifi'].descriptor()
    assert d['kind'] == 'unifi' and d['auth'] == 'token'
    assert d['default_type'] == 'Network'
