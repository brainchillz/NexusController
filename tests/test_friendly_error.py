"""friendly_error: transport exceptions condense to a terse UI reason;
semantic messages other layers key off pass through verbatim."""
from adapters.base import friendly_error


REAL_NO_ROUTE = ("HTTPSConnectionPool(host='192.168.2.72', port=8443): "
                 "Max retries exceeded with url: /api/summary (Caused by "
                 "NewConnectionError('<urllib3.connection.HTTPSConnection "
                 "object at 0x7f>: Failed to establish a new connection: "
                 "[Errno 113] No route to host'))")


def test_no_route_wins_over_max_retries():
    assert friendly_error(REAL_NO_ROUTE) == 'no route to host'


def test_common_transport_reasons():
    assert friendly_error('… [Errno 111] Connection refused …') == 'connection refused'
    assert friendly_error('… Read timed out. (read timeout=8)') == 'timed out'
    assert friendly_error('… Failed to resolve host.example.com …') == 'DNS lookup failed'
    assert friendly_error('… SSLError(SSLCertVerificationError …') == 'TLS error'
    assert friendly_error('… Connection aborted, RemoteDisconnected …') == 'connection dropped'


def test_semantic_messages_pass_through():
    fp = 'certificate fingerprint changed for https://h (pinned abcd1234…)'
    assert friendly_error(fp) == fp
    assert friendly_error('awaiting first poll') == 'awaiting first poll'
    assert friendly_error('HTTP 503') == 'HTTP 503'


def test_unknown_long_message_is_truncated():
    msg = 'x' * 300
    out = friendly_error(msg)
    assert len(out) <= 120 and out.endswith('…')


def test_empty_and_exception_inputs():
    assert friendly_error('') == ''
    assert friendly_error(None) == ''
    assert friendly_error(OSError('[Errno 113] No route to host')) == 'no route to host'
