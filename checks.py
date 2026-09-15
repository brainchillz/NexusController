"""Service checks: a catalog of well-known internet services + a socket-level
prober. The catalog and validation are pure (unit-tested); run_check() does
the actual network I/O — TCP connect (optionally exchanging a protocol
banner), TLS handshake, real HTTP GET, real DNS/SNTP query — under a hard
timeout, and never raises. app.py owns the store, the schedule (the monitor
loop), and the routes.

Unprivileged by design, like everything else here: no ICMP ping (raw sockets
need root) — reachability checks are per-service, which is what you actually
care about anyway.
"""
import re
import socket
import ssl
import struct
import time

from adapters.base import friendly_error

CHECK_TIMEOUT = 5

# The Add-check dropdown, in display order. `port` pre-populates the port box
# (editable); `kind` picks the probe: 'tcp' connect (optional `send` payload
# and/or `expect`ed reply prefix = a protocol-level liveness proof), 'tls'
# full handshake (no CA verification — self-signed certs everywhere), 'http'/
# 'https' a real GET (any HTTP status < 500 counts as up), 'dns' a real query
# (any well-formed response counts, even REFUSED), 'ntp' an SNTP exchange.
SERVICES = [
    {'id': 'http',      'label': 'HTTP',             'port': 80,    'kind': 'http'},
    {'id': 'https',     'label': 'HTTPS',            'port': 443,   'kind': 'https'},
    {'id': 'ssh',       'label': 'SSH',              'port': 22,    'kind': 'tcp', 'expect': 'SSH-'},
    {'id': 'dns',       'label': 'DNS',              'port': 53,    'kind': 'dns'},
    {'id': 'dot',       'label': 'DNS over TLS',     'port': 853,   'kind': 'tls'},
    {'id': 'ntp',       'label': 'NTP',              'port': 123,   'kind': 'ntp'},
    {'id': 'smtp',      'label': 'SMTP',             'port': 25,    'kind': 'tcp', 'expect': '220'},
    {'id': 'smtp-sub',  'label': 'SMTP submission',  'port': 587,   'kind': 'tcp', 'expect': '220'},
    {'id': 'smtps',     'label': 'SMTPS',            'port': 465,   'kind': 'tls'},
    {'id': 'imap',      'label': 'IMAP',             'port': 143,   'kind': 'tcp', 'expect': '* OK'},
    {'id': 'imaps',     'label': 'IMAPS',            'port': 993,   'kind': 'tls'},
    {'id': 'pop3',      'label': 'POP3',             'port': 110,   'kind': 'tcp', 'expect': '+OK'},
    {'id': 'pop3s',     'label': 'POP3S',            'port': 995,   'kind': 'tls'},
    {'id': 'ftp',       'label': 'FTP',              'port': 21,    'kind': 'tcp', 'expect': '220'},
    {'id': 'smb',       'label': 'SMB / CIFS',       'port': 445,   'kind': 'tcp'},
    {'id': 'nfs',       'label': 'NFS',              'port': 2049,  'kind': 'tcp'},
    {'id': 'dlna',      'label': 'DLNA / miniDLNA',  'port': 8200,  'kind': 'http'},
    {'id': 'iscsi',     'label': 'iSCSI',            'port': 3260,  'kind': 'tcp'},
    {'id': 'rdp',       'label': 'RDP',              'port': 3389,  'kind': 'tcp'},
    {'id': 'vnc',       'label': 'VNC',              'port': 5900,  'kind': 'tcp', 'expect': 'RFB'},
    {'id': 'telnet',    'label': 'Telnet',           'port': 23,    'kind': 'tcp'},
    {'id': 'mysql',     'label': 'MySQL / MariaDB',  'port': 3306,  'kind': 'tcp'},
    {'id': 'postgres',  'label': 'PostgreSQL',       'port': 5432,  'kind': 'tcp'},
    {'id': 'mssql',     'label': 'SQL Server',       'port': 1433,  'kind': 'tcp'},
    {'id': 'mongodb',   'label': 'MongoDB',          'port': 27017, 'kind': 'tcp'},
    {'id': 'redis',     'label': 'Redis',            'port': 6379,  'kind': 'tcp',
     'send': 'PING\r\n', 'expect': '+PONG'},
    {'id': 'memcached', 'label': 'Memcached',        'port': 11211, 'kind': 'tcp',
     'send': 'version\r\n', 'expect': 'VERSION'},
    {'id': 'ldap',      'label': 'LDAP',             'port': 389,   'kind': 'tcp'},
    {'id': 'ldaps',     'label': 'LDAPS',            'port': 636,   'kind': 'tls'},
    {'id': 'mqtt',      'label': 'MQTT',             'port': 1883,  'kind': 'tcp'},
    {'id': 'amqp',      'label': 'AMQP / RabbitMQ',  'port': 5672,  'kind': 'tcp'},
    {'id': 'elastic',   'label': 'Elasticsearch',    'port': 9200,  'kind': 'http'},
    {'id': 'kafka',     'label': 'Kafka',            'port': 9092,  'kind': 'tcp'},
    {'id': 'git',       'label': 'Git daemon',       'port': 9418,  'kind': 'tcp'},
    {'id': 'tcp',       'label': 'Custom TCP port',  'port': None,  'kind': 'tcp'},
]
SERVICE_MAP = {s['id']: s for s in SERVICES}

_TARGET = re.compile(r'^[A-Za-z0-9._:-]{1,253}\Z')   # IP (v4/v6) or hostname; \Z: `$` admits a trailing newline


def clean_check(data):
    """Validate/normalize a check definition from the API → (record, None) or
    (None, 'error message'). Pure. Whether a node_id pin actually exists is
    the caller's concern (it owns the registry)."""
    data = data or {}
    svc = SERVICE_MAP.get(str(data.get('service') or '').strip())
    if not svc:
        return None, 'unknown service'
    target = str(data.get('target') or '').strip()
    if not target or not _TARGET.match(target):
        return None, 'target must be an IP address or hostname'
    try:
        port = int(data.get('port') or svc['port'] or 0)
    except (TypeError, ValueError):
        return None, 'invalid port'
    if not 1 <= port <= 65535:
        return None, 'port must be 1-65535'
    name = str(data.get('name') or '').strip()[:48]
    node_id = str(data.get('node_id') or '').strip() or None
    return {'service': svc['id'], 'target': target, 'port': port,
            'name': name or '%s @ %s' % (svc['label'], target),
            'node_id': node_id}, None


def run_check(check, timeout=CHECK_TIMEOUT):
    """Probe one check → {'ok', 'latency_ms', 'detail'}. Never raises."""
    svc = SERVICE_MAP.get(check.get('service')) or {'kind': 'tcp'}
    kind = svc['kind']
    target, port = check['target'], int(check['port'])
    t0 = time.monotonic()
    try:
        if kind in ('http', 'https'):
            ok, detail = _probe_http(kind, target, port, timeout)
        elif kind == 'tls':
            ok, detail = _probe_tls(target, port, timeout)
        elif kind == 'dns':
            ok, detail = _probe_dns(target, port, timeout)
        elif kind == 'ntp':
            ok, detail = _probe_ntp(target, port, timeout)
        else:
            ok, detail = _probe_tcp(target, port, timeout,
                                    svc.get('send'), svc.get('expect'))
    except TimeoutError:                    # str() can be empty on a bare recv timeout
        ok, detail = False, 'timed out'
    except Exception as e:
        ok, detail = False, friendly_error(str(e) or e.__class__.__name__)
    return {'ok': ok, 'latency_ms': int((time.monotonic() - t0) * 1000),
            'detail': detail}


def _probe_tcp(target, port, timeout, send=None, expect=None):
    with socket.create_connection((target, port), timeout=timeout) as s:
        s.settimeout(timeout)
        if send:
            s.sendall(send.encode())
        if expect:
            data = s.recv(256).decode('latin-1', 'replace')
            line = data.split('\r\n')[0].split('\n')[0].strip()
            if not data:
                return False, 'connected but no reply'
            if not data.lstrip().startswith(expect):
                return False, 'unexpected reply: %r' % line[:40]
            return True, line[:80] or 'reply ok'
    return True, 'port open'


def _probe_tls(target, port, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((target, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=target) as s:
            return True, (s.version() or 'TLS') + ' handshake ok'


def _probe_http(scheme, target, port, timeout):
    import requests
    host = '[%s]' % target if ':' in target else target   # bare IPv6
    r = requests.get('%s://%s:%d/' % (scheme, host, port), timeout=timeout,
                     verify=False, allow_redirects=False)
    return r.status_code < 500, 'HTTP %d' % r.status_code


def _dns_query():
    """A minimal A query for example.com (id 0x4e43 'NC')."""
    q = struct.pack('>HHHHHH', 0x4e43, 0x0100, 1, 0, 0, 0)
    for part in ('example', 'com'):
        q += bytes([len(part)]) + part.encode()
    return q + b'\x00' + struct.pack('>HH', 1, 1)


def _udp_socket(target, port, timeout):
    """A UDP socket of the right family for the target. Hard-coding AF_INET
    made every DNS/NTP check against an IPv6 address fail with an address-
    family error while _TARGET happily accepted the address."""
    fam = socket.getaddrinfo(target, port, type=socket.SOCK_DGRAM)[0][0]
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    return s


def _probe_dns(target, port, timeout):
    # ANY well-formed response — even REFUSED — proves a DNS server answers.
    q = _dns_query()
    with _udp_socket(target, port, timeout) as s:
        s.sendto(q, (target, port))
        data, _ = s.recvfrom(512)
    if len(data) >= 12 and data[:2] == q[:2] and data[2] & 0x80:
        rcode = data[3] & 0x0f
        return True, 'DNS answering' + ('' if rcode == 0 else ' (rcode %d)' % rcode)
    return False, 'malformed DNS response'


def _probe_ntp(target, port, timeout):
    pkt = b'\x1b' + 47 * b'\0'   # SNTP v3 client request
    with _udp_socket(target, port, timeout) as s:
        s.sendto(pkt, (target, port))
        data, _ = s.recvfrom(256)
    if len(data) >= 48:
        return True, 'NTP stratum %d' % data[1]
    return False, 'malformed NTP response'
