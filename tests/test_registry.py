"""Pure-function tests for the controller: node-type classification, the
secret-stripping registry view, token encryption round-trip, and host/port
parsing. No network, no root."""
import app


# ── classify_node (proposal §6.7 heuristic) ──────────────────────────
def test_classify_storage_from_summary():
    s = {'zfs': {'pools': [{'name': 'tank'}]}, 'smb': {'shares': 0},
         'nfs': {'exports': 0}, 'iscsi': {'targets': 0}}
    assert app.classify_node(s, []) == 'Storage'


def test_classify_ai_from_llama_health():
    # No storage, but llama-server is healthy → AI (llama is fetched separately,
    # not part of /api/summary).
    s = {'zfs': {'pools': []}}
    llama = {'service': {'active': 'active'}, 'model': '/m/qwen.gguf', 'health': {'ok': True}}
    assert app.classify_node(s, [], llama) == 'AI'


def test_classify_ai_from_service_active_with_model():
    s = {'zfs': {'pools': []}}
    llama = {'service': {'active': 'active'}, 'model': '/m/q.gguf', 'health': {'ok': False}}
    assert app.classify_node(s, [], llama) == 'AI'  # active + model even if health probe failed


def test_classify_mixed_storage_plus_llama():
    s = {'zfs': {'pools': [{'name': 'tank'}]}, 'smb': {'shares': 2}}
    llama = {'service': {'active': 'active'}, 'model': '/m/q.gguf', 'health': {'ok': True}}
    assert app.classify_node(s, [], llama) == 'Mixed'


def test_serves_ai_helper():
    assert app._serves_ai({'health': {'ok': True}})
    assert app._serves_ai({'service': {'active': 'active'}, 'model': '/m/x.gguf'})
    assert not app._serves_ai({'service': {'active': 'inactive'}, 'model': '/m/x.gguf'})
    assert not app._serves_ai({'service': {'active': 'active'}})  # no model
    assert not app._serves_ai(None)


def test_classify_shares_count_as_storage():
    s = {'zfs': {'pools': []}, 'smb': {'shares': 3}}
    assert app.classify_node(s, []) == 'Storage'


def test_classify_idle_falls_back_to_capabilities():
    s = {'zfs': {'pools': []}, 'smb': {'shares': 0}}
    assert app.classify_node(s, ['zfs', 'nfs']) == 'Storage'
    assert app.classify_node(s, ['llama']) == 'AI'
    assert app.classify_node(s, ['zfs', 'llama']) == 'Mixed'
    assert app.classify_node(s, []) == 'Unknown'


# ── registry never leaks the token ───────────────────────────────────
def test_public_node_strips_token():
    n = {'id': 'a1', 'name': 'silo', 'token_enc': 'SECRET', 'cert_fp': 'ab'}
    pub = app._public_node(n)
    assert 'token_enc' not in pub
    assert pub['name'] == 'silo' and pub['cert_fp'] == 'ab'


# ── token encryption at rest ─────────────────────────────────────────
def test_encrypt_decrypt_round_trip():
    secret = 'sd_' + 'x' * 40
    enc = app.encrypt_secret(secret)
    assert enc != secret  # actually encrypted
    assert app.decrypt_secret(enc) == secret


def test_decrypt_garbage_returns_none():
    assert app.decrypt_secret('not-a-valid-token') is None


# ── URL parsing for cert pinning ─────────────────────────────────────
def test_split_host_port_defaults():
    assert app._split_host_port('https://192.168.1.10:8443') == ('192.168.1.10', 8443)
    assert app._split_host_port('https://node.local') == ('node.local', 443)
    assert app._split_host_port('http://node.local') == ('node.local', 80)


# ── human-byte parsing (matches the node's _human_bytes output) ──────
def test_parse_human_bytes():
    assert app.parse_human_bytes('1.0K') == 1024
    assert app.parse_human_bytes('2.0M') == 2 * 1024 ** 2
    assert app.parse_human_bytes('1.5G') == int(1.5 * 1024 ** 3)
    assert app.parse_human_bytes('512B') == 512
    assert app.parse_human_bytes('0B') == 0
    assert app.parse_human_bytes('') == 0
    assert app.parse_human_bytes(None) == 0
    assert app.parse_human_bytes('garbage') == 0


# ── fleet rollup aggregation ─────────────────────────────────────────
def _node(ok=True, alerts=0, pools=1, online=True, used='1.0T', size='2.0T', services=None):
    summary = {'alerts': ['a%d' % i for i in range(alerts)],
               'zfs': {'pools': pools, 'online': online, 'used': used, 'size': size},
               'services': services or {}}
    return {'ok': ok, 'summary': summary if ok else None, 'error': None if ok else 'down',
            'used_bytes': app.parse_human_bytes(used) if ok else 0,
            'size_bytes': app.parse_human_bytes(size) if ok else 0}


def test_compute_rollup_counts_and_storage():
    nodes = [_node(used='1.0T', size='2.0T'), _node(used='1.0T', size='2.0T', alerts=2)]
    r = app.compute_rollup(nodes)
    assert r['total'] == 2 and r['healthy'] == 2 and r['unreachable'] == 0
    assert r['alerts'] == 2
    assert r['storage_used'] == 2 * 1024 ** 4 and r['storage_size'] == 4 * 1024 ** 4
    assert r['degraded'] == 1  # the alerting node


def test_compute_rollup_unreachable_and_degraded():
    nodes = [_node(ok=False), _node(online=False)]
    r = app.compute_rollup(nodes)
    assert r['unreachable'] == 1 and r['healthy'] == 1
    assert r['degraded'] == 1  # the offline-pool node


def test_services_down_ignores_disabled():
    svcs = {'a': {'enabled': 'enabled', 'active': 'active'},
            'b': {'enabled': 'enabled', 'active': 'inactive'},   # down
            'c': {'enabled': 'disabled', 'active': 'inactive'}}  # intentionally off
    assert app._services_down({'services': svcs}) == 1


# ── drill-in HTML rewrite (reverse-proxy retargeting) ────────────────
def test_render_drillin_rewrites_api_and_static():
    html = ('<html><head><link rel="stylesheet" href="/static/css/style.css"></head>'
            '<body><script>fetch("/api/summary")</script></body></html>')
    out = app.render_drillin_html(html, 'abc123')
    # static asset retargeted to the controller's node-static proxy
    assert 'href="/nodes/abc123/static/css/style.css"' in out
    assert 'href="/static/' not in out
    # fetch-shim injected into <head> BEFORE the node's own script
    assert '/api/nodes/abc123/proxy/' in out
    assert out.index('var P=') < out.index('fetch("/api/summary")')
    # the node's own /api/ string is left intact (the shim rewrites at runtime)
    assert 'fetch("/api/summary")' in out


def test_render_drillin_handles_missing_head():
    out = app.render_drillin_html('<body>x</body>', 'n1')
    assert out.startswith('<script>')
    assert '/api/nodes/n1/proxy/' in out


# ── TLS certificate validation/install (cryptography, no openssl) ────
def _make_cert_key(cn='test'):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()).decode()
    return cert_pem, key_pem


def test_install_cert_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'TLS_DIR', str(tmp_path))
    monkeypatch.setattr(app, 'TLS_CERT', str(tmp_path / 'c.crt'))
    monkeypatch.setattr(app, 'TLS_KEY', str(tmp_path / 'c.key'))
    cert_pem, key_pem = _make_cert_key('install-test')
    ok, e = app.validate_and_install_cert(cert_pem, key_pem)
    assert ok and e == ''
    info = app.cert_info()
    assert info['present'] and 'install-test' in info['subject'] and info['self_signed']
    # key file must be 0600
    assert oct(__import__('os').stat(app.TLS_KEY).st_mode)[-3:] == '600'


def test_install_cert_rejects_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'TLS_DIR', str(tmp_path))
    monkeypatch.setattr(app, 'TLS_CERT', str(tmp_path / 'c.crt'))
    monkeypatch.setattr(app, 'TLS_KEY', str(tmp_path / 'c.key'))
    cert_pem, _ = _make_cert_key('a')
    _, other_key = _make_cert_key('b')
    ok, e = app.validate_and_install_cert(cert_pem, other_key)
    assert not ok and 'do not match' in e


def test_install_cert_rejects_garbage():
    assert app.validate_and_install_cert('not a cert', 'not a key')[0] is False
    ok, e = app.validate_and_install_cert('-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----',
                                          '-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----')
    assert not ok


# ── fleet bulk-action input validation ───────────────────────────────
# ── fan-out resilience: one down node must not crash the whole summary ─
def test_fetch_one_unreachable_pinned_node_returns_envelope(monkeypatch):
    """A pinned node that is offline raises a raw socket error from
    cert_fingerprint during _verify_pin. _fetch_one must catch it and return
    a down envelope, not propagate (which would 500 the whole fleet view)."""
    def boom(host, port):
        raise OSError('Connection refused')
    monkeypatch.setattr(app, 'cert_fingerprint', boom)
    node = {'id': 'n1', 'name': 'silo', 'base_url': 'https://10.0.0.1:8443',
            'cert_fp': 'deadbeef' * 8, 'role': 'admin'}
    out = app._fetch_one(node)
    assert out['ok'] is False
    assert out['id'] == 'n1' and out['error']


def test_fleet_action_allowlist_and_service_regex():
    assert app.FLEET_ACTIONS == {'start', 'stop', 'restart', 'enable', 'disable'}
    assert app.RE_SERVICE.match('smbd')
    assert app.RE_SERVICE.match('llama-server@1')
    # argument/path injection attempts are rejected
    assert not app.RE_SERVICE.match('smbd; rm -rf /')
    assert not app.RE_SERVICE.match('../../etc')
    assert not app.RE_SERVICE.match('a b')
