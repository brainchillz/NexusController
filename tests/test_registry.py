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
    assert app._split_host_port('https://192.168.1.88:8443') == ('192.168.1.88', 8443)
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
    """A pinned node that is offline raises NodeError from the pinned
    transport. _fetch_one must catch it and return a down envelope, not
    propagate (which would 500 the whole fleet view)."""
    import adapters.base

    def boom(method, url, fingerprint, **kw):
        raise adapters.base.NodeError('Connection refused')
    monkeypatch.setattr(adapters.base, 'pinned_request', boom)
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


# ── v2 node integration: new module ids in classification ────
def test_classify_gpu_capability_counts_as_ai():
    assert app.classify_node({}, ['gpu']) == 'AI'


def test_classify_v2_storage_mgmt_capabilities():
    assert app.classify_node({}, ['replication', 'schedules']) == 'Storage'
    assert app.classify_node({}, ['minidlna']) == 'Storage'


def test_classify_running_instances_is_virtualization():
    # A node running LXD instances and serving nothing else → Virtualization.
    assert app.classify_node({}, ['instances'], None, {'running': 3, 'total': 4}) == 'Virtualization'


def test_classify_storage_outranks_instances():
    # silo: ZFS pools + LXD → stays Storage (containers are secondary).
    s = {'zfs': {'pools': [{'name': 'tank'}]}}
    assert app.classify_node(s, ['zfs', 'instances'], None, {'running': 3, 'total': 4}) == 'Storage'


def test_classify_instances_capability_fallback():
    # Idle node whose only meaningful module is Containers → Virtualization.
    assert app.classify_node({}, ['instances', 'dashboard']) == 'Virtualization'
    # But any storage capability outranks it.
    assert app.classify_node({}, ['instances', 'zfs']) == 'Storage'


# ── version-skew flagging ─────────────────────────────────────────────
def test_version_skew_flags_laggards_only():
    rs = [{'ok': True, 'host_type': 'nexus', 'version': '2.0.0'},
          {'ok': True, 'host_type': 'nexus', 'version': '1.0.2'},
          {'ok': True, 'host_type': 'truenas', 'version': '25.10.2.1'},  # vendor version: ignored
          {'ok': False, 'host_type': 'nexus', 'version': '0.9.0'}]      # down: ignored
    app.flag_version_skew(rs)
    assert 'version_lag' not in rs[0]
    assert rs[1]['version_lag'] == '2.0.0'
    assert 'version_lag' not in rs[2]
    assert 'version_lag' not in rs[3]


def test_version_skew_uniform_fleet_unflagged():
    rs = [{'ok': True, 'host_type': 'nexus', 'version': '2.0.0'},
          {'ok': True, 'version': '2.0.0'}]   # no host_type = nexus
    app.flag_version_skew(rs)
    assert not any('version_lag' in r for r in rs)


def test_version_tuple_tolerant():
    assert app._version_tuple('2.0.0') == (2, 0, 0)
    assert app._version_tuple('v1.2') == (1, 2)
    assert app._version_tuple(None) == (0,)
    assert app._version_tuple('2.0.0') > app._version_tuple('1.9.9')


# ── rollup folds nexus LXD instances into VM/CT counts ────────────────
def test_rollup_counts_nexus_instances():
    rs = [{'ok': True, 'summary': {}, 'used_bytes': 0, 'size_bytes': 0,
           'instances': {'total': 4, 'running': 3, 'vms': 1, 'containers': 3}}]
    r = app.compute_rollup(rs)
    assert r['vms'] == 4 and r['containers'] == 3


# ── drill-in websocket shim ───────────────────────────────────────────
def test_render_drillin_websocket_shim():
    out = app.render_drillin_html('<html><head></head><body></body></html>', 'n1')
    assert 'window.WebSocket' in out
    assert '/nodes/n1/ws/' in out


# ── adapter descriptors (drive the Add/Edit-host modal) ───────────────
def test_adapter_descriptors_complete():
    import adapters
    ds = adapters.descriptors()
    kinds = [d['kind'] for d in ds]
    assert kinds[0] == 'nexus'   # first option in the Add-Host dropdown
    assert set(kinds) == {'nexus', 'proxmox', 'vcenter', 'esxi', 'truenas',
                          'synology', 'zimaos', 'unraid', 'omv', 'sparkdash',
                          'agent'}
    for d in ds:
        for k in ('kind', 'label', 'auth', 'secret_label', 'url_placeholder',
                  'username_placeholder', 'verify_tls', 'default_type', 'polled'):
            assert k in d, f"{d['kind']} missing {k}"
        assert d['auth'] in ('token', 'userpass')
    tn = next(d for d in ds if d['kind'] == 'truenas')
    assert tn['auth'] == 'token' and tn['secret_label'] == 'API key' and tn['verify_tls']


# ── controller user management ────────────────────────────────────────
def test_username_regex():
    assert app.RE_USERNAME.match('operator1')
    assert app.RE_USERNAME.match('a.b_c-d')
    assert not app.RE_USERNAME.match('bad name')
    assert not app.RE_USERNAME.match('x' * 33)
    assert not app.RE_USERNAME.match('')


def test_user_management_flow(client, monkeypatch):
    # admin session
    import app as A
    with client.session_transaction() as s:
        s['user'] = 'admin'
    # seed an admin user in the temp config
    cfg = A.load_config(); cfg.setdefault('users', {})['admin'] = {
        'password': A.generate_password_hash('x'*10), 'role': 'admin'}
    A.save_config(cfg)

    r = client.post('/api/users', json={'username': 'viewer1', 'role': 'viewer', 'password': 'p'*10})
    assert r.status_code == 200
    names = [u['username'] for u in client.get('/api/users').get_json()['users']]
    assert 'viewer1' in names
    # created users must change password on first login
    v = next(u for u in client.get('/api/users').get_json()['users'] if u['username'] == 'viewer1')
    assert v['must_change'] and v['role'] == 'viewer'
    # bad role / short password rejected
    assert client.post('/api/users', json={'username': 'x', 'role': 'root', 'password': 'p'*10}).status_code == 400
    assert client.post('/api/users', json={'username': 'y', 'role': 'viewer', 'password': 'short'}).status_code == 400
    # promote, then delete
    assert client.put('/api/users/viewer1', json={'role': 'operator'}).status_code == 200
    assert client.delete('/api/users/viewer1').status_code == 200
    # can't delete self / last admin
    assert client.delete('/api/users/admin').status_code == 400


# ── node cert review / re-pin ─────────────────────────────────────────
def _admin(client):
    import app as A
    with client.session_transaction() as s:
        s['user'] = 'admin'
    cfg = A.load_config(); cfg.setdefault('users', {})['admin'] = {
        'password': A.generate_password_hash('x' * 10), 'role': 'admin'}
    A.save_config(cfg)


def test_node_cert_reports_mismatch(client, monkeypatch):
    import app as A
    _admin(client)
    A.save_nodes({'nodes': [{'id': 'c1', 'name': 'silo', 'host_type': 'nexus',
                             'base_url': 'https://10.0.0.9:9143', 'cert_fp': 'aa' * 32}]})
    monkeypatch.setattr(A, 'cert_fingerprint', lambda h, p: 'bb' * 32)
    j = client.get('/api/nodes/c1/cert').get_json()
    assert j['pinned'] == 'aa' * 32 and j['observed'] == 'bb' * 32 and j['match'] is False
    assert client.get('/api/nodes/nope/cert').status_code == 404


def test_node_cert_http_has_no_certificate(client, monkeypatch):
    import app as A
    _admin(client)
    A.save_nodes({'nodes': [{'id': 'h1', 'name': 'plain', 'host_type': 'agent',
                             'base_url': 'http://10.0.0.9:9143', 'cert_fp': None}]})
    j = client.get('/api/nodes/h1/cert').get_json()
    assert j['scheme'] == 'http' and j['observed'] is None


def test_node_repin_accepts_reviewed_fp(client, monkeypatch):
    import app as A
    _admin(client)
    A.save_nodes({'nodes': [{'id': 'c2', 'name': 'silo', 'host_type': 'nexus',
                             'base_url': 'https://10.0.0.9:9143', 'cert_fp': 'aa' * 32}]})
    monkeypatch.setattr(A, 'cert_fingerprint', lambda h, p: 'bb' * 32)
    r = client.post('/api/nodes/c2/repin', json={'expected': 'bb' * 32})
    assert r.status_code == 200 and r.get_json()['cert_fp'] == 'bb' * 32
    # persisted
    n = A._find_node('c2')
    assert n['cert_fp'] == 'bb' * 32


def test_node_repin_rejects_stale_review(client, monkeypatch):
    """If the live cert changed again since the admin reviewed it, re-pin 409s
    rather than trusting whatever is served at click time."""
    import app as A
    _admin(client)
    A.save_nodes({'nodes': [{'id': 'c3', 'name': 'silo', 'host_type': 'nexus',
                             'base_url': 'https://10.0.0.9:9143', 'cert_fp': 'aa' * 32}]})
    monkeypatch.setattr(A, 'cert_fingerprint', lambda h, p: 'cc' * 32)  # now a 3rd cert
    r = client.post('/api/nodes/c3/repin', json={'expected': 'bb' * 32})
    assert r.status_code == 409
    assert A._find_node('c3')['cert_fp'] == 'aa' * 32  # unchanged


# ── tag-targeted fleet actions ────────────────────────────────────────
def test_fleet_action_targets_by_tag(client, monkeypatch):
    import app as A
    _admin(client)
    A.save_nodes({'nodes': [
        {'id': 'a', 'name': 'alpha', 'host_type': 'nexus', 'base_url': 'https://1', 'tags': ['prod', 'east']},
        {'id': 'b', 'name': 'bravo', 'host_type': 'nexus', 'base_url': 'https://2', 'tags': ['prod']},
        {'id': 'c', 'name': 'charlie', 'host_type': 'nexus', 'base_url': 'https://3', 'tags': ['dev']},
    ]})
    seen = []
    monkeypatch.setattr(A, '_proxy_service_action',
                        lambda n, s, act: (seen.append(n['name']) or
                                           {'id': n['id'], 'name': n['name'], 'ok': True, 'status': 200, 'error': None}))
    r = client.post('/api/fleet/action', json={'service': 'smbd', 'action': 'restart', 'tags': ['prod']})
    j = r.get_json()
    assert r.status_code == 200 and j['ok'] == 2
    assert sorted(seen) == ['alpha', 'bravo']   # charlie (dev) excluded
    assert 'prod' in j['scope']
    # a tag nobody has → 404
    assert client.post('/api/fleet/action', json={'service': 'smbd', 'action': 'restart', 'tags': ['nope']}).status_code == 404
