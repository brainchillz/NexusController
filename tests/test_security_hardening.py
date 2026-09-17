"""v0.14.0 hardening: cross-site request guard, response headers, and
session revocation (generation-stamped sessions). Each test names what it
guards against. The SSO callback tests in test_sso_callback.py are the other
half of this file — they must stay green alongside it.
"""
import pytest

import app as A
from tests.conftest import USER_PASSWORDS

HOST = 'https://ctl.example'
SAME = {'Origin': HOST, 'Sec-Fetch-Site': 'same-origin'}
FOREIGN = {'Origin': 'https://evil.example', 'Sec-Fetch-Site': 'cross-site'}
_WS = {'Upgrade': 'websocket', 'Connection': 'Upgrade'}


def _login(c, user, pw=None, headers=None):
    return c.post('/api/login', json={'username': user, 'password': pw or USER_PASSWORDS[user]},
                  headers=headers or SAME, base_url=HOST)


def _me(c):
    return c.get('/api/me', base_url=HOST)


# ── cross_site_request: the pure guard ──────────────────────────────────

OWN = {'ctl.example', 'ctl.example:9443'}


@pytest.mark.parametrize('method,endpoint,origin,site,refused', [
    # writes: Origin decides when present (host[:port] only, scheme ignored)
    ('POST', 'x', 'https://ctl.example', None, False),
    ('POST', 'x', 'http://ctl.example', None, False),      # behind a TLS proxy
    ('POST', 'x', 'https://ctl.example:9443', None, False),
    ('POST', 'x', 'https://evil.example', None, True),
    ('POST', 'x', 'https://ctl.example.evil.example', None, True),
    ('POST', 'x', 'null', None, True),                      # sandboxed / redirected
    ('POST', 'x', 'https://evil.example', 'same-origin', True),   # Origin wins
    # no Origin: fetch metadata decides
    ('PUT', 'x', None, 'same-origin', False),
    ('DELETE', 'x', None, 'none', False),                   # user-initiated
    ('PATCH', 'x', None, 'same-site', True),                # a sibling app on the domain
    ('POST', 'x', None, 'cross-site', True),
    # neither header: not a browser (curl, tests) — passes
    ('POST', 'x', None, None, False),
    # reads are never judged — the SSO callback arrives cross-site by design
    ('GET', 'sso_callback', None, 'cross-site', False),
    ('GET', 'index', 'https://evil.example', 'cross-site', False),
    # …except the websocket bridge, a GET that hands out a shell
    ('GET', 'node_ws', 'https://evil.example', 'cross-site', True),
    ('GET', 'node_ws', 'https://ctl.example', 'same-origin', False),
])
def test_cross_site_request(method, endpoint, origin, site, refused):
    assert A.cross_site_request(method, endpoint, OWN, origin, site) is refused


# ── the guard on real routes ─────────────────────────────────────────────

def test_foreign_origin_write_is_refused_before_credentials(client, real_users):
    r = _login(client, 'op1', headers=FOREIGN)
    assert r.status_code == 403
    assert 'Cross-site' in r.get_json()['error']
    assert _me(client).status_code == 401         # no login CSRF either


def test_same_origin_write_passes(client, real_users):
    assert _login(client, 'op1').status_code == 200
    assert _me(client).get_json()['user'] == 'op1'


def test_fetch_metadata_alone_is_enough_to_refuse(client, real_users):
    r = _login(client, 'op1', headers={'Sec-Fetch-Site': 'cross-site'})
    assert r.status_code == 403


def test_non_browser_clients_still_pass(client, real_users):
    """The existing test-suite pattern (json= with no browser headers) and
    scripted clients keep working."""
    r = client.post('/api/login', json={'username': 'op1', 'password': USER_PASSWORDS['op1']},
                    base_url=HOST)
    assert r.status_code == 200


def test_console_bridge_refuses_a_foreign_origin(client, real_users):
    _login(client, 'op1')
    r = client.get('/nodes/abc/ws/console/x', headers={**_WS, **FOREIGN}, base_url=HOST)
    assert r.status_code == 403
    assert 'Cross-site' in r.get_json()['error']
    r = client.get('/nodes/abc/ws/console/x', headers={**_WS, **SAME}, base_url=HOST)
    assert r.status_code != 403                 # (404: no such node — the guard let it through)


def test_trusted_proxy_forwarded_host_is_our_own(client, real_users, monkeypatch):
    """Behind a reverse proxy that rewrites Host, the browser's Origin names
    the PUBLIC host. Accepted only when X-Forwarded-Host comes from the
    configured trusted proxy."""
    hdr = {'Origin': 'https://public.example', 'X-Forwarded-Host': 'public.example'}
    assert _login(client, 'op1', headers=hdr).status_code == 403
    monkeypatch.setattr(A, '_TRUSTED_PROXY', '127.0.0.1')   # the test client's peer
    assert _login(client, 'op1', headers=hdr).status_code == 200


def test_refused_cross_site_write_is_audited(client, real_users, tmp_path, monkeypatch):
    log = tmp_path / 'audit.log'
    monkeypatch.setattr(A, 'AUDIT_FILE', str(log))
    _login(client, 'op1', headers=FOREIGN)
    assert 'cross-site request refused' in log.read_text()


# ── response headers ─────────────────────────────────────────────────────

def test_security_headers_pure():
    h = A.security_headers('index', '/', True, False)
    assert h['X-Frame-Options'] == 'DENY'
    assert h['X-Content-Type-Options'] == 'nosniff'
    assert "frame-ancestors 'none'" in h['Content-Security-Policy']
    assert "connect-src 'self'" in h['Content-Security-Policy']
    assert 'Strict-Transport-Security' not in h
    assert 'Cache-Control' not in h
    h = A.security_headers('api_me', '/api/me', True, True)
    assert h['Cache-Control'] == 'no-store'
    assert h['Strict-Transport-Security'].startswith('max-age=')
    assert 'Strict-Transport-Security' not in A.security_headers('api_me', '/api/me', False, True)


def test_drillin_gets_only_the_framing_rule():
    """The node's own page runs there; a full CSP would be ours imposed on a
    page we do not write. Framing is still denied."""
    for ep in ('node_drillin', 'node_static', 'node_plugin_asset', 'node_ws'):
        csp = A.security_headers(ep, '/nodes/x/', True, False)['Content-Security-Policy']
        assert csp == "frame-ancestors 'none'"
        assert 'script-src' not in csp


def test_headers_land_on_every_response(client):
    for path in ('/', '/api/me', '/api/status', '/no/such/route'):
        r = client.get(path)
        assert r.headers['X-Frame-Options'] == 'DENY', path
        assert r.headers['X-Content-Type-Options'] == 'nosniff', path
        assert 'Content-Security-Policy' in r.headers, path
        assert r.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
    assert client.get('/api/me').headers['Cache-Control'] == 'no-store'
    assert 'Cache-Control' not in client.get('/').headers or \
        'no-store' not in client.get('/').headers['Cache-Control']


def test_hsts_is_opt_in(client):
    assert 'Strict-Transport-Security' not in client.get('/').headers


# ── session revocation ───────────────────────────────────────────────────

def test_password_change_signs_out_the_other_sessions_only(real_users):
    a, b = A.app.test_client(), A.app.test_client()
    assert _login(a, 'op1').status_code == 200
    assert _login(b, 'op1').status_code == 200
    r = a.post('/api/account/password',
               json={'old_password': USER_PASSWORDS['op1'], 'new_password': 'rotated-pw-1'},
               headers=SAME, base_url=HOST)
    assert r.status_code == 200
    assert _me(a).status_code == 200, 'the session that changed it stays signed in'
    assert _me(b).status_code == 401, 'a stolen cookie stops working'
    assert _login(A.app.test_client(), 'op1', 'rotated-pw-1').status_code == 200


def test_forced_first_login_change_keeps_the_flow_signed_in(real_users):
    """must_change → the login flow calls change_password with the session it
    just got; that session must survive its own generation bump."""
    cfg = A.load_config(); cfg['users']['view1']['must_change'] = True; A.save_config(cfg)
    c = A.app.test_client()
    assert _login(c, 'view1').get_json()['must_change'] is True
    r = c.post('/api/account/password',
               json={'old_password': USER_PASSWORDS['view1'], 'new_password': 'my-own-pw-1'},
               headers=SAME, base_url=HOST)
    assert r.status_code == 200
    assert _me(c).get_json()['must_change'] is False


def test_admin_password_reset_revokes_that_users_sessions(real_users):
    admin, victim = A.app.test_client(), A.app.test_client()
    _login(admin, 'op1'); _login(victim, 'view1')
    assert _me(victim).status_code == 200
    r = admin.put('/api/users/view1', json={'password': 'admin-set-pw-1'}, headers=SAME, base_url=HOST)
    assert r.status_code == 200
    assert _me(victim).status_code == 401
    assert _me(admin).status_code == 200


def test_revoke_sessions_signs_out_an_sso_session_too(real_users, sso_live):
    """An SSO login is an ordinary session once minted, so the local
    generation bump is the ONLY revocation hook it has."""
    from tests.test_sso_callback import _callback, HOST as SSO_HOST
    sso = A.app.test_client()
    _callback(sso, sso_live, 'valid')
    assert sso.get('/api/me', base_url=SSO_HOST).status_code == 200
    admin = A.app.test_client(); _login(admin, 'op1')
    r = admin.put('/api/users/admin', json={'revoke_sessions': True}, headers=SAME, base_url=HOST)
    assert r.status_code == 200
    assert sso.get('/api/me', base_url=SSO_HOST).status_code == 401
    # and they can come straight back in (a fresh assertion is single-use; use
    # the password path here)
    assert _login(A.app.test_client(), 'admin').status_code == 200


def test_revoking_yourself_keeps_this_session(real_users):
    a, b = A.app.test_client(), A.app.test_client()
    _login(a, 'op1'); _login(b, 'op1')
    r = a.put('/api/users/op1', json={'revoke_sessions': True}, headers=SAME, base_url=HOST)
    assert r.status_code == 200
    assert _me(a).status_code == 200
    assert _me(b).status_code == 401


def test_revoke_is_audited(real_users, tmp_path, monkeypatch):
    log = tmp_path / 'audit.log'
    monkeypatch.setattr(A, 'AUDIT_FILE', str(log))
    admin = A.app.test_client(); _login(admin, 'op1')
    admin.put('/api/users/view1', json={'revoke_sessions': True}, headers=SAME, base_url=HOST)
    assert 'user:view1 (sessions revoked)' in log.read_text()


def test_pre_upgrade_sessions_and_records_still_match(client, real_users):
    """A cookie minted before the generation stamp existed (no 'gen') against
    a record that has no session_gen must still be valid — deploying this
    must not log everyone out."""
    with client.session_transaction(base_url=HOST) as s:
        s['user'] = 'op1'
    assert _me(client).status_code == 200
    # …until that user's generation moves.
    cfg = A.load_config(); A._bump_session_gen(cfg['users']['op1']); A.save_config(cfg)
    assert _me(client).status_code == 401


def test_garbage_generation_in_a_cookie_is_refused(client, real_users):
    with client.session_transaction(base_url=HOST) as s:
        s['user'] = 'op1'; s['gen'] = 'not-a-number'
    assert _me(client).status_code == 401


def test_session_gen_never_leaves_the_server(client, real_users):
    _login(client, 'op1')
    for u in client.get('/api/users', base_url=HOST).get_json()['users']:
        assert 'session_gen' not in u
        assert 'password' not in u
