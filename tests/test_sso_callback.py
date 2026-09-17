"""The SSO callback as the BROWSER delivers it.

The issuer is shared by every application in the estate, so this controller's
side of the exchange is a frozen contract. test_sso.py proves the verifier;
this file proves the ROUTE: a cross-site, top-level GET navigation carrying
the assertion in the query string, no Origin header (browsers send none on a
navigation), must come back as an ordinary local session.

Any future auth hardening — a cross-site request check, a new session field,
a cookie attribute change — has to leave every test here green. If one of
them fails, sign-in via the issuer is broken for this controller.
"""
import app as A

HOST = 'https://node1'   # the audience host; every request in a test uses it,
                         # or the cookie jar (keyed by host) withholds the session

# Exactly the fetch-metadata a browser attaches when the issuer redirects it
# back here: a cross-site navigation. There is deliberately no Origin.
BROWSER_NAV = {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate',
               'Sec-Fetch-Dest': 'document', 'Sec-Fetch-User': '?1'}


def _callback(client, fx, name, **extra):
    q = '/sso/callback?a=%s' % fx['assertions'][name]
    for k, v in extra.items():
        q += '&%s=%s' % (k, v)
    return client.get(q, headers=BROWSER_NAV, base_url=HOST)


def test_callback_turns_an_assertion_into_a_local_session(client, real_users, sso_live):
    r = _callback(client, sso_live, 'valid', next='/%3Ftab%3Dstorage')
    assert r.status_code == 302
    assert r.headers['Location'] == '/?tab=storage'
    assert 'session=' in r.headers.get('Set-Cookie', '')
    # The cookie the callback issued is now an ordinary login …
    me = client.get('/api/me', base_url=HOST).get_json()
    assert me['authenticated'] is True
    assert me['user'] == 'admin'
    # … whose ROLE comes from the local record (an operator here), never from
    # the assertion — the subject is literally named 'admin'.
    assert me['role'] == 'operator'


def test_callback_session_survives_a_state_changing_request(client, real_users, sso_live):
    """The session the callback minted must work for writes, not just reads —
    that is where a CSRF/origin guard would bite if it were mis-scoped."""
    _callback(client, sso_live, 'valid')
    r = client.post('/api/account/password',
                    json={'old_password': real_users['admin'], 'new_password': 'brand-new-pw-1'},
                    headers={'Sec-Fetch-Site': 'same-origin', 'Origin': HOST},
                    base_url=HOST)
    assert r.status_code == 200, r.get_json()


def test_callback_refuses_a_subject_with_no_local_account(client, real_users, sso_live):
    """SSO grants access to accounts that exist; it never creates one."""
    r = _callback(client, sso_live, 'unknown_user')
    assert r.status_code == 302
    assert r.headers['Location'] == '/?sso_error=unknown_user'
    assert client.get('/api/me', base_url=HOST).status_code == 401


def test_callback_refuses_a_bad_assertion_without_a_session(client, real_users, sso_live):
    for bad in ('expired', 'wrong_audience', 'wrong_issuer', 'signed_by_another_key'):
        r = _callback(client, sso_live, bad)
        assert r.status_code == 302
        assert r.headers['Location'] == '/?sso_error=1'
        assert client.get('/api/me', base_url=HOST).status_code == 401


def test_callback_is_single_use(client, real_users, sso_live):
    assert _callback(client, sso_live, 'valid').headers['Location'] == '/'
    fresh = A.app.test_client()
    r = _callback(fresh, sso_live, 'valid')
    assert r.headers['Location'] == '/?sso_error=1'
    assert fresh.get('/api/me', base_url=HOST).status_code == 401


def test_callback_discards_the_pre_login_session(client, real_users, sso_live):
    """Session fixation: whatever an anonymous browser carried in is gone."""
    with client.session_transaction(base_url=HOST) as s:
        s['planted'] = 'by-an-attacker'
    _callback(client, sso_live, 'valid')
    with client.session_transaction(base_url=HOST) as s:
        assert s.get('user') == 'admin'
        assert 'planted' not in s


def test_callback_collapses_a_hostile_next(client, real_users, sso_live):
    r = _callback(client, sso_live, 'valid', next='https://evil.example/')
    assert r.headers['Location'] == '/'
    r2 = _callback(A.app.test_client(), sso_live, 'valid', next='//evil.example/')
    assert r2.headers['Location'] in ('/', '/?sso_error=1')   # second use may be spent


def test_callback_stays_public_and_a_get(client):
    """The guard exempts it by endpoint name; the rule is websocket-free and
    GET-only. If either changes, the issuer's redirect can no longer land."""
    assert 'sso_callback' in A.PUBLIC_ENDPOINTS
    rule = next(r for r in A.app.url_map.iter_rules() if r.endpoint == 'sso_callback')
    assert rule.methods >= {'GET'} and 'POST' not in rule.methods
