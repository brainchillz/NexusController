"""v0.16.0 controller API tokens: a second credential for an EXISTING login,
resolved before the session, hashed at rest, minted only interactively."""
import app as A
from tests.conftest import USER_PASSWORDS

HOST = 'https://ctl.example'
SAME = {'Origin': HOST, 'Sec-Fetch-Site': 'same-origin'}


def _login(c, user):
    r = c.post('/api/login', json={'username': user, 'password': USER_PASSWORDS[user]},
               headers=SAME, base_url=HOST)
    assert r.status_code == 200, r.get_json()
    return c


def _mint(c, name='t'):
    r = c.post('/api/tokens', json={'name': name}, headers=SAME, base_url=HOST)
    assert r.status_code == 200, r.get_json()
    return r.get_json()


def _bearer(tok):
    return {'Authorization': 'Bearer ' + tok}


# ── parse_bearer: only controller tokens are candidates ────────────────

def test_parse_bearer():
    assert A.parse_bearer('Bearer ct_' + 'x' * 40) == 'ct_' + 'x' * 40
    assert A.parse_bearer('bearer  ct_' + 'x' * 40) == 'ct_' + 'x' * 40
    assert A.parse_bearer('Bearer na_nodetoken_xxxxxxxxxxxxxxxx') is None   # a node/agent token
    assert A.parse_bearer('Bearer eyJhbGciOi.eyJzdWIi.sig') is None         # an assertion
    assert A.parse_bearer('Basic Y3RfeA==') is None
    assert A.parse_bearer('Bearer ct_short') is None
    assert A.parse_bearer('') is None and A.parse_bearer(None) is None


# ── mint + use ─────────────────────────────────────────────────────────

def test_token_is_the_login_it_was_minted_for(real_users):
    c = _login(A.app.test_client(), 'op1')
    t = _mint(c, 'home-assistant')
    assert t['token'].startswith('ct_') and len(t['token']) > 40
    fresh = A.app.test_client()
    me = fresh.get('/api/me', headers=_bearer(t['token'])).get_json()
    assert me['authenticated'] is True and me['user'] == 'op1' and me['role'] == 'admin'


def test_secret_is_shown_once_and_only_its_hash_is_stored(real_users):
    c = _login(A.app.test_client(), 'op1')
    t = _mint(c, 'x')
    stored = A.load_config()['api_tokens']
    assert list(stored) == [A.token_hash(t['token'])]
    blob = open(A.AUTH_FILE).read()
    assert t['token'] not in blob and t['prefix'] in blob
    lst = c.get('/api/tokens', base_url=HOST).get_json()['tokens']
    assert lst[0]['name'] == 'x' and 'token' not in lst[0]
    assert lst[0]['prefix'] == t['token'][:10]


def test_token_carries_the_records_role_and_scope_live(real_users):
    c = _login(A.app.test_client(), 'op1')
    t = _mint(c)
    fresh = A.app.test_client()
    # demote the login afterwards: the token follows the record, not its birth
    cfg = A.load_config(); cfg['users']['op1']['role'] = 'viewer'
    cfg['users']['op1']['tags'] = ['lab']; A.save_config(cfg)
    me = fresh.get('/api/me', headers=_bearer(t['token'])).get_json()
    assert me['role'] == 'viewer' and me['scope_tags'] == ['lab']
    # …and viewer means read-only for the token too
    r = fresh.put('/api/nodes/abc', json={'name': 'x'}, headers=_bearer(t['token']))
    assert r.status_code == 403


def test_a_token_cannot_mint_tokens(real_users):
    c = _login(A.app.test_client(), 'op1')
    t = _mint(c)
    r = A.app.test_client().post('/api/tokens', json={'name': 'escalate'}, headers=_bearer(t['token']))
    assert r.status_code == 403
    assert 'interactive' in r.get_json()['error']


def test_bad_token_is_refused_not_ignored(real_users):
    """A presented-but-invalid token must not fall back to a session cookie
    that happens to be there: a bad credential is a bad credential."""
    c = _login(A.app.test_client(), 'op1')
    assert c.get('/api/me', base_url=HOST).status_code == 200
    r = c.get('/api/me', headers=_bearer('ct_' + 'z' * 40), base_url=HOST)
    assert r.status_code == 401


def test_non_controller_bearer_is_ignored_and_session_still_applies(real_users):
    c = _login(A.app.test_client(), 'op1')
    r = c.get('/api/me', headers=_bearer('na_agenttoken_xxxxxxxxxxxxxxxxxxxx'), base_url=HOST)
    assert r.status_code == 200


# ── revoke ──────────────────────────────────────────────────────────────

def test_revoke_own_token(real_users):
    c = _login(A.app.test_client(), 'op1')
    t = _mint(c)
    assert A.app.test_client().get('/api/me', headers=_bearer(t['token'])).status_code == 200
    r = c.delete('/api/tokens/' + t['id'], headers=SAME, base_url=HOST)
    assert r.status_code == 200
    assert A.app.test_client().get('/api/me', headers=_bearer(t['token'])).status_code == 401


def test_others_tokens_are_invisible_to_non_admins_but_admin_sees_and_revokes(real_users):
    victim = _login(A.app.test_client(), 'view1')     # a viewer may mint (read-only) tokens
    t = _mint(victim, 'viewer-script')
    other = _login(A.app.test_client(), 'admin')      # local role: operator
    assert other.get('/api/tokens', base_url=HOST).get_json()['tokens'] == []
    assert other.delete('/api/tokens/' + t['id'], headers=SAME, base_url=HOST).status_code == 404
    admin = _login(A.app.test_client(), 'op1')        # local role: admin
    lst = admin.get('/api/tokens', base_url=HOST).get_json()
    assert lst['admin'] is True and [x['user'] for x in lst['tokens']] == ['view1']
    assert admin.delete('/api/tokens/' + t['id'], headers=SAME, base_url=HOST).status_code == 200
    assert A.app.test_client().get('/api/me', headers=_bearer(t['token'])).status_code == 401


def test_deleting_the_login_revokes_its_tokens(real_users):
    victim = _login(A.app.test_client(), 'view1')
    t = _mint(victim)
    admin = _login(A.app.test_client(), 'op1')
    assert admin.delete('/api/users/view1', headers=SAME, base_url=HOST).status_code == 200
    assert A.app.test_client().get('/api/me', headers=_bearer(t['token'])).status_code == 401
    assert A.load_config().get('api_tokens') == {}


def test_password_change_does_not_revoke_tokens(real_users):
    """Tokens are revoked by name, not by rotating the password — that is the
    point of having them."""
    c = _login(A.app.test_client(), 'op1')
    t = _mint(c)
    r = c.post('/api/account/password', json={'old_password': USER_PASSWORDS['op1'], 'new_password': 'rotated-pw-1'},
               headers=SAME, base_url=HOST)
    assert r.status_code == 200
    assert A.app.test_client().get('/api/me', headers=_bearer(t['token'])).status_code == 200


# ── the guard, audit, and SSO ───────────────────────────────────────────

def test_token_requests_pass_the_cross_site_guard_and_are_audited(real_users, tmp_path, monkeypatch):
    log = tmp_path / 'audit.log'; monkeypatch.setattr(A, 'AUDIT_FILE', str(log))
    c = _login(A.app.test_client(), 'op1'); t = _mint(c)
    r = A.app.test_client().post('/api/nodes/test', json={}, headers=_bearer(t['token']))
    assert r.status_code == 400          # validation, not 401/403 — no browser headers needed
    assert ('"via": "token:%s"' % t['id']) in log.read_text()


def test_token_name_is_validated(real_users):
    c = _login(A.app.test_client(), 'op1')
    r = c.post('/api/tokens', json={'name': 'x' * 49}, headers=SAME, base_url=HOST)
    assert r.status_code == 400
    r = c.post('/api/tokens', json={'name': 'bad\x00name'}, headers=SAME, base_url=HOST)
    assert r.status_code == 400
    assert _mint(c, '')['name'] == 'token'


def test_sso_session_can_mint_without_a_password(real_users, sso_live):
    from tests.test_sso_callback import _callback, HOST as SSO_HOST
    c = A.app.test_client(); _callback(c, sso_live, 'valid')
    r = c.post('/api/tokens', json={'name': 'from-sso'}, headers={'Origin': SSO_HOST}, base_url=SSO_HOST)
    assert r.status_code == 200
    assert A.app.test_client().get('/api/me', headers=_bearer(r.get_json()['token'])).get_json()['user'] == 'admin'
