"""Regression tests for the 2026-07-29 auth hardening (login timing oracle +
deleted-user session rejection)."""


def test_deleted_user_session_is_rejected(client):
    """A session for a user not in the store must resolve to unauthenticated,
    not to the fail-safe 'viewer' default it used to fall through to."""
    import app as A
    assert A._user_role(None) == 'viewer'            # default is already safe...
    with A.app.test_request_context():
        from flask import session
        session['user'] = 'ghost'                    # never created
        name, role = A._resolve_identity()
    assert name is None and role is None             # ...but the session is rejected


def test_login_hashes_once_per_path(client, monkeypatch):
    """Unknown user and known-user-wrong-password each cost exactly one password
    hash, so response time cannot enumerate usernames."""
    import app as A
    calls = {'n': 0}
    real = A.check_password_hash
    monkeypatch.setattr(A, 'check_password_hash',
                        lambda h, p: (calls.__setitem__('n', calls['n'] + 1), real(h, p))[1])
    cfg = A.load_config(); cfg.setdefault('users', {})['admin'] = {
        'password': A.generate_password_hash('right'), 'role': 'admin'}
    A.save_config(cfg)
    A._login_fails.clear()
    calls['n'] = 0
    client.post('/api/login', json={'username': 'ghost', 'password': 'x'})
    assert calls['n'] == 1
    calls['n'] = 0
    client.post('/api/login', json={'username': 'admin', 'password': 'wrong'})
    assert calls['n'] == 1
