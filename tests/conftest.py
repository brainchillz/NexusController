import os
import sys
import tempfile

# Point config/secret files at a throwaway dir BEFORE importing app, so tests
# never touch a real controller-auth.json / nodes.json.
_tmp = tempfile.mkdtemp(prefix='nexusctl-test-')
os.environ.setdefault('CONTROLLER_AUTH_FILE', os.path.join(_tmp, 'controller-auth.json'))
os.environ.setdefault('CONTROLLER_NODES_FILE', os.path.join(_tmp, 'nodes.json'))
os.environ.setdefault('CONTROLLER_CHECKS_FILE', os.path.join(_tmp, 'checks.json'))
os.environ.setdefault('CONTROLLER_AUDIT_FILE', os.path.join(_tmp, 'audit.log'))
os.environ.setdefault('CONTROLLER_HISTORY_FILE', os.path.join(_tmp, 'history.db'))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import app as _app


@pytest.fixture
def client():
    """A Flask test client with a signing key set (no server, no TLS)."""
    _app.app.secret_key = 'test-secret-key'
    _app.app.config['TESTING'] = True
    return _app.app.test_client()


# ─── Real users + a live SSO configuration (route-level auth tests) ────
# Most route tests monkeypatch _resolve_identity. The tests that exercise the
# session itself (login, the SSO callback, revocation) need genuine user
# records in the auth file, and the SSO ones need the verifier configured
# against the committed issuer fixture with its clock frozen at that
# fixture's `now` (the assertions are real issuer output and have long since
# expired in wall-clock time).

import json as _json
import types as _types

from werkzeug.security import generate_password_hash as _hash

USER_PASSWORDS = {'admin': 'admin-pass-1', 'op1': 'oper-pass-1', 'view1': 'view-pass-1'}


@pytest.fixture
def real_users():
    """Write a known user set to the (temp) auth file; restore it after.
    The SSO fixture's assertion subject is 'admin' — that record is deliberately
    an OPERATOR here so a test can prove the local record, not the assertion,
    decides the role."""
    path = _app.AUTH_FILE
    before = None
    try:
        with open(path) as f:
            before = f.read()
    except FileNotFoundError:
        pass
    _app.save_config({'secret_key': 'test-secret-key', 'users': {
        'admin': {'password': _hash(USER_PASSWORDS['admin']), 'role': 'operator'},
        'op1': {'password': _hash(USER_PASSWORDS['op1']), 'role': 'admin'},
        'view1': {'password': _hash(USER_PASSWORDS['view1']), 'role': 'viewer'},
    }})
    yield USER_PASSWORDS
    if before is None:
        os.unlink(path)
    else:
        with open(path, 'w') as f:
            f.write(before)


@pytest.fixture
def sso_live(monkeypatch):
    """SSO configured from the committed issuer fixture, clock frozen at the
    fixture's `now`. Returns the fixture dict (issuer/audience/assertions)."""
    import sso
    fx = _json.loads(open(os.path.join(os.path.dirname(__file__),
                                       'fixtures', 'sso_assertions.json')).read())
    monkeypatch.setattr(sso, 'SSO_ISSUER', fx['issuer'])
    monkeypatch.setattr(sso, 'SSO_PUBKEY', fx['pubkey'])
    monkeypatch.setattr(sso, 'SSO_KID', fx['kid'])
    monkeypatch.setattr(sso, 'SSO_AUDIENCE', fx['audience'])
    monkeypatch.setattr(sso, '_seen', {})
    monkeypatch.setattr(sso, 'time', _types.SimpleNamespace(time=lambda: fx['now']))
    return fx
