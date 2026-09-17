"""v0.18.0 encrypted backup/restore: backup.py is pure; the route and CLI
are exercised against temp paths."""
import os
import json
import pytest

import app as A
import backup as B
from tests.conftest import USER_PASSWORDS

PW = 'correct horse battery'
FILES = {'controller-auth.json': '{"secret_key": "s", "fernet_key": "k"}',
         'nodes.json': '{"nodes": [{"id": "n1"}]}',
         'certs/controller.key': '-----BEGIN PRIVATE KEY-----\nabc\n'}


def test_roundtrip(monkeypatch):
    monkeypatch.setattr(B, 'KDF_ITERATIONS', 1000)   # keep the suite quick
    blob = B.make_bundle(FILES, PW, iterations=1000)
    assert B.inspect_bundle(blob)['members'] == sorted(FILES)
    assert B.open_bundle(blob, PW) == FILES
    # nothing readable in the envelope but the header
    assert b'BEGIN PRIVATE KEY' not in blob and b'fernet_key' not in blob


def test_wrong_passphrase_tamper_and_foreign_file():
    blob = B.make_bundle(FILES, PW, iterations=1000)
    with pytest.raises(ValueError, match='wrong passphrase'):
        B.open_bundle(blob, PW + 'x')
    env = json.loads(blob); env['data'] = env['data'][:-4] + 'AAAA'
    with pytest.raises(ValueError, match='wrong passphrase'):
        B.open_bundle(json.dumps(env).encode(), PW)
    for bad in (b'not json', b'{"format": "something-else"}', b'[]'):
        with pytest.raises(ValueError, match='not a controller backup'):
            B.open_bundle(bad, PW)


def test_short_passphrase_refused():
    with pytest.raises(ValueError, match='at least'):
        B.make_bundle(FILES, 'short', iterations=1000)


def test_collect_skips_missing(tmp_path):
    (tmp_path / 'a.json').write_text('{}')
    got = B.collect({'a': str(tmp_path / 'a.json'), 'b': str(tmp_path / 'nope.json')})
    assert got == {'a': '{}'}


def test_restore_refuses_overwrite_unless_forced_and_writes_0600(tmp_path):
    paths = {'controller-auth.json': str(tmp_path / 'auth.json'),
             'certs/controller.key': str(tmp_path / 'certs' / 'c.key'),
             'nodes.json': str(tmp_path / 'nodes.json')}
    written = B.restore(FILES, paths)
    assert sorted(written) == sorted(paths.values())
    assert oct(os.stat(paths['certs/controller.key']).st_mode & 0o777) == '0o600'
    assert open(paths['nodes.json']).read() == FILES['nodes.json']
    with pytest.raises(FileExistsError, match='refusing to overwrite'):
        B.restore(FILES, paths)
    assert B.restore({'nodes.json': 'new', 'unknown-member': 'x'}, paths, force=True) == [paths['nodes.json']]
    assert open(paths['nodes.json']).read() == 'new'
    assert not [p for p in os.listdir(tmp_path) if p.startswith('.restore-')]


# ── route ────────────────────────────────────────────────────────────────

def _login(c, user):
    assert c.post('/api/login', json={'username': user, 'password': USER_PASSWORDS[user]}).status_code == 200
    return c


def test_backup_route_is_admin_only_and_returns_a_decryptable_bundle(real_users, monkeypatch):
    monkeypatch.setattr(B, 'KDF_ITERATIONS', 1000)
    c = _login(A.app.test_client(), 'admin')          # local role: operator
    assert c.post('/api/backup', json={'passphrase': PW}).status_code == 403
    c = _login(A.app.test_client(), 'op1')            # admin
    assert c.post('/api/backup', json={'passphrase': 'short'}).status_code == 400
    r = c.post('/api/backup', json={'passphrase': PW})
    assert r.status_code == 200
    assert r.content_type == 'application/octet-stream'
    assert r.headers['Content-Disposition'].startswith('attachment; filename="nexus-controller-backup-')
    files = B.open_bundle(r.data, PW)
    assert 'controller-auth.json' in files
    assert json.loads(files['controller-auth.json'])['users']['op1']['role'] == 'admin'
    assert 'certs/controller.key' not in files or files['certs/controller.key']   # only present files


def test_backup_route_accepts_an_admin_api_token(real_users, monkeypatch):
    """A nightly cron is the point; an admin token is admin-equivalent anyway."""
    monkeypatch.setattr(B, 'KDF_ITERATIONS', 1000)
    c = _login(A.app.test_client(), 'op1')
    tok = c.post('/api/tokens', json={'name': 'nightly'}).get_json()['token']
    r = A.app.test_client().post('/api/backup', json={'passphrase': PW},
                                 headers={'Authorization': 'Bearer ' + tok})
    assert r.status_code == 200


# ── CLI ──────────────────────────────────────────────────────────────────

def test_cli_backup_then_restore_into_a_fresh_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(B, 'KDF_ITERATIONS', 1000)
    monkeypatch.setenv('CONTROLLER_BACKUP_PASSPHRASE', PW)
    src = tmp_path / 'src'; src.mkdir()
    (src / 'auth.json').write_text('{"users": {}}'); (src / 'nodes.json').write_text('{"nodes": []}')
    def point_at(d):
        import sso
        monkeypatch.setattr(A, 'AUTH_FILE', str(d / 'auth.json'))
        monkeypatch.setattr(A, 'NODES_FILE', str(d / 'nodes.json'))
        monkeypatch.setattr(A, 'CHECKS_FILE', str(d / 'checks.json'))
        monkeypatch.setattr(A, 'ACKS_FILE', str(d / 'acks.json'))
        monkeypatch.setattr(A, 'TLS_CERT', str(d / 'certs' / 'c.crt'))
        monkeypatch.setattr(A, 'TLS_KEY', str(d / 'certs' / 'c.key'))
        monkeypatch.setattr(sso, 'STORE', str(d / 'sso.json'))
    point_at(src)
    out = tmp_path / 'b.ncb'
    assert A.cli_backup(['app.py', 'backup', str(out)]) == 0
    assert oct(out.stat().st_mode & 0o777) == '0o600'
    assert 'nodes.json' in capsys.readouterr().out
    # restore into a new install location
    dst = tmp_path / 'dst'
    point_at(dst)
    assert A.cli_restore(['app.py', 'restore', str(out)]) == 0
    assert (dst / 'nodes.json').read_text() == '{"nodes": []}'
    assert not (dst / 'checks.json').exists()        # was not in the source
    # second restore refuses; --force overwrites
    assert A.cli_restore(['app.py', 'restore', str(out)]) == 1
    assert 'refusing to overwrite' in capsys.readouterr().out
    assert A.cli_restore(['app.py', 'restore', str(out), '--force']) == 0
    monkeypatch.setenv('CONTROLLER_BACKUP_PASSPHRASE', 'wrong passphrase!')
    assert A.cli_restore(['app.py', 'restore', str(out), '--force']) == 1
