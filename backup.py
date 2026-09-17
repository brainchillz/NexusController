"""Encrypted configuration backup + restore.

The registry (nodes.json) is useless without the Fernet key in the auth file,
and the auth file alone is a controller with no hosts — so the unit of backup
is the SET: auth, registry, checks, SSO enrollment, and the serving TLS
cert+key. history.db (disposable) and audit.log (append-only evidence, not
config) are deliberately left out.

Bundle = JSON envelope {format, created, salt, iterations, data} where `data`
is a Fernet token over the JSON file map, keyed by PBKDF2-HMAC-SHA256 of an
operator passphrase. Wrong passphrase, tampering and a foreign file all raise
ValueError. Pure (no app imports); the app owns the paths and the routes.
Restore is CLI-only by design: it must run while the controller is stopped
(in-process caches, the Fernet key), never into a live process.
"""
import os
import json
import base64
import tempfile
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

FORMAT = 'nexus-controller-backup/1'
KDF_ITERATIONS = 600_000
MIN_PASSPHRASE = 12
# Logical name → what it is (the app maps names to its configured paths).
MEMBERS = ('controller-auth.json', 'nodes.json', 'checks.json', 'sso.json',
           'certs/controller.crt', 'certs/controller.key')


def derive_key(passphrase, salt, iterations=KDF_ITERATIONS):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))


def make_bundle(files, passphrase, iterations=KDF_ITERATIONS, now=None):
    """{name: text} + passphrase → bundle bytes."""
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise ValueError('passphrase must be at least %d characters' % MIN_PASSPHRASE)
    salt = os.urandom(16)
    f = Fernet(derive_key(passphrase, salt, iterations))
    payload = json.dumps({'files': dict(files)}, sort_keys=True).encode('utf-8')
    env = {'format': FORMAT,
           'created': (now or datetime.now(timezone.utc)).isoformat(timespec='seconds'),
           'kdf': 'pbkdf2-sha256', 'iterations': iterations,
           'salt': base64.b64encode(salt).decode(),
           'members': sorted(files),
           'data': f.encrypt(payload).decode()}
    return (json.dumps(env, indent=1) + '\n').encode('utf-8')


def inspect_bundle(blob):
    """Header only (no passphrase): {'format','created','members'}."""
    try:
        env = json.loads(blob.decode('utf-8') if isinstance(blob, bytes) else blob)
    except (ValueError, UnicodeDecodeError):
        raise ValueError('not a controller backup')
    if not isinstance(env, dict) or env.get('format') != FORMAT:
        raise ValueError('not a controller backup')
    return {'format': env['format'], 'created': env.get('created'),
            'members': list(env.get('members') or [])}


def open_bundle(blob, passphrase):
    """bundle bytes + passphrase → {name: text}. ValueError on a wrong
    passphrase, a tampered bundle, or a file that is not a backup."""
    inspect_bundle(blob)
    env = json.loads(blob.decode('utf-8') if isinstance(blob, bytes) else blob)
    try:
        salt = base64.b64decode(env['salt'])
        iterations = int(env['iterations'])
        f = Fernet(derive_key(passphrase or '', salt, iterations))
        payload = json.loads(f.decrypt(env['data'].encode()).decode('utf-8'))
    except (KeyError, ValueError, TypeError, InvalidToken):
        raise ValueError('wrong passphrase or corrupt bundle')
    files = payload.get('files') if isinstance(payload, dict) else None
    if not isinstance(files, dict):
        raise ValueError('wrong passphrase or corrupt bundle')
    return files


def collect(paths):
    """{name: path} → {name: text} for the files that exist."""
    out = {}
    for name, path in paths.items():
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                out[name] = fh.read()
        except FileNotFoundError:
            continue
    return out


def restore(files, paths, force=False):
    """Write {name: text} to {name: path}. Refuses to overwrite ANY existing
    target unless force (a restore into a live install is the mistake this
    guards against). Files are written 0600, atomically, dirs created.
    Returns the paths written; unknown names are ignored."""
    targets = {n: paths[n] for n in files if n in paths}
    if not force:
        clash = [p for p in targets.values() if os.path.exists(p)]
        if clash:
            raise FileExistsError('refusing to overwrite: ' + ', '.join(sorted(clash)))
    written = []
    for name, path in targets.items():
        d = os.path.dirname(path) or '.'
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix='.restore-')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                fh.write(files[name])
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            written.append(path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    return written
