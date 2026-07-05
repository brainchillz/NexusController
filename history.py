"""Fleet history: a tiny SQLite ring buffer of per-host CPU / memory / storage
samples, plus pure trend math (availability, downsampling, capacity forecast).

The monitor thread records one row per host per cycle (reachable or not, so
availability is computable). Retention is a rolling window (HISTORY_DAYS),
pruned cheaply on each write. The store is deliberately small and disposable —
it lives in the same ./data volume as the registry, and losing it costs only
history, never configuration.

Pure functions (linreg / forecast / downsample) carry no I/O → unit-tested;
the store is exercised against a temp DB.
"""
import time
import sqlite3
import threading


# ─── Pure trend math ──────────────────────────────────────────────────
def linreg(points):
    """Least-squares slope+intercept for [(x, y), …] (x seconds, y bytes).
    Returns (slope_per_second, intercept) or (None, None) for <2 points or a
    degenerate x-range."""
    pts = [(float(x), float(y)) for x, y in points if x is not None and y is not None]
    n = len(pts)
    if n < 2:
        return None, None
    sx = sum(x for x, _ in pts)
    sy = sum(y for _, y in pts)
    sxx = sum(x * x for x, _ in pts)
    sxy = sum(x * y for x, y in pts)
    denom = n * sxx - sx * sx
    if denom == 0:
        return None, None
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    return slope, intercept


def forecast_capacity(points, size, used_now=None, min_span_hours=1.0):
    """Project when a filesystem fills. `points` = [(ts, used_bytes), …].
    Returns {'bytes_per_day', 'days_to_full', 'trend'} or None if there isn't
    enough signal (too few points, too short a span, or flat/shrinking)."""
    pts = [(x, y) for x, y in points if x is not None and y is not None]
    if len(pts) < 4 or not size:
        return None
    span = max(x for x, _ in pts) - min(x for x, _ in pts)
    if span < min_span_hours * 3600:
        return None
    slope, _ = linreg(pts)
    if slope is None:
        return None
    per_day = slope * 86400
    used = used_now if used_now is not None else pts[-1][1]
    # "flat" if it would take >10 years to move a full size at this rate
    if abs(per_day) < size / (3650 or 1):
        return {'bytes_per_day': per_day, 'days_to_full': None, 'trend': 'flat'}
    if per_day <= 0:
        return {'bytes_per_day': per_day, 'days_to_full': None, 'trend': 'shrinking'}
    remaining = max(0.0, size - used)
    return {'bytes_per_day': per_day,
            'days_to_full': remaining / per_day,
            'trend': 'growing'}


def downsample(rows, buckets):
    """Average [(ts, value), …] into at most `buckets` time-ordered buckets →
    [(bucket_ts, avg_value), …], skipping empty buckets. Values may be None
    (a down host); None-only buckets yield None."""
    rows = sorted((r for r in rows if r[0] is not None), key=lambda r: r[0])
    if not rows or buckets < 1:
        return []
    t0, t1 = rows[0][0], rows[-1][0]
    if t1 == t0:
        vals = [v for _, v in rows if v is not None]
        return [(t0, sum(vals) / len(vals) if vals else None)]
    width = (t1 - t0) / buckets
    acc = {}
    for ts, v in rows:
        b = min(buckets - 1, int((ts - t0) / width))
        acc.setdefault(b, []).append(v)
    out = []
    for b in sorted(acc):
        vals = [v for v in acc[b] if v is not None]
        out.append((int(t0 + b * width), (sum(vals) / len(vals)) if vals else None))
    return out


# ─── SQLite store ─────────────────────────────────────────────────────
class HistoryStore:
    """Thread-safe (one connection guarded by a lock; the writer is the single
    monitor thread, readers are request handlers). Small enough that a lock is
    fine."""

    def __init__(self, path, retention_days=30):
        self.path = path
        self.retention = retention_days * 86400
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute(
            'CREATE TABLE IF NOT EXISTS samples ('
            ' host_id TEXT NOT NULL, ts INTEGER NOT NULL, ok INTEGER NOT NULL,'
            ' cpu REAL, mem REAL, used INTEGER, size INTEGER)')
        self._db.execute(
            'CREATE INDEX IF NOT EXISTS ix_samples ON samples(host_id, ts)')
        self._db.commit()

    def record(self, results, now=None):
        """Persist one sample per host from a fan-out result set, then prune."""
        now = int(now if now is not None else time.time())
        rows = []
        for r in results:
            hid = r.get('id')
            if not hid:
                continue
            res = r.get('resources') or {}
            mem = (res.get('memory') or {}).get('pct')
            rows.append((hid, now, 1 if r.get('ok') else 0,
                         res.get('cpu_pct'), mem,
                         int(r.get('used_bytes') or 0) or None,
                         int(r.get('size_bytes') or 0) or None))
        with self._lock:
            self._db.executemany(
                'INSERT INTO samples(host_id,ts,ok,cpu,mem,used,size) '
                'VALUES (?,?,?,?,?,?,?)', rows)
            self._db.execute('DELETE FROM samples WHERE ts < ?', (now - self.retention,))
            self._db.commit()

    def _query(self, host_id, since, cols):
        with self._lock:
            cur = self._db.execute(
                f'SELECT ts,{cols} FROM samples WHERE host_id=? AND ts>=? ORDER BY ts',
                (host_id, since))
            return cur.fetchall()

    def series(self, host_id, hours, buckets, metric='cpu'):
        """Downsampled [(ts, value), …] for one metric over the last `hours`."""
        since = int(time.time()) - int(hours * 3600)
        col = {'cpu': 'cpu', 'mem': 'mem'}.get(metric, 'cpu')
        rows = self._query(host_id, since, col)
        return downsample([(ts, v) for ts, v in rows], buckets)

    def availability(self, host_id, hours):
        """Fraction of samples in the window where the host was reachable."""
        since = int(time.time()) - int(hours * 3600)
        with self._lock:
            cur = self._db.execute(
                'SELECT AVG(ok), COUNT(*) FROM samples WHERE host_id=? AND ts>=?',
                (host_id, since))
            avg, n = cur.fetchone()
        return (round(avg * 100, 2) if avg is not None else None), (n or 0)

    def storage_points(self, host_id, hours):
        """[(ts, used_bytes), …] for capacity forecasting (reachable samples)."""
        since = int(time.time()) - int(hours * 3600)
        return [(ts, used) for ts, used in self._query(host_id, since, 'used')
                if used is not None]

    def close(self):
        with self._lock:
            self._db.close()
