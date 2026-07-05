"""History: pure trend math (linreg / forecast / downsample) + the SQLite
store (temp DB)."""
import time
import history


def test_linreg_basic():
    slope, intercept = history.linreg([(0, 0), (10, 100), (20, 200)])
    assert round(slope, 3) == 10.0 and round(intercept, 3) == 0.0
    assert history.linreg([(5, 1)]) == (None, None)
    assert history.linreg([(5, 1), (5, 2)]) == (None, None)  # zero x-range


def test_forecast_growing_days_to_full():
    GB = 1024 ** 3
    size = 100 * GB
    # 5 samples over 5h, +1 GB/hour → 24 GB/day
    pts = [(i * 3600, (50 + i) * GB) for i in range(6)]
    fc = history.forecast_capacity(pts, size, used_now=55 * GB)
    assert fc['trend'] == 'growing'
    assert round(fc['bytes_per_day'] / GB) == 24
    assert round(fc['days_to_full']) == round((100 - 55) / 24)   # ~1.9 days


def test_forecast_flat_and_shrinking():
    GB = 1024 ** 3
    flat = [(i * 3600, 50 * GB) for i in range(6)]
    assert history.forecast_capacity(flat, 100 * GB)['trend'] == 'flat'
    shrink = [(i * 3600, (60 - i) * GB) for i in range(6)]
    fc = history.forecast_capacity(shrink, 100 * GB)
    assert fc['trend'] == 'shrinking' and fc['days_to_full'] is None


def test_forecast_needs_enough_signal():
    GB = 1024 ** 3
    assert history.forecast_capacity([(0, 1), (3600, 2)], 100 * GB) is None  # too few
    # 5 points but only 10 min span → not enough time
    short = [(i * 120, (50 + i) * GB) for i in range(6)]
    assert history.forecast_capacity(short, 100 * GB) is None


def test_downsample_buckets_and_gaps():
    rows = [(i, i * 1.0) for i in range(100)]
    out = history.downsample(rows, 10)
    assert len(out) == 10
    assert out[0][1] < out[-1][1]         # increasing
    # None values in a bucket are ignored; an all-None bucket yields None
    assert history.downsample([(0, None), (1, None)], 1)[0][1] is None


def test_store_record_series_availability(tmp_path):
    store = history.HistoryStore(str(tmp_path / 'h.db'), retention_days=1)
    now = int(time.time())
    GB = 1024 ** 3
    # 10 cycles: host up 8, down 2; cpu ramps
    for i in range(10):
        ok = i not in (3, 4)
        env = {'id': 'n1', 'name': 'silo', 'ok': ok,
               'resources': {'cpu_pct': float(i * 5), 'memory': {'pct': 40.0}} if ok else {},
               'used_bytes': (50 + i) * GB if ok else 0, 'size_bytes': 100 * GB if ok else 0}
        store.record([env], now=now - (10 - i) * 60)
    avail, n = store.availability('n1', hours=1)
    assert n == 10 and avail == 80.0
    ser = store.series('n1', hours=1, buckets=5, metric='cpu')
    assert ser and all(0 <= v <= 100 for _, v in ser if v is not None)
    sp = store.storage_points('n1', hours=1)
    assert len(sp) == 8 and sp[-1][1] > sp[0][1]
    store.close()


def test_store_prunes_old_rows(tmp_path):
    store = history.HistoryStore(str(tmp_path / 'h.db'), retention_days=1)
    now = int(time.time())
    store.record([{'id': 'n1', 'ok': True, 'resources': {'cpu_pct': 1}}], now=now - 3 * 86400)
    store.record([{'id': 'n1', 'ok': True, 'resources': {'cpu_pct': 2}}], now=now)
    _, n = store.availability('n1', hours=48)
    assert n == 1   # the 3-day-old row was pruned
    store.close()


# ── history HTTP endpoints ────────────────────────────────────────────
def test_history_endpoints(client, monkeypatch):
    import app as A
    with client.session_transaction() as s:
        s['user'] = 'admin'
    # a node in the registry + a seeded history row
    A.save_nodes({'nodes': [{'id': 'h1', 'name': 'box', 'base_url': 'https://x:9143',
                             'host_type': 'agent'}]})
    GB = 1024 ** 3
    hist = A.get_history()
    now = int(time.time())
    for i in range(8):
        hist.record([{'id': 'h1', 'ok': True,
                      'resources': {'cpu_pct': i * 8.0, 'memory': {'pct': 30.0}},
                      'used_bytes': (40 + i) * GB, 'size_bytes': 100 * GB}],
                    now=now - (8 - i) * 3600)
    sp = client.get('/api/history/spark?hours=48&buckets=8').get_json()
    assert 'h1' in sp['spark'] and len(sp['spark']['h1']) >= 2
    su = client.get('/api/history/summary?hours=48').get_json()
    assert su['hosts']['h1']['availability'] == 100.0
    hd = client.get('/api/history/h1?hours=48').get_json()
    assert hd['cpu'] and hd['availability'] == 100.0
    assert client.get('/api/history/nope').status_code == 404
