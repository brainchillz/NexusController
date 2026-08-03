"""Pure monitoring logic: turn a fan-out envelope into a set of alertable
CONDITIONS, diff successive snapshots into state-transition EVENTS, and format
those events + webhook bodies. No I/O, no threads → unit-tested; app.py owns
the monitor loop, the webhook POST, and the config store.
"""

# severity order (worst first) for sorting a digest
SEVERITY = {'critical': 0, 'warning': 1, 'info': 2}


def host_conditions(env):
    """Currently-firing alertable conditions for one host envelope →
    {key: {'severity', 'detail'}}. Only conditions worth waking someone for;
    transient enroll states (awaiting first poll) are deliberately excluded."""
    conds = {}
    if env.get('disabled'):
        return conds   # monitoring paused (host out of service on purpose)
    err = (env.get('error') or '')
    if not env.get('ok'):
        if 'await' in err.lower():
            return conds   # first-poll warmup — not an alert
        if 'fingerprint changed' in err.lower():
            conds['cert_changed'] = {'severity': 'critical',
                                     'detail': 'TLS certificate fingerprint changed'}
        else:
            conds['unreachable'] = {'severity': 'critical',
                                    'detail': err or 'host unreachable'}
        return conds   # a down host: don't also fire its stale sub-conditions

    summary = env.get('summary') or {}
    n_alerts = len(summary.get('alerts') or [])
    nas = env.get('nas') or {}
    n_alerts += nas.get('alerts') or 0
    if n_alerts:
        conds['alerts'] = {'severity': 'warning',
                           'detail': f'{n_alerts} active alert(s)'}

    if nas.get('pools_degraded'):
        conds['pool_degraded'] = {'severity': 'critical',
                                  'detail': f"{nas['pools_degraded']} pool(s) degraded"}
    spark = env.get('spark') or {}
    if spark and spark.get('healthy') is False:
        conds['cluster_unhealthy'] = {'severity': 'critical',
                                      'detail': 'cluster reports unhealthy'}
    zfs = summary.get('zfs') or {}
    if zfs.get('pools') and not zfs.get('online', True):
        conds['pool_degraded'] = {'severity': 'critical', 'detail': 'a ZFS pool is offline'}

    down = _services_down(summary)
    if down:
        conds['services_down'] = {'severity': 'warning',
                                  'detail': f'{down} enabled service(s) not running'}
    failed = [c for c in env.get('svc_checks') or [] if c.get('ok') is False]
    if failed:   # pinned service checks (ok None = not probed yet — not a failure)
        names = ', '.join(c.get('name') or '?' for c in failed)
        conds['check_failed'] = {'severity': 'warning',
                                 'detail': (f'service check failing: {names}'
                                            if len(failed) == 1 else
                                            f'{len(failed)} service checks failing: {names}')}
    if env.get('stale'):
        conds['stale'] = {'severity': 'warning', 'detail': 'background poll is stale'}
    if env.get('version_lag'):
        conds['version_lag'] = {'severity': 'info',
                                'detail': f"behind fleet (newest v{env['version_lag']})"}
    return conds


def _services_down(summary):
    svcs = (summary or {}).get('services') or {}
    return sum(1 for sv in svcs.values()
               if sv.get('enabled') == 'enabled' and sv.get('active') != 'active')


def health_entries(env):
    """Warning-or-worse conditions for one envelope as structured entries
    [{'key','severity','detail'}, …] — drives the status dot, its tooltip,
    and the Alerts tab. Info-level conditions (version_lag) stay out: they
    tint the version text, not the dot."""
    return [{'key': k, 'severity': c['severity'], 'detail': c['detail']}
            for k, c in host_conditions(env).items()
            if c['severity'] in ('warning', 'critical')]


# Wallboard resource thresholds (percent). A host that is otherwise healthy
# turns amber when any of these are breached.
BOARD_CPU_PCT = 90
BOARD_MEM_PCT = 90
BOARD_STORAGE_PCT = 90


def board_state(env):
    """Public wallboard state for one host envelope → (state, issues).
    'grey'  = monitoring paused on purpose
    'red'   = unreachable OR any warning+ health condition (incl. failing
              pinned checks) — the issues list carries the detail text
    'amber' = healthy but resource-constrained (CPU/memory/storage too high).
              Memory pressure is IGNORED for AI hosts (models pinned in RAM)
              and ZFS/TrueNAS storage hosts (ARC eats free memory by design).
    'green' = everything green. Pure → unit-tested."""
    if env.get('disabled'):
        return 'grey', []
    if not env.get('ok'):
        err = env.get('error') or ''
        if err.lower().startswith('await'):
            # first-poll warmup after a (re)start — transient, not a failure
            return 'amber', ['awaiting first poll']
        return 'red', [err or 'unreachable']
    issues = [e['detail'] for e in env.get('health') or []]
    if issues:
        return 'red', issues
    amber = []
    res = env.get('resources') or {}
    cpu = res.get('cpu_pct')
    if cpu is not None and cpu >= BOARD_CPU_PCT:
        amber.append('high CPU (%d%%)' % round(cpu))
    mem = (res.get('memory') or {}).get('pct')
    zfs = (env.get('summary') or {}).get('zfs') or {}
    mem_exempt = (env.get('type') == 'AI' or bool(zfs.get('pools'))
                  or env.get('host_type') == 'truenas')
    if mem is not None and mem >= BOARD_MEM_PCT and not mem_exempt:
        amber.append('high memory (%d%%)' % round(mem))
    size = env.get('size_bytes') or 0
    if size:
        pct = (env.get('used_bytes') or 0) * 100.0 / size
        if pct >= BOARD_STORAGE_PCT:
            amber.append('storage %d%% full' % round(pct))
    if amber:
        return 'amber', amber
    return 'green', []


def snapshot_conditions(results):
    """{host_id: {'name', 'conditions'}} for a whole fan-out result set."""
    return {r['id']: {'name': r.get('name', r['id']), 'conditions': host_conditions(r)}
            for r in results if r.get('id')}


def diff_snapshots(prev, cur):
    """Two snapshot_conditions() maps → a list of transition events. A condition
    that appears is a 'firing' event; one that clears is 'recovered'. Hosts that
    vanish from the registry are ignored (no orphan 'recovered' spam)."""
    events = []
    for hid, entry in cur.items():
        name = entry['name']
        pconds = (prev.get(hid) or {}).get('conditions', {})
        cconds = entry['conditions']
        for key, meta in cconds.items():
            if key not in pconds:
                events.append({'host_id': hid, 'host': name, 'key': key,
                               'kind': 'firing', 'severity': meta['severity'],
                               'detail': meta['detail']})
        for key, meta in pconds.items():
            if key not in cconds and hid in cur:
                events.append({'host_id': hid, 'host': name, 'key': key,
                               'kind': 'recovered', 'severity': meta['severity'],
                               'detail': meta['detail']})
    events.sort(key=lambda e: (e['kind'] != 'firing', SEVERITY.get(e['severity'], 3)))
    return events


_ICON = {'firing': {'critical': '🔴', 'warning': '🟠', 'info': '🟡'},
         'recovered': {'critical': '🟢', 'warning': '🟢', 'info': '🟢'}}


def format_event(ev):
    """One transition event → a human line."""
    icon = _ICON.get(ev['kind'], {}).get(ev['severity'], '•')
    if ev['kind'] == 'recovered':
        return f"{icon} *{ev['host']}* recovered: {ev['detail']}"
    return f"{icon} *{ev['host']}*: {ev['detail']}"


def format_digest(events, title='Nexus Controller'):
    """Batch of events → one notification body (title + lines)."""
    lines = [format_event(e) for e in events]
    return title, '\n'.join(lines)


def webhook_payload(fmt, title, text):
    """Build the (json, data, headers) tuple for one webhook flavor. 'text' is
    the message body; 'title' a short heading. Returns a dict the caller feeds
    to requests.post as keyword args."""
    fmt = (fmt or 'gchat').lower()
    full = (f'*{title}*\n{text}' if title else text)
    if fmt in ('gchat', 'google', 'slack', 'text'):
        # Google Chat + Slack both take {"text": …}; markdown-ish is fine.
        return {'json': {'text': full}}
    if fmt == 'ntfy':
        return {'data': text.encode('utf-8'),
                'headers': {'Title': title, 'Markdown': 'yes'}}
    if fmt == 'gotify':
        return {'json': {'title': title, 'message': text}}
    if fmt == 'discord':
        return {'json': {'content': full[:1900]}}
    # 'json' / anything else: a general structured body
    return {'json': {'title': title, 'text': text}}
