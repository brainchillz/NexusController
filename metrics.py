"""Prometheus / OpenMetrics exposition of the fleet. Pure: takes the fleet
snapshot the controller already holds (the fan-out cache) plus the check
definitions and their latest results, and renders text. No I/O → unit-tested.
The route (app.py) does scoping and serves the cache only — a scrape must
never trigger a fan-out.

Series (all gauges, prefix nexus_):
  nexus_controller_info{version}                     1
  nexus_fleet_generated_timestamp_seconds            when the snapshot was built
  nexus_fleet_hosts{state}                           healthy|unreachable|paused|degraded
  nexus_fleet_storage_bytes{kind}                    used|size (sum over hosts)
  per host  {host,name,host_type,category}:
    nexus_host_paused                                1|0 (every host)
    nexus_host_up                                    1|0 (non-paused hosts)
    nexus_host_cpu_percent / nexus_host_memory_percent
    nexus_host_storage_bytes{kind}                   used|size
    nexus_host_alerts                                node/NAS alert count
    nexus_host_health_issues                         warning+ conditions (count)
    nexus_host_health_issue{key,severity}            1 per active condition
    nexus_host_guests{kind,state}                    vm|container × running|total
    nexus_host_updates_pending / nexus_host_security_updates_pending
    nexus_host_reboot_required / nexus_host_version_lag / nexus_host_stale
  per check {check,name,service,target,host}:
    nexus_check_up                                   1|0 (absent while unprobed/paused)
    nexus_check_latency_seconds
"""
from datetime import datetime

CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8'


def _lv(v):
    """Escape a label value per the exposition format."""
    return str('' if v is None else v).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def _num(v):
    if isinstance(v, bool):
        return '1' if v else '0'
    if isinstance(v, int):
        return str(v)
    f = float(v)
    return str(int(f)) if f.is_integer() else repr(f)


def line(name, labels, value):
    if labels:
        lab = '{' + ','.join('%s="%s"' % (k, _lv(v)) for k, v in labels.items()) + '}'
    else:
        lab = ''
    return '%s%s %s' % (name, lab, _num(value))


def _ts(iso):
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return None


def _host_lines(r):
    labels = {'host': r.get('id'), 'name': r.get('name'),
              'host_type': r.get('host_type') or 'nexus',
              'category': r.get('type') or 'Unknown'}
    out = [line('nexus_host_paused', labels, bool(r.get('disabled')))]
    if r.get('disabled'):
        return out
    out.append(line('nexus_host_up', labels, bool(r.get('ok'))))
    res = r.get('resources') or {}
    if res.get('cpu_pct') is not None:
        out.append(line('nexus_host_cpu_percent', labels, res['cpu_pct']))
    mem = (res.get('memory') or {}).get('pct')
    if mem is not None:
        out.append(line('nexus_host_memory_percent', labels, mem))
    if r.get('size_bytes'):
        out.append(line('nexus_host_storage_bytes', {**labels, 'kind': 'used'}, r.get('used_bytes') or 0))
        out.append(line('nexus_host_storage_bytes', {**labels, 'kind': 'size'}, r['size_bytes']))
    if not r.get('ok'):
        return out
    s = r.get('summary') or {}
    nas = r.get('nas') or {}
    out.append(line('nexus_host_alerts', labels,
                    len(s.get('alerts') or []) + (nas.get('alerts') or 0)))
    health = r.get('health') or []
    out.append(line('nexus_host_health_issues', labels, len(health)))
    for e in health:
        out.append(line('nexus_host_health_issue',
                        {**labels, 'key': e.get('key'), 'severity': e.get('severity')}, 1))
    v = r.get('virt') or {}
    i = r.get('instances') or {}
    if v or i:
        vms_t = (v.get('vms') or 0) + (i.get('vms') or 0)
        vms_r = (v.get('vms_running') or 0) + (i.get('vms_running') or 0)
        ct_t = (v.get('containers') or 0) + (i.get('containers') or 0)
        ct_r = (v.get('containers_running') or 0) + (i.get('containers_running') or 0)
        if not i and v:
            pass
        if i and 'running' in i and 'vms_running' not in i:
            # nexus LXD block reports one running total, not per kind
            vms_r, ct_r = i.get('running') or 0, 0
        out.append(line('nexus_host_guests', {**labels, 'kind': 'vm', 'state': 'total'}, vms_t))
        out.append(line('nexus_host_guests', {**labels, 'kind': 'vm', 'state': 'running'}, vms_r))
        out.append(line('nexus_host_guests', {**labels, 'kind': 'container', 'state': 'total'}, ct_t))
        out.append(line('nexus_host_guests', {**labels, 'kind': 'container', 'state': 'running'}, ct_r))
    u = s.get('updates') or {}
    if u:
        out.append(line('nexus_host_updates_pending', labels, u.get('available') or 0))
        out.append(line('nexus_host_security_updates_pending', labels, u.get('security') or 0))
        out.append(line('nexus_host_reboot_required', labels, bool(u.get('reboot_required'))))
    out.append(line('nexus_host_version_lag', labels, bool(r.get('version_lag'))))
    out.append(line('nexus_host_stale', labels, bool(r.get('stale'))))
    return out


def _check_lines(c, res, host_names):
    labels = {'check': c.get('id'), 'name': c.get('name'), 'service': c.get('service'),
              'target': c.get('target'), 'host': host_names.get(c.get('node_id')) or ''}
    res = res or {}
    out = []
    if res.get('ok') is None or res.get('paused'):
        return out
    out.append(line('nexus_check_up', labels, bool(res.get('ok'))))
    if res.get('latency_ms') is not None:
        out.append(line('nexus_check_latency_seconds', labels, res['latency_ms'] / 1000.0))
    return out


def render(fleet, checks, check_results, host_names, version):
    """fleet = the (scoped) fleet payload {'nodes', 'rollup', 'generated_at'}
    or None while warming; checks = definitions; check_results = {id: result}.
    Returns the exposition text (trailing newline included)."""
    out = ['# HELP nexus_controller_info Nexus Controller build.',
           '# TYPE nexus_controller_info gauge',
           line('nexus_controller_info', {'version': version}, 1)]
    if fleet:
        ts = _ts(fleet.get('generated_at'))
        if ts is not None:
            out += ['# TYPE nexus_fleet_generated_timestamp_seconds gauge',
                    line('nexus_fleet_generated_timestamp_seconds', {}, ts)]
        ro = fleet.get('rollup') or {}
        out.append('# TYPE nexus_fleet_hosts gauge')
        for st, key in (('healthy', 'healthy'), ('unreachable', 'unreachable'),
                        ('paused', 'disabled'), ('degraded', 'degraded')):
            out.append(line('nexus_fleet_hosts', {'state': st}, ro.get(key) or 0))
        out += ['# TYPE nexus_fleet_storage_bytes gauge',
                line('nexus_fleet_storage_bytes', {'kind': 'used'}, ro.get('storage_used') or 0),
                line('nexus_fleet_storage_bytes', {'kind': 'size'}, ro.get('storage_size') or 0)]
        host_lines = []
        for r in sorted(fleet.get('nodes') or [], key=lambda r: str(r.get('name', '')).lower()):
            host_lines += _host_lines(r)
        if host_lines:
            out.append('# HELP nexus_host_up 1 when the last poll reached the host.')
            out += host_lines
    check_lines = []
    for c in checks or []:
        check_lines += _check_lines(c, (check_results or {}).get(c.get('id')), host_names or {})
    if check_lines:
        out.append('# HELP nexus_check_up 1 when the service check passed on its last run.')
        out += check_lines
    return '\n'.join(out) + '\n'
