"""UnifiDash — network host type.

Pulls one versioned snapshot from a UnifiDash instance's read-only API
(`/api/overview`) and normalizes it into an envelope carrying a `network`
block: WAN/LAN throughput, client counts, internet latency and issue counts.

Unlike every other host type here this describes a *network*, not a machine —
it has no CPU, memory or storage, so the envelope leaves those at their base
defaults and the SPA gives it its own row renderer rather than the usual
resource bars.

Auth: the token is OPTIONAL. `/api/overview` is served to anonymous callers
when UnifiDash's `access.publicOverview` setting is on, which is the common
case for a LAN instance; a token (`unfd_…`) is used when supplied and is
required if that setting is off. Same shape as the sparkdash adapter.
"""
from .base import (HostAdapter, NodeError, base_envelope, cert_fingerprint,
                   envelope_error, pinned_request, _split_host_port,
                   NODE_TIMEOUT)

# Severities UnifiDash reports, worst first. Only `critical` drives the red
# box; the rest are carried so the drill-in and the tooltip can show context.
SEVERITIES = ('critical', 'warning', 'info')


def _auth_headers(token):
    # UnifiDash accepts either; Bearer matches the rest of the suite.
    return {'Authorization': 'Bearer ' + token} if token else {}


def build_unifi_envelope(node, snap):
    """Normalize an /api/overview payload into a fleet envelope."""
    out = base_envelope(node)
    out['ok'] = True
    counts = snap.get('counts') or {}
    thr = snap.get('throughput') or {}
    wan = snap.get('wan') or {}

    # Only ACTIVE, UNACKNOWLEDGED issues are worth surfacing on the overview —
    # an acknowledged issue is one someone has already looked at, and a
    # resolved one is history. The tooltip shows the worst few in full.
    live = [i for i in (snap.get('issues') or [])
            if i.get('active') and not i.get('ackedAt')]
    live.sort(key=lambda i: (SEVERITIES.index(i['severity'])
                             if i.get('severity') in SEVERITIES else len(SEVERITIES),
                             -(i.get('occurrences') or 0)))

    def _tally(sev):
        return sum(1 for i in live if i.get('severity') == sev)

    out['network'] = {
        'wan_rx_bps': thr.get('wanRxBps') or 0,
        'wan_tx_bps': thr.get('wanTxBps') or 0,
        'lan_rx_bps': thr.get('lanRxBps') or 0,
        'lan_tx_bps': thr.get('lanTxBps') or 0,
        'clients': counts.get('clients') or 0,
        'wireless': counts.get('wireless') or 0,
        'wired': counts.get('wired') or 0,
        'devices_online': counts.get('devicesOnline') or 0,
        'devices_total': counts.get('devicesTotal') or 0,
        'latency_ms': wan.get('latencyMs'),
        'wan_status': wan.get('status') or 'unknown',
        'isp': wan.get('isp') or '',
        'critical': _tally('critical'),
        'warning': _tally('warning'),
        'info': _tally('info'),
        # Trimmed for the tooltip: enough to say what is wrong and where.
        'issues': [{'severity': i.get('severity'),
                    'kind': i.get('kind'),
                    'subject': i.get('subjectName') or i.get('subject') or '',
                    'message': i.get('message') or ''}
                   for i in live[:12]],
        'subsystems': [{'name': s.get('name'), 'status': s.get('status')}
                       for s in (snap.get('subsystems') or [])],
        'generated_at': snap.get('generatedAt'),
    }
    # A critical issue is the fleet-level health signal for this host; warnings
    # stay off the rollup so the overview does not cry wolf.
    if out['network']['critical']:
        out['summary'] = {'alerts': [
            '%s: %s' % (i['subject'], i['message']) for i in live
            if i.get('severity') == 'critical'][:5]}
    out['type_auto'] = 'Network'
    return out


class UnifiAdapter(HostAdapter):
    kind = 'unifi'
    label = 'UnifiDash (UniFi network)'
    auth = 'token'
    secret_label = 'API token'
    secret_placeholder = 'unfd_… (optional — blank uses the public overview)'
    url_placeholder = 'https://unifi-dash.local'
    default_type = 'Network'
    verify_tls = False   # pin-only, like the other self-signed hosts here

    # ── helpers ────────────────────────────────────────────────────────

    def _overview(self, base_url, fingerprint, token=None):
        """One pinned GET of the overview snapshot. Raises NodeError."""
        r = pinned_request('GET', base_url.rstrip('/') + '/api/overview',
                           fingerprint, headers=_auth_headers(token),
                           timeout=NODE_TIMEOUT)
        if r.status_code in (401, 403):
            raise NodeError('overview requires authentication — supply an API '
                            'token, or enable the public overview in UnifiDash')
        if r.status_code != 200:
            raise NodeError(f'overview failed (HTTP {r.status_code})')
        try:
            snap = r.json()
        except ValueError:
            raise NodeError('overview returned non-JSON (is this a UnifiDash URL?)')
        if not isinstance(snap, dict) or 'counts' not in snap or 'throughput' not in snap:
            raise NodeError('unexpected overview shape (is this a UnifiDash URL?)')
        return snap

    # ── contract ───────────────────────────────────────────────────────

    def probe(self, base_url, creds):
        token = ((creds or {}).get('token') or '').strip()
        host, port = _split_host_port(base_url)
        if not host:
            raise NodeError('invalid base URL')
        if not base_url.lower().startswith('https://'):
            # Pinning is the whole trust model for these host types, and there
            # is nothing to pin over plain HTTP. Refuse rather than silently
            # polling an unauthenticated, unencrypted endpoint.
            raise NodeError('UnifiDash must be reached over https:// so its '
                            'certificate can be pinned — put it behind a TLS '
                            'reverse proxy')
        try:
            fp = cert_fingerprint(host, port)
        except OSError as e:
            raise NodeError(f'cannot reach {host}:{port} ({e})')
        snap = self._overview(base_url, fp, token)
        return {'cert_fp': fp,
                'role': 'admin' if token else None,
                'version': None,
                'fqdn': host,
                'capabilities': [self.kind],
                'metrics': snap}

    def fetch(self, node):
        """Fan-out: one pinned call. MUST NOT raise — a single unreachable
        host must never crash the whole fleet view. envelope_error returns the
        condensed message, so it is attached to a base envelope rather than
        returned in place of one."""
        out = base_envelope(node)
        try:
            from .base import decrypt_secret
            token = decrypt_secret(node.get('token_enc', '')) if node.get('token_enc') else None
            snap = self._overview(node['base_url'], node.get('cert_fp'), token)
            return build_unifi_envelope(node, snap)
        except NodeError as e:
            out['error'] = envelope_error(node, e)
        except Exception as e:
            out['error'] = envelope_error(node, e)
        return out

    def native_url(self, node):
        # No controller-side drill-in for a network: send the operator to
        # UnifiDash itself, which is where the detail actually lives.
        return node['base_url']
