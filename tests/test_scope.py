"""Tag-scoped RBAC pure helpers: scope resolution from a user record, the
per-node allow check, fleet-payload filtering (with rollup recompute), and
scope-tag normalization. No network, no session."""
import app


# ── clean_scope_tags ─────────────────────────────────────────────────
def test_clean_tags_trims_dedupes_and_drops_empties():
    assert app.clean_scope_tags([' prod ', 'prod', '', '  ', 'lab']) == ['prod', 'lab']


def test_clean_tags_non_list_is_empty():
    assert app.clean_scope_tags('prod') == []
    assert app.clean_scope_tags(None) == []


def test_clean_tags_coerces_and_caps():
    assert app.clean_scope_tags([1, 2.5]) == ['1', '2.5']
    assert len(app.clean_scope_tags(['t%d' % i for i in range(50)])) == 32


# ── user_scope ───────────────────────────────────────────────────────
def test_admin_is_always_unscoped():
    assert app.user_scope({'role': 'admin', 'tags': ['prod']}, 'admin') is None


def test_untagged_account_is_unscoped():
    assert app.user_scope({'role': 'viewer'}, 'viewer') is None
    assert app.user_scope({'role': 'operator', 'tags': []}, 'operator') is None


def test_tagged_account_gets_tag_set():
    assert app.user_scope({'role': 'viewer', 'tags': ['prod', 'lab']}, 'viewer') \
        == {'prod', 'lab'}


def test_legacy_bare_record_is_unscoped():
    assert app.user_scope('bare-hash-string', 'viewer') is None


# ── scope_allows ─────────────────────────────────────────────────────
def test_unscoped_sees_everything():
    assert app.scope_allows(None, {'tags': []})
    assert app.scope_allows(None, {})


def test_scope_matches_any_tag():
    assert app.scope_allows({'prod'}, {'tags': ['prod', 'rack3']})
    assert app.scope_allows({'prod', 'lab'}, {'tags': ['lab']})


def test_scope_blocks_untagged_and_mismatched_hosts():
    assert not app.scope_allows({'prod'}, {'tags': ['lab']})
    assert not app.scope_allows({'prod'}, {'tags': []})
    assert not app.scope_allows({'prod'}, {})


# ── scoped_fleet ─────────────────────────────────────────────────────
def _fleet():
    return {'nodes': [
        {'id': 'a', 'name': 'a', 'ok': True, 'tags': ['prod'],
         'summary': {'alerts': []}, 'used_bytes': 10, 'size_bytes': 100},
        {'id': 'b', 'name': 'b', 'ok': False, 'tags': ['lab'], 'error': 'down'},
    ], 'rollup': app.compute_rollup([])}


def test_scoped_fleet_unscoped_passthrough():
    data = _fleet()
    assert app.scoped_fleet(data, None) is data


def test_scoped_fleet_filters_and_recomputes_rollup():
    out = app.scoped_fleet(_fleet(), {'prod'})
    assert [n['id'] for n in out['nodes']] == ['a']
    assert out['rollup']['total'] == 1
    assert out['rollup']['unreachable'] == 0   # the down lab box is invisible


def test_scoped_fleet_no_match_is_empty_not_error():
    out = app.scoped_fleet(_fleet(), {'nothing'})
    assert out['nodes'] == []
    assert out['rollup']['total'] == 0


# ── scope presets (named tag groupings) ──────────────────────────────
PRESETS = {'media': ['nas', 'docker'], 'labops': ['lab']}


def test_preset_resolves_live():
    rec = {'role': 'viewer', 'scope_preset': 'media'}
    assert app.user_scope(rec, 'viewer', PRESETS) == {'nas', 'docker'}


def test_preset_wins_over_literal_tags():
    rec = {'role': 'viewer', 'scope_preset': 'labops', 'tags': ['prod']}
    assert app.user_scope(rec, 'viewer', PRESETS) == {'lab'}


def test_dangling_preset_fails_closed():
    rec = {'role': 'operator', 'scope_preset': 'deleted-role'}
    scope = app.user_scope(rec, 'operator', PRESETS)
    assert scope == set()
    # an empty scope matches no host — even untagged ones
    assert not app.scope_allows(scope, {'tags': ['prod']})
    assert not app.scope_allows(scope, {})


def test_admin_ignores_presets():
    rec = {'role': 'admin', 'scope_preset': 'media'}
    assert app.user_scope(rec, 'admin', PRESETS) is None
