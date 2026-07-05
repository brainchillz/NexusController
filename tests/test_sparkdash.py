"""SparkDash adapter: envelope building from /api/v1/snapshot (fixture trimmed
from the live fred/barney cluster) + adapter wiring. Pure — no network."""
import app


SNAP = {
    'ts': 1783198905.6,
    'cluster_healthy': True,
    'node_count': 2,
    'ray': {'reachable': True, 'nodes_alive': 2, 'nodes_total': 2},
    'vllm': {'reachable': True, 'healthy': True,
             'model': 'lukealonso/MiniMax-M2.7-NVFP4', 'max_model_len': 225000,
             'metrics': {'vllm:num_requests_running': 0.0}},
    'recipe': {'running': True, 'name': 'MiniMax-M2.7-NVFP4', 'tp': 2},
    'nodes': [
        {'name': 'fred', 'ip': '192.168.2.75', 'role': 'head',
         'hostname': 'fred.example.com', 'online': True,
         'cpu_pct': 1.5, 'mem_used_pct': 88.7, 'gpu_util_pct': 12.0,
         'vram_used_mb': 98300.0, 'disk_used': 360760639488, 'disk_total': 4031871553536},
        {'name': 'barney', 'ip': '192.168.2.74', 'role': 'worker',
         'hostname': 'barney', 'online': True,
         'cpu_pct': 1.7, 'mem_used_pct': 87.1, 'gpu_util_pct': 34.0,
         'vram_used_mb': 98300.0, 'disk_used': 268122525696, 'disk_total': 4031871553536},
    ],
}

NODE = {'id': 's1', 'name': 'sparks', 'base_url': 'https://fred:7862',
        'host_type': 'sparkdash', 'role': 'admin'}


def test_spark_envelope_resources_from_head_node():
    env = app.build_spark_envelope(NODE, SNAP)
    assert env['ok'] is True
    assert env['resources'] == {'cpu_pct': 1.5, 'memory': {'pct': 88.7}}


def test_spark_envelope_sums_disks_across_nodes():
    env = app.build_spark_envelope(NODE, SNAP)
    assert env['used_bytes'] == 360760639488 + 268122525696
    assert env['size_bytes'] == 2 * 4031871553536


def test_spark_block_contents():
    s = app.build_spark_envelope(NODE, SNAP)['spark']
    assert s['healthy'] and s['nodes'] == 2 and s['nodes_online'] == 2
    assert s['gpu_util_pct'] == 34.0            # max across nodes
    assert s['vram_used_mb'] == 196600.0        # summed
    assert s['model'] == 'lukealonso/MiniMax-M2.7-NVFP4' and s['vllm_healthy']
    assert s['recipe'] == 'MiniMax-M2.7-NVFP4' and s['recipe_running']
    assert s['ray_alive'] == 2 and s['ray_total'] == 2
    assert [n['name'] for n in s['node_list']] == ['fred', 'barney']


def test_spark_envelope_classifies_ai():
    assert app.build_spark_envelope(NODE, SNAP)['type_auto'] == 'AI'


def test_spark_unhealthy_and_offline_node():
    snap = {**SNAP, 'cluster_healthy': False,
            'nodes': [SNAP['nodes'][0], {**SNAP['nodes'][1], 'online': False}]}
    s = app.build_spark_envelope(NODE, snap)['spark']
    assert s['healthy'] is False
    assert s['nodes_online'] == 1


def test_spark_envelope_empty_snapshot_survives():
    env = app.build_spark_envelope(NODE, {})
    assert env['ok'] is True and env['spark']['nodes'] == 0
    assert env['used_bytes'] == 0 and env['resources']['cpu_pct'] is None


def test_sparkdash_adapter_registered():
    a = app._adapter_for({'host_type': 'sparkdash'})
    assert a.kind == 'sparkdash' and a.auth == 'token'
    assert a.default_type == 'AI' and a.polled
    d = a.descriptor()
    assert d['label'].startswith('SparkDash') and not d['verify_tls']
