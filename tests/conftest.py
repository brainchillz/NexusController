import os
import sys
import tempfile

# Point config/secret files at a throwaway dir BEFORE importing app, so tests
# never touch a real controller-auth.json / nodes.json.
_tmp = tempfile.mkdtemp(prefix='nexusctl-test-')
os.environ.setdefault('CONTROLLER_AUTH_FILE', os.path.join(_tmp, 'controller-auth.json'))
os.environ.setdefault('CONTROLLER_NODES_FILE', os.path.join(_tmp, 'nodes.json'))
os.environ.setdefault('CONTROLLER_AUDIT_FILE', os.path.join(_tmp, 'audit.log'))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
