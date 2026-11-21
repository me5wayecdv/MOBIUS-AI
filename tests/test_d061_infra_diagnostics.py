"""Local-only unit tests. No namespace, command inventory, socket or root action."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'd061_infra', Path(__file__).parents[1] / 'scripts/d061/infra_netns_check.py')
infra = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(infra)


class InfraDiagnosticsTests(unittest.TestCase):
    def test_namespace_empty_requires_independent_confirmation(self):
        for raw in ('', ' \n'):
            with self.assertRaises(RuntimeError):
                infra.namespace_names(raw)
            self.assertEqual(infra.namespace_names(raw, empty_confirmed=True), set())
        self.assertEqual(infra.namespace_names('[]'), set())
        self.assertEqual(infra.namespace_names('[{"name":"previous"}]'), {'previous'})

    def test_namespace_invalid_never_becomes_empty(self):
        for raw in ('null', '{}', 'bad', '[', '[{}]', '[null]', '[{"name":""}]',
                    '[{"name":1}]', '[{"name":"same"},{"name":"same"}]'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, RuntimeError)):
                infra.namespace_names(raw, empty_confirmed=True)

    def test_inventory_json_requires_array_objects(self):
        for raw in ('', ' \n', 'null', '{}', 'broken', '[null]', '[1]', '["x"]'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, RuntimeError)):
                infra.json_rows(raw, 'inventory-test')
        self.assertEqual(infra.json_rows('[]', 'test'), [])
        self.assertEqual(infra.json_rows('[{"ifname":"lo"}]', 'test'), [{'ifname':'lo'}])

    def test_job_scoped_group_access_is_not_world_access(self):
        # Non-root local check of the exact directory group-inheritance and
        # mode strategy. Root-created runtime access is still unverified until
        # a reviewed CI run, never inferred from this local test.
        self.assertNotEqual(os.geteuid(), 0)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'job-evidence'
            out.mkdir()
            os.chown(out, os.getuid(), os.getgid())
            out.chmod(0o2750)
            old = os.umask(0o027)
            try:
                record = out / 'summary.json'
                record.write_text(json.dumps({'test': 'readable'}))
            finally:
                os.umask(old)
            self.assertEqual(record.stat().st_gid, os.getgid())
            self.assertEqual(record.stat().st_mode & 0o777, 0o640)
            self.assertEqual(out.stat().st_mode & 0o777, 0o750)
            result = subprocess.run(
                [sys.executable, '-I', '-c', 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())', str(record)],
                check=True, capture_output=True, text=True, close_fds=True)
            self.assertIn('readable', result.stdout)


if __name__ == '__main__':
    unittest.main()
