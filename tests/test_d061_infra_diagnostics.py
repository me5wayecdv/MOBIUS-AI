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

class ExactWorkflowContractTests(unittest.TestCase):
    def test_workflow_collector_arguments_parse_exactly(self):
        import shlex
        from unittest import mock
        import yaml
        spec = importlib.util.spec_from_file_location(
            'collector', Path(__file__).parents[1] / 'scripts/d061/infra_collect_evidence.py')
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        workflow = yaml.safe_load((Path(__file__).parents[1] / '.github/workflows/d061-infra-only.yml').read_text())
        step = next(s for s in workflow['jobs']['infra']['steps']
                    if 'infra_collect_evidence.py' in s.get('run', ''))
        command = step['run'].strip().replace('$(id -u)', '1000').replace('$(id -g)', '1000')
        command = command.replace('$RUNNER_TEMP', '/tmp/job-contract-test')
        argv = shlex.split(command)
        argv = ['collector'] + argv[argv.index('scripts/d061/infra_collect_evidence.py')+1:]
        # Stop immediately AFTER argparse has accepted the actual workflow
        # options, before any root/file action. Unknown options raise SystemExit.
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(collector.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(RuntimeError, 'root exporter required'):
                collector.main()

    def test_normal_finalization_keeps_original_and_cleanup_errors(self):
        from unittest import mock
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            argv = ['infra', '--review-authorized', '--collector-gid', str(os.getgid())]
            # Exercise the REAL normal-main exception/finally path without
            # root, network commands, namespaces or loopback sockets. Inject
            # failure at the first host snapshot, before mutation.
            with mock.patch.object(sys, 'argv', argv), \
                 mock.patch.object(infra.os, 'geteuid', return_value=0), \
                 mock.patch.object(infra.os, 'chown'), \
                 mock.patch.object(infra.tempfile, 'mkdtemp', return_value=str(out)), \
                 mock.patch.object(infra.signal, 'signal'), \
                 mock.patch.object(infra, 'phase_record'), \
                 mock.patch.object(infra, 'host_snapshot', side_effect=RuntimeError('injected pre-mutation failure')), \
                 mock.patch.object(infra, 'cleanup', return_value=['injected cleanup evidence failure']) as cleanup, \
                 mock.patch.object(infra, 'DIAGNOSTIC_ERRORS', ['injected diagnostic failure']), \
                 contextlib.redirect_stdout(io.StringIO()) as stdout:
                old_umask = os.umask(0o027)
                try:
                    rc = infra.main()
                finally:
                    os.umask(old_umask)
            self.assertEqual(rc, 1)
            cleanup.assert_called_once()
            summary = json.loads((out / 'summary.json').read_text())
            self.assertTrue(summary['failed'])
            self.assertIn('injected pre-mutation failure', summary['original_errors'][0])
            self.assertEqual(summary['cleanup_errors'], ['injected cleanup evidence failure', 'injected diagnostic failure'])
            self.assertIn('artifacts=', stdout.getvalue())
            self.assertNotIn('UnboundLocalError', stdout.getvalue())
