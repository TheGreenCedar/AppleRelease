import ast
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import capture_capability as capability
from policy import ReleaseError, digest_file


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name) / 'Speakerdesk.app'
        self.capture = self.bundle / capability.CAPTURE_PATH
        self.capture.parent.mkdir(parents=True)
        self.capture.write_bytes(b'approved ad-hoc helper')
        self.path = self.capture.with_name(self.capture.name + '.capability.json')
        self.app = {'bundle_id': 'com.speakerdesk.desktop', 'capture_helper': capability.CAPTURE_PATH}
        self.build = {'capture_capability': dict(capability.FIXED)}
        self.write_manifest()

    def write_manifest(self, **changes):
        value = {**capability.FIXED, 'helper_sha256': digest_file(self.capture), **changes}
        self.path.write_text(json.dumps(value))

    def admit(self, app=None, build=None):
        return capability.admit(self.bundle, self.app if app is None else app,
                                self.build if build is None else build, self.capture)

    def test_refresh_only_final_signed_helper_digest(self):
        admitted = self.admit()
        old_hash = digest_file(self.capture)
        self.capture.write_bytes(b'same approved helper with final code signature')
        report = capability.refresh(self.capture, admitted)
        value = json.loads(self.path.read_text())
        self.assertEqual(value, {**capability.FIXED, 'helper_sha256': digest_file(self.capture)})
        self.assertEqual(report['input_helper_sha256'], old_hash)
        self.assertEqual(report['signed_helper_sha256'], digest_file(self.capture))
        self.assertEqual(report['manifest_sha256'], digest_file(self.path))
        self.assertEqual(list(self.path.parent.glob('.capture-capability-*')), [])

    def test_opted_in_progress_contract_survives_signing_refresh(self):
        contract = {**capability.FIXED, 'progress_contract': 'audio_queue_fence_v1'}
        self.build['capture_capability'] = contract
        self.write_manifest(progress_contract='audio_queue_fence_v1')
        admitted = self.admit()
        original_hash = digest_file(self.capture)
        self.capture.write_bytes(b'final signed helper with audio queue fence')
        report = capability.refresh(self.capture, admitted)
        self.assertEqual(json.loads(self.path.read_text()),
                         {**contract, 'helper_sha256': digest_file(self.capture)})
        self.assertEqual(report['progress_contract'], 'audio_queue_fence_v1')
        self.assertEqual(report['input_helper_sha256'], original_hash)
        self.assertEqual(report['signed_helper_sha256'], digest_file(self.capture))
        self.assertIsNotNone(self.admit())

    def test_progress_contract_requires_exact_per_build_opt_in(self):
        self.write_manifest(progress_contract='audio_queue_fence_v1')
        with self.assertRaises(ReleaseError):
            self.admit()
        self.build['capture_capability'] = {
            **capability.FIXED, 'progress_contract': 'audio_queue_fence_v1'}
        for changes in ({}, {'progress_contract': 'future'}, {'progress_contract': False},
                        {'progress_contract': 'audio_queue_fence_v1', 'extra': True}):
            self.write_manifest(**changes)
            with self.subTest(changes=changes), self.assertRaises(ReleaseError):
                self.admit()
        self.write_manifest(progress_contract='audio_queue_fence_v1')
        for progress in ('future', False, None):
            with self.subTest(progress=progress), self.assertRaises(ReleaseError):
                self.admit(build={'capture_capability': {
                    **capability.FIXED, 'progress_contract': progress}})

    def test_legacy_untouched(self):
        self.path.unlink()
        self.assertIsNone(self.admit(build={}))
        self.assertIsNone(capability.refresh(self.capture, None))
        self.assertFalse(self.path.exists())

    def test_manifest_requires_registered_opt_in(self):
        with self.assertRaises(ReleaseError): self.admit(build={})

    def test_only_fixed_registered_schema(self):
        for entry in (True, {}, {**capability.FIXED, 'extra': 1},
                      {**capability.FIXED, 'export_contract': 'raw'},
                      {**capability.FIXED, 'capability_version': 'future'}):
            with self.subTest(entry=entry), self.assertRaises(ReleaseError):
                self.admit(build={'capture_capability': entry})

    def test_manifest_fields_and_input_binding(self):
        for changes in ({'helper_sha256': '0'*64}, {'extra': True},
                        {'export_contract': 'raw'}, {'helper_sha256': False}):
            self.write_manifest(**changes)
            with self.subTest(changes=changes), self.assertRaises(ReleaseError): self.admit()
        for text in ('[]', 'null', '{bad', '{"helper_sha256": 1, "helper_sha256": 2}'):
            self.path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ReleaseError): self.admit()

    def test_missing_oversize_and_linked_manifest(self):
        self.path.unlink()
        with self.assertRaises(ReleaseError): self.admit()
        self.path.write_bytes(b'x'*4097)
        with self.assertRaises(ReleaseError): self.admit()
        self.path.unlink()
        destination = self.path.parent / 'elsewhere.json'
        destination.write_text('{}')
        self.path.symlink_to(destination)
        with self.assertRaises(ReleaseError): self.admit()

    def test_linked_helper_refused(self):
        content = self.capture.read_bytes()
        self.capture.unlink()
        other = self.capture.parent / 'other-helper'
        other.write_bytes(content)
        self.capture.symlink_to(other)
        with self.assertRaises(ReleaseError): self.admit()

    def test_scope_bound_to_registered_speakerdesk_helper(self):
        for app in ({**self.app, 'bundle_id': 'foreign.app'},
                    {**self.app, 'capture_helper': 'Contents/MacOS/foreign'}):
            with self.subTest(app=app), self.assertRaises(ReleaseError): self.admit(app=app)
        with self.assertRaises(ReleaseError):
            capability.admit(self.bundle.parent, self.app, self.build, self.capture)

    def test_intermediate_manifest_mutation_refused(self):
        admitted = self.admit()
        self.path.write_text('{}')
        with self.assertRaises(ReleaseError): capability.refresh(self.capture, admitted)
        self.assertEqual(self.path.read_text(), '{}')

    def test_admitted_progress_contract_cannot_be_downgraded_during_refresh(self):
        self.build['capture_capability'] = {
            **capability.FIXED, 'progress_contract': 'audio_queue_fence_v1'}
        self.write_manifest(progress_contract='audio_queue_fence_v1')
        admitted = self.admit()
        admitted['contract'] = dict(capability.FIXED)
        before = self.path.read_bytes()
        with self.assertRaises(ReleaseError):
            capability.refresh(self.capture, admitted)
        self.assertEqual(self.path.read_bytes(), before)

    def test_signer_order_and_no_producer_execution(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts/sign_candidate.py').read_text()
        tree = ast.parse(source)
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        calls = [(node.lineno, node.func.id) for node in ast.walk(run)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        admit = next(line for line, name in calls if name == 'admit_capture_capability')
        inner = next(line for line, name in calls if name == 'sign_runtime')
        refresh = next(line for line, name in calls if name == 'refresh_capture_capability')
        outer = next(node.lineno for node in ast.walk(run) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == 'sign'
                     and isinstance(node.args[0], ast.Name) and node.args[0].id == 'bundle')
        loop = next(node for node in ast.walk(run) if isinstance(node, ast.For)
                    and isinstance(node.target, ast.Name) and node.target.id == 'path'
                    and any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                            and call.func.id == 'sign' for call in ast.walk(node)))
        self.assertLess(admit, inner)
        self.assertLess(loop.end_lineno, refresh)
        self.assertLess(refresh, outer)
        helper = ast.parse(Path(capability.__file__).read_text())
        imports = [node for node in ast.walk(helper) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any('subprocess' in ast.unparse(node) for node in imports))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in ('eval', 'exec', '__import__') for node in ast.walk(helper)))


if __name__ == '__main__': unittest.main()
