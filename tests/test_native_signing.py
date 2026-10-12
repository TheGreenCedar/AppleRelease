"""Synthetic signer inputs; native tools and notarization never run in this suite."""
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import sign_candidate as signer
from capture_capability import FIXED
from policy import ReleaseError, digest_file
from signing_progress import Progress, tool_label

MACHO = b'\xcf\xfa\xed\xfe'


class NativeSigningTests(unittest.TestCase):
    def setUp(self):
        self.candidate()

    def candidate(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve() / 'work'
        self.bundle = self.work / 'stage/Speakerdesk.app'
        self.app = {'app_name': 'Speakerdesk.app', 'product': 'Speakerdesk',
                    'repository': 'TheGreenCedar/Speakerdesk',
                    'bundle_id': 'com.speakerdesk.desktop', 'team_id': 'TESTTEAM',
                    'pyinstaller_runtime': 'Contents/MacOS/speakerdesk-runtime',
                    'capture_helper': 'Contents/Resources/speakerdesk-capture'}
        self.build = {'version': '0.7.0', 'runtime_kind': 'native',
                      'source_commit': 'a' * 40, 'run_id': 1, 'artifact_id': 2,
                      'artifact_sha256': 'b' * 64, 'capture_capability': dict(FIXED)}
        self.main = self.write('Contents/MacOS/speakerdesk', MACHO + b'main')
        self.capture = self.write(self.app['capture_helper'], MACHO + b'capture')
        self.echo = self.write('Contents/Resources/libspeakerdesk_echo.dylib', MACHO + b'echo')
        self.mlx = self.write('Contents/Frameworks/libmlx.dylib', MACHO + b'mlx')
        self.write('Contents/Resources/mlx/mlx.metallib', b'metal')
        self.write('Contents/Resources/THIRD_PARTY_NOTICES.txt', b'notices')
        self.main.chmod(0o755)
        self.capture.chmod(0o755)
        self.capability = self.write(self.app['capture_helper'] + '.capability.json',
                                    json.dumps({**FIXED, 'helper_sha256': digest_file(self.capture)}).encode())
        self.write('Contents/Info.plist', plistlib.dumps({
            'CFBundleIdentifier': self.app['bundle_id'],
            'CFBundleShortVersionString': self.build['version'],
            'CFBundleExecutable': 'speakerdesk'}))
        self.calls = []
        self.architectures = {}

    def write(self, name, data):
        path = self.bundle / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def tool(self, *args, **kwargs):
        tool_label(args)
        self.calls.append(args)
        command = args[0]
        if command == '/usr/bin/lipo':
            return self.architectures.get(args[-1], 'arm64')
        if command == '/usr/bin/codesign':
            path = Path(args[-1])
            if '--force' in args and path.is_file():
                path.write_bytes(path.read_bytes() + b'synthetic-signature')
            if '--display' in args:
                return 'TeamIdentifier=TESTTEAM\nAuthority=Developer ID Application: fixture\n'
        elif command == '/usr/bin/ditto':
            if '-c' in args:
                with zipfile.ZipFile(args[-1], 'w') as archive:
                    for path in self.bundle.rglob('*'):
                        if path.is_file():
                            archive.write(path, path.relative_to(self.bundle.parent))
            else:
                shutil.copytree(args[-2], args[-1])
        elif command == '/usr/bin/hdiutil':
            if args[1] == 'create':
                Path(args[-1]).write_bytes(b'synthetic-dmg')
            elif args[1] == 'attach':
                shutil.copytree(self.bundle, Path(args[-1]) / 'Speakerdesk.app')
        return ''

    def run_signer(self, *, legacy_count=3):
        (self.work / 'approved.json').write_text(json.dumps({
            'app': self.app, 'build': self.build, 'input_manifest': {'minimum_os': '15.0'}}))
        output = self.work / 'output'
        environment = {'APPLE_SIGNING_IDENTITY': 'Developer ID Application: fixture',
                       'APPLE_API_KEY_PATH': '/fixture/never-read.p8',
                       'APPLE_API_KEY': 'fixture', 'APPLE_API_ISSUER': 'fixture',
                       'GITHUB_SHA': 'c' * 40, 'GITHUB_RUN_ID': '3'}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, environment, clear=True))
            stack.enter_context(patch.object(signer, 'tool', side_effect=self.tool))
            runtime = stack.enter_context(patch.object(signer, 'sign_runtime', return_value=legacy_count))
            for name in ('rebuild', 'CArchiveReader'):
                stack.enter_context(patch.object(signer, name, side_effect=AssertionError('PyInstaller adapter invoked')))
            stack.enter_context(patch.object(signer, 'notarize', side_effect=lambda path, kind, *args, **kwargs:
                                           {'kind': kind, 'status': 'Accepted', 'id': 'synthetic'}))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            progress = Progress(self.work / 'progress.json')
            signer.run(self.work, output, progress)
        return json.loads((output / 'artifact-manifest.json').read_text()), runtime

    def test_native_signs_existing_code_refreshes_capture_and_reports_no_embedded_archive(self):
        original_hash = digest_file(self.capture)
        manifest, runtime = self.run_signer()
        runtime.assert_not_called()
        signed = [args for args in self.calls if args[0] == '/usr/bin/codesign' and '--force' in args]
        self.assertEqual({args[-1] for args in signed if Path(args[-1]).suffix != '.dmg'},
                         {self.main, self.capture, self.echo, self.mlx, self.bundle})
        self.assertEqual({args[-1] for args in self.calls if args[0] == '/usr/bin/lipo'},
                         {self.main, self.capture, self.echo, self.mlx})
        for path in (self.main, self.capture, self.echo, self.mlx):
            self.assertIn(('/usr/bin/codesign', '--verify', '--strict', path), self.calls)
        for args in signed:
            if args[-1] in {self.capture, self.bundle}:
                self.assertIn('--entitlements', args)
            elif args[-1] in {self.main, self.echo, self.mlx}:
                self.assertNotIn('--entitlements', args)
        capability = json.loads(self.capability.read_text())
        self.assertEqual(capability, {**FIXED, 'helper_sha256': digest_file(self.capture)})
        self.assertNotEqual(original_hash, capability['helper_sha256'])
        self.assertEqual(manifest['capture_capability']['input_helper_sha256'], original_hash)
        self.assertEqual(manifest['runtime_kind'], 'native')
        self.assertEqual(manifest['embedded_native_signatures_verified'], 0)
        self.assertEqual(manifest['source_commit'], self.build['source_commit'])
        self.assertFalse(manifest['public_ready'])

    def test_legacy_default_and_explicit_mode_still_transform_the_registered_runtime(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                self.candidate()
                if explicit:
                    self.build['runtime_kind'] = 'pyinstaller'
                else:
                    del self.build['runtime_kind']
                runtime_path = self.write(self.app['pyinstaller_runtime'], MACHO + b'legacy')
                manifest, runtime = self.run_signer()
                self.assertEqual(runtime.call_count, 1)
                self.assertEqual(runtime.call_args.args[:2], (runtime_path, 'Developer ID Application: fixture'))
                self.assertEqual(manifest['embedded_native_signatures_verified'], 3)
                self.assertNotIn('runtime_kind', manifest)
                self.assertFalse(any(args[0] == '/usr/bin/codesign' and '--force' in args
                                     and args[-1] == runtime_path for args in self.calls))

    def test_native_hostile_payload_matrix_fails_before_any_signing(self):
        mutations = {
            'missing main': (lambda: self.main.unlink(), 'Required native executable missing'),
            'text main': (lambda: self.main.write_bytes(b'script'), 'not Mach-O'),
            'text capture': (lambda: self.capture.write_bytes(b'script'), 'not Mach-O'),
            'text echo': (lambda: self.echo.write_bytes(b'text'), 'not Mach-O'),
            'text mlx': (lambda: self.mlx.write_bytes(b'text'), 'not Mach-O'),
            'non-executable main': (lambda: self.main.chmod(0o644), 'not executable'),
            'non-executable capture': (lambda: self.capture.chmod(0o644), 'not executable'),
            'empty metal': (lambda: (self.bundle / 'Contents/Resources/mlx/mlx.metallib').write_bytes(b''), 'resource missing'),
            'missing echo': (lambda: self.echo.unlink(), 'resource missing'),
            'missing mlx': (lambda: self.mlx.unlink(), 'resource missing'),
            'missing notices': (lambda: (self.bundle / 'Contents/Resources/THIRD_PARTY_NOTICES.txt').unlink(), 'resource missing'),
            'missing capability': (lambda: self.capability.unlink(), 'resource missing'),
            'Python source': (lambda: self.write('Contents/Resources/extra.py', b'never run'), 'Python runtime payload'),
            'Python bytecode': (lambda: self.write('Contents/Resources/extra.pyc', b'never run'), 'Python runtime payload'),
            'Python optimized': (lambda: self.write('Contents/Resources/extra.pyo', b'never run'), 'Python runtime payload'),
            'Python cache': (lambda: (self.bundle / 'Contents/Resources/__pycache__').mkdir(), 'Python runtime payload'),
            'Python library': (lambda: self.write('Contents/Frameworks/libpython3.13.dylib', MACHO), 'Python runtime payload'),
            'Python framework': (lambda: (self.bundle / 'Contents/Frameworks/Python.framework').mkdir(), 'Python runtime payload'),
            'legacy runtime': (lambda: self.write(self.app['pyinstaller_runtime'], MACHO), 'Python runtime payload'),
        }
        for label, (mutation, error) in mutations.items():
            with self.subTest(label=label):
                self.candidate()
                mutation()
                with self.assertRaisesRegex(ReleaseError, error):
                    self.run_signer()
                self.assertFalse(any(args[0] == '/usr/bin/codesign' and '--force' in args for args in self.calls))

    def test_native_architecture_and_helper_binding_still_fail_closed(self):
        for target in ('main', 'capture', 'echo', 'mlx', 'capability'):
            with self.subTest(target=target):
                self.candidate()
                if target == 'capability':
                    self.capability.write_text(json.dumps({**FIXED, 'helper_sha256': '0' * 64}))
                else:
                    self.architectures[getattr(self, target)] = 'x86_64'
                with self.assertRaisesRegex(ReleaseError, 'approved input helper' if target == 'capability' else 'non-arm64'):
                    self.run_signer()
                self.assertFalse(any(args[0] == '/usr/bin/codesign' and '--force' in args
                                     and args[-1] == self.bundle for args in self.calls))

    def test_unknown_mode_and_legacy_missing_runtime_are_rejected(self):
        for mode in ('unknown', None, True, [], 'pyinstaller'):
            with self.subTest(mode=mode):
                self.candidate()
                self.build['runtime_kind'] = mode
                with self.assertRaises(ReleaseError):
                    self.run_signer()
                self.assertEqual(self.calls, [])

    def test_native_executable_identity_and_linked_resources_are_rejected(self):
        for target in ('foreign main', 'main', 'capture', 'echo', 'mlx'):
            with self.subTest(target=target):
                self.candidate()
                if target == 'foreign main':
                    self.write('Contents/MacOS/foreign', MACHO + b'main').chmod(0o755)
                    metadata = plistlib.loads((self.bundle / 'Contents/Info.plist').read_bytes())
                    metadata['CFBundleExecutable'] = 'foreign'
                    self.write('Contents/Info.plist', plistlib.dumps(metadata))
                    error = 'Unexpected native Speakerdesk executable'
                else:
                    path = getattr(self, target)
                    original = path.with_name(path.name + '.original')
                    path.rename(original)
                    path.symlink_to(original.name)
                    error = 'Required native'
                with self.assertRaisesRegex(ReleaseError, error):
                    self.run_signer()
                self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
