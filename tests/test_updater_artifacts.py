"""Synthetic final-bundle contracts; no app execution, Apple calls or signing keys."""
import base64
import contextlib
import copy
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from policy import ROOT, ReleaseError
from signing_progress import Progress
from updater_archive import create, extract, inventory, verify
from updater_artifacts import configuration, produce, updater_tool

# Public minisign-verify documentation vector; no private counterpart is used.
PUBLIC = base64.b64encode(b'untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n').decode()


class UpdaterArchiveTests(unittest.TestCase):
    def bundle(self, root):
        bundle = root / 'Speakerdesk.app'
        (bundle / 'Contents/MacOS').mkdir(parents=True)
        executable = bundle / 'Contents/MacOS/app'; executable.write_bytes(b'final signed native fixture'); executable.chmod(0o755)
        (bundle / 'Contents/Info.plist').write_bytes(b'final version fixture')
        (bundle / 'Contents/notarization-ticket').write_bytes(b'final stapled ticket fixture')
        os.symlink('app', bundle / 'Contents/MacOS/alias')
        os.link(executable, bundle / 'Contents/MacOS/shared-inode')
        return bundle

    def test_final_archive_has_one_canonical_app_and_preserves_bytes_modes_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); bundle = self.bundle(root); archive = root / 'app.tar.gz'
            create(bundle, archive); restored = verify(archive, root / 'restored', bundle)
            with tarfile.open(archive) as reader:
                self.assertTrue(all(member.name == 'Speakerdesk.app' or member.name.startswith('Speakerdesk.app/Contents') for member in reader))
            self.assertEqual((restored / 'Contents/notarization-ticket').read_bytes(), b'final stapled ticket fixture')
            self.assertEqual((restored / 'Contents/MacOS/app').stat().st_mode & 0o777, 0o755)
            self.assertTrue((restored / 'Contents/MacOS/alias').is_symlink())
            self.assertEqual(os.readlink(restored / 'Contents/MacOS/alias'), 'app')
            self.assertEqual((restored / 'Contents/MacOS/shared-inode').read_bytes(), b'final signed native fixture')

    def test_final_app_changes_after_archive_are_rejected(self):
        for change in ['bytes', 'mode', 'missing', 'link']:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp); bundle = self.bundle(root); archive = root / 'app.tar.gz'; create(bundle, archive)
                executable = bundle / 'Contents/MacOS/app'
                if change == 'bytes': executable.write_bytes(b'changed after stapling')
                if change == 'mode': executable.chmod(0o644)
                if change == 'missing': (bundle / 'Contents/notarization-ticket').unlink()
                if change == 'link':
                    link = bundle / 'Contents/MacOS/alias'; link.unlink(); os.symlink('shared-inode', link)
                with self.subTest(change=change), self.assertRaisesRegex(ReleaseError, 'differs'):
                    verify(archive, root / 'restored', bundle)

    def test_unsafe_members_and_links_are_rejected_without_external_writes(self):
        cases = [('Other.app/Contents/file', tarfile.REGTYPE, ''),
                 ('Speakerdesk.app/../outside', tarfile.REGTYPE, ''),
                 ('./Speakerdesk.app/Contents/file', tarfile.REGTYPE, ''),
                 ('Speakerdesk.app/Contents/link', tarfile.LNKTYPE, 'Speakerdesk.app/Contents/file'),
                 ('Speakerdesk.app/Contents/pipe', tarfile.FIFOTYPE, ''),
                 ('Speakerdesk.app/Contents/link', tarfile.SYMTYPE, '../../outside'),
                 ('Speakerdesk.app/Contents/link', tarfile.SYMTYPE, '/tmp/outside')]
        for name, kind, target in cases:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp); archive = root / 'unsafe.tar.gz'; outside = root / 'outside'; outside.write_bytes(b'untouched')
                with tarfile.open(archive, 'w:gz') as writer:
                    member = tarfile.TarInfo(name); member.type = kind; member.linkname = target
                    member.size = 5 if kind == tarfile.REGTYPE else 0
                    writer.addfile(member, io.BytesIO(b'bytes') if member.size else None)
                with self.subTest(name=name, kind=kind), self.assertRaises(ReleaseError): extract(archive, root / 'stage', 'Speakerdesk.app')
                self.assertEqual(outside.read_bytes(), b'untouched')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); archive = root / 'special-mode.tar.gz'
            with tarfile.open(archive, 'w:gz') as writer:
                member = tarfile.TarInfo('Speakerdesk.app/Contents/file'); member.mode = 0o4755
                writer.addfile(member, io.BytesIO(b''))
            with self.assertRaisesRegex(ReleaseError, 'permissions'): extract(archive, root / 'stage', 'Speakerdesk.app')

    def test_bundle_symlink_escape_cannot_be_archived(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); bundle = self.bundle(root)
            os.symlink('../..', bundle / 'Contents/escape')
            with self.assertRaisesRegex(ReleaseError, 'escapes'): create(bundle, root / 'app.tar.gz')


class UpdaterArtifactTests(unittest.TestCase):
    def test_workflow_preflight_sets_only_trusted_mode_and_fails_without_public_key(self):
        script = ROOT / 'scripts/updater_artifacts.py'
        app = json.loads((ROOT / 'policy/apps.json').read_text())['apps']['speakerdesk']
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); context = root / 'approved.json'; output = root / 'workflow-output'
            environment = dict(os.environ, GITHUB_OUTPUT=str(output), PYTHONDONTWRITEBYTECODE='1')
            context.write_text(json.dumps({'app': app, 'build': app['approved_builds'][-1]}))
            result = subprocess.run([sys.executable, str(script), str(root)], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0); self.assertEqual(output.read_text(), 'enabled=false\n')
            context.write_text(json.dumps({'app': app, 'build': {'version': '0.6.2', 'updater': True}}))
            output.unlink()
            result = subprocess.run([sys.executable, str(script), str(root)], env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0); self.assertFalse(output.exists())
            self.assertIn('public key', result.stderr)
            context.write_text(json.dumps({'app': {**app, 'updater_public_key': PUBLIC}, 'build': {'version': '0.6.2', 'updater': True}}))
            result = subprocess.run([sys.executable, str(script), str(root)], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0); self.assertEqual(output.read_text(), 'enabled=true\n')

    def test_historical_builds_stay_disabled_and_opt_in_is_explicit(self):
        app = json.loads((ROOT / 'policy/apps.json').read_text())['apps']['speakerdesk']
        for build in app['approved_builds']:
            self.assertIsNone(configuration(app, build))
        for invalid in [True, 'true', {}, 1]:
            build = copy.deepcopy(app['approved_builds'][-1]); build['updater'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ReleaseError): configuration(app, build)
        next_build = {'version': '0.6.2', 'updater': True}
        with self.assertRaisesRegex(ReleaseError, 'public key'): configuration(app, next_build)
        self.assertEqual(configuration({**app, 'updater_public_key': PUBLIC}, next_build), PUBLIC)

    def test_metadata_is_never_returned_after_failed_cryptographic_verification(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'TAURI_SIGNING_PRIVATE_KEY': 'synthetic-inert-value'}, clear=True):
            root = Path(temp); work = root / 'work'; work.mkdir(); output = root / 'output'; output.mkdir()
            bundle = UpdaterArchiveTests().bundle(root)
            app = {'app_name': 'Speakerdesk.app', 'product': 'Speakerdesk', 'updater_public_key': PUBLIC}
            build = {'version': '0.6.2', 'updater': True}
            progress = Progress(root / 'diagnostics.json'); calls = []
            def fake_boundary(progress, operation, arguments, **kwargs):
                calls.append(operation)
                if operation == 'updater-sign':
                    archive = Path(arguments[-1]); archive.with_name(archive.name + '.sig').write_text(base64.b64encode(b'not a valid signature').decode())
                else: raise ReleaseError('Updater signature verification failed.')
            with patch('updater_artifacts.updater_tool', fake_boundary), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ReleaseError, 'signature verification'):
                    produce(app, build, bundle, work, output, progress=progress, native_tool=lambda *args: None)
            self.assertEqual(calls, ['updater-sign', 'updater-verify'])
            self.assertFalse((output / 'artifact-manifest.json').exists())

    def test_tool_boundary_suppresses_output_and_does_not_forward_other_credentials(self):
        environment = {'PATH': '/usr/bin', 'TAURI_SIGNING_PRIVATE_KEY': 'INERT-KEY-FIXTURE',
                       'TAURI_SIGNING_PRIVATE_KEY_PASSWORD': 'INERT-PASSWORD-FIXTURE', 'APPLE_API_KEY': 'INERT-APPLE-FIXTURE',
                       'ARTIFACT_READER_PRIVATE_KEY': 'INERT-READER-FIXTURE'}
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, environment, clear=True):
            progress = Progress(Path(temp) / 'diagnostics.json'); stdout = io.StringIO()
            result = subprocess.CompletedProcess([], 1, 'INERT-KEY-FIXTURE private raw failure')
            with patch('updater_artifacts.subprocess.run', return_value=result) as runner, contextlib.redirect_stdout(stdout):
                with self.assertRaisesRegex(ReleaseError, 'updater-sign'):
                    updater_tool(progress, 'updater-sign', ['fixed-tool', '--app-version', '0.6.2'], signing=True)
            self.assertEqual(runner.call_args.kwargs['env'], {key: environment[key] for key in ['PATH', 'TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD']})
            self.assertEqual(runner.call_args.kwargs['stdin'], subprocess.DEVNULL)
            diagnostics = stdout.getvalue() + progress.path.read_text()
            self.assertNotIn('INERT-', diagnostics); self.assertNotIn('private raw failure', diagnostics)


if __name__ == '__main__': unittest.main()
