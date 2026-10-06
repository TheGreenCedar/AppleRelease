"""Fake native-tool contracts only: no Apple calls, keys, signing or app execution."""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from policy import ReleaseError
from signing_progress import Progress, native_tool, notarize, NOTARY_BUDGET

IDENTIFIER = '12ab95c8-066e-4d06-aa5d-5a10cb939bc7'
OTHER = '22ab95c8-066e-4d06-aa5d-5a10cb939bc7'
CREDENTIALS = {'key_path': '/private/secret-api-key.p8', 'key_id': 'SECRET-KEY', 'issuer': 'SECRET-ISSUER'}


class NotaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'safe' / 'signing-progress.json'
        self.progress = Progress(self.path)
        self.now = 0
        self.calls = []
        self.output = io.StringIO()
        self.capture = contextlib.redirect_stdout(self.output)
        self.capture.__enter__()

    def tearDown(self):
        self.capture.__exit__(None, None, None)
        self.directory.cleanup()

    def sleep(self, seconds):
        self.now += seconds

    def runner(self, responses):
        def run(arguments, **kwargs):
            self.calls.append((arguments, kwargs))
            response = responses.pop(0) if len(responses) > 1 else responses[0]
            if isinstance(response, Exception):
                raise response
            code, payload = response
            return subprocess.CompletedProcess(arguments, code, payload if isinstance(payload, str) else json.dumps(payload))
        return run

    def notarize(self, responses, kind='app'):
        with patch('signing_progress.subprocess.run', self.runner(responses)):
            return notarize('/private/candidate.zip', kind, CREDENTIALS, self.progress,
                            tool=lambda *args, **kwargs: native_tool(self.progress, *args, **kwargs),
                            clock=lambda: self.now, sleep=self.sleep)

    def assert_safe(self):
        data = self.path.read_text() + self.output.getvalue()
        for forbidden in [*CREDENTIALS.values(), '/private/candidate.zip', 'PRIVATE RAW RESPONSE', '--issuer', '--key']:
            self.assertNotIn(forbidden, data)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_pending_then_accepted_is_one_submission_and_exact_success_receipt(self):
        receipt = self.notarize([(0, {'id': IDENTIFIER, 'message': 'PRIVATE RAW RESPONSE'}),
                                (0, {'id': IDENTIFIER, 'status': 'In Progress'}),
                                (0, {'id': IDENTIFIER, 'status': 'Accepted'})])
        self.assertEqual(receipt, {'id': IDENTIFIER, 'status': 'Accepted', 'kind': 'app'})
        self.assertEqual([args[2] for args, _ in self.calls], ['submit', 'info', 'info'])
        self.assertTrue(all('--wait' not in args for args, _ in self.calls))
        self.assertEqual(self.calls[0][1]['timeout'], 1800)
        self.assertTrue(all(kw['timeout'] <= 60 for _, kw in self.calls[1:]))
        self.assertEqual(json.loads(self.path.read_text())['notarization']['app']['status'], 'Accepted')
        self.assert_safe()

    def test_pending_deadline_retains_uuid_without_resubmitting(self):
        with self.assertRaisesRegex(ReleaseError, 'still pending'):
            self.notarize([(0, {'id': IDENTIFIER}), (0, {'id': IDENTIFIER, 'status': 'In Progress'})])
        data = json.loads(self.path.read_text())
        self.assertEqual(data['notarization']['app'], {'id': IDENTIFIER, 'status': 'In Progress'})
        self.assertEqual(data['phase'], 'app-notary')
        self.assertEqual(data['last_event']['state'], 'timeout')
        self.assertEqual(self.now, NOTARY_BUDGET)
        self.assertEqual(sum(args[2] == 'submit' for args, _ in self.calls), 1)
        self.assertLessEqual(len(data['events']), 128)
        self.assert_safe()

    def test_rejection_preserves_terminal_status_and_does_not_accept(self):
        with self.assertRaisesRegex(ReleaseError, 'rejected'):
            self.notarize([(0, {'id': IDENTIFIER}), (0, {'id': IDENTIFIER, 'status': 'Invalid', 'message': 'PRIVATE RAW RESPONSE'})])
        self.assertEqual(json.loads(self.path.read_text())['notarization']['app']['status'], 'Invalid')
        self.assert_safe()

    def test_info_error_or_timeout_retains_pending_uuid(self):
        for error in [(1, 'PRIVATE RAW RESPONSE'), subprocess.TimeoutExpired(['SECRET-KEY'], 60)]:
            with self.subTest(error=type(error).__name__), self.assertRaises(ReleaseError):
                self.notarize([(0, {'id': IDENTIFIER}), error])
            data = json.loads(self.path.read_text())
            self.assertEqual(data['notarization']['app'], {'id': IDENTIFIER, 'status': 'In Progress'})
            self.assertEqual(data['last_event']['tool'], 'notarytool-info')
            self.assert_safe()

    def test_submit_timeout_records_request_id_unavailable_and_never_retries(self):
        with self.assertRaisesRegex(ReleaseError, 'timed out'):
            self.notarize([subprocess.TimeoutExpired(['SECRET-KEY'], 1800)])
        self.assertEqual(len(self.calls), 1)
        data = json.loads(self.path.read_text())
        self.assertEqual(data['notarization']['app'], {'id': None, 'status': 'submission_started_request_id_unavailable'})
        self.assertEqual(data['last_event']['tool'], 'notarytool-submit')
        self.assert_safe()

    def test_wrong_id_unknown_status_and_bad_json_fail_closed(self):
        for result in [{'id': OTHER, 'status': 'Accepted'}, {'id': IDENTIFIER, 'status': 'Unknown'},
                       'PRIVATE RAW RESPONSE', {'id': '../../secret', 'status': 'Accepted'}]:
            with self.subTest(result=result), self.assertRaises(ReleaseError):
                self.notarize([(0, {'id': IDENTIFIER}), (0, result)])
            self.assert_safe()

    def test_two_successful_kinds_keep_both_accepted_receipts_and_final_state(self):
        app = self.notarize([(0, {'id': IDENTIFIER}), (0, {'id': IDENTIFIER, 'status': 'Accepted'})])
        dmg = self.notarize([(0, {'id': OTHER}), (0, {'id': OTHER, 'status': 'Accepted'})], kind='dmg')
        self.progress.phase('complete'); self.progress.finish('succeeded')
        self.assertEqual([app['kind'], dmg['kind']], ['app', 'dmg'])
        data = json.loads(self.path.read_text())
        self.assertEqual(data['state'], 'succeeded')
        self.assertTrue(all(receipt['status'] == 'Accepted' for receipt in data['notarization'].values()))
        self.assert_safe()

    def test_submit_status_does_not_replace_same_uuid_info_accepted_gate(self):
        with self.assertRaises(ReleaseError):
            self.notarize([(0, {'id': IDENTIFIER, 'status': 'Accepted'}),
                           (0, {'id': IDENTIFIER, 'status': 'Invalid'})])
        self.assertEqual([args[2] for args, _ in self.calls], ['submit', 'info'])

    def test_only_approved_identity_fields_are_copied_to_diagnostic(self):
        build = {'source_commit': 'a'*40, 'run_id': 7, 'artifact_id': 8,
                 'artifact_sha256': 'b'*64, 'unexpected_secret': 'SECRET-KEY'}
        self.progress.bind_input(build)
        self.assertEqual(json.loads(self.path.read_text())['approved_input'], {
            'source_commit': 'a'*40, 'producer_run_id': 7, 'input_artifact_id': 8,
            'input_artifact_sha256': 'b'*64})
        build['source_commit'] = 'SECRET-KEY'
        with self.assertRaises(ReleaseError):self.progress.bind_input(build)
        self.assert_safe()

    def test_only_fixed_tools_can_execute_and_failure_phase_is_durable(self):
        with patch('signing_progress.subprocess.run') as run, self.assertRaises(ReleaseError):
            native_tool(self.progress, '/bin/sh', '-c', 'SECRET-KEY')
        run.assert_not_called()
        self.progress.phase('bundle-signing')
        with patch('signing_progress.subprocess.run', self.runner([(2, 'PRIVATE RAW RESPONSE')])):
            with self.assertRaises(ReleaseError):
                native_tool(self.progress, '/usr/bin/codesign', '--sign', 'SECRET-KEY', '/private/candidate.zip')
        self.progress.finish('failed')
        data = json.loads(self.path.read_text())
        self.assertEqual(data['phase'], 'bundle-signing')
        self.assertEqual(data['state'], 'failed')
        self.assertEqual(data['events'][-2]['exit_code'], 2)
        self.assert_safe()


if __name__ == '__main__':
    unittest.main()
