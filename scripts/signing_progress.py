"""Safe fixed-tool progress. Never persist arguments, environment or raw output."""
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

from policy import ReleaseError, require

PHASES = {'validation', 'embedded-signing', 'bundle-signing', 'app-notary',
          'app-staple', 'dmg-build', 'dmg-notary', 'dmg-staple',
          'zip-verification', 'dmg-verification', 'updater-archive', 'updater-signing', 'manifest', 'complete'}
STATES = {'started', 'succeeded', 'failed', 'timeout', 'pending'}
STATUSES = {'In Progress', 'Accepted', 'Invalid', 'Rejected'}
NOTARY_BUDGET = 1800
POLL_SECONDS = 30
INFO_TIMEOUT = 60


def request_id(value):
    require(isinstance(value, str), 'Missing notary request UUID.')
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise ReleaseError('Invalid notary request UUID.') from None
    require(parsed == value.lower(), 'Invalid notary request UUID.')
    return parsed


def tool_label(arguments):
    """Only tools already selected by trusted signer code can run here."""
    path = str(arguments[0])
    fixed = {'/usr/bin/codesign': 'codesign', '/usr/bin/lipo': 'lipo',
             '/usr/bin/ditto': 'ditto', '/usr/bin/hdiutil': 'hdiutil',
             '/usr/sbin/spctl': 'spctl'}
    if path in fixed:
        return fixed[path]
    if path == '/usr/bin/xcrun' and len(arguments) > 2:
        action = (str(arguments[1]), str(arguments[2]))
        if action in {('notarytool', 'submit'), ('notarytool', 'info'),
                      ('stapler', 'staple'), ('stapler', 'validate')}:
            return '-'.join(action)
    raise ReleaseError('Unapproved native tool.')


class Progress:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        require(not self.path.exists() and not self.path.is_symlink(), 'Diagnostics already exist.')
        self.started = time.monotonic()
        self.data = {'schema_version': 1, 'kind': 'signing-diagnostics-not-a-candidate',
                     'state': 'started', 'phase': 'validation', 'event_count': 0,
                     'events': [], 'notarization': {}}
        self.save()

    def save(self):
        self.data['updated_unix_seconds'] = round(time.time(), 3)
        temporary = self.path.with_name(self.path.name + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'w') as output:
                json.dump(self.data, output, sort_keys=True, indent=2)
                output.write('\n'); output.flush(); os.fsync(output.fileno())
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def phase(self, phase):
        require(phase in PHASES, 'Unknown signer phase.')
        self.data['phase'] = phase
        self.event('phase', 'started')

    def bind_input(self, build):
        fields = {'source_commit': build['source_commit'], 'producer_run_id': build['run_id'],
                  'input_artifact_id': build['artifact_id'], 'input_artifact_sha256': build['artifact_sha256']}
        require(isinstance(fields['source_commit'], str) and re.fullmatch('[a-f0-9]{40}', fields['source_commit'])
                and isinstance(fields['input_artifact_sha256'], str)
                and re.fullmatch('[a-f0-9]{64}', fields['input_artifact_sha256'])
                and all(type(fields[key]) is int and fields[key] > 0
                        for key in ('producer_run_id', 'input_artifact_id')), 'Invalid diagnostic input identity.')
        self.data['approved_input'] = fields
        self.save()

    def event(self, tool, state, *, exit_code=None):
        require(state in STATES, 'Unknown diagnostic state.')
        # Labels originate exclusively in this module or the fixed phase setter.
        require(tool in {'phase', 'signer', 'codesign', 'lipo', 'ditto', 'hdiutil', 'spctl',
                         'notarytool-submit', 'notarytool-info', 'stapler-staple', 'stapler-validate',
                         'updater-sign', 'updater-verify'},
                'Unknown diagnostic tool.')
        event = {'phase': self.data['phase'], 'tool': tool, 'state': state,
                 'elapsed_seconds': round(time.monotonic() - self.started, 3)}
        if exit_code is not None:
            require(type(exit_code) is int, 'Invalid tool exit code.')
            event['exit_code'] = exit_code
        self.data['event_count'] += 1
        self.data['events'] = (self.data['events'] + [event])[-128:]
        self.data['last_event'] = event
        if state in ('failed', 'timeout') and tool != 'signer':
            self.data['failure_event'] = event
        self.save()
        print(f'Signer phase={event["phase"]} tool={tool} state={state}', flush=True)

    def notary(self, kind, identifier, status):
        require(kind in ('app', 'dmg') and status in STATUSES, 'Invalid notary progress.')
        identifier = request_id(identifier)
        self.data['notarization'][kind] = {'id': identifier, 'status': status}
        self.save()
        print(f'Notary kind={kind} request={identifier} status={status}', flush=True)

    def begin_notary(self, kind):
        require(kind in ('app', 'dmg'), 'Invalid notary kind.')
        self.data['notarization'][kind] = {'id': None, 'status': 'submission_started_request_id_unavailable'}
        self.save()

    def finish(self, state):
        require(state in ('succeeded', 'failed'), 'Invalid signer final state.')
        self.data['state'] = state
        self.event('signer', state)


def native_tool(progress, *arguments, timeout=1800):
    label = tool_label(arguments)
    if progress: progress.event(label, 'started')
    try:
        result = subprocess.run([str(arg) for arg in arguments], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        if progress: progress.event(label, 'timeout')
        raise ReleaseError(f'Native tool timed out: {label}.') from None
    except OSError:
        if progress: progress.event(label, 'failed')
        raise ReleaseError(f'Native tool could not start: {label}.') from None
    if progress: progress.event(label, 'succeeded' if result.returncode == 0 else 'failed', exit_code=result.returncode)
    require(result.returncode == 0, f'Native tool failed: {label} (exit {result.returncode}).')
    return result.stdout


def notarize(path, kind, credentials, progress, *, tool, clock=time.monotonic, sleep=time.sleep):
    """One upload and bounded same-request polling; only Accepted can return."""
    require(kind in ('app', 'dmg'), 'Invalid notary kind.')
    progress.phase(kind + '-notary')
    progress.begin_notary(kind)
    deadline = clock() + NOTARY_BUDGET
    auth = ['--key', credentials['key_path'], '--key-id', credentials['key_id'],
            '--issuer', credentials['issuer']]
    def parse(raw):
        try:
            result = json.loads(raw)
        except (ValueError, TypeError):
            raise ReleaseError('Invalid notary JSON response.') from None
        require(isinstance(result, dict), 'Invalid notary JSON response.')
        return result
    # No --wait. A pending UUID is persisted as soon as the upload returns.
    result = parse(tool('/usr/bin/xcrun', 'notarytool', 'submit', path, *auth,
                        '--output-format', 'json', timeout=NOTARY_BUDGET))
    identifier = request_id(result.get('id'))
    status = result.get('status', 'In Progress')
    require(status in STATUSES, 'Unexpected notary submission status.')
    progress.notary(kind, identifier, status)
    require(status in ('In Progress', 'Accepted'), f'Apple rejected the {kind} submission.')
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            progress.event('notarytool-info', 'timeout')
            raise ReleaseError(f'Notary {kind} still pending at the existing 1800s deadline; request {identifier}.')
        result = parse(tool('/usr/bin/xcrun', 'notarytool', 'info', identifier, *auth,
                            '--output-format', 'json', timeout=min(INFO_TIMEOUT, remaining)))
        require(request_id(result.get('id')) == identifier, 'Notary response belongs to another request.')
        status = result.get('status')
        require(status in STATUSES, 'Unexpected notary info status.')
        progress.notary(kind, identifier, status)
        if status == 'Accepted':
            return {'id': identifier, 'status': status, 'kind': kind}
        require(status == 'In Progress', f'Apple rejected the {kind} submission.')
        sleep(min(POLL_SECONDS, max(0, deadline - clock())))
