"""Opt-in final updater signing with trusted, independently locked tools only."""
import base64
import binascii
import os
import re
import subprocess
import sys
from pathlib import Path

from policy import ROOT, ReleaseError, digest_file, require
from updater_archive import create, verify

TOOLS = ROOT / 'tooling/updater'


def configuration(app, build):
    enabled = build.get('updater', False)
    require(type(enabled) is bool, 'Updater registration must be a boolean.')
    if not enabled: return None
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', build['version']), 'Invalid updater app version.')
    require(tuple(map(int, build['version'].split('.'))) >= (0, 6, 2), 'Legacy builds cannot opt into updater artifacts.')
    public = app.get('updater_public_key', '')
    require(isinstance(public, str) and public and len(public) <= 4096, 'Register the app-specific updater public key first.')
    try: decoded = base64.b64decode(public, validate=True).decode('utf-8')
    except (ValueError, UnicodeError, binascii.Error): raise ReleaseError('Invalid updater public key encoding.') from None
    require(len(decoded.splitlines()) == 2 and decoded.startswith('untrusted comment: '), 'Invalid updater public key format.')
    try: raw = base64.b64decode(decoded.splitlines()[1], validate=True)
    except (ValueError, binascii.Error): raise ReleaseError('Invalid updater public key payload.') from None
    require(len(raw) == 42 and raw.startswith(b'Ed'), 'Invalid updater public key payload.')
    # Only the public key is inspected here. Private values are consumed by the fixed CLI.
    return public


def updater_tool(progress, operation, arguments, *, signing=False):
    require(operation in {'updater-sign', 'updater-verify'}, 'Unknown updater tool.')
    environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'SYSTEMROOT', 'USERPROFILE')
                   if key in os.environ}
    if signing:
        # Never pass key values or paths on the command line; suppress raw tool output.
        require(bool(os.environ.get('TAURI_SIGNING_PRIVATE_KEY')), 'Configure the app-specific updater signing key first.')
        environment['TAURI_SIGNING_PRIVATE_KEY'] = os.environ['TAURI_SIGNING_PRIVATE_KEY']
        environment['TAURI_SIGNING_PRIVATE_KEY_PASSWORD'] = os.environ.get('TAURI_SIGNING_PRIVATE_KEY_PASSWORD', '')
    if progress: progress.event(operation, 'started')
    try:
        result = subprocess.run([str(arg) for arg in arguments], cwd=TOOLS, env=environment,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=180, text=True)
    except (OSError, subprocess.TimeoutExpired):
        if progress: progress.event(operation, 'failed')
        raise ReleaseError(f'Updater tool could not complete: {operation}.') from None
    if progress: progress.event(operation, 'succeeded' if result.returncode == 0 else 'failed', exit_code=result.returncode)
    require(result.returncode == 0, f'Updater tool failed: {operation}.')


def produce(app, build, bundle, work, output, *, progress, native_tool):
    public = configuration(app, build)
    if public is None: return [], None
    require(bool(os.environ.get('TAURI_SIGNING_PRIVATE_KEY')), 'Configure the app-specific updater signing key first.')
    archive = Path(output) / f'{app["product"]}_{build["version"]}_AppleSilicon.app.tar.gz'
    progress.phase('updater-archive')
    create(bundle, archive)
    extracted = verify(archive, Path(work) / 'verify-updater', bundle)
    native_tool('/usr/bin/codesign', '--verify', '--deep', '--strict', extracted)
    native_tool('/usr/bin/xcrun', 'stapler', 'validate', extracted)
    native_tool('/usr/sbin/spctl', '--assess', '--type', 'execute', extracted)
    # Paths originate in trusted AppleRelease source, never the producer archive.
    public_path = Path(work) / 'updater-public-key.txt'; public_path.write_text(public)
    before = digest_file(archive)
    progress.phase('updater-signing')
    updater_tool(progress, 'updater-sign', ['node', TOOLS / 'node_modules/@tauri-apps/cli/tauri.js',
                                          'signer', 'sign', '--app-version', build['version'], archive], signing=True)
    signature_path = archive.with_name(archive.name + '.sig')
    require(signature_path.is_file() and not signature_path.is_symlink() and 0 < signature_path.stat().st_size <= 8192,
            'Updater signature missing or invalid.')
    signature = signature_path.read_text(encoding='ascii')
    require(re.fullmatch('[A-Za-z0-9+/]+={0,2}', signature), 'Invalid updater signature encoding.')
    require(digest_file(archive) == before, 'Updater archive changed during signing.')
    updater_tool(progress, 'updater-verify', [TOOLS / 'verifier/target/release/applerelease-updater-verify',
                                            archive, signature_path, public_path, build['version']])
    metadata = {'platform': 'darwin-aarch64', 'filename': archive.name, 'signature_filename': signature_path.name,
                'signature': signature, 'public_key': public, 'require_signed_version': True}
    return [archive, signature_path], metadata


if __name__ == '__main__':
    # Workflow preflight: trusted approved context only, before loading signing credentials.
    try:
        import json
        require(len(sys.argv) == 2, 'Expected approved work directory.')
        context = json.loads((Path(sys.argv[1]) / 'approved.json').read_text())
        enabled = configuration(context['app'], context['build']) is not None
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            output.write('enabled=' + ('true' if enabled else 'false') + '\n')
        print('Approved updater artifact mode: ' + ('enabled' if enabled else 'legacy DMG/ZIP'))
    except Exception as error:
        print(str(error) if isinstance(error, ReleaseError) else 'Updater preflight failed.', file=sys.stderr)
        sys.exit(1)
