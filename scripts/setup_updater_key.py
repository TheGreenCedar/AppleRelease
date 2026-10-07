"""User-run, one-time setup. SOURCE REVIEW ONLY; never run by an agent or CI."""
import getpass
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tooling/updater'
REPOSITORY = 'TheGreenCedar/AppleRelease'
PRIVATE_NAME = 'TAURI_SIGNING_PRIVATE_KEY'
PASSWORD_NAME = 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD'


def run(arguments, *, environment, input_bytes=None, input_file=None, terminal=False):
    """No secret argument values, raw stdout, raw errors or plaintext temporary files."""
    if input_bytes is not None and input_file is not None: raise RuntimeError('Invalid setup input source.')
    inputs = {'input': input_bytes} if input_bytes is not None else {'stdin': input_file if input_file is not None else (None if terminal else subprocess.DEVNULL)}
    result = subprocess.run([str(arg) for arg in arguments], env=environment, **inputs,
                            stdout=subprocess.PIPE, stderr=None if terminal else subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('Setup command failed; no command output or credential value was logged.')
    return result.stdout


def main():
    if len(sys.argv) != 2 or not sys.stdin.isatty() or not sys.stderr.isatty():
        raise RuntimeError('Run interactively with one NEW private directory path outside this repository.')
    os.umask(0o077)
    directory = Path(sys.argv[1]).expanduser().absolute()
    if directory.exists() or directory.is_symlink() or directory.resolve().is_relative_to(ROOT):
        raise RuntimeError('Use a new persistent private directory outside this repository; no overwrite is allowed.')
    if not directory.parent.is_dir() or directory.parent.resolve() != directory.parent:
        raise RuntimeError('The parent directory must already exist and must not use symbolic links.')
    cli = TOOLS / 'node_modules/@tauri-apps/cli/tauri.js'
    verifier = TOOLS / 'verifier/target/release/applerelease-updater-verify'
    if not cli.is_file() or not verifier.is_file():
        raise RuntimeError('Prepare the locked CLI and verifier as documented before running setup.')
    environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'SYSTEMROOT', 'USERPROFILE') if key in os.environ}
    login = run(['gh', 'api', 'user', '--jq', '.login'], environment=environment).decode().strip()
    if login != 'TheGreenCedar': raise RuntimeError('Authenticate gh as TheGreenCedar before setting the repository Actions secrets.')
    metadata = json.loads(run(['gh', 'secret', 'list', '--repo', REPOSITORY, '--json', 'name'], environment=environment))
    if any(item['name'] in {PRIVATE_NAME, PASSWORD_NAME} for item in metadata):
        raise RuntimeError('Updater secrets already exist. Do not rotate the key with this setup script.')
    directory.mkdir(mode=0o700)
    key_path = directory / 'speakerdesk-updater.key'; public_path = Path(str(key_path) + '.pub')
    print('Choose a strong, nonempty password at the official Tauri prompts. Save it in your password manager.', file=sys.stderr)
    # --write-keys ensures official CLI prints no private key. No --ci/--force/password argument.
    run(['node', cli, 'signer', 'generate', '--write-keys', key_path], environment=environment, terminal=True)
    if not key_path.is_file() or key_path.is_symlink() or key_path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError('Generated private-key file did not have the required 0600 mode. Nothing uploaded.')
    password = getpass.getpass('Re-enter the same password for verification and GitHub Actions: ')
    if not password: raise RuntimeError('An encrypted key with a nonempty password is required. Nothing uploaded.')
    # A disposable PUBLIC probe proves the supplied password and public key match before submission.
    # The private key remains only in its persistent encrypted 0600 file, never a temp plaintext file.
    signing_environment = dict(environment, TAURI_SIGNING_PRIVATE_KEY_PASSWORD=password)
    with tempfile.TemporaryDirectory(prefix='speakerdesk-updater-public-probe-') as temp:
        probe = Path(temp) / 'public-probe'; probe.write_bytes(b'Speakerdesk updater setup public verification probe\n')
        run(['node', cli, 'signer', 'sign', '--private-key-path', key_path, '--app-version', '0.0.0', probe], environment=signing_environment)
        run([verifier, probe, Path(str(probe) + '.sig'), public_path, '0.0.0'], environment=environment)
    print('Verified key and password. Submitting the two Actions secrets to TheGreenCedar/AppleRelease.', file=sys.stderr)
    with key_path.open('rb') as source:
        run(['gh', 'secret', 'set', PRIVATE_NAME, '--repo', REPOSITORY, '--app', 'actions'], environment=environment, input_file=source)
    run(['gh', 'secret', 'set', PASSWORD_NAME, '--repo', REPOSITORY, '--app', 'actions'], environment=environment, input_bytes=password.encode())
    # Only the public key is emitted. Keep the encrypted key file/password in your own backup.
    print(public_path.read_text().strip())
    print('Keep the encrypted key file and password backed up. Share only the public key above for source configuration.', file=sys.stderr)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(str(error) if isinstance(error, RuntimeError) else 'Setup failed; credential values were not logged.', file=sys.stderr)
        sys.exit(1)
