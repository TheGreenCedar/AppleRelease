"""Fixed central-signing capability refresh; never execute producer code."""
import hashlib
import json
import os
from pathlib import Path
import tempfile

from policy import digest_file, require

FIXED = {'capability_version': 'apple_input_node_output_route_v1',
         'export_contract': 'apple_processed_mono16k_v1'}
CAPTURE_PATH = 'Contents/Resources/speakerdesk-capture'


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate capture capability field.')
        result[key] = value
    return result


def admit(bundle, app, build, capture):
    """Authenticate old helper/manifest binding before any signing mutation."""
    capture = Path(capture)
    path = capture.with_name(capture.name + '.capability.json')
    entry = build.get('capture_capability')
    if entry is None:
        require(not path.exists() and not path.is_symlink(),
                'Capture capability needs explicit registered build opt-in.')
        return None
    require(type(entry) is dict and entry == FIXED,
            'Unsupported registered capture capability contract.')
    require(app.get('bundle_id') == 'com.speakerdesk.desktop'
            and app.get('capture_helper') == CAPTURE_PATH
            and capture == Path(bundle) / CAPTURE_PATH,
            'Capture capability path is not the registered Speakerdesk helper.')
    require(capture.is_file() and not capture.is_symlink(),
            'Capture helper is missing or linked.')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4096,
            'Capture capability manifest is missing or unsafe.')
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError):
        require(False, 'Capture capability manifest is invalid JSON.')
    require(type(value) is dict
            and set(value) == {'helper_sha256', 'capability_version', 'export_contract'}
            and {key: value[key] for key in FIXED} == FIXED
            and value['helper_sha256'] == digest_file(capture),
            'Capture capability does not match the approved input helper.')
    return {'path': path, 'input_manifest_sha256': digest_file(path),
            'input_helper_sha256': value['helper_sha256']}


def refresh(capture, admitted):
    """Only update final helper digest after native signing, before outer signing."""
    if admitted is None:
        return None
    capture = Path(capture)
    path = admitted['path']
    require(path == capture.with_name(capture.name + '.capability.json')
            and path.is_file() and not path.is_symlink()
            and digest_file(path) == admitted['input_manifest_sha256'],
            'Capture capability changed during native signing.')
    require(capture.is_file() and not capture.is_symlink(),
            'Signed capture helper is missing or linked.')
    final_hash = digest_file(capture)
    value = {**FIXED, 'helper_sha256': final_hash}
    data = (json.dumps(value, sort_keys=True) + '\n').encode()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.capture-capability-',
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    require(digest_file(path) == hashlib.sha256(data).hexdigest(),
            'Final capture capability publication differs.')
    return {'manifest': CAPTURE_PATH + '.capability.json', **FIXED,
            'input_helper_sha256': admitted['input_helper_sha256'],
            'signed_helper_sha256': final_hash,
            'manifest_sha256': digest_file(path)}

