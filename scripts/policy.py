"""Fixed release policy. Dispatch inputs identify a preapproved build, never a URL."""
import hashlib
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MAX_ARCHIVE=300*1024**2
MAX_UNPACKED=1024**3
MAX_MEMBER=500*1024**2

class ReleaseError(Exception):
    pass

def require(condition, message):
    if not condition:raise ReleaseError(message)

def approved(app_key, run_id, artifact_id, digest, source_commit):
    config=json.loads((ROOT/'policy/apps.json').read_text())
    require(app_key in config['apps'], 'Application is not registered.')
    require(re.fullmatch(r'[0-9]{1,20}', str(run_id)) and re.fullmatch(r'[0-9]{1,20}', str(artifact_id)), 'Invalid numeric identity.')
    require(re.fullmatch(r'[0-9a-f]{64}',digest) and re.fullmatch(r'[0-9a-f]{40}',source_commit), 'Invalid source or artifact hash.')
    app=config['apps'][app_key]
    matches=[build for build in app['approved_builds'] if build['run_id']==int(run_id) and build['artifact_id']==int(artifact_id)
             and build['artifact_sha256']==digest and build['source_commit']==source_commit]
    require(len(matches)==1,'Build is not approved by the central policy.')
    return app,matches[0]

def archive_limit(build):
    """A registered build may pin its exact larger archive, never a loose cap."""
    exact=build.get('archive_bytes')
    if exact is None:return MAX_ARCHIVE
    require(type(exact) is int and 0<exact<=MAX_MEMBER,'Invalid exact archive byte pin.')
    return exact

def validate_metadata(app, build, run, artifact):
    require(run.get('id')==build['run_id'], 'Run identity mismatch.')
    require(run.get('repository',{}).get('id')==app['repository_id'] and run.get('head_repository',{}).get('id')==app['repository_id'], 'Foreign or forked repository.')
    require(run.get('repository',{}).get('full_name')==app['repository'], 'Repository name mismatch.')
    require(run.get('workflow_id')==app['workflow_id'] and run.get('path')==app['workflow_path'], 'Unexpected build workflow.')
    require(run.get('head_branch')==app['branch'] and run.get('event')==app['event'], 'Untrusted branch or event.')
    require(run.get('head_sha')==build['source_commit'] and run.get('status')=='completed' and run.get('conclusion')=='success', 'Source or build result mismatch.')
    require(artifact.get('id')==build['artifact_id'] and artifact.get('name')==build['artifact_name'], 'Artifact identity mismatch.')
    size=artifact.get('size_in_bytes',0)
    require(artifact.get('expired') is False and type(size) is int and 0<size<=archive_limit(build), 'Artifact is expired or too large.')
    if 'archive_bytes' in build:require(size==build['archive_bytes'],'Exact archive byte pin differs.')
    require(artifact.get('digest')=='sha256:'+build['artifact_sha256'], 'Artifact service digest mismatch.')
    origin=artifact.get('workflow_run',{})
    require(origin.get('id')==build['run_id'] and origin.get('repository_id')==app['repository_id']
            and origin.get('head_repository_id')==app['repository_id'] and origin.get('head_sha')==build['source_commit']
            and origin.get('head_branch')==app['branch'], 'Artifact provenance mismatch.')

def digest_file(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block:=stream.read(8*1024**2):digest.update(block)
    return digest.hexdigest()

def validate_manifest(app, build, manifest, directory):
    require(manifest.get('schema_version')==1 and manifest.get('product')==app['product'], 'Unexpected manifest product.')
    require(manifest.get('version')==build['version'] and manifest.get('source_commit')==build['source_commit'], 'Manifest source or version mismatch.')
    require(manifest.get('architecture')=='arm64' and manifest.get('platform')=='macos', 'Unexpected target.')
    require(manifest.get('channel')=='candidate' and manifest.get('public_ready') is False
            and manifest.get('signing')=='adhoc' and manifest.get('notarized') is False, 'Input must be an unpromoted ad-hoc candidate.')
    require(manifest.get('files')==build['files'], 'Manifest file inventory mismatch.')
    for item in build['files']:
        path=directory/item['filename']
        require(path.is_file() and not path.is_symlink() and path.stat().st_size==item['bytes'], 'Payload size mismatch.')
        require(digest_file(path)==item['sha256'],'Payload checksum mismatch.')
