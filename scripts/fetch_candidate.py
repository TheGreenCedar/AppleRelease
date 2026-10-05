"""Read only approved Actions artifacts. Never forward API credentials to blob storage."""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from policy import MAX_ARCHIVE, ReleaseError, approved, digest_file, require, validate_manifest, validate_metadata
from safe_zip import extract

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def storage_url_allowed(url):
    parsed=urllib.parse.urlsplit(url)
    host=parsed.hostname or ''
    return parsed.scheme=='https' and not parsed.username and not parsed.password and parsed.port in {None,443} and any(
        host.endswith(suffix) for suffix in ['.blob.core.windows.net','.actions.githubusercontent.com','.githubusercontent.com'])

def api(path, token, *, redirect=False):
    require(path.startswith('/repos/') or path=='/installation/repositories','Unexpected API endpoint.')
    request=urllib.request.Request('https://api.github.com'+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
    try:
        with urllib.request.build_opener(NoRedirect).open(request,timeout=60) as response:
            require(not redirect,'Artifact service did not provide a signed download URL.')
            return json.load(response)
    except urllib.error.HTTPError as error:
        if redirect and error.code==302:
            location=error.headers.get('Location','');require(storage_url_allowed(location),'Unexpected artifact storage destination.');return location
        raise ReleaseError(f'GitHub API request failed (HTTP {error.code}).') from None

def fetch(app_key,run_id,artifact_id,digest,source_commit,destination,token):
    app,build=approved(app_key,run_id,artifact_id,digest,source_commit)
    accessible=api('/installation/repositories',token)
    require(accessible.get('total_count')==1 and [repo['id'] for repo in accessible.get('repositories',[])]==[app['repository_id']],'Artifact token must cover only the registered producer repository.')
    base='/repos/'+app['repository']+'/actions/'
    run=api(base+'runs/'+str(build['run_id']),token)
    artifact=api(base+'artifacts/'+str(build['artifact_id']),token)
    validate_metadata(app,build,run,artifact)
    location=api(base+'artifacts/'+str(build['artifact_id'])+'/zip',token,redirect=True)
    work=Path(destination);work.mkdir(parents=True,exist_ok=False);work.chmod(0o700)
    archive=work/'candidate.zip';received=0
    # This request deliberately contains no GitHub Authorization header.
    try:
        with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(location),timeout=60) as response,archive.open('xb') as output:
            while block:=response.read(1024**2):
                received+=len(block);require(received<=MAX_ARCHIVE,'Artifact download exceeds limit.');output.write(block)
    except urllib.error.HTTPError as error:raise ReleaseError(f'Artifact storage request failed (HTTP {error.code}).') from None
    require(received==artifact['size_in_bytes'] and digest_file(archive)==build['artifact_sha256'],'Downloaded artifact integrity check failed.')
    expected=[item['filename'] for item in build['files']]+['artifact-manifest.json','SHA256SUMS']
    payload=extract(archive,work/'payload',expected_files=expected)
    manifest=json.loads((payload/'artifact-manifest.json').read_text())
    validate_manifest(app,build,manifest,payload)
    app_zip=payload/f'{app["product"]}_{build["version"]}_AppleSilicon.app.zip'
    extract(app_zip,work/'stage',root_name=app['app_name'])
    (work/'approved.json').write_text(json.dumps({'app_key':app_key,'app':app,'build':build,'input_manifest':manifest},indent=2)+'\n')
    print('Verified exact producer run, source, archive digest, payload hashes and bounded app extraction.')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('destination');args=parser.parse_args()
    try:fetch(os.environ['INPUT_APP'],os.environ['INPUT_RUN_ID'],os.environ['INPUT_ARTIFACT_ID'],os.environ['INPUT_ARTIFACT_SHA256'],os.environ['INPUT_SOURCE_COMMIT'],args.destination,os.environ['GH_TOKEN'])
    except Exception as error:
        print('Candidate validation failed: '+(str(error) if isinstance(error,ReleaseError) else type(error).__name__),file=sys.stderr);sys.exit(1)
