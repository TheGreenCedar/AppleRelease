"""Verify the exact artifact-reader App and installation using owner metadata access."""
import json
import re
import subprocess
import sys
from policy import ReleaseError,require

EXPECTED={'actions':'read','metadata':'read'}
def get(endpoint):
    result=subprocess.run(['gh','api',endpoint],capture_output=True,text=True)
    require(result.returncode==0,'GitHub metadata request failed; use an existing authorized owner session.')
    return json.loads(result.stdout)

def verify(slug):
    require(re.fullmatch(r'[a-z0-9-]{1,100}',slug),'Invalid App slug.')
    app=get('apps/'+slug)
    require(app.get('owner',{}).get('login')=='TheGreenCedar','App owner mismatch.')
    require(app.get('permissions')==EXPECTED and app.get('events')==[],'App requests excess permissions or events.')
    installations=get('user/installations?per_page=100')
    require(installations.get('total_count',0)<=100,'Installation pagination requires explicit review.')
    matches=[i for i in installations.get('installations',[]) if i.get('app_id')==app['id']]
    require(len(matches)==1,'Expected exactly one owner-accessible App installation.')
    installation=matches[0]
    require(installation.get('account',{}).get('login')=='TheGreenCedar' and installation.get('target_type')=='User','Installation account mismatch.')
    require(installation.get('repository_selection')=='selected' and installation.get('permissions')==EXPECTED
            and installation.get('suspended_at') is None,'Unexpected installation permissions or scope.')
    repositories=get(f'user/installations/{installation["id"]}/repositories?per_page=100')
    require(repositories.get('total_count')==1 and [(r['id'],r['full_name']) for r in repositories.get('repositories',[])]==[(1406057260,'TheGreenCedar/Speakerdesk')],'Installation must contain Speakerdesk only.')
    result={'app_id':app['id'],'slug':app['slug'],'installation_id':installation['id'],'permissions':EXPECTED,
            'repository_selection':'selected','repositories':['TheGreenCedar/Speakerdesk'],
            'ui_checks_required':['Only on this account','Webhooks inactive','OAuth/device flow disabled']}
    print(json.dumps(result,indent=2))
    return result

if __name__=='__main__':
    try:verify(sys.argv[1])
    except Exception as error:
        print('Registration verification failed: '+(str(error) if isinstance(error,ReleaseError) else type(error).__name__),file=sys.stderr);sys.exit(1)
