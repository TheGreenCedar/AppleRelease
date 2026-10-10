"""Fixed native signing/notarization tools; never execute the uploaded application."""
import json
import os
import plistlib
import sys
import tempfile
from pathlib import Path
from PyInstaller.utils.osx import fix_exe_for_code_signing,remove_signature_from_binary
from carchive import is_macho,rebuild,unpack_entry
from PyInstaller.archive.readers import CArchiveReader
from policy import ReleaseError,digest_file,require
from safe_zip import extract
from signing_progress import Progress,native_tool,notarize
from updater_artifacts import configuration as updater_configuration,produce as produce_updater
from capture_capability import admit as admit_capture_capability, refresh as refresh_capture_capability

ROOT=Path(__file__).resolve().parents[1]
PROGRESS=None

def tool(*arguments,timeout=1800):
    return native_tool(PROGRESS,*arguments,timeout=timeout)

def phase(name):
    if PROGRESS:PROGRESS.phase(name)

def sign(path,identity,*,entitlements=None):
    arguments=['/usr/bin/codesign','--force','--options','runtime','--timestamp','--sign',identity]
    if entitlements:arguments+=['--entitlements',str(entitlements)]
    tool(*arguments,path)
    tool('/usr/bin/codesign','--verify','--strict',path)

def sign_runtime(runtime,identity,directory):
    # Remove the old outer signature before changing __LINKEDIT/archive sizes.
    remove_signature_from_binary(str(runtime))
    counter=0
    def transform(name,data):
        nonlocal counter
        counter+=1;path=directory/f'embedded-{counter}'
        path.write_bytes(data);path.chmod(0o700)
        require(tool('/usr/bin/lipo','-archs',path).strip()=='arm64','Embedded code is not thin arm64.')
        sign(path,identity);signed=path.read_bytes();path.unlink();return signed
    replacement=runtime.with_name(runtime.name+'.resigned')
    changed=rebuild(runtime,replacement,transform)
    require(changed,'No embedded native libraries were found.')
    fix_exe_for_code_signing(str(replacement));replacement.replace(runtime)
    sign(runtime,identity)
    # Read back the reassembled archive and verify each embedded native signature.
    archive=CArchiveReader(str(runtime))
    for index,name in enumerate(changed):
        path=directory/f'verify-{index}';path.write_bytes(unpack_entry(archive,name))
        tool('/usr/bin/codesign','--verify','--strict',path);path.unlink()
    return len(changed)

def run(work,output,progress=None):
    global PROGRESS
    PROGRESS=progress
    phase('validation')
    work=Path(work).resolve();output=Path(output).resolve()
    context=json.loads((work/'approved.json').read_text());app=context['app'];build=context['build']
    if updater_configuration(app,build):
        require(bool(os.environ.get('TAURI_SIGNING_PRIVATE_KEY')),'Configure the app-specific updater signing key first.')
    require(PROGRESS is not None,'Persistent signer diagnostics are required.')
    PROGRESS.bind_input(build)
    bundle=work/'stage'/app['app_name'];require(bundle.is_dir(),'Validated app bundle missing.')
    metadata=plistlib.loads((bundle/'Contents/Info.plist').read_bytes())
    require(metadata.get('CFBundleIdentifier')==app['bundle_id'] and metadata.get('CFBundleShortVersionString')==build['version'],'Bundle identity or version mismatch.')
    executable=metadata.get('CFBundleExecutable','');require(executable and '/' not in executable and '\\' not in executable,'Invalid main executable.')
    main=bundle/'Contents/MacOS'/executable;runtime=bundle/app['pyinstaller_runtime'];capture=bundle/app['capture_helper']
    for path in [main,runtime,capture]:require(path.is_file() and not path.is_symlink(),'Required native executable missing.')
    capture_capability=admit_capture_capability(bundle,app,build,capture)
    identity=os.environ['APPLE_SIGNING_IDENTITY'];require(identity!='-','Developer ID signing is required.')
    entitlements=ROOT/'policy/audio-input.plist'
    phase('embedded-signing')
    with tempfile.TemporaryDirectory(prefix='speakerdesk-inner-sign-',dir=work) as temp:
        native_count=sign_runtime(runtime,identity,Path(temp))
    phase('bundle-signing')
    native=[]
    for directory,dirs,files in os.walk(bundle,followlinks=False):
        for name in files:
            path=Path(directory)/name
            if path.is_symlink():require(path.resolve().is_relative_to(bundle.resolve()),'External bundle link.');continue
            with path.open('rb') as stream:magic=stream.read(4)
            if is_macho(magic):native.append(path)
    for path in sorted(native,key=lambda p:len(p.parts),reverse=True):
        require(tool('/usr/bin/lipo','-archs',path).strip()=='arm64','Bundle contains a non-arm64 executable.')
        if path!=runtime:sign(path,identity,entitlements=entitlements if path==capture else None)
    capture_capability_metadata=refresh_capture_capability(capture,capture_capability)
    sign(bundle,identity,entitlements=entitlements)
    tool('/usr/bin/codesign','--verify','--deep','--strict',bundle)
    details=tool('/usr/bin/codesign','--display','--verbose=4',bundle)
    require('TeamIdentifier='+app['team_id'] in details and 'Authority=Developer ID Application:' in details,'Unexpected signing team or authority.')
    # Notarize the app first so both the ZIP and DMG contain a stapled app.
    output.mkdir(parents=True,exist_ok=False)
    archive=output/f'{app["product"]}_{build["version"]}_AppleSilicon.app.zip'
    tool('/usr/bin/ditto','-c','-k','--noextattr','--norsrc','--keepParent',bundle,archive)
    credentials={'key_path':Path(os.environ['APPLE_API_KEY_PATH']),
                 'key_id':os.environ['APPLE_API_KEY'],'issuer':os.environ['APPLE_API_ISSUER']}
    receipts=[notarize(archive,'app',credentials,PROGRESS,tool=tool)]
    phase('app-staple')
    tool('/usr/bin/xcrun','stapler','staple',bundle);tool('/usr/bin/xcrun','stapler','validate',bundle)
    tool('/usr/sbin/spctl','--assess','--type','execute',bundle)
    archive.unlink();tool('/usr/bin/ditto','-c','-k','--noextattr','--norsrc','--keepParent',bundle,archive)
    phase('dmg-build')
    installer=work/'installer';installer.mkdir();tool('/usr/bin/ditto','--noextattr','--norsrc',bundle,installer/app['app_name'])
    os.symlink('/Applications',installer/'Applications')
    dmg=output/f'{app["product"]}_{build["version"]}_AppleSilicon.dmg'
    tool('/usr/bin/hdiutil','create','-volname',app['product'],'-srcfolder',installer,'-format','UDZO','-fs','HFS+','-ov',dmg)
    tool('/usr/bin/codesign','--force','--timestamp','--sign',identity,dmg)
    receipts.append(notarize(dmg,'dmg',credentials,PROGRESS,tool=tool))
    phase('dmg-staple')
    tool('/usr/bin/xcrun','stapler','staple',dmg);tool('/usr/bin/xcrun','stapler','validate',dmg)
    tool('/usr/bin/codesign','--verify','--strict',dmg)
    phase('zip-verification')
    zipped=extract(archive,work/'verify-zip',root_name=app['app_name'])
    tool('/usr/bin/codesign','--verify','--deep','--strict',zipped)
    tool('/usr/bin/xcrun','stapler','validate',zipped)
    phase('dmg-verification')
    mount=work/'verify-dmg';mount.mkdir()
    tool('/usr/bin/hdiutil','attach',dmg,'-readonly','-nobrowse','-mountpoint',mount)
    try:
        installed=mount/app['app_name']
        tool('/usr/bin/codesign','--verify','--deep','--strict',installed)
        tool('/usr/bin/xcrun','stapler','validate',installed)
        tool('/usr/sbin/spctl','--assess','--type','execute',installed)
    finally:tool('/usr/bin/hdiutil','detach',mount)
    updater_files,updater_metadata=produce_updater(app,build,bundle,work,output,progress=PROGRESS,native_tool=tool)
    phase('manifest')
    manifest={'schema_version':1,'product':app['product'],'version':build['version'],'source_repository':app['repository'],
              'source_commit':build['source_commit'],'producer_run_id':build['run_id'],'input_artifact_id':build['artifact_id'],
              'input_artifact_sha256':build['artifact_sha256'],'signer_commit':os.environ['GITHUB_SHA'],'signer_run_id':os.environ['GITHUB_RUN_ID'],
              'platform':'macos','architecture':'arm64','minimum_os':context['input_manifest']['minimum_os'],
              'channel':'candidate','public_ready':False,'native_meeting_qa':'pending','signing':'developer-id','notarized':True,
              'embedded_native_signatures_verified':native_count,'notarization':receipts,
              'files':[{'filename':p.name,'bytes':p.stat().st_size,'sha256':digest_file(p)} for p in [dmg,archive,*updater_files]]}
    if updater_metadata is not None:manifest['updater']=updater_metadata
    if capture_capability_metadata is not None:manifest['capture_capability']=capture_capability_metadata
    (output/'artifact-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (output/'SHA256SUMS').write_text(''.join(f'{item["sha256"]}  {item["filename"]}\n' for item in manifest['files']))
    phase('complete')
    PROGRESS.finish('succeeded')
    print(f'Notarized private candidate; verified {native_count} embedded native signatures. Public readiness remains pending.')

if __name__=='__main__':
    progress=None
    try:
        require(len(sys.argv)==4,'Expected approved work, candidate output and safe diagnostics path.')
        progress=Progress(sys.argv[3])
        run(sys.argv[1],sys.argv[2],progress)
    except Exception as error:
        if progress:progress.finish('failed')
        print('Signing failed: '+(str(error) if isinstance(error,ReleaseError) else type(error).__name__),file=sys.stderr);sys.exit(1)
