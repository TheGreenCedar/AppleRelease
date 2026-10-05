"""CPU-only policy, extraction and archive preservation tests; no AI, keys or signing."""
import copy
import hashlib
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from policy import ROOT,ReleaseError,approved,validate_metadata,validate_manifest
from safe_zip import extract
from fetch_candidate import storage_url_allowed
from carchive import rebuild,unpack_entry
from PyInstaller.archive.readers import CArchiveReader
from PyInstaller.archive.writers import CArchiveWriter

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.app=json.loads((ROOT/'policy/apps.json').read_text())['apps']['speakerdesk'];self.build=self.app['approved_builds'][0]
        self.run={'id':self.build['run_id'],'repository':{'id':self.app['repository_id'],'full_name':self.app['repository']},'head_repository':{'id':self.app['repository_id']},'workflow_id':self.app['workflow_id'],'path':self.app['workflow_path'],'head_branch':'main','event':'workflow_dispatch','head_sha':self.build['source_commit'],'status':'completed','conclusion':'success'}
        self.artifact={'id':self.build['artifact_id'],'name':self.build['artifact_name'],'expired':False,'size_in_bytes':100,'digest':'sha256:'+self.build['artifact_sha256'],'workflow_run':{'id':self.build['run_id'],'repository_id':self.app['repository_id'],'head_repository_id':self.app['repository_id'],'head_sha':self.build['source_commit'],'head_branch':'main'}}
    def test_registered_exact_build_passes(self):
        app,build=approved('speakerdesk',str(self.build['run_id']),str(self.build['artifact_id']),self.build['artifact_sha256'],self.build['source_commit'])
        validate_metadata(app,build,self.run,self.artifact)
    def test_unknown_app_run_source_and_hash_are_rejected(self):
        original=['speakerdesk',str(self.build['run_id']),str(self.build['artifact_id']),self.build['artifact_sha256'],self.build['source_commit']]
        for index,value in [(0,'foreign'),(1,'1'),(2,'2'),(3,'0'*64),(4,'0'*40),(1,'1; echo forbidden')]:
            inputs=original.copy();inputs[index]=value
            with self.subTest(index=index),self.assertRaises(ReleaseError):approved(*inputs)
    def test_forks_wrong_branches_failed_runs_and_workflows_are_rejected(self):
        for key,value in [('event','pull_request'),('head_branch','feature'),('conclusion','failure'),('status','in_progress'),('workflow_id',1),('path','evil.yml'),('head_sha','0'*40),('head_repository',{'id':1})]:
            run=copy.deepcopy(self.run);run[key]=value
            with self.subTest(key=key),self.assertRaises(ReleaseError):validate_metadata(self.app,self.build,run,self.artifact)
    def test_artifact_provenance_and_digest_cannot_be_substituted(self):
        for key,value in [('id',1),('name','foreign'),('expired',True),('digest','sha256:'+'0'*64),('size_in_bytes',10**12),('workflow_run',{})]:
            artifact=copy.deepcopy(self.artifact);artifact[key]=value
            with self.subTest(key=key),self.assertRaises(ReleaseError):validate_metadata(self.app,self.build,self.run,artifact)
    def test_payload_hash_and_public_ready_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);data=b'candidate';(root/'file.zip').write_bytes(data)
            build=copy.deepcopy(self.build);build['files']=[{'filename':'file.zip','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}]
            manifest={'schema_version':1,'product':self.app['product'],'version':build['version'],'source_commit':build['source_commit'],'architecture':'arm64','platform':'macos','channel':'candidate','public_ready':False,'signing':'adhoc','notarized':False,'files':build['files']}
            validate_manifest(self.app,build,manifest,root)
            manifest['public_ready']=True
            with self.assertRaises(ReleaseError):validate_manifest(self.app,build,manifest,root)
            manifest['public_ready']=False;(root/'file.zip').write_bytes(b'tampered!')
            with self.assertRaises(ReleaseError):validate_manifest(self.app,build,manifest,root)
    def test_signed_blob_download_hosts_and_schemes_are_restricted(self):
        self.assertTrue(storage_url_allowed('https://results.blob.core.windows.net/archive?sig=temporary'))
        for url in ['http://results.blob.core.windows.net/a','https://blob.core.windows.net.attacker.example/a','https://user:pass@results.blob.core.windows.net/a','file:///tmp/a','https://example.com/a','https://results.blob.core.windows.net:8080/a']:
            with self.subTest(url=url):self.assertFalse(storage_url_allowed(url))

class ZipTests(unittest.TestCase):
    def archive(self,root,entries):
        path=root/'input.zip'
        with zipfile.ZipFile(path,'w') as writer:
            for name,data,mode in entries:
                member=zipfile.ZipInfo(name);member.external_attr=mode<<16;writer.writestr(member,data)
        return path
    def test_regular_files_preserve_execution_permission(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);archive=self.archive(root,[('Speakerdesk.app/Contents/MacOS/app',b'bytes',stat.S_IFREG|0o755)])
            app=extract(archive,root/'stage',root_name='Speakerdesk.app')
            self.assertEqual((app/'Contents/MacOS/app').read_bytes(),b'bytes')
            self.assertEqual((app/'Contents/MacOS/app').stat().st_mode&0o777,0o755)
    def test_traversal_special_files_and_foreign_roots_are_rejected(self):
        for name,mode in [('../outside',stat.S_IFREG|0o644),('/absolute',stat.S_IFREG|0o644),('Speakerdesk.app/../outside',stat.S_IFREG|0o644),('Speakerdesk.app/pipe',stat.S_IFIFO|0o644),('Other.app/file',stat.S_IFREG|0o644),('Speakerdesk.app\\file',stat.S_IFREG|0o644)]:
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);archive=self.archive(root,[(name,b'bytes',mode)])
                with self.subTest(name=name),self.assertRaises(ReleaseError):extract(archive,root/'stage',root_name='Speakerdesk.app')
    def test_external_symlink_and_internal_link_are_handled(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);archive=self.archive(root,[('Speakerdesk.app/real',b'bytes',stat.S_IFREG|0o644),('Speakerdesk.app/link',b'real',stat.S_IFLNK|0o777)])
            app=extract(archive,root/'stage',root_name='Speakerdesk.app');self.assertEqual((app/'link').read_bytes(),b'bytes')
        for target in [b'../../outside',b'/tmp/outside']:
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);archive=self.archive(root,[('Speakerdesk.app/link',target,stat.S_IFLNK|0o777)])
                with self.assertRaises(ReleaseError):extract(archive,root/'stage',root_name='Speakerdesk.app')
    def test_outer_artifact_inventory_is_exact(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);archive=self.archive(root,[('extra',b'bytes',stat.S_IFREG|0o644)])
            with self.assertRaises(ReleaseError):extract(archive,root/'stage',expected_files=['expected'])

class ArchiveTests(unittest.TestCase):
    def test_embedded_native_transform_preserves_pyz_scripts_options_and_prefix(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);entries=[]
            for name,data,kind in [('PYZ.pyz',b'PYZ bytes never executed','z'),('boot',b'marshaled code bytes never executed','s'),('native.dylib',b'\xcf\xfa\xed\xfe'+b'native bytes','b'),('notice',b'license bytes','x')]:
                source=root/(name+'.payload');source.write_bytes(data)
                # Raw blob writer creates a small archive without compiling or loading a script.
                entries.append((name,data,kind))
            writer=CArchiveWriter.__new__(CArchiveWriter);archive=root/'archive.pkg'
            import struct
            with archive.open('wb') as stream:
                toc=[writer._write_blob(stream,data,name,kind,True) for name,data,kind in entries]
                toc.append((stream.tell(),0,0,0,'o','pyi-contents-directory _internal'))
                offset=stream.tell();table=writer._serialize_toc(toc);stream.write(table)
                stream.write(struct.pack(writer._COOKIE_FORMAT,writer._COOKIE_MAGIC_PATTERN,stream.tell()+writer._COOKIE_LENGTH,offset,len(table),313,b'Python'))
            original=root/'runtime';prefix=b'fixed-executable-prefix';original.write_bytes(prefix+archive.read_bytes())
            output=root/'rewritten';changed=rebuild(original,output,lambda name,data:data+b'signature-fixture')
            self.assertEqual(changed,['native.dylib']);self.assertTrue(output.read_bytes().startswith(prefix))
            before=CArchiveReader(str(original));after=CArchiveReader(str(output));self.assertEqual(before.options,after.options)
            for name,_,_ in entries:
                expected=unpack_entry(before,name)+(b'signature-fixture' if name=='native.dylib' else b'')
                self.assertEqual(unpack_entry(after,name),expected)

if __name__=='__main__':unittest.main()
