"""Synthetic P12 import tests. No real Keychain, credentials, or network access."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'scripts/prepare_credentials.sh'

class CredentialPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.key=self.root/'synthetic.key';self.cert=self.root/'synthetic.pem';self.p12=self.root/'synthetic.p12'
        self.log=self.root/'commands.jsonl';self.bin=self.root/'bin';self.bin.mkdir()
        subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(self.key)],capture_output=True,check=True)
        subprocess.run(['openssl','req','-new','-x509','-key',str(self.key),'-out',str(self.cert),'-subj','/CN=Synthetic Credential Fixture','-days','1'],capture_output=True,check=True)
        security=self.bin/'security'
        security.write_text('''#!/usr/bin/env python3
import json,os,subprocess,sys
from pathlib import Path
a=sys.argv[1:]
with Path(os.environ['TEST_SECURITY_LOG']).open('a') as log:log.write(json.dumps(a[0])+'\\n')
if a[0]=='import':
 password=a[a.index('-P')+1]
 check=subprocess.run(['openssl','pkcs12','-in',a[1],'-info','-noout','-passin','stdin'],input=password+'\\n',text=True,capture_output=True)
 if check.returncode:print('Synthetic P12 import validation failed',file=sys.stderr);sys.exit(1)
elif a[0]=='list-keychains' and '-s' not in a:print('"synthetic-existing.keychain-db"')
elif a[0] not in ('create-keychain','set-keychain-settings','unlock-keychain','set-key-partition-list','list-keychains','default-keychain'):sys.exit(2)
''');security.chmod(0o700)

    def tearDown(self):self.temp.cleanup()

    def invoke(self,export_password,provided_password=None,missing=None):
        subprocess.run(['openssl','pkcs12','-export','-inkey',str(self.key),'-in',str(self.cert),'-out',str(self.p12),'-passout','stdin'],input=export_password+'\n',text=True,capture_output=True,check=True)
        environment=os.environ.copy()
        environment.update({'PATH':str(self.bin)+os.pathsep+environment['PATH'],'RUNNER_TEMP':str(self.root),'GITHUB_ENV':str(self.root/'github-env'),
                            'TEST_SECURITY_LOG':str(self.log),'APPLE_API_KEY':'SYNTHETIC0','APPLE_API_ISSUER':'11111111-2222-4333-8444-555555555555',
                            'APPLE_API_KEY_CONTENT':self.key.read_text(),'APPLE_CERTIFICATE':base64.b64encode(self.p12.read_bytes()).decode(),
                            'APPLE_CERTIFICATE_PASSWORD':export_password if provided_password is None else provided_password,'APPLE_SIGNING_IDENTITY':'Synthetic identity'})
        if missing:environment.pop(missing)
        return subprocess.run(['bash',str(SCRIPT)],env=environment,capture_output=True,text=True,timeout=30)

    def test_empty_password_valid_p12_reaches_authenticated_import(self):
        result=self.invoke('')
        self.assertEqual(result.returncode,0)
        self.assertIn('import',self.log.read_text())
        self.assertEqual((self.root/'applerelease-certificate.p12').read_bytes(),self.p12.read_bytes())

    def test_nonempty_password_still_authenticates_p12(self):
        result=self.invoke('synthetic-export-password')
        self.assertEqual(result.returncode,0)

    def test_empty_password_cannot_import_nonempty_password_export(self):
        result=self.invoke('synthetic-export-password',provided_password='')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('set-key-partition-list',self.log.read_text())

    def test_missing_certificate_stops_before_keychain_or_import(self):
        result=self.invoke('',missing='APPLE_CERTIFICATE')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Central credential APPLE_CERTIFICATE is missing',result.stderr)
        self.assertFalse(self.log.exists())

if __name__=='__main__':unittest.main()
