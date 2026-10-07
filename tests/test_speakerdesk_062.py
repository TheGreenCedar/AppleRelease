"""Exact0.6.2 registration controls; CPU only, no signing or credentials."""
import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from policy import approved,ReleaseError

class Speakerdesk062RegistrationTests(unittest.TestCase):
    inputs=['speakerdesk','37667438255','11502509180','1c001548010a37ecb585e17896fb9acb5cca3374b307e36b68842e1debf10716','30fe9332494103b30cf25a41a6439b526820dff6']
    def test_exact_verified_tuple_and_payloads(self):
        app,build=approved(*self.inputs)
        self.assertEqual(app['repository_id'],1406057260)
        self.assertEqual(build['version'],'0.6.2')
        self.assertEqual(build['files'],[
            {'filename':'Speakerdesk_0.6.2_AppleSilicon.dmg','bytes':129059186,'sha256':'b779b525e693715e68e76f6487121c8d3d8aa2fb7c2b2779d7076216ce378f4f'},
            {'filename':'Speakerdesk_0.6.2_AppleSilicon.app.zip','bytes':126081628,'sha256':'bee88e64920affba2abdb80700bf50153d0d183e2e1450bc56fd950137c20dca'}])
    def test_substitution_or_previous_source_is_rejected(self):
        for i,value in [(1,'37569576386'),(2,'11460481550'),(3,'0'*64),(4,'71f48c9d81307e57a6a12bf29515f72c1e21eb67')]:
            inputs=self.inputs.copy();inputs[i]=value
            with self.subTest(index=i),self.assertRaises(ReleaseError):approved(*inputs)

if __name__=='__main__':unittest.main()
