"""Exact0.6.1 registration controls; CPU only, no signing or credentials."""
import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from policy import approved,ReleaseError

class Speakerdesk061RegistrationTests(unittest.TestCase):
    inputs=['speakerdesk','37654212796','11496874151','e84950ce1fbd2bc4ba946b0cd4ed8763e86a66c60f65f7ba1c8da77e32c5df21','01d36a05108cf1fffb2bf149ddc4698c11e9a345']
    def test_exact_verified_tuple_and_payloads(self):
        app,build=approved(*self.inputs)
        self.assertEqual(app['repository_id'],1406057260)
        self.assertEqual(build['version'],'0.6.1')
        self.assertEqual(build['files'],[
            {'filename':'Speakerdesk_0.6.1_AppleSilicon.dmg','bytes':129054339,'sha256':'ea1cf7d00b22e5d0adacf53e0717403663cb5951e907e553ec58fd7116b2627d'},
            {'filename':'Speakerdesk_0.6.1_AppleSilicon.app.zip','bytes':126076967,'sha256':'60694549fa89d8abcf0edd184353731d3598c52b333d2259b55e49e4a7e07452'}])
    def test_substitution_or_previous_source_is_rejected(self):
        for i,value in [(1,'37569576386'),(2,'11460481550'),(3,'0'*64),(4,'71f48c9d81307e57a6a12bf29515f72c1e21eb67')]:
            inputs=self.inputs.copy();inputs[i]=value
            with self.subTest(index=i),self.assertRaises(ReleaseError):approved(*inputs)

if __name__=='__main__':unittest.main()
