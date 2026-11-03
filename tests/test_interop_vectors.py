"""Fixed, public test-only vectors for supported flat signed messages."""
import json
import unittest
from pathlib import Path
from edgeguardra.gate import APPROVAL_FIELDS,PROPOSAL_FIELDS,_envelope,canonical_bytes,sign

class InteroperabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).resolve().parents[1]/'examples'/'signature_vectors.json'
        cls.vectors=json.loads(path.read_text(encoding='utf-8'))['vectors']

    def test_canonical_bytes_and_hmac_match_fixed_vectors(self):
        for vector in self.vectors:
            with self.subTest(name=vector['name']):
                key=bytes.fromhex(vector['key_hex'])
                self.assertEqual(canonical_bytes(vector['payload']).decode('ascii'),vector['canonical_ascii'])
                self.assertEqual(sign(vector['payload'],key)['signature'],vector['hmac_sha256_hex'])

    def test_action_and_approval_vectors_match_runtime_schemas(self):
        for vector in self.vectors:
            if vector['name'] in ('proposal','approval'):
                schema=PROPOSAL_FIELDS if vector['name']=='proposal' else APPROVAL_FIELDS
                envelope={'payload':vector['payload'],'signature':vector['hmac_sha256_hex']}
                self.assertIsNotNone(_envelope(envelope,schema))

if __name__=='__main__':unittest.main()
