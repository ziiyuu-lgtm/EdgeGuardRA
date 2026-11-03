"""Audit anchors must not trust Python objects' custom equality methods."""
import hashlib
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from edgeguardra.store import AuditCheckpointError, Store

NOW = 1_700_000_000


class AlwaysEqual:
    def __eq__(self, other):
        return True


class MisleadingString(str):
    def __eq__(self, other):
        return True
    def __ne__(self, other):
        return False
    __hash__ = str.__hash__


class MisleadingCheckpoint(dict):
    def __eq__(self, other):
        return True
    def __ne__(self, other):
        return False


class AnchorTypeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'state.db', create=True)
        self.store.put_device('pump-01', 'routine', 'normal', NOW-1, now=NOW)
        self.checkpoint = self.store.audit_checkpoint()

    def test_nonstring_expected_head_cannot_claim_anchor(self):
        result = self.store.verify_audit(expected_head=AlwaysEqual())
        self.assertFalse(result['valid'])
        self.assertFalse(result['anchored'])
        self.assertEqual(result['code'], 'invalid_expected_head')
        self.assertTrue(self.store.verify_audit(expected_head=self.checkpoint['hash'])['valid'])

    def test_misleading_expected_head_uses_actual_string(self):
        wrong = '0' * 64 if self.checkpoint['hash'] != '0' * 64 else '1' * 64
        self.assertFalse(self.store.verify_audit(expected_head=MisleadingString(wrong))['valid'])
        self.assertTrue(self.store.verify_audit(expected_head=MisleadingString(self.checkpoint['hash']))['valid'])

    def test_misleading_checkpoint_id_cannot_claim_another_database(self):
        other = '0' * 32 if self.checkpoint['audit_id'] != '0' * 32 else '1' * 32
        altered = dict(self.checkpoint, audit_id=MisleadingString(other))
        result = self.store.verify_audit(checkpoint=altered)
        self.assertFalse(result['valid'])
        self.assertEqual(result['code'], 'checkpoint_database_mismatch')
        with self.assertRaises(AuditCheckpointError):
            Store(self.store.path, required_checkpoint=altered)

    def test_supplied_checkpoint_subclass_cannot_bypass_required_anchor(self):
        guarded = Store(self.store.path, required_checkpoint=self.checkpoint)
        # Deliberate external SQL rewrite is a fault fixture, not a remote attack.
        with sqlite3.connect(self.store.path) as raw:
            previous = raw.execute('SELECT prev_hash FROM audit WHERE seq=1').fetchone()[0]
            body = '{"event":"altered"}'
            digest = hashlib.sha256(previous.encode('ascii') + b'\x00' + body.encode('ascii')).hexdigest()
            raw.execute('UPDATE audit SET body=?,entry_hash=? WHERE seq=1', (body, digest))
        alternate = MisleadingCheckpoint(audit_id=self.checkpoint['audit_id'], seq=1, hash=digest)
        self.assertTrue(self.store.verify_audit(checkpoint=alternate)['valid'])
        result = guarded.verify_audit(checkpoint=alternate)
        self.assertFalse(result['valid'])
        self.assertEqual(result['code'], 'required_checkpoint_failed')
        self.assertEqual(result['required_checkpoint_code'], 'checkpoint_hash_mismatch')
        with self.assertRaises(AuditCheckpointError):
            guarded.device('pump-01')

    def test_valid_subclass_values_and_two_anchors_still_work(self):
        cp = MisleadingCheckpoint(audit_id=MisleadingString(self.checkpoint['audit_id']),
                                  seq=self.checkpoint['seq'], hash=MisleadingString(self.checkpoint['hash']))
        guarded = Store(self.store.path, required_checkpoint=cp)
        result = guarded.verify_audit(checkpoint=cp, expected_head=MisleadingString(self.checkpoint['hash']))
        self.assertTrue(result['valid'])
        self.assertEqual(result['required_anchored_through'], self.checkpoint['seq'])
        self.assertEqual(result['anchored_through'], self.checkpoint['seq'])

    def test_invalid_or_unstable_checkpoint_is_denied(self):
        class Unstable(dict):
            def keys(self):
                raise RuntimeError('dictionary changed during copying')
            def __iter__(self):
                raise RuntimeError('dictionary changed during copying')

        for checkpoint in (Unstable(self.checkpoint), dict(self.checkpoint, seq=True),
                           dict(self.checkpoint, hash='not-a-hash')):
            with self.subTest(checkpoint=type(checkpoint).__name__):
                result = self.store.verify_audit(checkpoint=checkpoint)
                self.assertFalse(result['valid'])
                self.assertEqual(result['code'], 'invalid_checkpoint')
                with self.assertRaises(AuditCheckpointError):
                    Store(self.store.path, required_checkpoint=checkpoint)


if __name__ == '__main__':
    unittest.main()
