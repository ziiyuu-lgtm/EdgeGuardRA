"""An existing Store must not silently switch to a different audit identity."""
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import sqlite3
import unittest

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import AuditCheckpointError, Store

NOW = 1_700_000_000
A, R, S = b'A' * 32, b'R' * 32, b'S' * 32


class DatabaseIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'live.db'
        self.store, self.gate, self.sensor = self.configured(self.path)
        self.other_path = Path(self.tmp.name) / 'other.db'
        self.other, self.other_gate, self.other_sensor = self.configured(self.other_path)

    def configured(self, path):
        store = Store(path, create=True)
        store.put_device('pump-01', 'routine', 'compromised', NOW-2, now=NOW)
        store.put_device('plc-01', 'critical', 'compromised', NOW-2, now=NOW)
        gate = self.gate_for(store)
        gate.activate_configuration()
        sensor = EvidenceIngestor(store, source_keys={'sensor': {'v1': S}},
                                  allowed_devices={'sensor': ['pump-01']}, clock=lambda: NOW)
        sensor.activate_configuration()
        return store, gate, sensor

    def gate_for(self, store):
        return Gate(store, example_policy(), agent_keys={'defender': {'v1': A}},
                    reviewer_keys={'reviewer': {'v1': R}}, clock=lambda: NOW)

    def request(self, name='r', *, target='pump-01', action='inspect'):
        return sign(make_proposal(name, 'nonce-'+name, NOW, target=target, action=action), A)

    def replace(self):
        os.replace(self.other_path, self.path)

    def test_same_request_is_not_accepted_after_different_database_replacement(self):
        request = self.request()
        self.assertEqual(self.gate.evaluate(request).outcome, 'allow')
        self.replace()
        decision = self.gate.evaluate(request)
        self.assertEqual((decision.outcome, decision.code), ('block', 'state_store_unavailable'))
        replacement = Store(self.path)
        self.assertIsNone(replacement.decision('r', agent_id='defender'))

    def test_reads_and_administration_fail_without_changing_replacement(self):
        self.replace()
        pristine = self.path.read_bytes()
        reads = (lambda: self.store.device('pump-01'),
                 lambda: self.store.decision('r', agent_id='defender'),
                 self.store.audit_head, self.store.active_configuration)
        for read in reads:
            with self.subTest(read=read), self.assertRaisesRegex(ValueError, 'identity changed'):
                read()
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            self.store.put_device('pump-01', 'routine', 'normal', NOW-1, now=NOW)
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            self.gate.activate_configuration()
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            self.sensor.activate_configuration()
        self.assertFalse(self.store.record_denial('fixture', NOW))
        self.assertEqual(self.path.read_bytes(), pristine)

    def test_existing_authorization_approval_and_evidence_paths_refuse_replacement(self):
        allowed = self.other_gate.evaluate(self.request('allowed', action='quarantine'))
        self.assertEqual(allowed.outcome, 'allow')
        pending = self.other_gate.evaluate(self.request('pending', target='plc-01', action='quarantine'))
        self.assertEqual(pending.code, 'review_required')
        self.replace()
        self.assertFalse(Sandbox(self.gate).execute('allowed', agent_id='defender')['executed'])
        approval = self.gate.approve(sign(make_approval(pending, 'review-nonce', NOW), R))
        self.assertEqual(approval.outcome, 'block')
        evidence = sign({'source_id': 'sensor', 'key_id': 'v1', 'device_id': 'pump-01',
                         'signal': 'normal', 'observed_at': NOW-1, 'issued_at': NOW, 'nonce': 'sensor-n'}, S)
        self.assertFalse(self.sensor.ingest(evidence)['accepted'])
        fresh = Store(self.path)
        self.assertEqual(fresh.decision('allowed', agent_id='defender')['status'], 'allowed')
        self.assertEqual(fresh.decision('pending', agent_id='defender')['status'], 'pending')
        self.assertEqual(fresh.device('pump-01')['signal'], 'compromised')
        self.assertEqual(fresh.device('pump-01')['quarantined'], 0)

    def test_audit_verification_and_checkpoint_do_not_adopt_new_identity(self):
        self.replace()
        result = self.store.verify_audit()
        self.assertEqual(result, {'valid': False, 'anchored': False, 'entries': 0,
                                  'code': 'database_identity_changed'})
        with self.assertRaises(ValueError):
            self.store.audit_checkpoint()
        self.assertTrue(Store(self.path).verify_audit()['valid'])

    def test_explicit_reopen_adopts_new_identity_but_cannot_recover_history(self):
        request = self.request()
        self.assertEqual(self.gate.evaluate(request).outcome, 'allow')
        self.replace()
        # Negative control: a deliberate new Store pins whichever database is
        # opened. Pinning is not persistent independent recovery evidence.
        reopened = self.gate_for(Store(self.path))
        self.assertEqual(reopened.evaluate(request).outcome, 'allow')

    def test_same_identity_snapshot_is_not_rollback_detection(self):
        backup = Path(self.tmp.name) / 'earlier.db'
        with closing(self.store.connect()) as src, closing(sqlite3.connect(backup)) as dst:
            src.backup(dst)
        request = self.request()
        self.assertEqual(self.gate.evaluate(request).outcome, 'allow')
        os.replace(backup, self.path)
        # Negative control: an older snapshot retains its original audit ID.
        self.assertEqual(self.gate.evaluate(request).outcome, 'allow')

    def test_recent_required_checkpoint_still_rejects_same_identity_rollback(self):
        backup = Path(self.tmp.name) / 'earlier.db'
        with closing(self.store.connect()) as src, closing(sqlite3.connect(backup)) as dst:
            src.backup(dst)
        request = self.request()
        self.assertEqual(self.gate.evaluate(request).outcome, 'allow')
        checkpoint = self.store.audit_checkpoint()
        guarded = Store(self.path, required_checkpoint=checkpoint)
        gate = self.gate_for(guarded)
        os.replace(backup, self.path)
        self.assertEqual(gate.evaluate(request).outcome, 'block')
        with self.assertRaises(AuditCheckpointError):
            guarded.device('pump-01')

    @unittest.skipUnless(hasattr(os, 'symlink'), 'requires symbolic links')
    def test_symlink_retargeting_is_not_followed_by_existing_instance(self):
        alias = Path(self.tmp.name) / 'selected.db'
        try:
            alias.symlink_to(self.path)
        except OSError:
            self.skipTest('symbolic links unavailable')
        gate = self.gate_for(Store(alias))
        alias.unlink()
        alias.symlink_to(self.other_path)
        self.assertEqual(gate.evaluate(self.request()).outcome, 'block')
        self.assertIsNone(self.other.decision('r', agent_id='defender'))


if __name__ == '__main__':
    unittest.main()
