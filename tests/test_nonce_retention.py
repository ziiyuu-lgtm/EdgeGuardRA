"""Replay records must survive later increases in allowed message lifetime."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.store import Store
from edgeguardra.validation import MAX_CLOCK_SKEW, MAX_TIME_TO_LIVE, NONCE_RETENTION_MARGIN

NOW = 1_700_000_000
AGENT, REVIEWER, SOURCE = b'A' * 32, b'R' * 32, b'S' * 32


class NonceRetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = NOW
        self.store = Store(Path(self.tmp.name) / 'state.db', create=True)
        for name, criticality, signal in [('pump-01', 'routine', 'normal'),
                                          ('spare-01', 'routine', 'normal'),
                                          ('plc-01', 'critical', 'compromised')]:
            self.store.put_device(name, criticality, signal, NOW-10, now=NOW)
        self.gate = Gate(self.store, example_policy(), agent_keys={'defender': {'v1': AGENT}},
                         reviewer_keys={'reviewer': {'v1': REVIEWER}}, clock=lambda: self.now)
        self.gate.activate_configuration()
        self.sensor = self.make_sensor(ttl=2, skew=0)
        self.sensor.activate_configuration()

    def make_sensor(self, *, ttl, skew):
        return EvidenceIngestor(self.store, source_keys={'sensor': {'v1': SOURCE}},
                                allowed_devices={'sensor': ['pump-01', 'spare-01']},
                                clock=lambda: self.now, ttl=ttl, skew=skew)

    def evidence(self, *, nonce='sensor-nonce', target='pump-01', observed=NOW-2, issued=NOW):
        return sign({'source_id': 'sensor', 'key_id': 'v1', 'device_id': target,
                     'signal': 'compromised', 'observed_at': observed, 'issued_at': issued,
                     'nonce': nonce}, SOURCE)

    def old_nonce_count(self):
        with self.store.read_transaction() as c:
            return c.execute("SELECT count(*) FROM nonces WHERE kind='evidence' AND principal='sensor' AND nonce='sensor-nonce'").fetchone()[0]

    def test_replay_blocked_after_ttl_increase_and_backdated_admin_update(self):
        old = self.evidence()
        self.assertTrue(self.sensor.ingest(old)['accepted'])
        self.now = NOW + 3
        advance = sign(make_proposal('advance', 'advance-nonce', self.now, action='inspect'), AGENT)
        self.assertEqual(self.gate.evaluate(advance).outcome, 'allow')
        self.store.put_device('pump-01', 'routine', 'normal', NOW-10, now=self.now)
        replacement = self.make_sensor(ttl=120, skew=0)
        replacement.activate_configuration()
        self.assertEqual(replacement.ingest(old)['code'], 'evidence_replay')
        self.assertEqual(self.store.device('pump-01')['signal'], 'normal')
        proposal = sign(make_proposal('quarantine', 'quarantine-nonce', self.now), AGENT)
        decision = self.gate.evaluate(proposal)
        self.assertEqual((decision.outcome, decision.code), ('defer', 'insufficient_or_conflicting_evidence'))

    def test_each_message_path_preserves_expired_evidence_nonce(self):
        for path in ('proposal', 'approval', 'evidence'):
            with self.subTest(path=path):
                # Isolate each path with a separate store and clock.
                with TemporaryDirectory() as tmp:
                    clock = [NOW]
                    store = Store(Path(tmp) / 's.db', create=True)
                    store.put_device('pump-01', 'routine', 'normal', NOW-10, now=NOW)
                    store.put_device('plc-01', 'critical', 'compromised', NOW-10, now=NOW)
                    gate = Gate(store, example_policy(), agent_keys={'defender': {'v1': AGENT}},
                                reviewer_keys={'reviewer': {'v1': REVIEWER}}, clock=lambda: clock[0])
                    gate.activate_configuration()
                    sensor = EvidenceIngestor(store, source_keys={'sensor': {'v1': SOURCE}},
                                              allowed_devices={'sensor': ['pump-01', 'plc-01']},
                                              clock=lambda: clock[0], ttl=2, skew=0)
                    sensor.activate_configuration()
                    self.assertTrue(sensor.ingest(self.evidence())['accepted'])
                    pending = None
                    if path == 'approval':
                        pending = gate.evaluate(sign(make_proposal('review', 'review-proposal', NOW,
                                                                   target='plc-01'), AGENT))
                        self.assertEqual(pending.code, 'review_required')
                    clock[0] = NOW + 3
                    if path == 'proposal':
                        self.assertEqual(gate.evaluate(sign(make_proposal('p', 'p-nonce', clock[0],
                                                                         action='inspect'), AGENT)).outcome, 'allow')
                    elif path == 'approval':
                        self.assertEqual(gate.approve(sign(make_approval(pending, 'review-nonce', clock[0]), REVIEWER)).code,
                                         'approved_for_sandbox')
                    else:
                        new = self.evidence(nonce='other', target='plc-01', observed=NOW+2, issued=clock[0])
                        self.assertTrue(sensor.ingest(new)['accepted'])
                    with store.read_transaction() as c:
                        count = c.execute("SELECT count(*) FROM nonces WHERE kind='evidence' AND nonce='sensor-nonce'").fetchone()[0]
                    self.assertEqual(count, 1)

    def test_retention_covers_maximum_new_ttl_and_skew_boundary(self):
        old = self.evidence()
        self.assertTrue(self.sensor.ingest(old)['accepted'])
        self.now = NOW + MAX_TIME_TO_LIVE + MAX_CLOCK_SKEW
        self.store.put_device('pump-01', 'routine', 'normal', NOW-10, now=self.now)
        replacement = self.make_sensor(ttl=MAX_TIME_TO_LIVE, skew=MAX_CLOCK_SKEW)
        replacement.activate_configuration()
        self.assertEqual(replacement.ingest(old)['code'], 'evidence_replay')
        self.assertEqual(self.old_nonce_count(), 1)

    def test_expired_nonce_can_be_removed_after_extended_retention(self):
        old = self.evidence()
        self.assertTrue(self.sensor.ingest(old)['accepted'])
        original_expiry = NOW + 2
        self.now = original_expiry + NONCE_RETENTION_MARGIN
        e1 = self.evidence(nonce='fresh-1', target='spare-01', observed=self.now, issued=self.now)
        self.assertTrue(self.sensor.ingest(e1)['accepted'])
        self.assertEqual(self.old_nonce_count(), 1)
        self.now += 1
        e2 = self.evidence(nonce='fresh-2', target='spare-01', observed=self.now, issued=self.now)
        self.assertTrue(self.sensor.ingest(e2)['accepted'])
        self.assertEqual(self.old_nonce_count(), 0)
        self.assertEqual(self.sensor.ingest(old)['code'], 'invalid_evidence_time')
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_missing_legacy_nonce_is_not_reconstructed_and_rekey_rejects_old_message(self):
        old = self.evidence()
        self.assertTrue(self.sensor.ingest(old)['accepted'])
        # Model a nonce already pruned by an older version before migration.
        with self.store.transaction() as c:
            c.execute("DELETE FROM nonces WHERE kind='evidence' AND principal='sensor' AND nonce='sensor-nonce'")
        self.now = NOW + 3
        self.store.put_device('pump-01', 'routine', 'normal', NOW-10, now=self.now)
        unchanged_key = self.make_sensor(ttl=120, skew=0)
        unchanged_key.activate_configuration()
        self.assertTrue(unchanged_key.ingest(old)['accepted'])  # negative control: history is gone
        rotated = EvidenceIngestor(self.store, source_keys={'sensor': {'v2': b'N' * 32}},
                                   allowed_devices={'sensor': ['pump-01', 'spare-01']},
                                   clock=lambda: self.now, ttl=120, skew=0)
        rotated.activate_configuration()
        self.assertEqual(rotated.ingest(old)['code'], 'invalid_source_authentication')


if __name__ == '__main__':
    unittest.main()
