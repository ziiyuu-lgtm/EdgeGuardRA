"""Same-time contradictory authenticated observations must fail closed."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import json
import unittest

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW = 1_700_000_000
AGENT, REVIEWER, A, B = b'A' * 32, b'R' * 32, b'S' * 32, b'T' * 32


class EqualTimeConflictTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = NOW
        self.store = Store(Path(self.tmp.name) / 'state.db', create=True)
        self.store.put_device('pump-01', 'routine', 'normal', NOW - 10, now=NOW)
        self.store.put_device('plc-01', 'critical', 'normal', NOW - 10, now=NOW)
        self.gate = Gate(self.store, example_policy(), agent_keys={'defender': {'v1': AGENT}},
                         reviewer_keys={'reviewer': {'v1': REVIEWER}}, clock=lambda: self.now)
        self.gate.activate_configuration()
        self.sensor = self.new_ingestor()
        self.sensor.activate_configuration()

    def new_ingestor(self):
        return EvidenceIngestor(self.store, source_keys={'sensor-a': {'v1': A}, 'sensor-b': {'v1': B}},
                                allowed_devices={'sensor-a': ['pump-01', 'plc-01'],
                                                 'sensor-b': ['pump-01', 'plc-01']},
                                clock=lambda: self.now)

    def report(self, source, signal, nonce, *, device='pump-01', observed=NOW - 1, issued=NOW):
        payload = {'source_id': source, 'key_id': 'v1', 'device_id': device, 'signal': signal,
                   'observed_at': observed, 'issued_at': issued, 'nonce': nonce}
        return sign(payload, A if source == 'sensor-a' else B)

    def proposal(self, name='req', *, device='pump-01', action='quarantine'):
        return sign(make_proposal(name, 'nonce-' + name, NOW, target=device, action=action), AGENT)

    def test_conflict_invalidates_allowed_action_before_execution(self):
        first = self.sensor.ingest(self.report('sensor-a', 'compromised', 'a'))
        self.assertTrue(first['accepted'])
        self.assertEqual(self.gate.evaluate(self.proposal()).outcome, 'allow')
        second = self.sensor.ingest(self.report('sensor-b', 'normal', 'b'))
        self.assertEqual((second['accepted'], second['code']), (True, 'evidence_conflict'))
        ctx = self.store.device('pump-01')
        self.assertEqual((ctx['signal'], ctx['source_id']), ('unknown', ''))
        self.assertEqual(ctx['version'], first['context_version'] + 1)
        self.assertEqual(len(ctx['evidence_hash']), 64)
        self.assertEqual(Sandbox(self.gate).execute('req', agent_id='defender')['code'], 'state_policy_or_time_changed')
        self.assertEqual(self.gate.evaluate(self.proposal('next')).code, 'insufficient_or_conflicting_evidence')
        self.assertEqual(self.store.device('pump-01')['quarantined'], 0)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_both_arrival_orders_and_later_equal_reports_remain_unknown(self):
        for first_signal, second_signal in [('compromised', 'normal'), ('normal', 'compromised')]:
            with self.subTest(first=first_signal):
                self.store.put_device('pump-01', 'routine', 'normal', NOW-10, now=NOW)
                self.assertTrue(self.sensor.ingest(self.report('sensor-a', first_signal, 'a-'+first_signal))['accepted'])
                self.assertEqual(self.sensor.ingest(self.report('sensor-b', second_signal, 'b-'+first_signal))['code'],
                                 'evidence_conflict')
                self.assertEqual(self.store.device('pump-01')['signal'], 'unknown')
                third = self.sensor.ingest(self.report('sensor-a', second_signal, 'c-'+first_signal))
                self.assertEqual(third['code'], 'evidence_conflict')
                self.assertEqual(self.store.device('pump-01')['signal'], 'unknown')

    def test_newer_authenticated_evidence_can_replace_unknown(self):
        self.sensor.ingest(self.report('sensor-a', 'compromised', 'a'))
        self.sensor.ingest(self.report('sensor-b', 'normal', 'b'))
        self.now += 1
        newer = self.sensor.ingest(self.report('sensor-b', 'normal', 'new', observed=NOW, issued=self.now))
        self.assertEqual(newer['code'], 'evidence_accepted')
        ctx = self.store.device('pump-01')
        self.assertEqual((ctx['signal'], ctx['source_id'], ctx['observed_at']), ('normal', 'sensor-b', NOW))

    def test_same_signal_or_older_does_not_change_context(self):
        self.sensor.ingest(self.report('sensor-a', 'compromised', 'a'))
        initial = self.store.device('pump-01')
        self.assertEqual(self.sensor.ingest(self.report('sensor-b', 'compromised', 'same'))['code'], 'out_of_order')
        self.assertEqual(self.sensor.ingest(self.report('sensor-b', 'normal', 'older', observed=NOW-2))['code'],
                         'out_of_order')
        self.assertEqual(self.store.device('pump-01'), initial)

    def test_conflict_invalidates_pending_and_approved_review(self):
        self.sensor.ingest(self.report('sensor-a', 'compromised', 'a1', device='plc-01'))
        pending = self.gate.evaluate(self.proposal('pending', device='plc-01'))
        approved = self.gate.evaluate(self.proposal('approved', device='plc-01'))
        self.assertEqual(pending.code, 'review_required')
        self.assertEqual(self.gate.approve(sign(make_approval(approved, 'review-1', NOW), REVIEWER)).code,
                         'approved_for_sandbox')
        self.assertEqual(self.sensor.ingest(self.report('sensor-b', 'normal', 'b1', device='plc-01'))['code'],
                         'evidence_conflict')
        self.assertEqual(self.gate.approve(sign(make_approval(pending, 'review-2', NOW), REVIEWER)).code,
                         'binding_or_expiry_mismatch')
        self.assertEqual(Sandbox(self.gate).execute('approved', agent_id='defender')['code'],
                         'state_policy_or_time_changed')

    def test_invalid_source_cannot_create_conflict(self):
        self.sensor.ingest(self.report('sensor-a', 'compromised', 'a'))
        before = self.store.device('pump-01')
        invalid = self.report('sensor-b', 'normal', 'b')
        invalid['signature'] = '0' * 64
        self.assertEqual(self.sensor.ingest(invalid)['code'], 'invalid_source_authentication')
        self.assertEqual(self.store.device('pump-01'), before)

    def test_conflict_message_replay_does_not_change_context(self):
        self.sensor.ingest(self.report('sensor-a', 'compromised', 'a'))
        conflict = self.report('sensor-b', 'normal', 'b')
        self.assertEqual(self.sensor.ingest(conflict)['code'], 'evidence_conflict')
        before = self.store.device('pump-01')
        self.assertEqual(self.sensor.ingest(conflict)['code'], 'evidence_replay')
        self.assertEqual(self.store.device('pump-01'), before)

    def test_initial_unknown_cannot_be_resolved_at_same_timestamp(self):
        self.assertEqual(self.sensor.ingest(self.report('sensor-a', 'unknown', 'a'))['code'], 'evidence_accepted')
        self.assertEqual(self.sensor.ingest(self.report('sensor-b', 'normal', 'b'))['code'], 'evidence_conflict')
        self.assertEqual(self.store.device('pump-01')['signal'], 'unknown')

    def test_old_evidence_instance_cannot_change_context_after_reactivation(self):
        self.sensor.ingest(self.report('sensor-a', 'compromised', 'a'))
        replacement = self.new_ingestor()
        replacement.activate_configuration()
        before = self.store.device('pump-01')
        self.assertEqual(self.sensor.ingest(self.report('sensor-b', 'normal', 'old'))['code'],
                         'configuration_not_active')
        self.assertEqual(self.store.device('pump-01'), before)
        self.assertEqual(replacement.ingest(self.report('sensor-b', 'normal', 'current'))['code'],
                         'evidence_conflict')
        self.assertEqual(self.store.device('pump-01')['signal'], 'unknown')

    def test_late_conflict_does_not_reverse_an_already_executed_action(self):
        self.sensor.ingest(self.report('sensor-a', 'compromised', 'a'))
        self.assertEqual(self.gate.evaluate(self.proposal()).outcome, 'allow')
        self.assertTrue(Sandbox(self.gate).execute('req', agent_id='defender')['executed'])
        self.assertEqual(self.sensor.ingest(self.report('sensor-b', 'normal', 'b'))['code'],
                         'evidence_conflict')
        ctx = self.store.device('pump-01')
        self.assertEqual((ctx['signal'], ctx['quarantined']), ('unknown', 1))

    def test_conflict_audit_identifies_both_inputs_without_forging_source_evidence(self):
        self.sensor.ingest(self.report('sensor-a', 'compromised', 'a'))
        prior = self.store.device('pump-01')
        result = self.sensor.ingest(self.report('sensor-b', 'normal', 'b'))
        with self.store.read_transaction() as c:
            entry = json.loads(c.execute('SELECT body FROM audit ORDER BY seq DESC LIMIT 1').fetchone()['body'])
        details = entry['details']
        self.assertEqual(entry['event'], 'evidence_conflict')
        self.assertEqual((details['prior_source_id'], details['source_id']), ('sensor-a', 'sensor-b'))
        self.assertEqual((details['prior_signal'], details['reported_signal']), ('compromised', 'normal'))
        self.assertEqual(details['prior_evidence_hash'], prior['evidence_hash'])
        self.assertEqual(details['conflict_digest'], self.store.device('pump-01')['evidence_hash'])
        self.assertEqual(details['context_version'], result['context_version'])

    def test_concurrent_sources_produce_unknown_in_either_lock_order(self):
        other = self.new_ingestor()
        barrier = Barrier(2)
        def send(ingestor, message):
            barrier.wait(timeout=5)
            return ingestor.ingest(message)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(send, self.sensor, self.report('sensor-a', 'compromised', 'a'))
            second = pool.submit(send, other, self.report('sensor-b', 'normal', 'b'))
            codes = {first.result(timeout=10)['code'], second.result(timeout=10)['code']}
        self.assertEqual(codes, {'evidence_accepted', 'evidence_conflict'})
        self.assertEqual(self.store.device('pump-01')['signal'], 'unknown')
        self.assertTrue(self.store.verify_audit()['valid'])


if __name__ == '__main__':
    unittest.main()
