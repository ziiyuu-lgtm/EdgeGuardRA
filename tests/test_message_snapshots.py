"""Signed data and schema checks must use the same detached payload."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from unittest.mock import patch
import unittest

import edgeguardra.evidence as evidence_module
import edgeguardra.gate as gate_module
from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.agents import validate_candidate
from edgeguardra.gate import Gate, _scalar_text, parse_json_envelope, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW = 1_700_000_000
AGENT_KEY, REVIEW_KEY, SOURCE_KEY = b'A' * 32, b'R' * 32, b'S' * 32


class MessageSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'state.db', create=True)
        self.store.put_device('pump-01', 'routine', 'normal', NOW-10, now=NOW)
        self.store.put_device('plc-01', 'critical', 'compromised', NOW-10, now=NOW)
        self.gate = Gate(self.store, example_policy(),
                         agent_keys={'defender': {'v1': AGENT_KEY}},
                         reviewer_keys={'reviewer': {'v1': REVIEW_KEY}}, clock=lambda: NOW)
        self.gate.activate_configuration()
        self.sensor = EvidenceIngestor(self.store, source_keys={'sensor': {'v1': SOURCE_KEY}},
                                       allowed_devices={'sensor': ['pump-01']}, clock=lambda: NOW)
        self.sensor.activate_configuration()

    def mutate_during_validation(self, module, nonce, envelope, callback, change):
        """Deterministically reproduce a caller changing a shared dictionary."""
        ready, resume = Event(), Event()
        identifier = module._identifier

        def pause(value):
            valid = identifier(value)
            if value == nonce:
                ready.set()
                if not resume.wait(5):
                    raise RuntimeError('test synchronization failed')
            return valid

        with patch.object(module, '_identifier', pause), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(callback, envelope)
            try:
                self.assertTrue(ready.wait(5), 'validation did not reach the synchronized point')
                change(envelope['payload'])
            finally:
                resume.set()
            return future.result(timeout=8)

    def test_mutated_extra_proposal_field_cannot_bypass_schema(self):
        proposal = make_proposal('r1', 'proposal-sync', NOW, action='inspect')
        altered = dict(proposal, unexpected='extra')
        envelope = {'payload': proposal, 'signature': sign(altered, AGENT_KEY)['signature']}
        result = self.mutate_during_validation(gate_module, 'proposal-sync', envelope,
                                               self.gate.evaluate, lambda p: p.update(unexpected='extra'))
        self.assertEqual((result.outcome, result.code), ('block', 'invalid_signature'))
        self.assertIsNone(self.store.decision('r1', agent_id='defender'))
        self.assertEqual(self.gate.evaluate(sign(make_proposal('r1', 'proposal-sync', NOW,
                                                               action='inspect'), AGENT_KEY)).outcome, 'allow')

    def test_valid_signature_is_bound_to_original_snapshot(self):
        proposal = make_proposal('r2', 'proposal-valid', NOW, action='inspect')
        envelope = sign(proposal, AGENT_KEY)
        result = self.mutate_during_validation(gate_module, 'proposal-valid', envelope,
                                               self.gate.evaluate, lambda p: p.update(unexpected='extra'))
        self.assertEqual((result.outcome, result.code), ('allow', 'checks_passed'))
        self.assertTrue(Sandbox(self.gate).execute('r2', agent_id='defender')['executed'])

    def test_mutated_approval_does_not_authorize(self):
        decision = self.gate.evaluate(sign(make_proposal('r3', 'proposal-r3', NOW,
                                                        target='plc-01'), AGENT_KEY))
        self.assertEqual(decision.code, 'review_required')
        approval = make_approval(decision, 'approval-sync', NOW)
        envelope = {'payload': approval, 'signature': sign(dict(approval, unexpected='extra'), REVIEW_KEY)['signature']}
        result = self.mutate_during_validation(gate_module, 'approval-sync', envelope,
                                               self.gate.approve, lambda p: p.update(unexpected='extra'))
        self.assertEqual((result.outcome, result.code), ('block', 'invalid_approval_signature'))
        self.assertEqual(self.store.decision('r3', agent_id='defender')['status'], 'pending')
        valid = sign(make_approval(decision, 'approval-sync', NOW), REVIEW_KEY)
        self.assertEqual(self.gate.approve(valid).code, 'approved_for_sandbox')
        self.assertTrue(Sandbox(self.gate).execute('r3', agent_id='defender')['executed'])

    def test_mutated_evidence_does_not_change_device(self):
        data = {'source_id': 'sensor', 'key_id': 'v1', 'device_id': 'pump-01',
                'signal': 'compromised', 'observed_at': NOW-1, 'issued_at': NOW, 'nonce': 'evidence-sync'}
        envelope = {'payload': data, 'signature': sign(dict(data, unexpected='extra'), SOURCE_KEY)['signature']}
        before = self.store.device('pump-01')
        result = self.mutate_during_validation(evidence_module, 'evidence-sync', envelope,
                                               self.sensor.ingest, lambda p: p.update(unexpected='extra'))
        self.assertEqual(result, {'accepted': False, 'code': 'invalid_source_authentication'})
        self.assertEqual(self.store.device('pump-01'), before)
        valid = dict(data); valid.pop('unexpected')
        self.assertTrue(self.sensor.ingest(sign(valid, SOURCE_KEY))['accepted'])

    def test_invalid_extra_fields_are_still_rejected_without_concurrency(self):
        proposal = make_proposal('r4', 'nonce-r4', NOW, action='inspect')
        result = self.gate.evaluate(sign(dict(proposal, unexpected='extra'), AGENT_KEY))
        self.assertEqual((result.outcome, result.code), ('block', 'invalid_schema'))
        self.assertIsNone(self.store.decision('r4', agent_id='defender'))

    def test_unstable_dictionary_copy_is_rejected_by_all_message_paths(self):
        class Unstable(dict):
            def keys(self):
                raise RuntimeError('dictionary changed during copying')
            def __iter__(self):
                raise RuntimeError('dictionary changed during copying')

        proposal = sign(make_proposal('r5', 'nonce-r5', NOW, action='inspect'), AGENT_KEY)
        proposal['payload'] = Unstable(proposal['payload'])
        self.assertEqual(self.gate.evaluate(proposal).code, 'invalid_schema')
        approval = {'payload': Unstable({'irrelevant': 'value'}), 'signature': '0' * 64}
        self.assertEqual(self.gate.approve(approval).code, 'invalid_approval_schema')
        evidence = {'payload': Unstable({'irrelevant': 'value'}), 'signature': '0' * 64}
        self.assertEqual(self.sensor.ingest(evidence), {'accepted': False, 'code': 'invalid_schema'})
        self.assertIsNone(self.store.decision('r5', agent_id='defender'))

    def test_signed_reject_cannot_be_spoofed_as_approval_by_string_subclass(self):
        class MisleadingVerdict(str):
            def __eq__(self, other):
                return other == 'approve'
            def __ne__(self, other):
                return not self.__eq__(other)
            __hash__ = str.__hash__

        decision = self.gate.evaluate(sign(make_proposal('r6', 'nonce-r6', NOW,
                                                        target='plc-01'), AGENT_KEY))
        payload = make_approval(decision, 'review-r6', NOW)
        payload['verdict'] = 'reject'
        envelope = sign(payload, REVIEW_KEY)
        envelope['payload']['verdict'] = MisleadingVerdict('reject')
        self.assertEqual(self.gate.approve(envelope).code, 'invalid_approval_schema')
        self.assertEqual(self.store.decision('r6', agent_id='defender')['status'], 'pending')
        self.assertFalse(Sandbox(self.gate).execute('r6', agent_id='defender')['executed'])

    def test_candidate_action_is_validated_as_its_actual_string_value(self):
        class MisleadingAction(str):
            def __eq__(self, other):
                return other == 'inspect'
            __hash__ = lambda self: hash('inspect')

        with self.assertRaisesRegex(ValueError, 'unsupported action'):
            validate_candidate({'action': MisleadingAction('delete'), 'target': 'pump-01', 'reason': 'test'})

    def test_string_overrides_cannot_hide_invalid_unicode_or_size(self):
        class MisleadingText(str):
            def __len__(self):
                return 1
            def encode(self, *args, **kwargs):
                return b'{}'

        class MisleadingBytes(bytes):
            def __len__(self):
                return 1
            def decode(self, *args, **kwargs):
                return '{}'

        self.assertFalse(_scalar_text(MisleadingText('\ud800')))
        self.assertFalse(_scalar_text(MisleadingText('x' * 513)))
        with self.assertRaises(ValueError):
            parse_json_envelope(MisleadingText('x' * 16385))
        with self.assertRaises(ValueError):
            parse_json_envelope(MisleadingBytes(b'x' * 16385))


if __name__ == '__main__':
    unittest.main()
