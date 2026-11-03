"""Schema checks must reject non-string objects before comparing enum values."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW = 1_700_000_000
AGENT, REVIEWER, SOURCE = b'A' * 32, b'R' * 32, b'S' * 32


class MimicInt(int):
    """A JSON number that compares equal to a specified string in Python."""
    def __new__(cls, value, target):
        obj = super().__new__(cls, value)
        obj.target = target
        return obj
    def __eq__(self, other):
        return other == self.target
    def __ne__(self, other):
        return not self.__eq__(other)
    def __hash__(self):
        return hash(self.target)


class MimicList(list):
    def __eq__(self, other):
        return other == 'approve'
    def __ne__(self, other):
        return not self.__eq__(other)


class ScalarTypeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'state.db', create=True)
        self.store.put_device('pump-01', 'routine', 'normal', NOW-10, now=NOW)
        self.store.put_device('plc-01', 'critical', 'compromised', NOW-10, now=NOW)
        self.gate = Gate(self.store, example_policy(),
                         agent_keys={'defender': {'v1': AGENT}},
                         reviewer_keys={'reviewer': {'v1': REVIEWER}}, clock=lambda: NOW)
        self.gate.activate_configuration()
        self.sensor = EvidenceIngestor(self.store, source_keys={'sensor': {'v1': SOURCE}},
                                       allowed_devices={'sensor': ['pump-01']}, clock=lambda: NOW)
        self.sensor.activate_configuration()

    def pending(self, request='pending'):
        proposal = make_proposal(request, 'nonce-'+request, NOW, target='plc-01')
        decision = self.gate.evaluate(sign(proposal, AGENT))
        self.assertEqual(decision.code, 'review_required')
        return decision

    def test_signed_numeric_verdict_cannot_approve_or_consume_nonce(self):
        decision = self.pending()
        payload = make_approval(decision, 'review-nonce', NOW)
        payload['verdict'] = 0
        envelope = sign(payload, REVIEWER)
        envelope['payload']['verdict'] = MimicInt(0, 'approve')
        self.assertEqual(self.gate.approve(envelope).code, 'invalid_approval_schema')
        self.assertEqual(self.store.decision('pending', agent_id='defender')['status'], 'pending')
        self.assertFalse(Sandbox(self.gate).execute('pending', agent_id='defender')['executed'])
        valid = sign(make_approval(decision, 'review-nonce', NOW), REVIEWER)
        self.assertEqual(self.gate.approve(valid).code, 'approved_for_sandbox')
        self.assertTrue(Sandbox(self.gate).execute('pending', agent_id='defender')['executed'])

    def test_signed_list_verdict_cannot_approve(self):
        decision = self.pending()
        payload = make_approval(decision, 'list-review', NOW)
        payload['verdict'] = []
        envelope = sign(payload, REVIEWER)
        envelope['payload']['verdict'] = MimicList()
        self.assertEqual(self.gate.approve(envelope).code, 'invalid_approval_schema')
        self.assertEqual(self.store.decision('pending', agent_id='defender')['status'], 'pending')

    def test_nonstring_action_is_rejected_before_recording(self):
        payload = make_proposal('action-test', 'action-nonce', NOW, action='inspect')
        payload['action'] = 0
        envelope = sign(payload, AGENT)
        envelope['payload']['action'] = MimicInt(0, 'inspect')
        self.assertEqual(self.gate.evaluate(envelope).code, 'invalid_schema')
        self.assertIsNone(self.store.decision('action-test', agent_id='defender'))
        valid = sign(make_proposal('action-test', 'action-nonce', NOW, action='inspect'), AGENT)
        self.assertEqual(self.gate.evaluate(valid).outcome, 'allow')

    def test_nonstring_signal_is_rejected_without_changing_device(self):
        payload = {'source_id': 'sensor', 'key_id': 'v1', 'device_id': 'pump-01',
                   'signal': 0, 'observed_at': NOW-1, 'issued_at': NOW, 'nonce': 'signal-nonce'}
        envelope = sign(payload, SOURCE)
        envelope['payload']['signal'] = MimicInt(0, 'normal')
        before = self.store.device('pump-01')
        self.assertEqual(self.sensor.ingest(envelope), {'accepted': False, 'code': 'invalid_schema'})
        self.assertEqual(self.store.device('pump-01'), before)
        payload['signal'] = 'normal'
        self.assertTrue(self.sensor.ingest(sign(payload, SOURCE))['accepted'])

    def test_plain_nested_action_has_schema_error(self):
        payload = make_proposal('nested', 'nested-nonce', NOW, action='inspect')
        payload['action'] = []
        self.assertEqual(self.gate.evaluate(sign(payload, AGENT)).code, 'invalid_schema')
        self.assertIsNone(self.store.decision('nested', agent_id='defender'))

    def test_string_subclass_with_valid_underlying_verdict_remains_usable(self):
        class Approved(str):
            pass
        decision = self.pending()
        envelope = sign(make_approval(decision, 'valid-review', NOW), REVIEWER)
        envelope['payload']['verdict'] = Approved('approve')
        self.assertEqual(self.gate.approve(envelope).code, 'approved_for_sandbox')


if __name__ == '__main__':
    unittest.main()
