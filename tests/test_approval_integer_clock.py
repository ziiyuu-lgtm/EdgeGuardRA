"""Bound approval versions and retain valid time on input exceptions."""
from contextlib import closing
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW = 1_700_000_000
AK, RK = b'A' * 32, b'R' * 32


class Clock:
    def __init__(self):
        self.value = NOW
        self.script = []

    def __call__(self):
        value = self.script.pop(0) if self.script else self.value
        if isinstance(value, BaseException):
            raise value
        return value


class ApprovalIntegerClockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'state.db', create=True)
        self.store.put_device('pump-01', 'routine', 'normal', NOW - 1, now=NOW)
        self.store.put_device('plc-01', 'critical', 'compromised', NOW - 1, now=NOW)
        self.policy = example_policy()
        self.policy.update(request_ttl=1, clock_skew=0)
        self.clock = Clock()
        self.gate = self.make_gate(self.store)
        self.gate.activate_configuration()

    def make_gate(self, store):
        return Gate(store, self.policy, agent_keys={'defender': {'v1': AK}},
                    reviewer_keys={'reviewer': {'v1': RK}}, clock=self.clock)

    def request(self, request='undelivered', issued=NOW):
        return sign(make_proposal(request, 'nonce-' + request, issued, action='inspect'), AK)

    def approval_payload(self, context_version):
        return {'agent_id': 'defender', 'request_id': 'absent', 'request_hash': '0' * 64,
                'policy_hash': '0' * 64, 'context_version': context_version,
                'review_challenge': '0' * 64, 'reviewer_id': 'reviewer', 'key_id': 'v1',
                'nonce': 'review-nonce', 'issued_at': NOW, 'verdict': 'approve'}

    def highwater(self):
        with closing(self.store.connect()) as c:
            return c.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone()[0]

    def assert_old_request_blocked(self):
        self.assertEqual(self.highwater(), NOW + 10)
        self.clock.value = NOW + 1
        result = self.gate.evaluate(self.request())
        self.assertEqual((result.outcome, result.code), ('block', 'clock_rollback'))
        self.assertIsNone(self.store.decision('undelivered', agent_id='defender'))

    def test_oversized_unsigned_integer_cannot_erase_observed_time(self):
        # Use a plain integer and dictionary, with no valid reviewer signature.
        envelope = {'payload': self.approval_payload(10 ** 5000), 'signature': '0' * 64}
        self.clock.value = NOW + 1
        self.clock.script = [NOW + 10, NOW + 1]
        result = self.gate.approve(envelope)
        self.assertEqual(result.code, 'clock_rollback')
        self.assert_old_request_blocked()

    def test_context_version_outside_persistable_range_is_schema_error(self):
        for value in (0, -1, True, 1.0, '1', 1 << 63):
            with self.subTest(value=value):
                result = self.gate.approve(sign(self.approval_payload(value), RK))
                self.assertEqual((result.outcome, result.code), ('block', 'invalid_approval_schema'))
        # In-range versions still authenticate and reach normal state checks.
        for value in (1, (1 << 63) - 1):
            with self.subTest(in_range=value):
                self.assertEqual(self.gate.approve(sign(self.approval_payload(value), RK)).code, 'not_pending')

    def test_rejected_large_version_leaves_pending_approval_and_nonce_usable(self):
        proposal = sign(make_proposal('pending', 'pending-nonce', NOW, target='plc-01'), AK)
        pending = self.gate.evaluate(proposal)
        self.assertEqual(pending.code, 'review_required')
        payload = make_approval(pending, 'same-review-nonce', NOW)
        invalid = sign({**payload, 'context_version': 1 << 63}, RK)
        self.assertEqual(self.gate.approve(invalid).code, 'invalid_approval_schema')
        self.assertEqual(self.store.decision('pending', agent_id='defender')['status'], 'pending')
        self.assertEqual(self.gate.approve(sign(payload, RK)).code, 'approved_for_sandbox')
        self.assertTrue(Sandbox(self.gate).execute('pending', agent_id='defender')['executed'])

    def test_input_exception_paths_keep_valid_time_on_rollback(self):
        for method in ('evaluate', 'approve'):
            for error in (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
                with self.subTest(method=method, error=error.__name__):
                    self.clock.script = [NOW + 10, NOW + 1]
                    with patch('edgeguardra.gate._envelope', side_effect=error('injected input failure')):
                        self.assertEqual(getattr(self.gate, method)({}).code, 'clock_rollback')
                    self.assert_old_request_blocked()

    def test_exception_followed_by_clock_failure_keeps_valid_time(self):
        head = self.store.audit_head()
        for method in ('evaluate', 'approve'):
            with self.subTest(method=method):
                self.clock.script = [NOW + 10, RuntimeError('clock offline')]
                with patch('edgeguardra.gate._envelope', side_effect=ValueError('input failure')):
                    self.assertEqual(getattr(self.gate, method)({}).code, 'invalid_clock')
                self.assert_old_request_blocked()
                self.assertEqual(self.store.audit_head(), head)

    def test_exception_rejection_records_fresh_forward_time_and_expected_event(self):
        for index, (method, code) in enumerate((('evaluate', 'invalid_input'), ('approve', 'invalid_approval'))):
            with self.subTest(method=method):
                observed = NOW + 10 + index * 10
                fresh = observed + 1
                self.clock.script = [observed, fresh]
                with patch('edgeguardra.gate._envelope', side_effect=ValueError('input failure')):
                    self.assertEqual(getattr(self.gate, method)({}).code, code)
                self.assertEqual(self.highwater(), fresh)
                with closing(self.store.connect()) as c:
                    body = json.loads(c.execute('SELECT body FROM audit ORDER BY seq DESC LIMIT 1').fetchone()[0])
                self.assertEqual(body, {'event': 'denied', 'details': {'code': code}, 'time': fresh})
                self.assertTrue(self.store.verify_audit()['valid'])
                self.clock.value = fresh
                self.assertEqual(self.gate.evaluate(self.request('fresh-' + method, fresh)).outcome, 'allow')

    def test_no_valid_clock_does_not_fabricate_observation(self):
        head = self.store.audit_head()
        for method in ('evaluate', 'approve'):
            with self.subTest(method=method):
                self.clock.script = [RuntimeError('clock offline'), RuntimeError('clock offline')]
                self.assertEqual(getattr(self.gate, method)({}).code, 'invalid_clock')
                self.assertEqual(self.highwater(), NOW)
                self.assertEqual(self.store.audit_head(), head)

    def test_recording_failure_blocks_without_claiming_time_persistence(self):
        head = self.store.audit_head()
        self.clock.script = [NOW + 10, NOW + 10]
        with patch('edgeguardra.gate._envelope', side_effect=ValueError('input failure')):
            with patch.object(Store, 'append_audit', side_effect=OSError('storage unavailable')):
                self.assertEqual(self.gate.approve({}).code, 'state_store_unavailable')
        self.assertEqual(self.highwater(), NOW)
        self.assertEqual(self.store.audit_head(), head)

    def test_exception_highwater_is_shared_with_reopened_process(self):
        self.clock.script = [NOW + 10, NOW + 1]
        with patch('edgeguardra.gate._envelope', side_effect=ValueError('input failure')):
            self.assertEqual(self.gate.approve({}).code, 'clock_rollback')
        # Reuse the installed/source package in a fresh interpreter, not an
        # inherited Store or process-local clock.
        code = '''from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from edgeguardra.demo import example_policy, make_proposal
from edgeguardra.gate import Gate, sign
from edgeguardra.store import Store
store = Store(sys.argv[2])
policy = example_policy()
policy.update(request_ttl=1, clock_skew=0)
gate = Gate(store, policy, agent_keys={'defender': {'v1': b'A'*32}},
            reviewer_keys={'reviewer': {'v1': b'R'*32}}, clock=lambda: 1700000001)
result = gate.evaluate(sign(make_proposal('reopened', 'reopened-nonce', 1700000000, action='inspect'), b'A'*32))
assert (result.outcome, result.code) == ('block', 'clock_rollback'), result
print('reopened process blocks rollback')
'''
        import edgeguardra
        package_parent = str(Path(edgeguardra.__file__).resolve().parent.parent)
        result = subprocess.run([sys.executable, '-c', code, package_parent, self.store.path],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('blocks rollback', result.stdout)

    def test_exception_highwater_persists_with_required_checkpoint(self):
        checkpoint = self.store.audit_checkpoint()
        required = Store(self.store.path, required_checkpoint=checkpoint)
        gate = self.make_gate(required)
        self.clock.script = [NOW + 10, NOW + 1]
        with patch('edgeguardra.gate._envelope', side_effect=ValueError('input failure')):
            self.assertEqual(gate.approve({}).code, 'clock_rollback')
        self.assert_old_request_blocked()
        verification = required.verify_audit()
        self.assertTrue(verification['valid'])
        self.assertEqual(verification['anchored_through'], checkpoint['seq'])


if __name__ == '__main__':
    unittest.main()
