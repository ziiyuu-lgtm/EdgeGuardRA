"""Credential-reuse rejection keeps time while preserving active configuration."""
from concurrent.futures import ThreadPoolExecutor
import json
import multiprocessing
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
from threading import Event
import unittest
from unittest.mock import patch

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

N = 1_700_000_000
A, R, S, T = b'A' * 32, b'R' * 32, b'S' * 32, b'T' * 32


def _worker_after_rejected_activation(path, queue):
    try:
        policy = example_policy()
        policy['clock_skew'] = 0
        gate = Gate(Store(path), policy, agent_keys={'defender': {'v1': A}},
                    reviewer_keys={'reviewer': {'v1': R}}, clock=lambda: N+1)
        request = sign(make_proposal('child', 'child-nonce', N-115, action='inspect'), A)
        result = gate.evaluate(request)
        queue.put((result.outcome, result.code))
    except Exception as exc:
        queue.put(('error', type(exc).__name__))


class ActivationRejectionClockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = N
        self.store = Store(Path(self.tmp.name) / 'state.db', create=True)
        self.store.put_device('pump-01', 'routine', 'compromised', N-2, now=N)
        self.store.put_device('plc-01', 'critical', 'compromised', N-2, now=N)
        self.policy = example_policy()
        self.policy['clock_skew'] = 0
        self.gate = self.make_gate()
        self.gate.activate_configuration()
        self.sensor = self.make_sensor(S)
        self.sensor.activate_configuration()

    def make_gate(self, key=A, *, versions=None, store=None):
        return Gate(store or self.store, self.policy,
                    agent_keys={'defender': versions or {'v1': key}},
                    reviewer_keys={'reviewer': {'v1': R}}, clock=lambda: self.now)

    def make_sensor(self, key, *, store=None):
        return EvidenceIngestor(store or self.store, source_keys={'sensor': {'v1': key}},
                                allowed_devices={'sensor': ['pump-01']}, clock=lambda: self.now)

    def highwater(self):
        with self.store.read_transaction() as c:
            return c.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone()[0]

    def configuration_state(self):
        with self.store.read_transaction() as c:
            keys = [tuple(row) for row in c.execute('SELECT kind,owner,key_id,fingerprint FROM configuration_keys ORDER BY kind,owner,key_id')]
        return self.store.active_configuration('gate'), self.store.active_configuration('evidence'), keys

    def request(self, name='request', *, issued=N, target='pump-01', action='inspect'):
        return sign(make_proposal(name, 'nonce-'+name, issued, target=target, action=action), A)

    def reject_activation(self, kind='evidence'):
        candidate = self.make_sensor(A) if kind == 'evidence' else self.make_gate(S)
        self.now = N+10
        with self.assertRaisesRegex(ValueError, 'secret reused'):
            candidate.activate_configuration()
        return candidate

    def test_each_role_rejection_keeps_time_and_blocks_rolled_back_old_request(self):
        before = self.configuration_state()
        for kind in ('evidence', 'gate'):
            with self.subTest(kind=kind):
                self.reject_activation(kind)
                self.assertEqual(self.highwater(), N+10)
                self.assertEqual(self.configuration_state(), before)
                self.now = N+1
                # This undelivered request expires at N+5; it was already
                # expired at the trusted N+10 observation during activation.
                result = self.gate.evaluate(self.request('old-'+kind, issued=N-115))
                self.assertEqual((result.outcome, result.code), ('block', 'clock_rollback'))
                self.assertIsNone(self.store.decision('old-'+kind, agent_id='defender'))

    def test_partial_key_registration_is_rolled_back(self):
        before = self.configuration_state()
        # Distinct raw keys with the same HMAC-normalized key get the same
        # fingerprint. The first insert can succeed before the second fails.
        candidate = self.make_gate(versions={'v1': A, 'v2': A+b'\x00'})
        self.now = N+10
        with self.assertRaisesRegex(ValueError, 'secret reused'):
            candidate.activate_configuration()
        self.assertEqual(self.configuration_state(), before)
        self.assertEqual(self.highwater(), N+10)

    def test_rejection_audit_and_clock_commit_under_required_checkpoint(self):
        checkpoint = self.store.audit_checkpoint()
        guarded = Store(self.store.path, required_checkpoint=checkpoint)
        candidate = self.make_sensor(A, store=guarded)
        before = self.configuration_state()
        self.now = N+10
        with self.assertRaisesRegex(ValueError, 'secret reused'):
            candidate.activate_configuration()
        self.assertEqual(self.configuration_state(), before)
        self.assertEqual(self.highwater(), N+10)
        checked = guarded.verify_audit()
        self.assertTrue(checked['valid'])
        self.assertEqual(checked['anchored_through'], checkpoint['seq'])
        with guarded.read_transaction() as c:
            event = json.loads(c.execute('SELECT body FROM audit ORDER BY seq DESC LIMIT 1').fetchone()['body'])
        self.assertEqual(event, {'event': 'configuration_rejected',
                                 'details': {'kind': 'evidence', 'code': 'secret_reuse'}, 'time': N+10})

    @unittest.skipUnless('fork' in multiprocessing.get_all_start_methods(), 'requires POSIX fork')
    def test_committed_rejection_time_is_visible_after_process_reopen(self):
        self.reject_activation()
        ctx = multiprocessing.get_context('fork')
        queue = ctx.Queue()
        process = ctx.Process(target=_worker_after_rejected_activation, args=(self.store.path, queue))
        process.start()
        process.join(timeout=10)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
            self.fail('child process did not finish')
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(queue.get(timeout=2), ('block', 'clock_rollback'))

    def test_later_valid_activation_advances_only_once(self):
        before = self.store.active_configuration('evidence')
        self.reject_activation()
        self.now = N+11
        replacement = self.make_sensor(T)
        replacement.activate_configuration()
        self.assertEqual(self.store.active_configuration('evidence'),
                         (replacement.configuration_hash, before[1]+1))
        message = {'source_id': 'sensor', 'key_id': 'v1', 'device_id': 'pump-01',
                   'signal': 'normal', 'observed_at': N+10, 'issued_at': N+11, 'nonce': 'fresh'}
        self.assertEqual(self.sensor.ingest(sign(message, S))['code'], 'configuration_not_active')
        self.assertTrue(replacement.ingest(sign(message, T))['accepted'])

    def test_pending_review_can_proceed_when_clock_catches_up(self):
        pending = self.gate.evaluate(self.request('pending', target='plc-01', action='quarantine'))
        self.assertEqual(pending.code, 'review_required')
        self.reject_activation()
        self.assertEqual(self.store.decision('pending', agent_id='defender')['status'], 'pending')
        approval = sign(make_approval(pending, 'review-nonce', N+10), R)
        self.assertEqual(self.gate.approve(approval).code, 'approved_for_sandbox')
        self.assertTrue(Sandbox(self.gate).execute('pending', agent_id='defender')['executed'])

    def test_allowed_and_approved_decisions_are_not_invalidated_by_rejection(self):
        self.assertEqual(self.gate.evaluate(self.request('allowed', action='quarantine')).outcome, 'allow')
        critical = self.gate.evaluate(self.request('approved', target='plc-01', action='quarantine'))
        self.assertEqual(self.gate.approve(sign(make_approval(critical, 'review-nonce', N), R)).code,
                         'approved_for_sandbox')
        self.reject_activation('gate')
        self.assertTrue(Sandbox(self.gate).execute('allowed', agent_id='defender')['executed'])
        self.assertTrue(Sandbox(self.gate).execute('approved', agent_id='defender')['executed'])

    def test_audit_storage_failure_can_prevent_clock_persistence(self):
        before, head = self.configuration_state(), self.store.audit_head()
        candidate = self.make_sensor(A)
        self.now = N+10
        # Negative control: an unavailable audit store aborts the transaction.
        # The software cannot promise persistence when its storage fails.
        with patch.object(Store, 'append_audit', side_effect=sqlite3.OperationalError('fixture audit unavailable')):
            with self.assertRaises(sqlite3.OperationalError):
                candidate.activate_configuration()
        self.assertEqual(self.configuration_state(), before)
        self.assertEqual(self.store.audit_head(), head)
        self.assertEqual(self.highwater(), N)

    def test_waiting_request_sees_rejection_time_after_lock_is_released(self):
        at_rejection, release_rejection, request_clock_seen = Event(), Event(), Event()
        def request_clock():
            request_clock_seen.set()
            return N+1
        waiting_gate = Gate(self.store, self.policy, agent_keys={'defender': {'v1': A}},
                            reviewer_keys={'reviewer': {'v1': R}}, clock=request_clock)
        candidate = self.make_sensor(A)
        self.now = N+10
        original = Store.append_audit
        def pause_rejection(connection, event, details, now):
            if event == 'configuration_rejected':
                at_rejection.set()
                if not release_rejection.wait(timeout=5):
                    raise RuntimeError('fixture release timed out')
            return original(connection, event, details, now)
        with patch.object(Store, 'append_audit', side_effect=pause_rejection):
            with ThreadPoolExecutor(max_workers=2) as pool:
                activation = pool.submit(candidate.activate_configuration)
                try:
                    self.assertTrue(at_rejection.wait(timeout=5))
                    request = pool.submit(waiting_gate.evaluate, self.request('waiting', issued=N-115))
                    self.assertTrue(request_clock_seen.wait(timeout=5))
                finally:
                    release_rejection.set()
                with self.assertRaisesRegex(ValueError, 'secret reused'):
                    activation.result(timeout=10)
                decision = request.result(timeout=10)
        self.assertEqual((decision.outcome, decision.code), ('block', 'clock_rollback'))
        self.assertIsNone(self.store.decision('waiting', agent_id='defender'))


if __name__ == '__main__':
    unittest.main()
