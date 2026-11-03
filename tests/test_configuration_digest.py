"""Malformed configuration digests must not deactivate valid workers."""
from contextlib import closing
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW = 1_700_000_000
AK, RK, SK = b'A'*32, b'R'*32, b'S'*32


class ConfigurationDigestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'state.db'
        self.store = Store(self.path, create=True)
        self.store.put_device('pump-01','routine','normal',NOW-2,now=NOW)
        self.store.put_device('plc-01','critical','compromised',NOW-2,now=NOW)
        self.gate = self.make_gate(self.store)
        self.gate.activate_configuration()
        self.sensor = self.make_sensor(self.store)
        self.sensor.activate_configuration()

    def make_gate(self, store):
        return Gate(store,example_policy(),agent_keys={'defender':{'v1':AK}},
                    reviewer_keys={'reviewer':{'v1':RK}},clock=lambda:NOW)

    def make_sensor(self, store):
        return EvidenceIngestor(store,source_keys={'sensor':{'v1':SK}},
            allowed_devices={'sensor':['pump-01']},clock=lambda:NOW)

    def registrations(self, kind):
        with closing(self.store.connect()) as c:
            return tuple(tuple(row) for row in c.execute(
                'SELECT owner,key_id,fingerprint FROM configuration_keys WHERE kind=? ORDER BY owner,key_id',
                (kind,)))

    def file_digest(self):
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def inspect_request(self, name='inspect'):
        return sign(make_proposal(name,'nonce-'+name,NOW,action='inspect'),AK)

    def pending(self):
        proposal = sign(make_proposal('pending','pending-nonce',NOW,target='plc-01'),AK)
        result = self.gate.evaluate(proposal)
        self.assertEqual(result.code, 'review_required')
        return result

    def reject_both(self):
        for kind in ('gate','evidence'):
            with self.assertRaisesRegex(ValueError,'invalid configuration digest'):
                self.store.activate_configuration('ab'*31+'  ',now=NOW,kind=kind,
                    key_fingerprints=self.registrations(kind))

    def test_whitespace_digests_fail_before_clock_read_or_transaction(self):
        before = self.file_digest()
        values = (' '*64, '\t'*64, 'ab'*31+'  ', ' \tab'+'ab'*30,
                  'a'*30+'\n\r'+'a'*32, 'a'*62+'\v\f')
        for kind in ('gate','evidence'):
            registrations = self.registrations(kind)
            for value in values:
                with self.subTest(kind=kind, value=repr(value)):
                    self.assertEqual(len(value),64)
                    clock = Mock(return_value=NOW+10)
                    with patch.object(self.store,'transaction',side_effect=AssertionError('transaction opened')):
                        with self.assertRaisesRegex(ValueError,'invalid configuration digest'):
                            self.store.activate_configuration(value,now=clock,kind=kind,
                                key_fingerprints=registrations)
                    clock.assert_not_called()
        self.assertEqual(self.file_digest(),before)

    def test_invalid_types_lengths_and_nonhex_digits_leave_state_intact(self):
        before = self.file_digest()
        values = (None, True, 64, b'a'*64, [], '', 'a'*63, 'a'*65, 'g'*64, 'a'*63+'\u00e9')
        for kind in ('gate','evidence'):
            for value in values:
                with self.subTest(kind=kind, value=repr(value)):
                    clock = Mock(return_value=NOW+10)
                    with self.assertRaisesRegex(ValueError,'invalid configuration digest'):
                        self.store.activate_configuration(value,now=clock,kind=kind,
                            key_fingerprints=self.registrations(kind))
                    clock.assert_not_called()
        self.assertEqual(self.file_digest(),before)

    def test_valid_digest_case_variants_still_activate_and_normalize(self):
        for kind in ('gate','evidence'):
            digest, generation = self.store.active_configuration(kind)
            registrations = self.registrations(kind)
            for text in (digest.upper(), digest.swapcase(), digest):
                with self.subTest(kind=kind, text=text):
                    generation += 1
                    self.assertEqual(self.store.activate_configuration(text,now=NOW,kind=kind,
                        key_fingerprints=registrations),generation)
                    self.assertEqual(self.store.active_configuration(kind),(digest,generation))
                    self.assertEqual(self.registrations(kind),registrations)
        gate = self.make_gate(self.store)
        self.assertEqual(gate.evaluate(self.inspect_request()).outcome,'allow')
        sensor = self.make_sensor(self.store)
        evidence = sign({'source_id':'sensor','key_id':'v1','device_id':'pump-01','signal':'normal',
            'observed_at':NOW-1,'issued_at':NOW,'nonce':'fresh-evidence'},SK)
        self.assertTrue(sensor.ingest(evidence)['accepted'])

    def test_allowed_and_pending_decisions_remain_usable_after_rejection(self):
        self.assertEqual(self.gate.evaluate(self.inspect_request()).outcome,'allow')
        pending = self.pending()
        before = self.file_digest()
        self.reject_both()
        self.assertEqual(self.file_digest(),before)
        self.assertTrue(Sandbox(self.gate).execute('inspect',agent_id='defender')['executed'])
        review = sign(make_approval(pending,'review-nonce',NOW),RK)
        self.assertEqual(self.gate.approve(review).code,'approved_for_sandbox')
        self.assertTrue(Sandbox(self.gate).execute('pending',agent_id='defender')['executed'])

    def test_approved_decision_remains_usable_after_rejection(self):
        pending = self.pending()
        self.assertEqual(self.gate.approve(sign(make_approval(pending,'approved-nonce',NOW),RK)).code,
                         'approved_for_sandbox')
        before = self.file_digest()
        self.reject_both()
        self.assertEqual(self.file_digest(),before)
        self.assertTrue(Sandbox(self.gate).execute('pending',agent_id='defender')['executed'])

    def test_reopening_and_independent_audit_anchors_preserve_prior_configuration(self):
        checkpoint = self.store.audit_checkpoint()
        head = self.store.audit_head()
        configurations = {kind:self.store.active_configuration(kind) for kind in ('gate','evidence')}
        registrations = {kind:self.registrations(kind) for kind in ('gate','evidence')}
        self.reject_both()
        result = Store.verify_audit_file(self.path,head,checkpoint=checkpoint)
        self.assertTrue(result['valid'])
        self.assertTrue(result['anchored'])
        reopened = Store(self.path,required_checkpoint=checkpoint)
        for kind in ('gate','evidence'):
            self.assertEqual(reopened.active_configuration(kind),configurations[kind])
            self.assertEqual(self.registrations(kind),registrations[kind])
        self.assertEqual(self.make_gate(reopened).evaluate(self.inspect_request('reopened')).outcome,'allow')


if __name__ == '__main__':
    unittest.main()
