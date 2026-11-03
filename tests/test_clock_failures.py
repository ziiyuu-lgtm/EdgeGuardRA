"""Clock dependency failures must not authorize or partially mutate state."""
from pathlib import Path
import tempfile
import unittest

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW=1700000000
AK,RK,SK=b'A'*32,b'R'*32,b'S'*32


class Clock:
    def __init__(self):self.failure=None;self.script=[]
    def __call__(self):
        value=self.script.pop(0) if self.script else self.failure
        if isinstance(value,BaseException):raise value
        return NOW if value is None else value


class ClockFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'db',create=True)
        self.store.put_device('pump-01','routine','compromised',NOW-2,now=NOW)
        self.store.put_device('plc-01','critical','compromised',NOW-2,now=NOW)
        self.clock=Clock()
        self.gate=Gate(self.store,example_policy(),agent_keys={'defender':{'v1':AK}},
                       reviewer_keys={'reviewer':{'v1':RK}},clock=self.clock)
        self.gate.activate_configuration()
        self.sensor=EvidenceIngestor(self.store,source_keys={'sensor':{'v1':SK}},
                                     allowed_devices={'sensor':['pump-01']},clock=self.clock)
        self.sensor.activate_configuration()

    def proposal(self,request,nonce,*,action='inspect',target='pump-01'):
        return sign(make_proposal(request,nonce,NOW,action=action,target=target),AK)

    def evidence(self,nonce='sensor-nonce'):
        return sign({'source_id':'sensor','key_id':'v1','device_id':'pump-01','signal':'normal',
                     'observed_at':NOW-1,'issued_at':NOW,'nonce':nonce},SK)

    def test_clock_exception_denies_all_stateful_paths(self):
        accepted=self.gate.evaluate(self.proposal('ready','ready-nonce'))
        pending=self.gate.evaluate(self.proposal('review','review-nonce',action='quarantine',target='plc-01'))
        self.assertEqual((accepted.outcome,pending.code),('allow','review_required'))
        approval=sign(make_approval(pending,'reviewer-nonce',NOW),RK)
        before=self.store.audit_head()
        for failure in (RuntimeError('clock unavailable'),OSError('clock unavailable'),KeyError('clock unavailable')):
            with self.subTest(error=type(failure).__name__):
                self.clock.failure=failure
                self.assertEqual(self.gate.evaluate(self.proposal('other','other-nonce')).outcome,'block')
                self.assertEqual(self.gate.approve(approval).outcome,'block')
                self.assertFalse(Sandbox(self.gate).execute('ready',agent_id='defender')['executed'])
                self.assertFalse(self.sensor.ingest(self.evidence())['accepted'])
        self.clock.failure=None
        self.assertEqual(self.store.audit_head(),before)
        self.assertEqual(self.store.decision('ready',agent_id='defender')['status'],'allowed')
        self.assertEqual(self.store.decision('review',agent_id='defender')['status'],'pending')
        self.assertEqual(self.store.device('pump-01')['signal'],'compromised')
        self.assertTrue(Sandbox(self.gate).execute('ready',agent_id='defender')['executed'])
        self.assertEqual(self.gate.approve(approval).code,'approved_for_sandbox')
        self.assertTrue(self.sensor.ingest(self.evidence())['accepted'])

    def test_clock_exception_after_lock_rolls_back_and_request_can_retry(self):
        envelope=self.proposal('retry','retry-nonce')
        self.clock.script=[NOW,RuntimeError('clock failed under lock')]
        self.assertEqual(self.gate.evaluate(envelope).outcome,'block')
        self.assertIsNone(self.store.decision('retry',agent_id='defender'))
        self.assertEqual(self.gate.evaluate(envelope).outcome,'allow')
        sensor_envelope=self.evidence('retry-sensor')
        self.clock.script=[NOW,RuntimeError('clock failed under lock')]
        self.assertFalse(self.sensor.ingest(sensor_envelope)['accepted'])
        self.assertTrue(self.sensor.ingest(sensor_envelope)['accepted'])

    def test_failed_configuration_activation_preserves_generation(self):
        before_gate=self.store.active_configuration('gate')
        before_sensor=self.store.active_configuration('evidence')
        self.clock.failure=RuntimeError('clock unavailable')
        with self.assertRaisesRegex(ValueError,'trusted clock unavailable'):self.gate.activate_configuration()
        with self.assertRaisesRegex(ValueError,'trusted clock unavailable'):self.sensor.activate_configuration()
        self.clock.failure=None
        self.assertEqual(self.store.active_configuration('gate'),before_gate)
        self.assertEqual(self.store.active_configuration('evidence'),before_sensor)
        self.assertEqual(self.gate.evaluate(self.proposal('after','after-nonce')).outcome,'allow')

    def test_late_clock_failure_preserves_approval_and_execution_state(self):
        pending=self.gate.evaluate(self.proposal('review','review-nonce',action='quarantine',target='plc-01'))
        approval=sign(make_approval(pending,'reviewer-nonce',NOW),RK)
        self.clock.script=[NOW,RuntimeError('clock failed under lock')]
        self.assertEqual(self.gate.approve(approval).outcome,'block')
        self.assertEqual(self.store.decision('review',agent_id='defender')['status'],'pending')
        self.assertEqual(self.gate.approve(approval).code,'approved_for_sandbox')
        self.clock.script=[NOW,NOW,RuntimeError('clock failed before effect')]
        self.assertFalse(Sandbox(self.gate).execute('review',agent_id='defender')['executed'])
        self.assertEqual(self.store.decision('review',agent_id='defender')['status'],'approved')
        self.assertEqual(self.store.device('plc-01')['quarantined'],0)
        self.assertTrue(Sandbox(self.gate).execute('review',agent_id='defender')['executed'])
        self.assertEqual(self.store.device('plc-01')['quarantined'],1)


if __name__=='__main__':unittest.main()
