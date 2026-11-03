"""Persist trusted time observations on rejection paths before a rollback."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import multiprocessing
from pathlib import Path
import tempfile
import threading
import unittest

from edgeguardra.demo import example_policy,make_approval,make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate,parse_json_envelope,sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW=1700000000
AK,RK,SK=b'A'*32,b'R'*32,b'S'*32

def _process_after_rejection(path,queue):
    try:
        store=Store(path)
        gate=Gate(store,example_policy(),agent_keys={'defender':{'v1':AK}},
                  reviewer_keys={'reviewer':{'v1':RK}},clock=lambda:NOW+100)
        request=sign(make_proposal('worker','worker-nonce',NOW,action='inspect'),AK)
        result=gate.evaluate(request)
        queue.put((result.outcome,result.code))
    except BaseException as exc:
        queue.put(('error',type(exc).__name__))

class Clock:
    def __init__(self):self.value=NOW;self.script=[];self.called=threading.Event()
    def __call__(self):
        value=self.script.pop(0) if self.script else self.value
        self.called.set()
        if isinstance(value,BaseException):raise value
        return value

class RejectionClockTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'state.db',create=True)
        self.store.put_device('pump-01','routine','normal',NOW-1,now=NOW)
        self.store.put_device('plc-01','critical','compromised',NOW-1,now=NOW)
        self.clock=Clock();self.policy=example_policy()
        self.gate=self.make_gate();self.gate.activate_configuration()
        self.sensor=self.make_sensor();self.sensor.activate_configuration()

    def make_gate(self):
        return Gate(self.store,self.policy,agent_keys={'defender':{'v1':AK}},
                    reviewer_keys={'reviewer':{'v1':RK}},clock=self.clock)
    def make_sensor(self):
        return EvidenceIngestor(self.store,source_keys={'sensor':{'v1':SK}},
                                allowed_devices={'sensor':['pump-01']},clock=self.clock)
    def request(self,request='request',nonce='nonce',*,action='inspect',target='pump-01',issued=NOW):
        return sign(make_proposal(request,nonce,issued,action=action,target=target),AK)
    def sensor_request(self,issued,nonce='sensor'):
        return sign({'source_id':'sensor','key_id':'v1','device_id':'pump-01','signal':'normal',
                     'observed_at':issued-1,'issued_at':issued,'nonce':nonce},SK)
    def highwater(self):
        with closing(self.store.connect()) as c:
            return c.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone()[0]
    def assert_rollback_blocks_old_request(self,gate=None):
        self.assertEqual(self.highwater(),NOW+150)
        self.clock.value=NOW+100
        result=(gate or self.gate).evaluate(self.request('later','later-nonce'))
        self.assertEqual((result.outcome,result.code),('block','clock_rollback'))
        self.assertIsNone(self.store.decision('later',agent_id='defender'))

    def test_invalid_signature_advances_highwater_and_blocks_rollback(self):
        valid=self.request();bad={**valid,'signature':'0'*64}
        self.clock.value=NOW+150
        self.assertEqual(self.gate.evaluate(bad).code,'invalid_signature')
        self.assert_rollback_blocks_old_request()

    @unittest.skipUnless('fork' in multiprocessing.get_all_start_methods(),'requires POSIX fork')
    def test_rejection_highwater_is_shared_by_another_process(self):
        self.clock.value=NOW+150
        self.assertEqual(self.gate.evaluate({**self.request(),'signature':'0'*64}).code,'invalid_signature')
        ctx=multiprocessing.get_context('fork');queue=ctx.Queue()
        worker=ctx.Process(target=_process_after_rejection,args=(self.store.path,queue))
        worker.start();worker.join(timeout=10)
        self.assertEqual(worker.exitcode,0)
        self.assertEqual(queue.get(timeout=2),('block','clock_rollback'))

    def test_invalid_evidence_advances_highwater_and_blocks_rollback(self):
        self.clock.value=NOW+150
        self.assertEqual(self.sensor.ingest({})['code'],'invalid_schema')
        self.assert_rollback_blocks_old_request()

    def test_invalid_json_and_direct_record_denial_advance_highwater(self):
        self.clock.value=NOW+150
        self.assertEqual(self.gate.evaluate_json('{bad').code,'invalid_json')
        self.assertEqual(self.highwater(),NOW+150)
        self.assertTrue(self.store.record_denial('test',NOW+150))
        self.assert_rollback_blocks_old_request()

    def test_stale_gate_configuration_denial_advances_highwater(self):
        stale=self.gate;fresh=self.make_gate();fresh.activate_configuration()
        self.clock.value=NOW+150
        self.assertEqual(stale.evaluate(self.request(issued=NOW+150)).code,'configuration_not_active')
        self.assert_rollback_blocks_old_request(fresh)

    def test_stale_reviewer_configuration_denial_advances_highwater(self):
        pending=self.gate.evaluate(self.request('review','review-nonce',action='quarantine',target='plc-01'))
        stale=self.gate;fresh=self.make_gate();fresh.activate_configuration()
        self.clock.value=NOW+150
        approval=sign(make_approval(pending,'reviewer-nonce',NOW+150),RK)
        self.assertEqual(stale.approve(approval).code,'configuration_not_active')
        self.assert_rollback_blocks_old_request(fresh)

    def test_stale_evidence_configuration_denial_advances_highwater(self):
        stale=self.sensor;fresh_sensor=self.make_sensor();fresh_sensor.activate_configuration()
        self.clock.value=NOW+150
        self.assertEqual(stale.ingest(self.sensor_request(NOW+150))['code'],'configuration_not_active')
        self.assert_rollback_blocks_old_request()

    def test_stale_sandbox_configuration_denial_advances_highwater(self):
        accepted=self.gate.evaluate(self.request('ready','ready-nonce'))
        self.assertEqual(accepted.outcome,'allow')
        stale=self.gate;fresh=self.make_gate();fresh.activate_configuration()
        self.clock.value=NOW+150
        self.assertEqual(Sandbox(stale).execute('ready',agent_id='defender')['code'],'configuration_not_active')
        self.assert_rollback_blocks_old_request(fresh)

    def test_rejection_rechecks_clock_after_waiting_for_lock(self):
        bad={**self.request(),'signature':'0'*64}
        self.clock.value=NOW+150;self.clock.called.clear()
        before_head=self.store.audit_head()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.store.transaction():
                future=pool.submit(self.gate.evaluate,bad)
                self.assertTrue(self.clock.called.wait(timeout=2))
                self.clock.value=NOW+140
            self.assertEqual(future.result(timeout=5).code,'clock_rollback')
        self.assertEqual(self.store.audit_head(),before_head)
        self.assert_rollback_blocks_old_request()

    def test_failed_second_clock_read_keeps_first_valid_observation(self):
        bad={**self.request(),'signature':'0'*64}
        head=self.store.audit_head()
        self.clock.script=[NOW+150,RuntimeError('clock unavailable')]
        self.assertEqual(self.gate.evaluate(bad).code,'invalid_clock')
        self.assertEqual(self.store.audit_head(),head)
        self.assert_rollback_blocks_old_request()

    def test_invalid_evidence_rechecks_clock_under_lock(self):
        self.clock.script=[NOW+150,NOW+140]
        self.assertEqual(self.sensor.ingest({})['code'],'clock_rollback')
        self.assert_rollback_blocks_old_request()

    def test_action_clock_failure_under_lock_preserves_first_observation(self):
        self.clock.script=[NOW+150,RuntimeError('clock unavailable')]
        self.assertEqual(self.gate.evaluate(self.request(issued=NOW+150)).outcome,'block')
        self.assert_rollback_blocks_old_request()

    def test_approval_clock_failure_under_lock_preserves_first_observation(self):
        pending=self.gate.evaluate(self.request('review','review-nonce',action='quarantine',target='plc-01'))
        approval=sign(make_approval(pending,'reviewer-nonce',NOW+150),RK)
        self.clock.script=[NOW+150,RuntimeError('clock unavailable')]
        self.assertEqual(self.gate.approve(approval).code,'invalid_clock')
        self.assert_rollback_blocks_old_request()

    def test_evidence_clock_failure_under_lock_preserves_first_observation(self):
        self.clock.script=[NOW+150,RuntimeError('clock unavailable')]
        self.assertEqual(self.sensor.ingest(self.sensor_request(NOW+150))['code'],'invalid_clock')
        self.assert_rollback_blocks_old_request()

    def test_execution_clock_failure_under_lock_preserves_first_observation(self):
        self.assertEqual(self.gate.evaluate(self.request('ready','ready-nonce')).outcome,'allow')
        self.clock.script=[NOW+150,RuntimeError('clock unavailable')]
        self.assertFalse(Sandbox(self.gate).execute('ready',agent_id='defender')['executed'])
        self.assertEqual(self.highwater(),NOW+150)
        self.clock.value=NOW+100
        self.assertEqual(Sandbox(self.gate).execute('ready',agent_id='defender')['code'],'clock_rollback')
        self.assertEqual(self.store.decision('ready',agent_id='defender')['status'],'allowed')

    def test_final_execution_clock_failure_keeps_previous_observation(self):
        self.assertEqual(self.gate.evaluate(self.request('ready','ready-nonce')).outcome,'allow')
        self.clock.script=[NOW+100,NOW+100,RuntimeError('clock unavailable')]
        self.assertEqual(Sandbox(self.gate).execute('ready',agent_id='defender')['code'],'invalid_clock')
        self.assertEqual(self.highwater(),NOW+100)
        self.clock.value=NOW+50
        self.assertEqual(Sandbox(self.gate).execute('ready',agent_id='defender')['code'],'clock_rollback')
        self.assertEqual(self.store.decision('ready',agent_id='defender')['status'],'allowed')

class JsonBoundsTests(unittest.TestCase):
    def test_oversized_text_rejected_before_encoding(self):
        class Probe(str):
            def encode(self,*args,**kwargs):raise AssertionError('must not encode oversized string')
        with self.assertRaisesRegex(ValueError,'oversized'):
            parse_json_envelope(Probe('a'*16385))

    def test_multibyte_utf8_limit_is_still_enforced(self):
        value='"'+'é'*8191+'"'
        self.assertEqual(len(value.encode('utf-8')),16384)
        self.assertEqual(len(parse_json_envelope(value)),8191)
        with self.assertRaises(ValueError):parse_json_envelope('"'+'é'*8192+'"')

    def test_invalid_size_limits_are_rejected(self):
        for limit in (0,-1,True,1.5):
            with self.subTest(limit=limit),self.assertRaises(ValueError):parse_json_envelope('{}',limit)

if __name__=='__main__':unittest.main()
