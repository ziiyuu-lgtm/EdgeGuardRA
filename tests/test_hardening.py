"""Regression tests for configuration epochs, lock timing and key separation."""
import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW=1700000000
AK,RK,SK,BK=b'A'*32,b'R'*32,b'S'*32,b'B'*32

class Clock:
    def __init__(self): self.value=NOW; self.called=threading.Event()
    def __call__(self):
        snapshot=self.value
        self.called.set()
        return snapshot

class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'state.db', create=True);self.clock=Clock()
        self.store.put_device('pump-01','routine','compromised',NOW-200,now=NOW)
        self.store.put_device('plc-01','critical','compromised',NOW-2,now=NOW)
        self.policy=example_policy();self.policy['max_context_age']=300
        self.gate=self.new_gate();self.gate.activate_configuration()
        self.sensor=self.new_sensor();self.sensor.activate_configuration()

    def new_gate(self, policy=None, agent_key=AK):
        return Gate(self.store,policy or self.policy,agent_keys={'defender':{'v1':agent_key}},
                    reviewer_keys={'reviewer':{'v1':RK}},clock=self.clock)

    def new_sensor(self,key=SK):
        return EvidenceIngestor(self.store,source_keys={'sensor':{'v1':key}},
                                allowed_devices={'sensor':['pump-01']},clock=self.clock)

    def proposal(self, request_id='r',nonce='n',issued=NOW,action='inspect',target='pump-01'):
        return sign(make_proposal(request_id,nonce,issued,action=action,target=target),AK)

    def evidence(self, issued=NOW-125):
        return sign({'source_id':'sensor','key_id':'v1','device_id':'pump-01','signal':'compromised',
                     'observed_at':NOW-125,'issued_at':issued,'nonce':'evidence-n'},SK)

    def during_lock_and_advance(self,fn):
        self.clock.called.clear()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.store.transaction():
                future=pool.submit(fn)
                self.assertTrue(self.clock.called.wait(1),'worker did not read its initial clock')
                self.clock.value+=1
            return future.result(timeout=5)

    def test_original_decision_does_not_revive_after_aba_policy_rotation(self):
        decision=self.gate.evaluate(self.proposal())
        changed=copy.deepcopy(self.policy);changed['version']='alternate'
        self.new_gate(changed).activate_configuration()
        restored=self.new_gate();restored.activate_configuration()
        self.assertEqual(Sandbox(self.gate).execute(decision.request_id,agent_id='defender')['code'],'configuration_not_active')
        self.assertEqual(Sandbox(restored).execute(decision.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')

    def test_pending_approval_does_not_revive_after_aba_policy_rotation(self):
        decision=self.gate.evaluate(self.proposal(action='quarantine',target='plc-01'))
        changed=copy.deepcopy(self.policy);changed['version']='alternate'
        self.new_gate(changed).activate_configuration()
        restored=self.new_gate();restored.activate_configuration()
        approval=sign(make_approval(decision,'review',NOW),RK)
        self.assertEqual(restored.approve(approval).code,'binding_or_expiry_mismatch')

    def test_reactivating_identical_configuration_invalidates_old_instances(self):
        decision=self.gate.evaluate(self.proposal())
        replacement=self.new_gate();replacement.activate_configuration()
        self.assertEqual(self.gate.evaluate(self.proposal('r2','n2')).code,'configuration_not_active')
        self.assertFalse(Sandbox(replacement).execute(decision.request_id,agent_id='defender')['executed'])

    def test_evidence_aba_does_not_reactivate_old_instance(self):
        old=self.sensor
        self.new_sensor(BK).activate_configuration()
        restored=self.new_sensor();restored.activate_configuration()
        self.assertEqual(old.ingest(self.evidence())['code'],'configuration_not_active')
        self.assertTrue(restored.ingest(self.evidence())['accepted'])

    def test_source_rotation_invalidates_preexisting_evidence_and_decision(self):
        self.assertTrue(self.sensor.ingest(self.evidence())['accepted'])
        decision=self.gate.evaluate(self.proposal(action='quarantine'))
        self.assertEqual(decision.outcome,'allow')
        replacement=self.new_sensor(BK);replacement.activate_configuration()
        self.assertEqual(Sandbox(self.gate).execute(decision.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')
        self.assertEqual(self.gate.evaluate(self.proposal('r2','n2',action='quarantine')).code,'evidence_configuration_changed')
        update={'source_id':'sensor','key_id':'v1','device_id':'pump-01','signal':'compromised',
                'observed_at':NOW-1,'issued_at':NOW,'nonce':'fresh-evidence'}
        self.assertTrue(replacement.ingest(sign(update,BK))['accepted'])
        self.assertEqual(self.gate.evaluate(self.proposal('r3','n3',action='quarantine')).outcome,'allow')

    def test_source_rotation_invalidates_pending_review(self):
        sensor=EvidenceIngestor(self.store,source_keys={'sensor':{'v1':SK}},
                                allowed_devices={'sensor':['plc-01']},clock=self.clock)
        sensor.activate_configuration()
        update={'source_id':'sensor','key_id':'v1','device_id':'plc-01','signal':'compromised',
                'observed_at':NOW-1,'issued_at':NOW,'nonce':'plc-evidence'}
        self.assertTrue(sensor.ingest(sign(update,SK))['accepted'])
        decision=self.gate.evaluate(self.proposal(action='quarantine',target='plc-01'))
        self.assertEqual(decision.code,'review_required')
        replacement=EvidenceIngestor(self.store,source_keys={'sensor':{'v1':BK}},
                                     allowed_devices={'sensor':['plc-01']},clock=self.clock)
        replacement.activate_configuration()
        approval=sign(make_approval(decision,'review',NOW),RK)
        self.assertEqual(self.gate.approve(approval).code,'binding_or_expiry_mismatch')

    def test_source_rotation_invalidates_previously_approved_action(self):
        sensor=EvidenceIngestor(self.store,source_keys={'sensor':{'v1':SK}},
                                allowed_devices={'sensor':['plc-01']},clock=self.clock)
        sensor.activate_configuration()
        update={'source_id':'sensor','key_id':'v1','device_id':'plc-01','signal':'compromised',
                'observed_at':NOW-1,'issued_at':NOW,'nonce':'plc-evidence'}
        self.assertTrue(sensor.ingest(sign(update,SK))['accepted'])
        decision=self.gate.evaluate(self.proposal(action='quarantine',target='plc-01'))
        self.assertEqual(self.gate.approve(sign(make_approval(decision,'review',NOW),RK)).code,'approved_for_sandbox')
        replacement=EvidenceIngestor(self.store,source_keys={'sensor':{'v1':BK}},
                                     allowed_devices={'sensor':['plc-01']},clock=self.clock)
        replacement.activate_configuration()
        self.assertEqual(Sandbox(self.gate).execute(decision.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')

    def test_identical_source_reactivation_still_requires_fresh_evidence(self):
        self.assertTrue(self.sensor.ingest(self.evidence())['accepted'])
        self.new_sensor().activate_configuration()
        self.assertEqual(self.gate.evaluate(self.proposal(action='quarantine')).code,'evidence_configuration_changed')

    def test_admin_update_replaces_prior_sensor_provenance(self):
        self.assertTrue(self.sensor.ingest(self.evidence())['accepted'])
        self.store.put_device('pump-01','routine','normal',NOW,now=NOW)
        device=self.store.device('pump-01')
        self.assertEqual((device['source_id'],device['evidence_hash'],device['evidence_generation']),('operator','',0))

    def test_request_expires_while_waiting_for_database_lock(self):
        e=self.proposal(issued=NOW-125)
        self.assertEqual(self.during_lock_and_advance(lambda:self.gate.evaluate(e)).code,'expired_or_future_request')

    def test_approval_expires_while_waiting_for_database_lock(self):
        d=self.gate.evaluate(self.proposal(action='quarantine',target='plc-01',issued=NOW+5))
        e=sign(make_approval(d,'review',NOW),RK)
        self.clock.value=NOW+125
        self.assertEqual(self.during_lock_and_advance(lambda:self.gate.approve(e)).code,'expired_or_future_approval')

    def test_sandbox_decision_expires_while_waiting_for_database_lock(self):
        d=self.gate.evaluate(self.proposal())
        self.clock.value=NOW+125
        self.assertEqual(self.during_lock_and_advance(lambda:Sandbox(self.gate).execute(d.request_id,agent_id='defender'))['code'],'state_policy_or_time_changed')

    def test_evidence_expires_while_waiting_for_database_lock(self):
        self.assertEqual(self.during_lock_and_advance(lambda:self.sensor.ingest(self.evidence()))['code'],'invalid_evidence_time')
        self.assertEqual(self.store.device('pump-01')['source_id'],'operator')

    def test_duplicate_key_cannot_impersonate_another_agent_or_version(self):
        with self.assertRaisesRegex(ValueError,'reused'):
            Gate(self.store,self.policy,agent_keys={'a':{'v1':AK},'b':{'v1':AK}},reviewer_keys={'r':{'v1':RK}})
        with self.assertRaisesRegex(ValueError,'reused'):
            Gate(self.store,self.policy,agent_keys={'a':{'v1':AK,'v2':AK}},reviewer_keys={'r':{'v1':RK}})

    def test_source_cannot_reuse_agent_or_reviewer_key_and_failure_is_atomic(self):
        for reused in (AK,RK):
            with self.assertRaisesRegex(ValueError,'reused'):
                self.new_sensor(reused).activate_configuration()
        self.assertTrue(self.sensor.ingest(self.evidence())['accepted'])
        self.assertEqual(self.gate.evaluate(self.proposal()).outcome,'allow')

    def test_evidence_configuration_is_read_only(self):
        with self.assertRaises(TypeError): self.sensor.keys['sensor']['v1']=BK
        with self.assertRaises(TypeError): self.sensor.allowed_devices['sensor']=frozenset({'plc-01'})
        with self.assertRaises(AttributeError): self.sensor.keys={}
        with self.assertRaises(AttributeError): self.sensor.ttl=9999
        with self.assertRaises(AttributeError): self.sensor.configuration_hash='0'*64

    def test_early_evidence_rejection_is_audited_without_secrets(self):
        old_head=self.store.audit_head()
        envelope=self.evidence();envelope['payload']['signal']='normal'
        self.assertEqual(self.sensor.ingest(envelope)['code'],'invalid_source_authentication')
        self.assertNotEqual(old_head,self.store.audit_head())
        with self.store.connect() as c:
            body=c.execute('SELECT body FROM audit ORDER BY seq DESC LIMIT 1').fetchone()['body']
        entry=json.loads(body)
        self.assertEqual(entry['event'],'evidence_rejected')
        self.assertEqual(entry['details']['code'],'invalid_source_authentication')
        self.assertNotIn(SK.decode(),body)

    def test_invalid_json_audit_uses_the_current_clock(self):
        self.gate.evaluate_json(b'{bad json')
        with self.store.connect() as c:
            body=c.execute('SELECT body FROM audit ORDER BY seq DESC LIMIT 1').fetchone()['body']
        self.assertEqual(json.loads(body)['time'],NOW)

    def test_store_unavailable_denies_all_stateful_paths(self):
        request=self.proposal()
        pending=self.gate.evaluate(self.proposal('r2','n2',action='quarantine',target='plc-01'))
        approval=sign(make_approval(pending,'review',NOW),RK)
        with patch.object(self.store,'connect',side_effect=sqlite3.OperationalError('simulated fault')):
            self.assertEqual(self.gate.evaluate(request).outcome,'block')
            self.assertEqual(self.gate.approve(approval).outcome,'block')
            self.assertFalse(Sandbox(self.gate).execute('r2',agent_id='defender')['executed'])
            self.assertFalse(self.sensor.ingest(self.evidence())['accepted'])

    def test_old_database_schema_is_rejected_without_changing_it(self):
        path=Path(self.tmp.name)/'old.db'
        with sqlite3.connect(path) as c: c.execute('CREATE TABLE decisions (request_id TEXT PRIMARY KEY)')
        with self.assertRaisesRegex(ValueError,'earlier database schema'): Store(path)
        with sqlite3.connect(path) as c:
            self.assertEqual(c.execute('PRAGMA user_version').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT count(*) FROM decisions').fetchone()[0],0)

    def test_missing_nonce_table_is_not_silently_recreated(self):
        with self.store.transaction() as c: c.execute('DROP TABLE nonces')
        with self.assertRaisesRegex(ValueError,'incomplete database schema'): Store(self.store.path)
        with self.store.connect() as c:
            row=c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nonces'").fetchone()
            self.assertIsNone(row)

class CliPolicyTests(unittest.TestCase):
    def test_duplicate_policy_keys_fail_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy=Path(tmp)/'policy.json';policy.write_text('{"version":"a","version":"b"}')
            result=subprocess.run([sys.executable,'-m','edgeguardra','check-policy',str(policy)],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertIn('duplicate JSON field',result.stderr)

    def test_oversized_policy_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy=Path(tmp)/'policy.json';policy.write_bytes(b' '*65537)
            result=subprocess.run([sys.executable,'-m','edgeguardra','check-policy',str(policy)],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertIn('oversized',result.stderr)

if __name__=='__main__': unittest.main()
