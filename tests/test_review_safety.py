"""Regression tests for review scope, chronology and clock movement."""
import copy
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from edgeguardra.demo import example_policy,make_approval,make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate,canonical_bytes,sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW=1700000000
AK,RK,LK,SELFK,SK=b'A'*32,b'R'*32,b'L'*32,b'D'*32,b'S'*32

class Clock:
    def __init__(self): self.value=NOW;self.called=threading.Event()
    def __call__(self):
        v=self.value;self.called.set();return v

class ReviewAndClockTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'state.db', create=True);self.clock=Clock()
        self.store.put_device('pump-01','routine','compromised',NOW-2,now=NOW)
        self.store.put_device('plc-01','critical','compromised',NOW-2,now=NOW)
        self.policy=example_policy()
        self.policy['review_grants']['limited']={'restore':['plc-01']}
        self.policy['review_grants']['defender']={'quarantine':['plc-01']}
        self.gate=Gate(self.store,self.policy,agent_keys={'defender':{'v1':AK}},
                       reviewer_keys={'reviewer':{'v1':RK},'limited':{'v1':LK},'defender':{'v1':SELFK}},clock=self.clock)
        self.gate.activate_configuration()
        self.sensor=EvidenceIngestor(self.store,source_keys={'sensor':{'v1':SK}},
                                     allowed_devices={'sensor':['pump-01']},clock=self.clock)
        self.sensor.activate_configuration()

    def propose(self,id='r1',nonce='n1',target='plc-01',action='quarantine',reason='sensitive-reason-fixture'):
        return sign(make_proposal(id,nonce,NOW,target=target,action=action,reason=reason),AK)

    def pending(self,id='r1',nonce='n1'):
        d=self.gate.evaluate(self.propose(id,nonce));self.assertEqual(d.code,'review_required');return d

    def signed_review(self,d,reviewer='reviewer',key=RK,nonce='review',issued=NOW):
        return sign(make_approval(d,nonce,issued,reviewer_id=reviewer),key)

    def rollback_during_lock(self,fn):
        self.clock.value=NOW+10;self.clock.called.clear()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.store.transaction():
                future=pool.submit(fn)
                self.assertTrue(self.clock.called.wait(1),'initial clock read missing')
                self.clock.value=NOW+5
            result=future.result(timeout=5)
        with self.store.connect() as c:
            self.assertEqual(c.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone()[0],NOW+10)
        return result

    def test_reviewer_without_action_grant_is_rejected(self):
        d=self.pending()
        self.assertEqual(self.gate.approve(self.signed_review(d,'limited',LK)).code,'reviewer_not_authorized')
        self.assertEqual(self.gate.approve(self.signed_review(d,nonce='legitimate')).code,'approved_for_sandbox')

    def test_self_review_is_rejected_even_when_granted(self):
        d=self.pending()
        self.assertEqual(self.gate.approve(self.signed_review(d,'defender',SELFK)).code,'self_approval_forbidden')

    def test_challenge_is_distinct_and_bound_to_decision(self):
        first=self.pending();second=self.pending('r2','n2')
        self.assertEqual(len(first.review_challenge),64);self.assertNotEqual(first.review_challenge,second.review_challenge)
        p=make_approval(first,'review',NOW);p['review_challenge']=second.review_challenge
        self.assertEqual(self.gate.approve(sign(p,RK)).code,'binding_or_expiry_mismatch')
        self.assertEqual(self.gate.approve(self.signed_review(first,nonce='actual')).code,'approved_for_sandbox')

    def test_approval_without_challenge_is_rejected(self):
        d=self.pending();p=make_approval(d,'review',NOW);del p['review_challenge']
        self.assertEqual(self.gate.approve(sign(p,RK)).code,'invalid_approval_schema')

    def test_approval_timestamp_cannot_precede_decision(self):
        d=self.pending()
        self.assertEqual(self.gate.approve(self.signed_review(d,issued=NOW-1)).code,'approval_before_decision')

    def test_allow_does_not_expose_unneeded_review_challenge(self):
        decision=self.gate.evaluate(self.propose(target='pump-01'))
        self.assertEqual(decision.outcome,'allow');self.assertIsNone(decision.review_challenge)

    def test_request_clock_rollback_between_reads_is_rejected(self):
        e=self.propose(target='pump-01')
        self.assertEqual(self.rollback_during_lock(lambda:self.gate.evaluate(e)).code,'clock_rollback')

    def test_approval_clock_rollback_between_reads_is_rejected(self):
        d=self.pending();e=self.signed_review(d)
        self.assertEqual(self.rollback_during_lock(lambda:self.gate.approve(e)).code,'clock_rollback')

    def test_execution_clock_rollback_between_reads_is_rejected(self):
        d=self.gate.evaluate(self.propose(target='pump-01'))
        self.assertEqual(self.rollback_during_lock(lambda:Sandbox(self.gate).execute(d.request_id,agent_id='defender'))['code'],'clock_rollback')
        self.assertEqual(self.store.device('pump-01')['quarantined'],0)

    def test_evidence_clock_rollback_between_reads_is_rejected(self):
        p={'source_id':'sensor','key_id':'v1','device_id':'pump-01','signal':'compromised',
           'observed_at':NOW-1,'issued_at':NOW,'nonce':'sensor-n'}
        self.assertEqual(self.rollback_during_lock(lambda:self.sensor.ingest(sign(p,SK)))['code'],'clock_rollback')
        self.assertEqual(self.store.device('pump-01')['source_id'],'operator')

    def test_clock_rollback_fails_until_the_high_water_recovers(self):
        self.assertEqual(self.rollback_during_lock(lambda:self.gate.evaluate(self.propose(target='pump-01'))).code,'clock_rollback')
        self.assertEqual(self.gate.evaluate(self.propose('r2','n2',target='pump-01')).code,'clock_rollback')
        self.clock.value=NOW+10
        self.assertEqual(self.gate.evaluate(self.propose('r3','n3',target='pump-01')).outcome,'allow')

    def test_audit_links_decision_approval_and_execution_without_reason(self):
        d=self.pending();approval=self.signed_review(d)
        self.assertEqual(self.gate.approve(approval).code,'approved_for_sandbox')
        self.assertTrue(Sandbox(self.gate).execute(d.request_id,agent_id='defender')['executed'])
        with self.store.connect() as c: entries=[json.loads(r['body']) for r in c.execute('SELECT body FROM audit')]
        decision=next(e['details'] for e in entries if e['event']=='decision')
        reviewed=next(e['details'] for e in entries if e['event']=='approved')
        executed=next(e['details'] for e in entries if e['event']=='sandbox_executed')
        self.assertEqual((decision['agent_id'],decision['target'],decision['request_hash']),('defender','plc-01',d.request_hash))
        self.assertEqual(reviewed['approval_hash'],hashlib.sha256(canonical_bytes(approval['payload'])).hexdigest())
        self.assertEqual(executed['request_hash'],d.request_hash)
        self.assertNotIn('sensitive-reason-fixture',json.dumps(entries))
        self.assertNotIn(RK.decode(),json.dumps(entries))

    def test_evidence_audit_has_source_generation_and_version(self):
        p={'source_id':'sensor','key_id':'v1','device_id':'pump-01','signal':'compromised',
           'observed_at':NOW-1,'issued_at':NOW,'nonce':'sensor-n'}
        result=self.sensor.ingest(sign(p,SK));self.assertTrue(result['accepted'])
        with self.store.connect() as c: row=c.execute('SELECT body FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        entry=json.loads(row['body']);self.assertEqual(entry['event'],'evidence_accepted')
        self.assertEqual(entry['details']['context_version'],result['context_version'])
        self.assertEqual(entry['details']['key_id'],'v1')

    def test_malformed_audit_body_is_reported_as_invalid(self):
        self.gate.evaluate(self.propose(target='pump-01'))
        with self.store.transaction() as c:c.execute("UPDATE audit SET body=? WHERE seq=1",('\u975e ASCII',))
        self.assertFalse(self.store.verify_audit()['valid'])

    def test_policy_requires_explicit_review_grants(self):
        policy=copy.deepcopy(self.policy);del policy['review_grants']
        with self.assertRaises(ValueError):
            Gate(self.store,policy,agent_keys={'defender':{'v1':AK}},reviewer_keys={'reviewer':{'v1':RK}})

    def test_older_database_version_is_rejected(self):
        path=Path(self.tmp.name)/'older.db'
        with sqlite3.connect(path) as c:c.execute('PRAGMA user_version=3')
        with self.assertRaisesRegex(ValueError,'unsupported database schema version'):Store(path)

class CliMalformedTests(unittest.TestCase):
    def test_unhashable_denied_action_has_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy=example_policy();policy['denied_actions']=[[]]
            p=Path(tmp)/'p.json';p.write_text(json.dumps(policy))
            r=subprocess.run([sys.executable,'-m','edgeguardra','check-policy',str(p)],capture_output=True,text=True)
            self.assertEqual(r.returncode,2);self.assertIn('invalid denied action list',r.stderr);self.assertNotIn('Traceback',r.stderr)

if __name__=='__main__': unittest.main()
