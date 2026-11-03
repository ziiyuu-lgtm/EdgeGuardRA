"""Tests of per-agent request isolation and independently retained checkpoints."""
import hashlib
import json
import multiprocessing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from edgeguardra.demo import example_policy,make_approval,make_proposal
from edgeguardra.gate import Gate,sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW=1700000000
AK,OK,RK=b'A'*32,b'O'*32,b'R'*32


def _worker(path,policy,envelope,barrier,queue):
    try:
        store=Store(path)
        gate=Gate(store,policy,agent_keys={'defender':{'v1':AK},'observer':{'v1':OK}},
                  reviewer_keys={'reviewer':{'v1':RK}},clock=lambda:NOW)
        barrier.wait(timeout=8)
        result=gate.evaluate(envelope)
        queue.put((envelope['payload']['agent_id'],result.code))
    except BaseException as exc:
        queue.put(('error',type(exc).__name__))

class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'state.db', create=True)
        self.store.put_device('pump-01','routine','normal',NOW-1,now=NOW)
        self.store.put_device('plc-01','critical','compromised',NOW-1,now=NOW)
        self.policy=example_policy();self.policy['grants']['observer']['quarantine']=['plc-01']
        self.gate=Gate(self.store,self.policy,agent_keys={'defender':{'v1':AK},'observer':{'v1':OK}},
                       reviewer_keys={'reviewer':{'v1':RK}},clock=lambda:NOW)
        self.gate.activate_configuration()

    def request(self,agent,action='inspect',target='pump-01',request_id='shared',nonce='same-nonce'):
        p=make_proposal(request_id,nonce,NOW,agent_id=agent,action=action,target=target)
        return sign(p,AK if agent=='defender' else OK)

    def test_identical_request_id_and_nonce_are_isolated_by_agent(self):
        observer=self.gate.evaluate(self.request('observer'))
        defender=self.gate.evaluate(self.request('defender'))
        self.assertEqual((observer.outcome,defender.outcome),('allow','allow'))
        self.assertEqual((observer.agent_id,defender.agent_id),('observer','defender'))
        self.assertNotEqual(observer.request_hash,defender.request_hash)
        self.assertEqual(self.store.decision('shared',agent_id='observer')['agent_id'],'observer')
        self.assertEqual(self.store.decision('shared',agent_id='defender')['agent_id'],'defender')
        broker=Sandbox(self.gate)
        self.assertEqual(broker.execute('shared')['code'],'invalid_agent_id')
        self.assertTrue(broker.execute('shared',agent_id='observer')['executed'])
        self.assertTrue(broker.execute('shared',agent_id='defender')['executed'])

    def test_same_agent_duplicate_request_id_still_blocked(self):
        self.assertEqual(self.gate.evaluate(self.request('defender')).outcome,'allow')
        self.assertEqual(self.gate.evaluate(self.request('defender',nonce='different')).code,'duplicate_request_id')

    def test_approval_and_execution_cannot_cross_agent_scope(self):
        d1=self.gate.evaluate(self.request('defender',action='quarantine',target='plc-01'))
        d2=self.gate.evaluate(self.request('observer',action='quarantine',target='plc-01'))
        self.assertEqual((d1.code,d2.code),('review_required','review_required'))
        approval=make_approval(d1,'review-a',NOW);approval['agent_id']='observer'
        self.assertEqual(self.gate.approve(sign(approval,RK)).code,'binding_or_expiry_mismatch')
        self.assertEqual(self.gate.approve(sign(make_approval(d1,'review-b',NOW),RK)).code,'approved_for_sandbox')
        self.assertEqual(Sandbox(self.gate).execute('shared',agent_id='observer')['code'],'not_authorized')
        self.assertEqual(self.store.decision('shared',agent_id='defender')['status'],'approved')
        self.assertEqual(self.store.decision('shared',agent_id='observer')['status'],'pending')
        self.assertEqual(self.gate.approve(sign(make_approval(d2,'review-c',NOW),RK)).code,'approved_for_sandbox')

    @unittest.skipUnless('fork' in multiprocessing.get_all_start_methods(),'requires POSIX fork')
    def test_different_agents_same_id_and_nonce_across_processes(self):
        ctx=multiprocessing.get_context('fork');barrier=ctx.Barrier(2);queue=ctx.Queue()
        envelopes=[self.request('defender'),self.request('observer')]
        workers=[ctx.Process(target=_worker,args=(self.store.path,self.policy,e,barrier,queue)) for e in envelopes]
        for proc in workers:proc.start()
        for proc in workers:proc.join(timeout=12)
        self.assertTrue(all(proc.exitcode==0 for proc in workers))
        self.assertCountEqual([queue.get(timeout=2),queue.get(timeout=2)],
                              [('defender','checks_passed'),('observer','checks_passed')])

class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'state.db', create=True)
        self.store.put_device('pump-01','routine','normal',NOW-1,now=NOW)
        self.checkpoint=self.store.audit_checkpoint()

    def append(self):self.store.put_device('pump-01','routine','normal',NOW,now=NOW)

    def test_checkpoint_remains_valid_after_legitimate_append(self):
        self.append();result=self.store.verify_audit(checkpoint=self.checkpoint)
        self.assertTrue(result['valid']);self.assertTrue(result['anchored'])
        self.assertEqual(result['anchored_through'],self.checkpoint['seq'])
        self.assertGreater(result['entries'],self.checkpoint['seq'])
        self.assertFalse(self.store.verify_audit(expected_head=self.checkpoint['hash'])['valid'])

    def test_checkpoint_rejects_another_database(self):
        other=Store(Path(self.tmp.name)/'other.db', create=True);other.put_device('pump-01','routine','normal',NOW-1,now=NOW)
        result=other.verify_audit(checkpoint=self.checkpoint)
        self.assertFalse(result['valid']);self.assertEqual(result['code'],'checkpoint_database_mismatch')

    def test_recomputed_prefix_is_detected_by_external_checkpoint(self):
        self.append()
        with self.store.transaction() as c:
            _,previous=Store._audit_genesis(c)
            rows=c.execute('SELECT seq,body FROM audit ORDER BY seq').fetchall()
            for index,row in enumerate(rows):
                body='{"event":"altered"}' if index==0 else row['body']
                digest=hashlib.sha256(previous.encode('ascii')+b'\x00'+body.encode('ascii')).hexdigest()
                c.execute('UPDATE audit SET body=?,prev_hash=?,entry_hash=? WHERE seq=?',(body,previous,digest,row['seq']))
                previous=digest
        self.assertTrue(self.store.verify_audit()['valid'])
        self.assertEqual(self.store.verify_audit(checkpoint=self.checkpoint)['code'],'checkpoint_hash_mismatch')

    def test_checkpoint_does_not_claim_suffix_is_immutable(self):
        self.append()
        with self.store.transaction() as c:
            row=c.execute('SELECT seq,prev_hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
            body='{"event":"altered suffix"}'
            digest=hashlib.sha256(row['prev_hash'].encode('ascii')+b'\x00'+body.encode('ascii')).hexdigest()
            c.execute('UPDATE audit SET body=?,entry_hash=? WHERE seq=?',(body,digest,row['seq']))
        result=self.store.verify_audit(checkpoint=self.checkpoint)
        self.assertTrue(result['valid']);self.assertEqual(result['anchored_through'],self.checkpoint['seq'])

    def test_tail_deletion_and_new_entry_exposes_sequence_gap(self):
        with self.store.transaction() as c:c.execute('DELETE FROM audit WHERE seq=(SELECT max(seq) FROM audit)')
        self.append()
        self.assertEqual(self.store.verify_audit()['code'],'audit_sequence_gap')
        self.assertFalse(self.store.verify_audit(checkpoint=self.checkpoint)['valid'])

    def test_checkpoint_is_not_available_for_an_empty_chain(self):
        other=Store(Path(self.tmp.name)/'empty.db', create=True)
        with self.assertRaises(ValueError):other.audit_checkpoint()

    def test_invalid_or_missing_checkpoint_is_denied(self):
        for cp in ({'audit_id':'x','seq':1,'hash':'0'*64},
                   {'audit_id':self.checkpoint['audit_id'],'seq':True,'hash':'0'*64},
                   {'audit_id':self.checkpoint['audit_id'],'seq':999,'hash':'0'*64}):
            with self.subTest(checkpoint=cp):self.assertFalse(self.store.verify_audit(checkpoint=cp)['valid'])

    def test_missing_database_audit_identity_is_rejected(self):
        with self.store.transaction() as c:c.execute("DELETE FROM metadata_text WHERE key='audit_id'")
        with self.assertRaisesRegex(ValueError,'audit identity'):Store(self.store.path)
        self.assertFalse(self.store.verify_audit()['valid'])

    def test_previous_database_version_is_rejected(self):
        path=Path(self.tmp.name)/'previous.db'
        with sqlite3.connect(path) as c:c.execute('PRAGMA user_version=4')
        with self.assertRaisesRegex(ValueError,'unsupported database schema version'):Store(path)

if __name__=='__main__':unittest.main()
