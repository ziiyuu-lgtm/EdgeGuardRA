import copy
import json
import multiprocessing
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store
from edgeguardra.validation import NONCE_RETENTION_MARGIN

NOW = 1700000000
AK, OK, RK, SK = b'A'*32, b'O'*32, b'R'*32, b'S'*32  # test fixtures only


class Clock:
    def __init__(self): self.value=NOW
    def __call__(self): return self.value


def _process_decide(path, envelope, barrier, output):
    try:
        s=Store(path)
        g=Gate(s,example_policy(),agent_keys={'defender':{'v1':AK},'observer':{'v1':OK}},
               reviewer_keys={'reviewer':{'v1':RK}},clock=lambda:NOW)
        barrier.wait(timeout=8)
        output.put(g.evaluate(envelope).code)
    except BaseException as exc:
        output.put('error:'+type(exc).__name__)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'state.db', create=True)
        self.clock=Clock()
        self.store.put_device('pump-01','routine','compromised',NOW-2,now=NOW)
        self.store.put_device('plc-01','critical','compromised',NOW-2,now=NOW)
        self.store.put_device('spare-01','routine','compromised',NOW-2,now=NOW)
        self.policy=example_policy()
        self.gate=self.new_gate()
        self.gate.activate_configuration()
        self.ingestor().activate_configuration()

    def new_gate(self, policy=None, *, clock=None):
        return Gate(self.store,self.policy if policy is None else policy,
                    agent_keys={'defender':{'v1':AK},'observer':{'v1':OK}},
                    reviewer_keys={'reviewer':{'v1':RK}},clock=clock or self.clock)

    def request(self, id='r1', nonce='n1', **kwargs):
        p=make_proposal(id,nonce,self.clock.value,**kwargs)
        return sign(p,OK if p['agent_id']=='observer' else AK)

    def critical(self, id='critical', nonce='nc'):
        return self.gate.evaluate(self.request(id,nonce,target='plc-01'))

    def approve(self, d, nonce='review-1', key=RK):
        return self.gate.approve(sign(make_approval(d,nonce,self.clock.value),key))

    def test_explicit_keyrings_required(self):
        with self.assertRaises(TypeError): Gate(self.store,self.policy)
        with self.assertRaises(ValueError):
            Gate(self.store,self.policy,agent_keys={'defender':{'v1':b''}},reviewer_keys={'reviewer':{'v1':RK}})

    def test_reviewer_must_have_a_distinct_key(self):
        with self.assertRaises(ValueError):
            Gate(self.store,self.policy,agent_keys={'defender':{'v1':AK}},reviewer_keys={'reviewer':{'v1':AK}})

    def test_short_signing_key_rejected(self):
        with self.assertRaises(ValueError): sign({},b'short')

    def test_normal_isolation_allowed(self):
        self.assertEqual(self.gate.evaluate(self.request()).code,'checks_passed')

    def test_tampered_request_is_blocked(self):
        e=self.request();e['payload']['target']='plc-01'
        self.assertEqual(self.gate.evaluate(e).code,'invalid_signature')

    def test_uppercase_mac_is_accepted(self):
        e=self.request();e['signature']=e['signature'].upper()
        self.assertEqual(self.gate.evaluate(e).outcome,'allow')

    def test_unpaired_surrogate_is_blocked_without_exception(self):
        p=make_proposal('r','n',NOW);p['reason']='\ud800'
        self.assertEqual(self.gate.evaluate({'payload':p,'signature':'0'*64}).outcome,'block')

    def test_malformed_unhashable_action_is_blocked(self):
        e=self.request();e['payload']['action']=[]
        self.assertEqual(self.gate.evaluate(e).outcome,'block')

    def test_duplicate_json_fields_are_rejected(self):
        self.assertEqual(self.gate.evaluate_json(b'{"payload":{},"payload":{},"signature":"x"}').code,'invalid_json')

    def test_bad_utf8_and_oversized_json_are_rejected(self):
        self.assertEqual(self.gate.evaluate_json(b'\xff').outcome,'block')
        self.assertEqual(self.gate.evaluate_json(b' '*16385).code,'invalid_json')

    def test_invalid_clock_cannot_allow(self):
        g=self.new_gate(clock=lambda:True)
        self.assertEqual(g.evaluate(self.request()).outcome,'block')

    def test_future_skew_boundary(self):
        p=make_proposal('rf','nf',NOW+5,action='inspect')
        self.assertEqual(self.gate.evaluate(sign(p,AK)).outcome,'allow')
        p=make_proposal('rf2','nf2',NOW+6,action='inspect')
        self.assertEqual(self.gate.evaluate(sign(p,AK)).code,'expired_or_future_request')

    def test_expired_request_blocked(self):
        p=make_proposal('old','oldn',NOW-126,action='inspect')
        self.assertEqual(self.gate.evaluate(sign(p,AK)).code,'expired_or_future_request')

    def test_valid_request_survives_policy_input_mutation(self):
        self.policy['grants']['defender']['quarantine'].clear()
        self.assertEqual(self.gate.evaluate(self.request()).outcome,'allow')

    def test_explicit_target_grant_required(self):
        self.assertEqual(self.gate.evaluate(self.request(target='spare-01')).code,'unauthorized_target_or_action')

    def test_grant_does_not_imply_known_target(self):
        p=copy.deepcopy(self.policy);p['grants']['defender']['inspect'].append('ghost')
        gate=self.new_gate(p);gate.activate_configuration()
        self.assertEqual(gate.evaluate(self.request(action='inspect',target='ghost')).code,'unknown_target')

    def test_permission_denial_cannot_be_approved(self):
        d=self.gate.evaluate(self.request(agent_id='observer'))
        self.assertEqual(d.outcome,'block')
        with self.assertRaises(ValueError): make_approval(d,'review',NOW)

    def test_hard_deny_cannot_be_approved(self):
        p=copy.deepcopy(self.policy);p['denied_actions']=['quarantine']
        gate=self.new_gate(p);gate.activate_configuration()
        d=gate.evaluate(self.request())
        self.assertEqual(d.code,'hard_denied')
        with self.assertRaises(ValueError): make_approval(d,'review',NOW)

    def test_same_instance_replay_blocked(self):
        e=self.request();self.assertEqual(self.gate.evaluate(e).outcome,'allow')
        self.assertEqual(self.gate.evaluate(e).code,'replay')

    def test_new_instance_same_database_replay_blocked(self):
        e=self.request();self.assertEqual(self.gate.evaluate(e).outcome,'allow')
        self.assertEqual(self.new_gate().evaluate(e).code,'replay')

    def test_concurrent_instances_allow_at_most_one(self):
        e=self.request();barrier=threading.Barrier(2)
        def work():
            g=self.new_gate();barrier.wait();return g.evaluate(e).code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(lambda _:work(),range(2)))
        self.assertCountEqual(outcomes,['checks_passed','replay'])

    @unittest.skipUnless('fork' in multiprocessing.get_all_start_methods(),'requires POSIX fork')
    def test_concurrent_processes_share_persistent_replay_state(self):
        ctx=multiprocessing.get_context('fork');barrier=ctx.Barrier(2);output=ctx.Queue();e=self.request()
        processes=[ctx.Process(target=_process_decide,args=(self.store.path,e,barrier,output)) for _ in range(2)]
        for p in processes: p.start()
        for p in processes: p.join(timeout=12)
        self.assertTrue(all(p.exitcode==0 for p in processes))
        outcomes=[output.get(timeout=2),output.get(timeout=2)]
        self.assertCountEqual(outcomes,['checks_passed','replay'])

    def test_expired_nonce_is_retained_then_cleaned_after_extra_window(self):
        self.assertEqual(self.gate.evaluate(self.request(action='inspect')).outcome,'allow')
        self.clock.value+=126
        e=self.request(id='r2',nonce='n1',action='inspect')
        self.assertEqual(self.gate.evaluate(e).code,'replay')
        self.clock.value=NOW+125+NONCE_RETENTION_MARGIN+1
        e=self.request(id='r2',nonce='n1',action='inspect')
        self.assertEqual(self.gate.evaluate(e).outcome,'allow')
        with self.store.connect() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM nonces WHERE kind='proposal'").fetchone()[0],1)

    def test_clock_rollback_fails_closed_across_instances(self):
        self.clock.value+=10
        self.assertEqual(self.gate.evaluate(self.request(action='inspect')).outcome,'allow')
        self.clock.value-=5
        other=self.new_gate()
        self.assertEqual(other.evaluate(self.request(id='r2',nonce='n2',action='inspect')).code,'clock_rollback')

    def test_administrator_cannot_register_context_with_earlier_clock(self):
        self.clock.value+=10;self.gate.evaluate(self.request(action='inspect'))
        with self.assertRaises(ValueError):
            self.store.put_device('pump-01','routine','normal',NOW,now=NOW)

    def test_duplicate_request_id_cannot_be_reused_with_new_nonce(self):
        self.gate.evaluate(self.request())
        self.assertEqual(self.gate.evaluate(self.request(nonce='another')).code,'duplicate_request_id')

    def test_missing_sensor_context_defers(self):
        self.store.put_device('pump-01','routine','unknown',NOW,now=NOW)
        self.assertEqual(self.gate.evaluate(self.request()).code,'insufficient_or_conflicting_evidence')

    def test_stale_sensor_context_defers(self):
        self.clock.value+=61
        self.assertEqual(self.gate.evaluate(self.request()).code,'stale_context')

    def test_critical_action_requires_review(self):
        self.assertEqual(self.critical().code,'review_required')

    def test_approval_and_simulated_execution_only_once(self):
        d=self.critical();self.assertEqual(self.approve(d).code,'approved_for_sandbox')
        broker=Sandbox(self.gate)
        self.assertTrue(broker.execute(d.request_id,agent_id='defender')['executed'])
        self.assertEqual(broker.execute(d.request_id,agent_id='defender')['code'],'not_authorized')
        self.assertEqual(self.store.device('plc-01')['quarantined'],1)

    def test_no_execution_of_pending_action(self):
        d=self.critical()
        self.assertFalse(Sandbox(self.gate).execute(d.request_id,agent_id='defender')['executed'])

    def test_wrong_approval_key_is_blocked(self):
        d=self.critical();self.assertEqual(self.approve(d,key=AK).code,'invalid_approval_signature')

    def test_approval_bound_to_request_hash(self):
        d=self.critical();p=make_approval(d,'nr',NOW);p['request_hash']='0'*64
        self.assertEqual(self.gate.approve(sign(p,RK)).code,'binding_or_expiry_mismatch')

    def test_approval_bound_to_policy_version(self):
        d=self.critical();p=make_approval(d,'nr',NOW);p['policy_hash']='0'*64
        self.assertEqual(self.gate.approve(sign(p,RK)).code,'binding_or_expiry_mismatch')

    def test_context_change_before_approval_blocks(self):
        d=self.critical();self.store.put_device('plc-01','critical','compromised',NOW,now=NOW)
        self.assertEqual(self.approve(d).code,'binding_or_expiry_mismatch')

    def test_context_change_after_approval_blocks_execution(self):
        d=self.critical();self.approve(d)
        self.store.put_device('plc-01','critical','compromised',NOW,now=NOW)
        self.assertEqual(Sandbox(self.gate).execute(d.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')

    def test_evidence_aging_before_review_blocks_approval(self):
        d=self.critical();self.clock.value+=61
        self.assertEqual(self.approve(d).code,'binding_or_expiry_mismatch')

    def test_evidence_aging_before_execution_blocks(self):
        d=self.gate.evaluate(self.request());self.clock.value+=61
        self.assertEqual(Sandbox(self.gate).execute(d.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')

    def test_execution_respects_shorter_approval_validity(self):
        policy=copy.deepcopy(self.policy);policy['max_context_age']=200
        gate=self.new_gate(policy);gate.activate_configuration()
        decision=gate.evaluate(sign(make_proposal('future','nf',NOW+5,target='plc-01'),AK))
        approval=sign(make_approval(decision,'valid-approval',NOW),RK)
        self.assertEqual(gate.approve(approval).code,'approved_for_sandbox')
        self.clock.value+=126
        self.assertEqual(Sandbox(gate).execute(decision.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')

    def test_agent_key_replacement_invalidates_existing_decision(self):
        d=self.gate.evaluate(self.request())
        replacement=Gate(self.store,self.policy,agent_keys={'defender':{'v1':b'B'*32}},
                         reviewer_keys={'reviewer':{'v1':RK}},clock=self.clock)
        replacement.activate_configuration()
        self.assertEqual(Sandbox(replacement).execute(d.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')
        self.assertEqual(Sandbox(self.gate).execute(d.request_id,agent_id='defender')['code'],'configuration_not_active')
        self.assertEqual(self.gate.evaluate(self.request(id='new',nonce='new')).code,'configuration_not_active')

    def test_revoked_agent_key_blocks_pending_approval(self):
        d=self.critical()
        replacement=Gate(self.store,self.policy,agent_keys={'defender':{'v1':b'B'*32}},
                         reviewer_keys={'reviewer':{'v1':RK}},clock=self.clock)
        replacement.activate_configuration()
        e=sign(make_approval(d,'nr',NOW),RK)
        self.assertEqual(replacement.approve(e).code,'binding_or_expiry_mismatch')
        self.assertEqual(self.gate.approve(e).code,'configuration_not_active')

    def test_revoked_reviewer_key_blocks_approved_execution(self):
        d=self.critical();self.approve(d)
        replacement=Gate(self.store,self.policy,agent_keys={'defender':{'v1':AK}},
                         reviewer_keys={'reviewer':{'v1':b'Z'*32}},clock=self.clock)
        replacement.activate_configuration()
        self.assertEqual(Sandbox(replacement).execute(d.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')

    def test_policy_change_invalidates_existing_decision(self):
        d=self.gate.evaluate(self.request())
        changed=copy.deepcopy(self.policy);changed['version']='demo-v2'
        replacement=self.new_gate(changed)
        replacement.activate_configuration()
        self.assertEqual(Sandbox(replacement).execute(d.request_id,agent_id='defender')['code'],'state_policy_or_time_changed')

    def test_same_approval_cannot_be_used_twice(self):
        d=self.critical();e=sign(make_approval(d,'nr',NOW),RK)
        self.assertEqual(self.gate.approve(e).outcome,'allow')
        self.assertEqual(self.gate.approve(e).code,'not_pending')

    def test_separate_decision_and_approval_are_logged_without_secrets(self):
        d=self.critical();self.approve(d)
        self.assertTrue(self.store.verify_audit()['valid'])
        with self.store.connect() as c: rows=c.execute('SELECT body FROM audit').fetchall()
        content=''.join(row[0] for row in rows)
        self.assertNotIn(AK.decode(),content);self.assertNotIn(RK.decode(),content)

    def test_audit_detects_modified_record(self):
        self.gate.evaluate(self.request())
        with self.store.transaction() as c: c.execute("UPDATE audit SET body='{}' WHERE seq=1")
        self.assertFalse(self.store.verify_audit()['valid'])

    def test_external_head_detects_tail_deletion(self):
        self.gate.evaluate(self.request());head=self.store.audit_head()
        with self.store.transaction() as c: c.execute('DELETE FROM audit WHERE seq=(SELECT max(seq) FROM audit)')
        self.assertTrue(self.store.verify_audit()['valid'])
        self.assertFalse(self.store.verify_audit(expected_head=head)['valid'])

    def ingestor(self):
        return EvidenceIngestor(self.store,source_keys={'sensor':{'v1':SK}},allowed_devices={'sensor':['pump-01']},clock=self.clock)

    def evidence(self, **updates):
        p={'source_id':'sensor','key_id':'v1','device_id':'pump-01','signal':'compromised',
           'observed_at':NOW-1,'issued_at':NOW,'nonce':'sensor-n1'}
        p.update(updates);return sign(p,SK)

    def test_authenticated_evidence_updates_context(self):
        result=self.ingestor().ingest(self.evidence())
        self.assertTrue(result['accepted'])
        self.assertEqual(self.store.device('pump-01')['source_id'],'sensor')

    def test_revoked_evidence_configuration_stops_old_instances(self):
        old=self.ingestor()
        replacement=EvidenceIngestor(self.store,source_keys={'sensor':{'v1':b'Z'*32}},
                                     allowed_devices={'sensor':['pump-01']},clock=self.clock)
        replacement.activate_configuration()
        self.assertEqual(old.ingest(self.evidence())['code'],'configuration_not_active')
        envelope=self.evidence(nonce='new-evidence')
        self.assertTrue(replacement.ingest(sign(envelope['payload'],b'Z'*32))['accepted'])

    def test_unactivated_configuration_fails_closed(self):
        other=Store(Path(self.tmp.name)/'other.db', create=True)
        other.put_device('pump-01','routine','compromised',NOW-1,now=NOW)
        gate=Gate(other,self.policy,agent_keys={'defender':{'v1':AK}},
                  reviewer_keys={'reviewer':{'v1':RK}},clock=self.clock)
        self.assertEqual(gate.evaluate(self.request()).code,'configuration_not_active')
        sensor=EvidenceIngestor(other,source_keys={'sensor':{'v1':SK}},
                                allowed_devices={'sensor':['pump-01']},clock=self.clock)
        self.assertEqual(sensor.ingest(self.evidence())['code'],'configuration_not_active')

    def test_evidence_replay_across_instances_blocked(self):
        e=self.evidence();self.assertTrue(self.ingestor().ingest(e)['accepted'])
        self.assertEqual(self.ingestor().ingest(e)['code'],'evidence_replay')

    def test_evidence_does_not_change_criticality(self):
        e=self.evidence();e['payload']['criticality']='routine'
        self.assertEqual(self.ingestor().ingest(e)['code'],'invalid_schema')

    def test_evidence_source_limited_to_allowed_devices(self):
        self.assertEqual(self.ingestor().ingest(self.evidence(device_id='plc-01'))['code'],'source_not_authorized_for_device')

    def test_evidence_cannot_arrive_out_of_order(self):
        self.assertEqual(self.ingestor().ingest(self.evidence(observed_at=NOW-3))['code'],'out_of_order')

    def test_modified_evidence_fails_authentication(self):
        e=self.evidence();e['payload']['signal']='normal'
        self.assertEqual(self.ingestor().ingest(e)['code'],'invalid_source_authentication')

    def test_signed_false_evidence_can_still_cause_wrong_decision(self):
        # The fixture's independent physical truth is normal, but a compromised
        # sensor honestly signs an incorrect 'compromised' signal.
        self.assertTrue(self.ingestor().ingest(self.evidence())['accepted'])
        self.assertEqual(self.gate.evaluate(self.request()).outcome,'allow')


if __name__=='__main__': unittest.main()

