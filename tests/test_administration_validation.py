"""Administrative input bounds and invalid persisted-clock recovery behavior."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from edgeguardra.demo import example_policy,make_proposal
from edgeguardra.gate import Gate,MAX_TIMESTAMP,sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW=1700000000
AK,RK=b'A'*32,b'R'*32

class AdministrationValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'state.db';self.store=Store(self.path,create=True)
        self.store.put_device('pump-01','routine','normal',NOW-1,now=NOW)
        self.policy=example_policy()
        self.gate=Gate(self.store,self.policy,agent_keys={'defender':{'v1':AK}},
                       reviewer_keys={'reviewer':{'v1':RK}},clock=lambda:NOW)
        self.gate.activate_configuration()

    def state(self):
        with closing(self.store.connect()) as c:
            high=c.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone()[0]
            return high,c.execute('SELECT count(*) FROM audit').fetchone()[0]

    def test_invalid_admin_clock_cannot_poison_highwater_or_device(self):
        before=self.state();device=self.store.device('pump-01')
        for invalid in (NOW*1000,MAX_TIMESTAMP+1,-1,True,1.5,'1700000000'):
            with self.subTest(now=invalid),self.assertRaisesRegex(ValueError,'invalid context time'):
                self.store.put_device('pump-01','routine','compromised',NOW,now=invalid)
        self.assertEqual(self.state(),before);self.assertEqual(self.store.device('pump-01'),device)
        proposal=sign(make_proposal('good','nonce',NOW,action='inspect'),AK)
        self.assertEqual(self.gate.evaluate(proposal).outcome,'allow')

    def test_invalid_observed_time_does_not_mutate_inventory(self):
        before=self.state();device=self.store.device('pump-01')
        for invalid in (NOW*1000,MAX_TIMESTAMP+1,-1,True,1.5,'1700000000'):
            with self.subTest(observed_at=invalid),self.assertRaisesRegex(ValueError,'invalid context time'):
                self.store.put_device('pump-01','routine','compromised',invalid,now=NOW)
        self.assertEqual(self.state(),before);self.assertEqual(self.store.device('pump-01'),device)

    def test_invalid_device_identifier_is_rejected_before_mutation(self):
        before=self.state()
        for invalid in ('','pump 01','pump/01','pump\n01','\u8bbe\u5907','a'*129,'\ud800',None):
            with self.subTest(device_id=repr(invalid)),self.assertRaisesRegex(ValueError,'invalid device id'):
                self.store.put_device(invalid,'routine','normal',NOW,now=NOW)
        self.assertEqual(self.state(),before)
        with closing(self.store.connect()) as c:self.assertEqual(c.execute('SELECT count(*) FROM devices').fetchone()[0],1)

    def test_valid_identifier_is_usable_end_to_end(self):
        device='pump:region.1-_'
        self.store.put_device(device,'routine','normal',NOW,now=NOW)
        p=example_policy();p['grants']['defender']['inspect'].append(device)
        gate=Gate(self.store,p,agent_keys={'defender':{'v1':AK}},reviewer_keys={'reviewer':{'v1':RK}},clock=lambda:NOW)
        gate.activate_configuration()
        decision=gate.evaluate(sign(make_proposal('r','n',NOW,action='inspect',target=device),AK))
        self.assertEqual(decision.outcome,'allow')
        self.assertTrue(Sandbox(gate).execute('r',agent_id='defender')['executed'])

    def test_future_but_in_range_observation_remains_conservatively_deferred(self):
        self.store.put_device('pump-01','routine','normal',NOW+1,now=NOW)
        result=self.gate.evaluate(sign(make_proposal('r','n',NOW,action='inspect'),AK))
        self.assertEqual((result.outcome,result.code),('defer','invalid_context_time'))

    def test_inclusive_time_boundaries_are_accepted(self):
        path=Path(self.tmp.name)/'bounds.db';s=Store(path,create=True)
        self.assertEqual(s.put_device('pump-01','routine','normal',0,now=0),1)
        self.assertEqual(s.put_device('pump-01','routine','normal',MAX_TIMESTAMP,now=MAX_TIMESTAMP),2)
        gate=Gate(s,example_policy(),agent_keys={'defender':{'v1':AK}},reviewer_keys={'reviewer':{'v1':RK}},clock=lambda:MAX_TIMESTAMP)
        gate.activate_configuration()
        request=sign(make_proposal('r','n',MAX_TIMESTAMP,action='inspect'),AK)
        self.assertEqual(gate.evaluate(request).outcome,'allow')

    def test_direct_clock_check_rejects_invalid_values_without_modification(self):
        before=self.state()
        for invalid in (True,-1,MAX_TIMESTAMP+1,'bad'):
            with self.subTest(value=invalid),self.assertRaisesRegex(ValueError,'invalid trusted clock'):
                with self.store.transaction() as c:Store.check_clock(c,invalid)
        self.assertEqual(self.state(),before)

    def test_invalid_persisted_highwater_rejected_without_repair(self):
        for i,invalid in enumerate((-1,MAX_TIMESTAMP+1,'invalid',1700000000.5)):
            path=Path(self.tmp.name)/f'bad-{i}.db';store=Store(path,create=True)
            store.put_device('pump-01','routine','normal',NOW,now=NOW)
            with sqlite3.connect(path) as c:c.execute("UPDATE metadata SET value=? WHERE key='clock_high_water'",(invalid,))
            with self.subTest(value=invalid),self.assertRaisesRegex(ValueError,'invalid persisted clock high-water mark'):
                Store(path)
            with sqlite3.connect(path) as c:
                self.assertEqual(c.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone()[0],invalid)
                self.assertEqual(c.execute('SELECT count(*) FROM audit').fetchone()[0],1)

    def test_already_open_worker_fails_closed_on_invalid_persisted_highwater(self):
        with sqlite3.connect(self.path) as c:c.execute("UPDATE metadata SET value=? WHERE key='clock_high_water'",(MAX_TIMESTAMP+1,))
        proposal=sign(make_proposal('r','n',NOW,action='inspect'),AK)
        self.assertEqual(self.gate.evaluate(proposal).outcome,'block')
        self.assertFalse(Sandbox(self.gate).execute('r',agent_id='defender')['executed'])
        with self.assertRaisesRegex(ValueError,'invalid persisted clock high-water mark'):Store(self.path)
        with closing(self.store.connect()) as c:
            self.assertEqual(c.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone()[0],MAX_TIMESTAMP+1)

if __name__=='__main__':unittest.main()
