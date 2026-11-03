"""A lost high-water mark must not silently reinitialize a populated store."""
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from edgeguardra.demo import example_policy, make_approval, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import Store

NOW = 1_700_000_000
AGENT, REVIEWER, SOURCE = b'A' * 32, b'R' * 32, b'S' * 32


class MissingClockStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state.db'
        self.store = Store(self.path, create=True)
        self.now = NOW
        self.store.put_device('pump-01', 'routine', 'normal', NOW-10, now=NOW)
        self.store.put_device('plc-01', 'critical', 'compromised', NOW-10, now=NOW)
        self.gate = Gate(self.store, example_policy(),
                         agent_keys={'defender': {'v1': AGENT}},
                         reviewer_keys={'reviewer': {'v1': REVIEWER}}, clock=lambda: self.now)
        self.gate.activate_configuration()
        self.sensor = EvidenceIngestor(self.store, source_keys={'sensor': {'v1': SOURCE}},
                                       allowed_devices={'sensor': ['pump-01']}, clock=lambda: self.now)
        self.sensor.activate_configuration()

    def delete_mark(self):
        # Models accidental state loss or a partial restore outside the trusted DB boundary.
        with sqlite3.connect(self.path) as raw:
            raw.execute("DELETE FROM metadata WHERE key='clock_high_water'")

    def test_missing_mark_cannot_make_old_request_fresh_after_rollback(self):
        delayed = sign(make_proposal('delayed', 'delayed-nonce', NOW, action='inspect'), AGENT)
        self.now = NOW + 200
        advance = sign(make_proposal('advance', 'advance-nonce', self.now, action='inspect'), AGENT)
        self.assertEqual(self.gate.evaluate(advance).outcome, 'allow')
        self.delete_mark()
        with self.assertRaisesRegex(ValueError, 'missing persisted clock high-water mark'):
            Store(self.path)
        self.now = NOW
        self.assertEqual(self.gate.evaluate(delayed).outcome, 'block')
        with sqlite3.connect(self.path) as raw:
            self.assertIsNone(raw.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone())
            self.assertIsNone(raw.execute("SELECT 1 FROM decisions WHERE request_id='delayed'").fetchone())

    def test_open_workers_and_guarded_workers_fail_closed_without_mutation(self):
        pending = self.gate.evaluate(sign(make_proposal('critical', 'pending-nonce', NOW,
                                                        target='plc-01'), AGENT))
        allowed = self.gate.evaluate(sign(make_proposal('routine', 'routine-nonce', NOW,
                                                        action='inspect'), AGENT))
        self.assertEqual(pending.code, 'review_required')
        self.assertEqual(allowed.outcome, 'allow')
        checkpoint = self.store.audit_checkpoint()
        guarded = Store(self.path, required_checkpoint=checkpoint)
        guarded_gate = Gate(guarded, example_policy(), agent_keys={'defender': {'v1': AGENT}},
                            reviewer_keys={'reviewer': {'v1': REVIEWER}}, clock=lambda: self.now)
        evidence = {'source_id': 'sensor', 'key_id': 'v1', 'device_id': 'pump-01',
                    'signal': 'compromised', 'observed_at': NOW-1, 'issued_at': NOW, 'nonce': 'sensor-nonce'}
        approval = sign(make_approval(pending, 'review-nonce', NOW), REVIEWER)
        with sqlite3.connect(self.path) as raw:
            count = raw.execute('SELECT count(*) FROM audit').fetchone()[0]
        before = self.store.device('pump-01')
        self.delete_mark()
        self.assertEqual(self.gate.approve(approval).outcome, 'block')
        self.assertFalse(self.sensor.ingest(sign(evidence, SOURCE))['accepted'])
        self.assertFalse(Sandbox(guarded_gate).execute('routine', agent_id='defender')['executed'])
        with self.assertRaisesRegex(ValueError, 'missing persisted clock high-water mark'):
            self.gate.activate_configuration()
        with self.assertRaisesRegex(ValueError, 'missing persisted clock high-water mark'):
            self.store.put_device('pump-01', 'routine', 'normal', NOW, now=NOW)
        with sqlite3.connect(self.path) as raw:
            self.assertEqual(raw.execute('SELECT count(*) FROM audit').fetchone()[0], count)
            self.assertEqual(raw.execute("SELECT status FROM decisions WHERE request_id='critical'").fetchone()[0], 'pending')
            self.assertEqual(raw.execute("SELECT status FROM decisions WHERE request_id='routine'").fetchone()[0], 'allowed')
        self.assertEqual(self.store.device('pump-01'), before)

    def test_empty_database_can_reopen_and_initialize_normally(self):
        path = Path(self.tmp.name) / 'empty.db'
        Store(path, create=True)
        reopened = Store(path)
        with sqlite3.connect(path) as raw:
            self.assertIsNone(raw.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone())
        self.assertEqual(reopened.put_device('fresh-01', 'routine', 'normal', NOW, now=NOW), 1)
        self.assertIsNotNone(Store(path).device('fresh-01'))

    def test_inventory_detects_missing_mark_even_if_audit_is_also_missing(self):
        self.delete_mark()
        with sqlite3.connect(self.path) as raw:
            raw.execute('DELETE FROM audit')
        with self.assertRaisesRegex(ValueError, 'missing persisted clock high-water mark'):
            Store(self.path)

    def test_single_retained_state_table_prevents_false_fresh_initialization(self):
        inserts = [
            ("INSERT INTO devices(device_id,criticality,signal,observed_at,version) VALUES('d','routine','normal',?,1)", (NOW,)),
            ("INSERT INTO nonces(kind,principal,nonce,expires_at) VALUES('proposal','agent','n',?)", (NOW,)),
            ("INSERT INTO decisions(request_id,agent_id,key_id,key_binding,target,action,request_hash,policy_hash,configuration_epoch,context_version,outcome,code,status,expires_at,created_at) VALUES('r','a','k','b','d','inspect','h','p',1,1,'allow','x','allowed',?,?)", (NOW, NOW)),
            ("INSERT INTO audit(body,prev_hash,entry_hash) VALUES('{}','a','b')", ()),
            ("INSERT INTO metadata(key,value) VALUES('generation_gate',1)", ()),
            ("INSERT INTO metadata_text(key,value) VALUES('active_gate_configuration','x')", ()),
            ("INSERT INTO configuration_keys(kind,owner,key_id,fingerprint) VALUES('gate','agent:a','v1',?)", ('a'*64,)),
        ]
        for i, (sql, params) in enumerate(inserts):
            path = Path(self.tmp.name) / f'isolated-{i}.db'
            Store(path, create=True)
            with sqlite3.connect(path) as raw:
                raw.execute(sql, params)
            with self.subTest(table=i), self.assertRaisesRegex(ValueError, 'missing persisted clock high-water mark'):
                Store(path)


if __name__ == '__main__':
    unittest.main()
