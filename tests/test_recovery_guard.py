"""Recovery checks and explicit negative controls for the optional audit anchor."""
from contextlib import closing
import hashlib
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from edgeguardra.demo import example_policy, make_proposal
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate, sign
from edgeguardra.sandbox import Sandbox
from edgeguardra.store import AuditCheckpointError, Store

NOW = 1700000000
AK, RK, SK = b'A' * 32, b'R' * 32, b'S' * 32


def _guarded_worker(path, checkpoint, barrier, queue):
    try:
        store = Store(path, required_checkpoint=checkpoint)
        gate = Gate(store, example_policy(), agent_keys={'defender': {'v1': AK}},
                    reviewer_keys={'reviewer': {'v1': RK}}, clock=lambda: NOW)
        envelope = sign(make_proposal('parallel', 'parallel-nonce', NOW, action='inspect'), AK)
        barrier.wait(timeout=8)
        queue.put(gate.evaluate(envelope).outcome)
    except BaseException as exc:
        queue.put('error:' + type(exc).__name__)


class RecoveryGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state ? sample.db'
        self.store = Store(self.path, create=True)
        self.store.put_device('pump-01', 'routine', 'normal', NOW-2, now=NOW)
        self.policy = example_policy()
        self.gate = self.make_gate(self.store)
        self.gate.activate_configuration()
        self.sensor = self.make_sensor(self.store)
        self.sensor.activate_configuration()

    def make_gate(self, store):
        return Gate(store, self.policy, agent_keys={'defender': {'v1': AK}},
                    reviewer_keys={'reviewer': {'v1': RK}}, clock=lambda: NOW)

    def make_sensor(self, store):
        return EvidenceIngestor(store, source_keys={'sensor': {'v1': SK}},
                                allowed_devices={'sensor': ['pump-01']}, clock=lambda: NOW)

    def request(self, request_id='test', nonce='nonce'):
        return sign(make_proposal(request_id, nonce, NOW, action='inspect'), AK)

    def backup(self, name):
        path = Path(self.tmp.name) / name
        with closing(self.store.connect()) as src, closing(sqlite3.connect(path)) as dest:
            src.backup(dest)
        return path

    def test_missing_and_empty_databases_are_not_created_or_initialized(self):
        missing = Path(self.tmp.name) / 'missing.db'
        with self.assertRaises(FileNotFoundError): Store(missing)
        self.assertFalse(missing.exists())
        with self.assertRaises(FileNotFoundError): Store(missing, required_checkpoint=self.store.audit_checkpoint())
        self.assertFalse(missing.exists())
        empty = Path(self.tmp.name) / 'empty.db'
        empty.touch()
        with self.assertRaisesRegex(ValueError, 'uninitialized'): Store(empty)
        self.assertEqual(empty.stat().st_size, 0)

    def test_explicit_creation_is_exclusive(self):
        checkpoint = self.store.audit_checkpoint()
        with self.assertRaises(FileExistsError): Store(self.path, create=True)
        self.assertTrue(self.store.verify_audit(checkpoint=checkpoint)['valid'])
        fresh = Path(self.tmp.name) / 'fresh.db'
        with self.assertRaises(ValueError): Store(fresh, create=True, required_checkpoint=checkpoint)
        self.assertFalse(fresh.exists())

    def test_deleted_database_is_not_recreated_by_existing_worker(self):
        self.path.rename(Path(self.tmp.name) / 'moved.db')
        decision = self.gate.evaluate(self.request())
        self.assertEqual(decision.outcome, 'block')
        self.assertFalse(self.path.exists())
        self.assertFalse(Sandbox(self.gate).execute('test', agent_id='defender')['executed'])
        self.assertFalse(self.path.exists())

    def test_old_backup_is_rejected_by_recent_checkpoint(self):
        old = self.backup('old.db')
        self.assertEqual(self.gate.evaluate(self.request()).outcome, 'allow')
        cp = self.store.audit_checkpoint()
        with self.assertRaises(AuditCheckpointError): Store(old, required_checkpoint=cp)
        current = Store(self.path, required_checkpoint=cp)
        self.assertEqual(self.make_gate(current).evaluate(self.request()).outcome, 'block')
        # Negative control: a caller who omits the independent anchor still permits replay.
        self.assertEqual(self.make_gate(Store(old)).evaluate(self.request()).outcome, 'allow')

    def test_rollback_after_open_is_rejected_in_transaction(self):
        old = self.backup('old.db')
        self.assertEqual(self.gate.evaluate(self.request()).outcome, 'allow')
        cp = self.store.audit_checkpoint()
        guarded = Store(self.path, required_checkpoint=cp)
        guarded_gate = self.make_gate(guarded)
        os.replace(old, self.path)
        self.assertEqual(guarded_gate.evaluate(self.request('new', 'new')).outcome, 'block')
        with self.assertRaises(AuditCheckpointError): guarded.device('pump-01')

    def test_explicit_older_checkpoint_cannot_override_required_checkpoint(self):
        older = self.store.audit_checkpoint()
        old_file = self.backup('older.db')
        self.store.put_device('pump-01','routine','normal',NOW-1,now=NOW)
        newer = self.store.audit_checkpoint()
        guarded = Store(self.path, required_checkpoint=newer)
        # On an intact database both independent prefixes must validate.
        result = guarded.verify_audit(checkpoint=older)
        self.assertTrue(result['valid'])
        self.assertEqual(result['anchored_through'],older['seq'])
        intact_result=result
        os.replace(old_file,self.path)
        # The older prefix is valid in this restored backup, but the required
        # newer prefix is absent, and must not be silently overridden.
        self.assertTrue(Store(self.path).verify_audit(checkpoint=older)['valid'])
        result=guarded.verify_audit(checkpoint=older)
        self.assertFalse(result['valid'])
        self.assertEqual(result['code'],'required_checkpoint_failed')
        self.assertEqual(result['required_checkpoint_code'],'checkpoint_missing')
        self.assertEqual(intact_result['required_anchored_through'],newer['seq'])
        self.assertFalse(guarded.verify_audit(expected_head=older['hash'],checkpoint=older)['valid'])

    def test_two_checkpoint_checks_share_one_snapshot(self):
        older=self.store.audit_checkpoint()
        self.store.put_device('pump-01','routine','normal',NOW-1,now=NOW)
        newer=self.store.audit_checkpoint()
        guarded=Store(self.path,required_checkpoint=newer)
        bad=dict(older);bad['hash']='0'*64
        self.assertEqual(guarded.verify_audit(checkpoint=bad)['code'],'checkpoint_hash_mismatch')
        self.assertTrue(guarded.verify_audit(expected_head=newer['hash'],checkpoint=older)['valid'])
        self.assertFalse(guarded.verify_audit(expected_head='0'*64,checkpoint=older)['valid'])
        with closing(self.store.connect()) as c:
            self.assertEqual(c.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower(),'wal')
        original=Store._verify_audit_connection
        changed=[]
        def verify_and_write(connection, expected_head=None, *, checkpoint=None):
            result=original(connection,expected_head,checkpoint=checkpoint)
            if checkpoint == newer and not changed:
                with sqlite3.connect(self.path) as writer:
                    writer.execute("UPDATE audit SET body='{}' WHERE seq=?",(newer['seq'],))
                changed.append(True)
            return result
        with patch.object(Store,'_verify_audit_connection',side_effect=verify_and_write):
            self.assertTrue(guarded.verify_audit(checkpoint=older)['valid'])
        self.assertTrue(changed)
        self.assertFalse(guarded.verify_audit()['valid'])

    def test_checkpoint_is_copied_and_valid_after_append(self):
        cp = self.store.audit_checkpoint()
        old_seq = cp['seq']
        guarded = Store(self.path, required_checkpoint=cp)
        cp['hash'] = '0' * 64
        self.assertIsNotNone(guarded.device('pump-01'))
        guarded.put_device('pump-01', 'routine', 'normal', NOW-1, now=NOW)
        checked = guarded.verify_audit()
        self.assertTrue(checked['valid'])
        self.assertEqual(checked['anchored_through'], old_seq)
        new_cp = guarded.audit_checkpoint()
        self.assertGreater(new_cp['seq'], old_seq)
        self.assertIsNotNone(Store(self.path, required_checkpoint=new_cp).device('pump-01'))

    @unittest.skipUnless('fork' in multiprocessing.get_all_start_methods(), 'requires POSIX fork')
    def test_guarded_processes_still_share_replay_state(self):
        ctx=multiprocessing.get_context('fork')
        barrier, queue = ctx.Barrier(2), ctx.Queue()
        cp=self.store.audit_checkpoint()
        workers=[ctx.Process(target=_guarded_worker,args=(str(self.path),cp,barrier,queue)) for _ in range(2)]
        for worker in workers: worker.start()
        for worker in workers: worker.join(timeout=12)
        self.assertTrue(all(worker.exitcode == 0 for worker in workers))
        self.assertCountEqual([queue.get(timeout=2),queue.get(timeout=2)],['allow','block'])

    def test_corrupt_anchor_fails_all_guarded_stateful_paths(self):
        self.assertEqual(self.gate.evaluate(self.request()).outcome, 'allow')
        cp = self.store.audit_checkpoint()
        guarded = Store(self.path, required_checkpoint=cp)
        gate, sensor = self.make_gate(guarded), self.make_sensor(guarded)
        with sqlite3.connect(self.path) as raw:
            raw.execute("UPDATE audit SET body='{}' WHERE seq=1")
        self.assertEqual(gate.evaluate(self.request('other', 'other')).outcome, 'block')
        self.assertFalse(Sandbox(gate).execute('test', agent_id='defender')['executed'])
        evidence = {'source_id':'sensor', 'key_id':'v1', 'device_id':'pump-01', 'signal':'normal',
                    'observed_at':NOW-1, 'issued_at':NOW, 'nonce':'sensor-nonce'}
        self.assertFalse(sensor.ingest(sign(evidence, SK))['accepted'])
        with self.assertRaises(AuditCheckpointError): guarded.device('pump-01')
        with self.assertRaises(ValueError): guarded.audit_checkpoint()
        with self.assertRaises(AuditCheckpointError): Store(self.path, required_checkpoint=cp)

    def test_checkpoint_does_not_protect_rewritten_unanchored_suffix(self):
        cp = self.store.audit_checkpoint()
        guarded = Store(self.path, required_checkpoint=cp)
        guarded.put_device('pump-01', 'routine', 'normal', NOW-1, now=NOW)
        with sqlite3.connect(self.path) as raw:
            seq, previous = raw.execute('SELECT seq,prev_hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
            body = '{"event":"rewritten suffix"}'
            digest = hashlib.sha256(previous.encode('ascii')+b'\x00'+body.encode('ascii')).hexdigest()
            raw.execute('UPDATE audit SET body=?,entry_hash=? WHERE seq=?', (body,digest,seq))
        self.assertTrue(guarded.verify_audit()['valid'])
        self.assertEqual(guarded.verify_audit()['anchored_through'],cp['seq'])

    def test_checkpoint_does_not_attest_other_state_tables(self):
        envelope = self.request()
        self.assertEqual(self.gate.evaluate(envelope).outcome, 'allow')
        cp = self.store.audit_checkpoint()
        guarded = Store(self.path, required_checkpoint=cp)
        gate = self.make_gate(guarded)
        # This models a trusted-boundary violation, not a network attack.
        with sqlite3.connect(self.path) as raw:
            raw.execute('DELETE FROM nonces')
            raw.execute('DELETE FROM decisions')
        self.assertTrue(guarded.verify_audit()['valid'])
        self.assertEqual(gate.evaluate(envelope).outcome, 'allow')


if __name__ == '__main__': unittest.main()
