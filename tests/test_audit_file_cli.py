"""Read-only file verification must expose its scope and honor both anchors."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from edgeguardra.store import Store

NOW = 1_700_000_000


class AuditFileCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'state ? # %.db'
        self.store = Store(self.path, create=True)
        self.store.put_device('pump-01', 'routine', 'normal', NOW-2, now=NOW)

    def cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'edgeguardra', 'verify-audit',
                               str(self.path), *map(str, args)],
                              capture_output=True, text=True, timeout=10)

    def checkpoint_file(self):
        path = self.root / 'checkpoint.json'
        path.write_text(json.dumps(self.store.audit_checkpoint()))
        return path

    def digest(self):
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def backup(self, name):
        path = self.root / name
        with closing(self.store.connect()) as source, closing(sqlite3.connect(path)) as destination:
            source.backup(destination)
        return path

    def test_unanchored_read_does_not_construct_store_or_change_database(self):
        before = self.digest()
        with patch.object(Store, '__init__', side_effect=AssertionError('must not open application Store')):
            result = Store.verify_audit_file(self.path)
        self.assertTrue(result['valid'])
        self.assertFalse(result['anchored'])
        self.assertEqual(result['scope'], 'audit_chain_only')
        self.assertEqual(result['head'], self.store.audit_head())
        self.assertEqual(self.digest(), before)

    def test_checkpoint_prefix_and_exact_head_are_both_checked(self):
        checkpoint = self.store.audit_checkpoint()
        self.store.put_device('pump-01', 'routine', 'normal', NOW-1, now=NOW)
        head = self.store.audit_head()
        result = Store.verify_audit_file(self.path, head, checkpoint=checkpoint)
        self.assertTrue(result['valid'])
        self.assertTrue(result['anchored'])
        self.assertEqual(result['anchored_through'], checkpoint['seq'])
        self.assertFalse(Store.verify_audit_file(self.path, checkpoint['hash'], checkpoint=checkpoint)['valid'])
        wrong = {**checkpoint, 'hash': '0'*64}
        self.assertEqual(Store.verify_audit_file(self.path, head, checkpoint=wrong)['code'], 'checkpoint_hash_mismatch')

    def test_missing_prefix_and_different_database_are_rejected(self):
        old = self.backup('old.db')
        self.store.put_device('pump-01', 'routine', 'normal', NOW-1, now=NOW)
        checkpoint = self.store.audit_checkpoint()
        self.assertEqual(Store.verify_audit_file(old, checkpoint=checkpoint)['code'], 'checkpoint_missing')
        # Without a recent independent anchor, this old but consistent chain
        # remains valid. File verification cannot infer missing recent history.
        self.assertTrue(Store.verify_audit_file(old)['valid'])
        other_path = self.root / 'other.db'
        other = Store(other_path, create=True)
        other.put_device('pump-01', 'routine', 'normal', NOW-1, now=NOW)
        self.assertEqual(Store.verify_audit_file(other_path, checkpoint=checkpoint)['code'], 'checkpoint_database_mismatch')

    def test_changed_audit_body_fails_without_repairing_the_file(self):
        with sqlite3.connect(self.path) as writer:
            writer.execute("UPDATE audit SET body='{}' WHERE seq=1")
        before = self.digest()
        result = Store.verify_audit_file(self.path)
        self.assertFalse(result['valid'])
        self.assertEqual(result['code'], 'audit_hash_mismatch')
        self.assertEqual(self.digest(), before)

    def test_missing_empty_and_unsupported_files_are_not_initialized(self):
        missing = self.root / 'missing.db'
        self.assertFalse(Store.verify_audit_file(missing)['valid'])
        self.assertFalse(missing.exists())
        empty = self.root / 'empty.db'
        empty.touch()
        self.assertEqual(Store.verify_audit_file(empty)['code'], 'unsupported_database_schema')
        self.assertEqual(empty.stat().st_size, 0)
        unsupported = self.root / 'unsupported.db'
        with sqlite3.connect(unsupported) as writer:
            writer.execute('PRAGMA user_version=4')
        before = unsupported.read_bytes()
        self.assertEqual(Store.verify_audit_file(unsupported)['code'], 'unsupported_database_schema')
        self.assertEqual(unsupported.read_bytes(), before)

    def test_empty_initialized_audit_is_consistent_but_unanchored(self):
        path = self.root / 'fresh.db'
        Store(path, create=True)
        result = Store.verify_audit_file(path)
        self.assertEqual((result['valid'], result['anchored'], result['entries']), (True, False, 0))
        self.assertEqual(len(result['head']), 64)

    def test_read_only_connection_refuses_an_injected_write(self):
        before = self.digest()
        def attempt_write(connection, *args, **kwargs):
            connection.execute('CREATE TABLE write_probe(value TEXT)')
            raise AssertionError('write unexpectedly succeeded')
        with patch.object(Store, '_verify_audit_connection', side_effect=attempt_write):
            result = Store.verify_audit_file(self.path)
        self.assertFalse(result['valid'])
        self.assertEqual(self.digest(), before)

    def test_read_can_run_while_an_application_writer_holds_reserved_lock(self):
        with self.store.transaction():
            result = Store.verify_audit_file(self.path)
        self.assertTrue(result['valid'])

    def test_checkpoint_and_head_use_one_wal_snapshot(self):
        checkpoint = self.store.audit_checkpoint()
        head = self.store.audit_head()
        with closing(self.store.connect()) as connection:
            self.assertEqual(connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower(), 'wal')
        original = Store._verify_audit_connection
        changed = []
        def write_after_snapshot(connection, expected_head=None, *, checkpoint=None):
            with sqlite3.connect(self.path) as writer:
                writer.execute("UPDATE audit SET body='{}' WHERE seq=1")
            changed.append(True)
            return original(connection, expected_head, checkpoint=checkpoint)
        with patch.object(Store, '_verify_audit_connection', side_effect=write_after_snapshot):
            result = Store.verify_audit_file(self.path, head, checkpoint=checkpoint)
        self.assertTrue(changed)
        self.assertTrue(result['valid'])
        self.assertFalse(Store.verify_audit_file(self.path)['valid'])

    def test_cli_emits_json_and_verifies_checkpoint_and_head(self):
        before = self.digest()
        unanchored = self.cli()
        self.assertEqual(unanchored.returncode, 0, unanchored.stderr)
        self.assertFalse(json.loads(unanchored.stdout)['anchored'])
        result = self.cli('--checkpoint', self.checkpoint_file(), '--expected-head', self.store.audit_head())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['anchored'])
        self.assertEqual(json.loads(result.stdout)['scope'], 'audit_chain_only')
        self.assertEqual(self.digest(), before)

    def test_cli_failed_verification_returns_one_without_creating_missing_file(self):
        result = self.cli('--expected-head', '0'*64)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(json.loads(result.stdout)['valid'])
        self.assertEqual(json.loads(result.stdout)['code'], 'expected_head_mismatch')
        self.path.unlink()
        result = self.cli()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(json.loads(result.stdout)['valid'])
        self.assertFalse(self.path.exists())

    def test_cli_explicit_invalid_checkpoint_never_downgrades_to_unanchored(self):
        file = self.root / 'bad.json'
        before = self.digest()
        for raw in ('null', '[]', '{}', '{bad', '{"seq":1,"seq":2}', ' '*65537):
            with self.subTest(raw=raw[:30]):
                file.write_text(raw)
                result = self.cli('--checkpoint', file)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(self.digest(), before)

    def test_invalid_api_anchors_do_not_report_validity(self):
        for checkpoint in ({}, [], {'audit_id': '0'*32, 'seq': True, 'hash': '0'*64}):
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(Store.verify_audit_file(self.path, checkpoint=checkpoint)['code'], 'invalid_checkpoint')
        for head in (True, 1, 'A'*64, 'short'):
            with self.subTest(head=head):
                self.assertEqual(Store.verify_audit_file(self.path, head)['code'], 'invalid_expected_head')

    def test_valid_chain_does_not_attest_inventory_state(self):
        checkpoint = self.store.audit_checkpoint()
        # This fixture deliberately changes trusted local state. The verifier
        # promises only audit-chain verification, not protection from DB writers.
        with sqlite3.connect(self.path) as writer:
            writer.execute("UPDATE devices SET signal='compromised' WHERE device_id='pump-01'")
        result = Store.verify_audit_file(self.path, checkpoint=checkpoint)
        self.assertTrue(result['valid'])
        self.assertEqual(result['scope'], 'audit_chain_only')


if __name__ == '__main__':
    unittest.main()
