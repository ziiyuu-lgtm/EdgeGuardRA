"""Reject incomplete uniqueness constraints in a structurally altered database."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from edgeguardra.demo import example_policy
from edgeguardra.evidence import EvidenceIngestor
from edgeguardra.gate import Gate
from edgeguardra.store import Store

NOW=1700000000


class SchemaConstraintTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'db';Store(self.path,create=True)

    def replace_key_table(self,*,full):
        with sqlite3.connect(self.path) as c:
            c.execute('DROP TABLE configuration_keys')
            c.execute('CREATE TABLE configuration_keys (kind TEXT NOT NULL, owner TEXT NOT NULL, '
                      'key_id TEXT NOT NULL, fingerprint TEXT NOT NULL, PRIMARY KEY(kind,owner,key_id))')
            c.execute("CREATE UNIQUE INDEX partial_fingerprint ON configuration_keys(fingerprint) WHERE kind='gate'")
            if full:c.execute('CREATE UNIQUE INDEX full_fingerprint ON configuration_keys(fingerprint)')

    def test_partial_unique_index_does_not_satisfy_cross_role_constraint(self):
        self.replace_key_table(full=False)
        with self.assertRaisesRegex(ValueError,'configuration-key schema'):Store(self.path)

    def test_full_unique_index_prevents_cross_role_key_reuse(self):
        self.replace_key_table(full=True)
        store=Store(self.path)
        gate=Gate(store,example_policy(),agent_keys={'defender':{'v1':b'A'*32}},
                  reviewer_keys={'reviewer':{'v1':b'R'*32}},clock=lambda:NOW)
        gate.activate_configuration()
        source=EvidenceIngestor(store,source_keys={'sensor':{'v1':b'A'*32}},
                                allowed_devices={'sensor':['pump-01']},clock=lambda:NOW)
        with self.assertRaisesRegex(ValueError,'secret reused'):source.activate_configuration()
        self.assertIsNone(store.active_configuration('evidence'))


if __name__=='__main__':unittest.main()
