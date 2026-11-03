"""SQLite state for a trusted local research sandbox.

This is not a secure multi-host service. The database directory and process
must be controlled by the experiment operator. Multiple local processes must
point at the same supported local SQLite database for nonce uniqueness.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
import hmac
import json
import os
import re
import secrets
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterator
from .validation import NONCE_RETENTION_MARGIN, is_identifier, is_timestamp


def _audit_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _validated_checkpoint(value: Any) -> dict[str, Any] | None:
    """Detach and validate a checkpoint without trusting overridden equality."""
    if not isinstance(value, dict):
        return None
    try:
        checkpoint = dict(value)
    except (RuntimeError, TypeError, ValueError):
        return None
    if any(type(key) is not str for key in checkpoint) or set(checkpoint) != {'audit_id', 'seq', 'hash'}:
        return None
    audit_id, seq, digest = checkpoint['audit_id'], checkpoint['seq'], checkpoint['hash']
    if not isinstance(audit_id, str) or not isinstance(digest, str) or type(seq) is not int or seq < 1:
        return None
    audit_id, digest = str.__str__(audit_id), str.__str__(digest)
    if not re.fullmatch(r'[0-9a-f]{32}', audit_id) or not re.fullmatch(r'[0-9a-f]{64}', digest):
        return None
    return {'audit_id': audit_id, 'seq': seq, 'hash': digest}


class AuditCheckpointError(ValueError):
    """A required independently retained audit checkpoint did not verify."""


class StoreIdentityError(ValueError):
    """An existing Store encountered a different database audit identity."""


class Store:
    def __init__(self, path: str | Path, *, create: bool = False,
                 required_checkpoint: dict[str, Any] | None = None):
        if str(path) == ":memory:":
            raise ValueError("a persistent file is required for shared state")
        if type(create) is not bool:
            raise ValueError('create must be a boolean')
        if create and required_checkpoint is not None:
            raise ValueError('a new store cannot already have a checkpoint')
        self.path = str(Path(path).absolute())
        self._required_checkpoint = None
        self._audit_identity = None
        parent = Path(self.path).resolve().parent
        if not parent.is_dir():
            raise ValueError("database parent directory must exist")
        if create:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        elif not Path(self.path).is_file():
            raise FileNotFoundError('database does not exist; use create=True for a new database')
        # Initialization is serialized; prior database schemas require migration.
        with self.transaction() as c:
            version = c.execute('PRAGMA user_version').fetchone()[0]
            tables = {row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if version == 0 and tables:
                raise ValueError('unsupported earlier database schema; migration is required')
            if version not in (0, 5):
                raise ValueError('unsupported database schema version; migration is required')
            if version == 5:
                required={'devices','nonces','metadata','metadata_text','decisions','audit','configuration_keys'}
                if not required.issubset(tables):
                    raise ValueError('incomplete database schema; state must not be recreated silently')
                decision_cols={row['name'] for row in c.execute('PRAGMA table_info(decisions)')}
                decision_pk=sorted((row['pk'],row['name']) for row in c.execute('PRAGMA table_info(decisions)') if row['pk'])
                device_cols={row['name'] for row in c.execute('PRAGMA table_info(devices)')}
                nonce_pk=sorted((row['pk'],row['name']) for row in c.execute('PRAGMA table_info(nonces)') if row['pk'])
                if (not {'configuration_epoch','review_challenge'}.issubset(decision_cols) or 'evidence_generation' not in device_cols
                    or nonce_pk != [(1,'kind'),(2,'principal'),(3,'nonce')]
                    or decision_pk != [(1,'agent_id'),(2,'request_id')]):
                    raise ValueError('invalid database schema')
                unique_fingerprint=False
                for idx in c.execute('PRAGMA index_list(configuration_keys)').fetchall():
                    # A partial unique index cannot enforce cross-role
                    # uniqueness outside its WHERE predicate.
                    if idx['unique'] and not idx['partial']:
                        quoted='"'+idx['name'].replace('"','""')+'"'
                        columns=[item['name'] for item in c.execute('PRAGMA index_info('+quoted+')')]
                        unique_fingerprint |= columns == ['fingerprint']
                if not unique_fingerprint:
                    raise ValueError('invalid configuration-key schema')
                audit_identity, _ = self._audit_genesis(c)
                self._clock_high_water(c)
                if required_checkpoint is not None:
                    candidate=_validated_checkpoint(required_checkpoint)
                    if candidate is None:
                        raise AuditCheckpointError('invalid required audit checkpoint')
                    result=self._verify_audit_connection(c,checkpoint=candidate)
                    if not result['valid']:
                        raise AuditCheckpointError('required audit checkpoint failed: '+result.get('code','invalid'))
                    self._required_checkpoint=candidate
                self._audit_identity = audit_identity
                return
            if not create:
                raise ValueError('uninitialized database; use create=True on a new path')
            statements = ("""CREATE TABLE IF NOT EXISTS devices (
              device_id TEXT PRIMARY KEY,
              criticality TEXT NOT NULL CHECK(criticality IN ('routine','critical')),
              signal TEXT NOT NULL CHECK(signal IN ('normal','compromised','unknown')),
              observed_at INTEGER NOT NULL, version INTEGER NOT NULL,
              source_id TEXT NOT NULL DEFAULT 'operator', evidence_hash TEXT NOT NULL DEFAULT '',
              evidence_generation INTEGER NOT NULL DEFAULT 0,
              quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0,1))
            )""", """CREATE TABLE IF NOT EXISTS nonces (
              kind TEXT NOT NULL, principal TEXT NOT NULL, nonce TEXT NOT NULL,
              expires_at INTEGER NOT NULL, PRIMARY KEY(kind,principal,nonce)
            )""", """CREATE TABLE IF NOT EXISTS metadata (
              key TEXT PRIMARY KEY, value INTEGER NOT NULL
            )""", """CREATE TABLE IF NOT EXISTS metadata_text (
              key TEXT PRIMARY KEY, value TEXT NOT NULL
            )""", """CREATE TABLE IF NOT EXISTS decisions (
              request_id TEXT NOT NULL, agent_id TEXT NOT NULL, key_id TEXT NOT NULL,
              key_binding TEXT NOT NULL, target TEXT NOT NULL,
              action TEXT NOT NULL, request_hash TEXT NOT NULL, policy_hash TEXT NOT NULL,
              configuration_epoch INTEGER NOT NULL, context_version INTEGER NOT NULL, outcome TEXT NOT NULL, code TEXT NOT NULL,
              status TEXT NOT NULL, expires_at INTEGER NOT NULL, risk INTEGER,
              reviewer_id TEXT, reviewer_key_id TEXT, reviewer_binding TEXT, review_challenge TEXT, created_at INTEGER NOT NULL,
              PRIMARY KEY(agent_id,request_id)
            )""", """CREATE TABLE IF NOT EXISTS audit (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL,
              prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
            )""", """CREATE TABLE IF NOT EXISTS configuration_keys (
              kind TEXT NOT NULL, owner TEXT NOT NULL, key_id TEXT NOT NULL,
              fingerprint TEXT NOT NULL UNIQUE, PRIMARY KEY(kind,owner,key_id)
            )""")
            for statement in statements:
                c.execute(statement)
            c.execute("INSERT INTO metadata_text(key,value) VALUES('audit_id',?)",(secrets.token_hex(16),))
            c.execute('PRAGMA user_version=5')
            self._audit_identity = self._audit_genesis(c)[0]

    def connect(self) -> sqlite3.Connection:
        # mode=rw never silently recreates a database deleted after initialization.
        uri=Path(self.path).resolve().as_uri()+'?mode=rw'
        c = sqlite3.connect(uri, uri=True, timeout=3.0, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=3000")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA synchronous=FULL")
        return c

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        c = self.connect()
        try:
            c.execute("BEGIN IMMEDIATE")
            self._enforce_checkpoint(c)
            yield c
            c.execute("COMMIT")
        except BaseException:
            if c.in_transaction:
                c.execute("ROLLBACK")
            raise
        finally:
            c.close()

    @contextmanager
    def read_transaction(self) -> Iterator[sqlite3.Connection]:
        c=self.connect()
        try:
            c.execute('BEGIN')
            self._enforce_checkpoint(c)
            yield c
            c.execute('COMMIT')
        except BaseException:
            if c.in_transaction:c.execute('ROLLBACK')
            raise
        finally:
            c.close()

    def _enforce_checkpoint(self, c: sqlite3.Connection) -> None:
        self._enforce_identity(c)
        if self._required_checkpoint is not None:
            result=self._verify_audit_connection(c,checkpoint=self._required_checkpoint)
            if not result['valid']:
                raise AuditCheckpointError('required audit checkpoint failed: '+result.get('code','invalid'))

    def _enforce_identity(self, c: sqlite3.Connection) -> None:
        # The identity is pinned only for this Store's lifetime. A same-ID
        # snapshot can still be stale; independent recovery evidence is needed.
        if self._audit_identity is not None:
            actual = self._audit_genesis(c)[0]
            if not hmac.compare_digest(actual, self._audit_identity):
                raise StoreIdentityError('database identity changed; stop workers and assess recovery')

    @staticmethod
    def _clock_high_water(c: sqlite3.Connection) -> int | None:
        """Distinguish a new empty store from state with a lost clock mark."""
        row = c.execute("SELECT value FROM metadata WHERE key='clock_high_water'").fetchone()
        if row is None:
            # Every supported persistent state change records the clock first.
            # A missing mark alongside other state is therefore not a fresh DB.
            has_state = c.execute("""SELECT
                EXISTS(SELECT 1 FROM devices LIMIT 1) OR
                EXISTS(SELECT 1 FROM nonces LIMIT 1) OR
                EXISTS(SELECT 1 FROM decisions LIMIT 1) OR
                EXISTS(SELECT 1 FROM audit LIMIT 1) OR
                EXISTS(SELECT 1 FROM configuration_keys LIMIT 1) OR
                EXISTS(SELECT 1 FROM metadata LIMIT 1) OR
                EXISTS(SELECT 1 FROM metadata_text WHERE key != 'audit_id' LIMIT 1)
            """).fetchone()[0]
            if has_state:
                raise ValueError('missing persisted clock high-water mark; recovery required')
            return None
        if not is_timestamp(row['value']):
            raise ValueError('invalid persisted clock high-water mark; recovery required')
        return row['value']

    @staticmethod
    def check_clock(c: sqlite3.Connection, now: int) -> bool:
        """Fail closed on a missing, invalid, or rolled-back clock mark."""
        if not is_timestamp(now):
            raise ValueError('invalid trusted clock')
        previous = Store._clock_high_water(c)
        if previous is not None and now < previous:
            return False
        c.execute("INSERT INTO metadata(key,value) VALUES('clock_high_water',?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (now,))
        return True

    @staticmethod
    def prune_nonces(c: sqlite3.Connection, now: int) -> None:
        """Retain nonce records across any supported later validity window."""
        if not is_timestamp(now):
            raise ValueError('invalid trusted clock')
        c.execute('DELETE FROM nonces WHERE expires_at < ?', (now - NONCE_RETENTION_MARGIN,))

    @staticmethod
    def _audit_genesis(c: sqlite3.Connection) -> tuple[str,str]:
        row=c.execute("SELECT value FROM metadata_text WHERE key='audit_id'").fetchone()
        if row is None or not isinstance(row['value'],str) or not re.fullmatch(r'[0-9a-f]{32}',row['value']):
            raise ValueError('missing or invalid audit identity')
        audit_id=row['value']
        genesis=hashlib.sha256(b'edgeguardra-audit-v050\x00'+bytes.fromhex(audit_id)).hexdigest()
        return audit_id,genesis

    @staticmethod
    def append_audit(c: sqlite3.Connection, event: str, details: dict[str, Any], now: int) -> str:
        if type(now) is not int:
            raise ValueError("audit time must be an integer")
        row = c.execute("SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row["entry_hash"] if row else Store._audit_genesis(c)[1]
        body = _audit_bytes({"event": event, "details": details, "time": now})
        digest = hashlib.sha256(previous.encode("ascii") + b"\x00" + body).hexdigest()
        c.execute("INSERT INTO audit(body,prev_hash,entry_hash) VALUES(?,?,?)", (body.decode("ascii"), previous, digest))
        return digest

    def record_denial(self, code: str, now: int) -> bool:
        """Record a denial and its clock observation; false on failure or rollback."""
        return self._record_rejection('denied',code,now)=='recorded'

    def _record_rejection(self, event: str, code: str, before_lock: int,
                          *, clock: Callable[[], int] | None = None) -> str:
        """Persist rejection timing under the same transaction as its audit event."""
        if event not in ('denied','evidence_rejected'):
            return 'state_store_unavailable'
        if not is_timestamp(before_lock):
            return 'invalid_clock'
        try:
            with self.transaction() as c:
                if not self.check_clock(c,before_lock):
                    return 'clock_rollback'
                try:
                    after_lock=clock() if clock is not None else before_lock
                except Exception:
                    # Preserve the valid pre-lock observation even if the
                    # second clock read fails; no audit time is fabricated.
                    return 'invalid_clock'
                if not is_timestamp(after_lock):
                    return 'invalid_clock'
                if not self.check_clock(c,after_lock):
                    return 'clock_rollback'
                self.append_audit(c,event,{'code':code},after_lock)
            return 'recorded'
        except (sqlite3.Error, OSError, ValueError, TypeError, OverflowError):
            return 'state_store_unavailable'

    def activate_configuration(self, digest: str, *, now: int | Callable[[], int], kind: str = 'gate',
                               key_fingerprints: tuple[tuple[str, str, str], ...]) -> int:
        """Trusted operator operation; old process configurations fail closed.

        The database and calling process remain part of the trusted boundary.
        """
        if kind not in ('gate','evidence') or not isinstance(digest,str):
            raise ValueError('invalid configuration digest')
        digest = str.__str__(digest)
        # fromhex accepts ASCII whitespace, so length plus decodability does
        # not establish a 32-byte digest. Reject before observing time or
        # opening a configuration transaction.
        if re.fullmatch(r'[0-9a-fA-F]{64}', digest) is None:
            raise ValueError('invalid configuration digest')
        rejection = None
        with self.transaction() as c:
            now = now() if callable(now) else now
            if not is_timestamp(now):
                raise ValueError('invalid trusted clock')
            if not self.check_clock(c, now):
                raise ValueError('clock rollback')
            # Roll back the attempted registration independently of the valid
            # clock observation. The outer transaction can then commit the
            # watermark and rejection without changing the active config.
            c.execute('SAVEPOINT configuration_update')
            c.execute('DELETE FROM configuration_keys WHERE kind=?', (kind,))
            try:
                c.executemany('INSERT INTO configuration_keys(kind,owner,key_id,fingerprint) VALUES(?,?,?,?)',
                              ((kind,owner,key_id,fingerprint) for owner,key_id,fingerprint in key_fingerprints))
            except sqlite3.IntegrityError as exc:
                c.execute('ROLLBACK TO SAVEPOINT configuration_update')
                c.execute('RELEASE SAVEPOINT configuration_update')
                self.append_audit(c,'configuration_rejected',{'kind':kind,'code':'secret_reuse'},now)
                rejection = exc
            else:
                c.execute('RELEASE SAVEPOINT configuration_update')
                row=c.execute('SELECT value FROM metadata WHERE key=?',('generation_'+kind,)).fetchone()
                generation=(row['value'] if row else 0)+1
                c.execute("INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          ('generation_'+kind,generation))
                c.execute("INSERT INTO metadata_text(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          ('active_'+kind+'_configuration',digest.lower()))
                self.append_audit(c,'configuration_activated',{'kind':kind,'digest':digest.lower(),'generation':generation},now)
                return generation
        # Raising inside the outer transaction would undo the watermark again.
        raise ValueError('secret reused across identities or roles') from rejection

    def active_configuration(self, kind: str = 'gate') -> tuple[str, int] | None:
        with self.read_transaction() as c:
            row=c.execute('SELECT t.value AS digest, m.value AS generation FROM metadata_text t JOIN metadata m ON m.key=? WHERE t.key=?',
                          ('generation_'+kind,'active_'+kind+'_configuration')).fetchone()
            return (row['digest'],row['generation']) if row else None

    @staticmethod
    def configuration_matches(c: sqlite3.Connection, digest: str, generation: int | None, kind: str = 'gate') -> bool:
        row=c.execute('SELECT t.value AS digest, m.value AS generation FROM metadata_text t JOIN metadata m ON m.key=? WHERE t.key=?',
                      ('generation_'+kind,'active_'+kind+'_configuration')).fetchone()
        return row is not None and row['digest']==digest and row['generation']==generation

    @staticmethod
    def active_generation(c: sqlite3.Connection, kind: str) -> int | None:
        row=c.execute('SELECT m.value AS generation FROM metadata_text t JOIN metadata m ON m.key=? WHERE t.key=?',
                      ('generation_'+kind,'active_'+kind+'_configuration')).fetchone()
        return row['generation'] if row else None

    def put_device(self, device_id: str, criticality: str, signal: str, observed_at: int, *, now: int) -> int:
        """Trusted experiment-administrator operation, not a network endpoint."""
        if not is_identifier(device_id):
            raise ValueError("invalid device id")
        if criticality not in ("routine", "critical") or signal not in ("normal", "compromised", "unknown"):
            raise ValueError("invalid device context")
        if not is_timestamp(observed_at) or not is_timestamp(now):
            raise ValueError("invalid context time")
        with self.transaction() as c:
            if not self.check_clock(c, now):
                raise ValueError("clock rollback")
            existing = c.execute("SELECT version,quarantined FROM devices WHERE device_id=?", (device_id,)).fetchone()
            version = (existing["version"] + 1) if existing else 1
            quarantined = existing["quarantined"] if existing else 0
            c.execute("""INSERT INTO devices(device_id,criticality,signal,observed_at,version,quarantined,source_id,evidence_hash,evidence_generation)
                VALUES(?,?,?,?,?,?,'operator','',0) ON CONFLICT(device_id) DO UPDATE SET
                criticality=excluded.criticality, signal=excluded.signal,
                observed_at=excluded.observed_at, version=excluded.version,
                source_id='operator', evidence_hash='', evidence_generation=0""",
                (device_id, criticality, signal, observed_at, version, quarantined))
            self.append_audit(c, "device_context_updated", {"device_id": device_id, "version": version}, now)
            return version

    def device(self, device_id: str) -> dict[str, Any] | None:
        with self.read_transaction() as c:
            row = c.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
            return dict(row) if row else None

    def decision(self, request_id: str, *, agent_id: str) -> dict[str, Any] | None:
        with self.read_transaction() as c:
            row = c.execute("SELECT * FROM decisions WHERE agent_id=? AND request_id=?", (agent_id,request_id)).fetchone()
            return dict(row) if row else None

    def audit_head(self) -> str:
        with self.read_transaction() as c:
            row = c.execute("SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            return row["entry_hash"] if row else self._audit_genesis(c)[1]

    def audit_checkpoint(self) -> dict[str, Any]:
        """Return the last verified nonempty prefix for independent retention."""
        result=self.verify_audit()
        if not result['valid'] or not result['entries']:
            raise ValueError('a valid nonempty audit chain is required')
        return {'audit_id':result['audit_id'],'seq':result['entries'],'hash':result['head']}

    def verify_audit(self, expected_head: str | None = None, *, checkpoint: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate a chain and an optional independently retained prefix checkpoint.

        A checkpoint anchors only the prefix through its sequence. A suffix
        after that point can still be rewritten if no newer anchor is held. A
        caller-supplied checkpoint cannot override this store's required one.
        """
        required=self._required_checkpoint
        try:
            with closing(self.connect()) as c:
                c.execute('BEGIN')
                self._enforce_identity(c)
                # Both anchors must be checked against the same SQLite snapshot.
                # An explicit older anchor is an additional check, not an override.
                if required is not None and checkpoint is not None:
                    pinned=self._verify_audit_connection(c,checkpoint=required)
                    if not pinned['valid']:
                        return {'valid':False,'anchored':False,'entries':pinned['entries'],
                                'code':'required_checkpoint_failed',
                                'required_checkpoint_code':pinned.get('code','invalid')}
                    result=self._verify_audit_connection(c,expected_head=expected_head,checkpoint=checkpoint)
                    if result['valid']:
                        result['required_anchored_through']=required['seq']
                    return result
                return self._verify_audit_connection(c,expected_head=expected_head,
                                                     checkpoint=required if checkpoint is None else checkpoint)
        except StoreIdentityError:
            return {'valid':False,'anchored':False,'entries':0,'code':'database_identity_changed'}
        except (UnicodeError, TypeError, AttributeError, ValueError, sqlite3.Error, OSError):
            return {'valid':False,'anchored':False,'entries':0,'code':'invalid_or_unavailable_audit'}

    @staticmethod
    def verify_audit_file(path: str | Path, expected_head: str | None = None,
                          *, checkpoint: dict[str, Any] | None = None) -> dict[str, Any]:
        """Verify a schema-5 file's audit chain using one read-only snapshot.

        This does not construct a Store, pin identity across calls, validate
        other tables or install a checkpoint guard on application workers.
        Supplied anchors must be retained independently by the caller.
        """
        result = {'valid': False, 'anchored': False, 'entries': 0,
                  'code': 'invalid_or_unavailable_audit'}
        try:
            uri = Path(path).resolve().as_uri() + '?mode=ro'
            with closing(sqlite3.connect(uri, uri=True, timeout=3.0, isolation_level=None)) as c:
                c.row_factory = sqlite3.Row
                c.execute('PRAGMA query_only=ON')
                c.execute('BEGIN')
                if c.execute('PRAGMA user_version').fetchone()[0] != 5:
                    result = {'valid': False, 'anchored': False, 'entries': 0,
                              'code': 'unsupported_database_schema'}
                else:
                    result = Store._verify_audit_connection(c, expected_head, checkpoint=checkpoint)
        except (UnicodeError, TypeError, AttributeError, ValueError, sqlite3.Error, OSError):
            pass
        return {**result, 'scope': 'audit_chain_only'}

    @staticmethod
    def _verify_audit_connection(c: sqlite3.Connection, expected_head: str | None = None,
                                 *, checkpoint: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate within the caller's transaction, without opening another connection."""
        count = 0
        requested = expected_head is not None or checkpoint is not None
        if expected_head is not None:
            if not isinstance(expected_head, str):
                return {'valid':False,'anchored':False,'entries':0,'code':'invalid_expected_head'}
            expected_head = str.__str__(expected_head)
            if not re.fullmatch(r'[0-9a-f]{64}', expected_head):
                return {'valid':False,'anchored':False,'entries':0,'code':'invalid_expected_head'}
        if checkpoint is not None:
            checkpoint = _validated_checkpoint(checkpoint)
            if checkpoint is None:
                return {'valid':False,'anchored':False,'entries':0,'code':'invalid_checkpoint'}
        try:
            audit_id,previous=Store._audit_genesis(c)
            if checkpoint is not None and checkpoint['audit_id']!=audit_id:
                return {'valid':False,'anchored':False,'entries':0,'code':'checkpoint_database_mismatch'}
            seen=False
            for row in c.execute("SELECT seq,body,prev_hash,entry_hash FROM audit ORDER BY seq ASC"):
                if row['seq'] != count+1:
                    return {'valid':False,'anchored':False,'entries':count,'code':'audit_sequence_gap'}
                actual = hashlib.sha256(previous.encode("ascii") + b"\x00" + row["body"].encode("ascii")).hexdigest()
                if row["prev_hash"] != previous or row["entry_hash"] != actual:
                    return {"valid": False, "anchored": False, "entries": count,
                            "code": "audit_hash_mismatch"}
                previous = actual
                count += 1
                if checkpoint is not None and count==checkpoint['seq']:
                    if not hmac.compare_digest(previous,checkpoint['hash']):
                        return {'valid':False,'anchored':False,'entries':count,'code':'checkpoint_hash_mismatch'}
                    seen=True
        except (UnicodeError, TypeError, AttributeError, ValueError, sqlite3.Error, OSError):
            return {"valid":False,"anchored":False,"entries":count,"code":"invalid_or_unavailable_audit"}
        if checkpoint is not None and not seen:
            return {'valid':False,'anchored':False,'entries':count,'code':'checkpoint_missing'}
        valid = expected_head is None or hmac.compare_digest(previous,expected_head)
        result={'valid':valid,'anchored':bool(requested and valid),'entries':count,'head':previous,'audit_id':audit_id}
        if not valid:result['code']='expected_head_mismatch'
        if checkpoint is not None and valid:result['anchored_through']=checkpoint['seq']
        return result

