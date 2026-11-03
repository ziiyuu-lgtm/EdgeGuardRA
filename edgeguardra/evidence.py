"""Authenticated evidence ingestion for the local research simulator.

Authentication proves possession of a configured shared key, not that a
sensor observation is physically correct or that the host is uncompromised.
"""
from __future__ import annotations
import hashlib
import hmac
import sqlite3
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping
from .gate import HEX256, _binding, _identifier, _keyring, _key_fingerprint, _snapshot_dict, _time, canonical_bytes
from .store import Store
from .validation import MAX_TIME_TO_LIVE, MAX_CLOCK_SKEW

FIELDS = frozenset({"source_id", "key_id", "device_id", "signal", "observed_at", "issued_at", "nonce"})


class EvidenceIngestor:
    def __init__(self, store: Store, *, source_keys: Mapping[str, Mapping[str, bytes]],
                 allowed_devices: Mapping[str, list[str]], clock: Callable[[], int] | None = None,
                 ttl: int = 120, skew: int = 5):
        if not isinstance(store, Store):
            raise ValueError("a Store is required")
        self.store = store
        ring = _keyring(source_keys, "evidence source")
        self._keys = MappingProxyType({k: MappingProxyType(v) for k,v in ring.items()})
        if not isinstance(allowed_devices, Mapping) or any(not _identifier(k) or not isinstance(v, list) or
            any(not _identifier(device) for device in v) for k,v in allowed_devices.items()):
            raise ValueError("invalid evidence source grants")
        self._allowed_devices = MappingProxyType({k: frozenset(v) for k,v in allowed_devices.items()})
        if type(ttl) is not int or not 1 <= ttl <= MAX_TIME_TO_LIVE or type(skew) is not int or not 0 <= skew <= MAX_CLOCK_SKEW:
            raise ValueError("invalid evidence timing configuration")
        self._ttl, self._skew = ttl, skew
        self._clock = clock or (lambda: int(time.time()))
        commitments = {principal: {key_id: _binding(key, 'config-evidence', principal + ':' + key_id)
                                   for key_id, key in sorted(versions.items())}
                       for principal, versions in sorted(self.keys.items())}
        configuration = {'key_commitments': commitments,
                         'grants': {k: sorted(v) for k, v in sorted(self.allowed_devices.items())},
                         'ttl': ttl, 'skew': skew}
        self._configuration_hash = hashlib.sha256(canonical_bytes(configuration)).hexdigest()
        self._key_fingerprints=tuple(('source:'+principal,key_id,_key_fingerprint(key))
                                     for principal,versions in self.keys.items() for key_id,key in versions.items())
        active=self.store.active_configuration('evidence')
        self._configuration_epoch=active[1] if active and active[0]==self.configuration_hash else None

    @property
    def configuration_hash(self): return self._configuration_hash

    @property
    def keys(self): return self._keys

    @property
    def allowed_devices(self): return self._allowed_devices

    @property
    def ttl(self): return self._ttl

    @property
    def skew(self): return self._skew

    def _now(self):
        try:
            value=self._clock()
        except Exception as exc:
            raise ValueError('trusted clock unavailable') from exc
        if not _time(value): raise ValueError('trusted clock unavailable')
        return value

    def activate_configuration(self) -> None:
        """Trusted operator action shared by all instances using this store."""
        self._configuration_epoch=self.store.activate_configuration(
            self.configuration_hash,now=self._now,kind='evidence',key_fingerprints=self._key_fingerprints)

    def _reject(self, code: str, now: int) -> dict[str, Any]:
        status=self.store._record_rejection('evidence_rejected',code,now,clock=self._now)
        return {'accepted':False,'code':code if status=='recorded' else status}

    def ingest(self, envelope: Any) -> dict[str, Any]:
        now = None
        try:
            now = self._now()
            # Evidence fields are scalar; detach the mappings before checking
            # them so concurrent caller changes cannot bypass the schema.
            envelope = _snapshot_dict(envelope)
            if envelope is None or set(envelope) != {"payload", "signature"}:
                return self._reject('invalid_schema',now)
            p, mac = envelope["payload"], envelope["signature"]
            p = _snapshot_dict(p)
            if p is None or set(p) != FIELDS or not isinstance(mac, str) or not HEX256.fullmatch(mac):
                return self._reject('invalid_schema',now)
            if not all(_identifier(p[k]) for k in ("source_id", "key_id", "device_id", "nonce")):
                return self._reject('invalid_schema',now)
            if (type(p["signal"]) is not str or p["signal"] not in ("normal", "compromised", "unknown")
                or not _time(p["observed_at"]) or not _time(p["issued_at"])):
                return self._reject('invalid_schema',now)
            # Freeze the signed data before evaluating it.
            import json
            p = json.loads(canonical_bytes(p))
            key = self.keys.get(p["source_id"], {}).get(p["key_id"])
            if key is None or not hmac.compare_digest(hmac.new(key, canonical_bytes(p), hashlib.sha256).digest(), bytes.fromhex(mac)):
                return self._reject('invalid_source_authentication',now)
            if p["device_id"] not in self.allowed_devices.get(p["source_id"], frozenset()):
                return self._reject('source_not_authorized_for_device',now)
            if (p["issued_at"] > now+self.skew or now > p["issued_at"]+self.ttl+self.skew
                or p["observed_at"] > now+self.skew or p["observed_at"] > p["issued_at"]+self.skew):
                return self._reject('invalid_evidence_time',now)
            digest=hashlib.sha256(canonical_bytes(p)).hexdigest()
            before_lock=now
            with self.store.transaction() as c:
                if not Store.check_clock(c,before_lock):
                    return {'accepted':False,'code':'clock_rollback'}
                try:
                    now=self._now()
                except ValueError:
                    return {'accepted':False,'code':'invalid_clock'}
                if not Store.check_clock(c,now):
                    Store.append_audit(c, "evidence_rejected", {"code":"clock_rollback"}, now)
                    return {"accepted": False, "code": "clock_rollback"}
                if not Store.configuration_matches(c, self.configuration_hash, self._configuration_epoch, kind='evidence'):
                    Store.append_audit(c, 'evidence_rejected', {'code':'configuration_not_active'}, now)
                    return {'accepted': False, 'code': 'configuration_not_active'}
                if (p['issued_at'] > now+self.skew or now > p['issued_at']+self.ttl+self.skew
                    or p['observed_at'] > now+self.skew or p['observed_at'] > p['issued_at']+self.skew):
                    Store.append_audit(c,'evidence_rejected',{'code':'invalid_evidence_time'},now)
                    return {'accepted':False,'code':'invalid_evidence_time'}
                Store.prune_nonces(c, now)
                try:
                    c.execute("INSERT INTO nonces(kind,principal,nonce,expires_at) VALUES('evidence',?,?,?)",
                        (p["source_id"], p["nonce"], p["issued_at"]+self.ttl+self.skew))
                except sqlite3.IntegrityError:
                    Store.append_audit(c, "evidence_rejected", {"code":"evidence_replay"}, now)
                    return {"accepted": False, "code": "evidence_replay"}
                device = c.execute("SELECT * FROM devices WHERE device_id=?", (p["device_id"],)).fetchone()
                if device is None:
                    Store.append_audit(c, "evidence_rejected", {"code":"unknown_device"}, now)
                    return {"accepted": False, "code": "unknown_device"}
                if p["observed_at"] == device["observed_at"] and p["signal"] != device["signal"]:
                    # Equal-time contradictory reports cannot be ordered. Keep
                    # an explicit unknown context, including when an earlier
                    # conflict has already produced unknown, so a third report
                    # at the same timestamp cannot silently resolve the tie.
                    conflict = {'kind': 'equal-time-conflict-v1', 'device_id': p['device_id'],
                                'observed_at': p['observed_at'], 'prior_source_id': device['source_id'],
                                'prior_signal': device['signal'], 'prior_evidence_hash': device['evidence_hash'],
                                'incoming_digest': digest}
                    conflict_digest = hashlib.sha256(canonical_bytes(conflict)).hexdigest()
                    c.execute("UPDATE devices SET signal='unknown',version=version+1,source_id='',"
                              "evidence_hash=?,evidence_generation=? WHERE device_id=?",
                              (conflict_digest, self._configuration_epoch, p['device_id']))
                    Store.append_audit(c, 'evidence_conflict', {
                        'device_id': p['device_id'], 'source_id': p['source_id'], 'key_id': p['key_id'],
                        'reported_signal': p['signal'], 'incoming_digest': digest,
                        'observed_at': p['observed_at'], 'prior_source_id': device['source_id'],
                        'prior_signal': device['signal'], 'prior_evidence_hash': device['evidence_hash'],
                        'conflict_digest': conflict_digest, 'evidence_generation': self._configuration_epoch,
                        'context_version': device['version'] + 1}, now)
                    return {'accepted': True, 'code': 'evidence_conflict', 'context_version': device['version'] + 1}
                if p["observed_at"] <= device["observed_at"]:
                    Store.append_audit(c, "evidence_rejected", {"code":"out_of_order"}, now)
                    return {"accepted": False, "code": "out_of_order"}
                c.execute("UPDATE devices SET signal=?,observed_at=?,version=version+1,source_id=?,evidence_hash=?,evidence_generation=? WHERE device_id=?",
                    (p["signal"],p["observed_at"],p["source_id"],digest,self._configuration_epoch,p["device_id"]))
                Store.append_audit(c, "evidence_accepted", {"device_id":p["device_id"],"source_id":p["source_id"],
                    "key_id":p["key_id"],"digest":digest,"observed_at":p["observed_at"],
                    "evidence_generation":self._configuration_epoch,"context_version":device["version"]+1}, now)
                return {"accepted":True,"code":"evidence_accepted","context_version":device["version"]+1}
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
            return self._reject('invalid_evidence',now) if _time(now) else {'accepted':False,'code':'invalid_clock'}
        except (sqlite3.Error, OSError):
            return {"accepted": False, "code": "state_store_unavailable"}

