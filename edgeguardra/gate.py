"""Validated action decisions and action-bound simulated approvals.

All configuration, keys, clock, database files and device updates must be
controlled by a trusted experiment operator. This Python library is not an
OS security boundary and must not be connected directly to production OT.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from typing import Any, Callable, Mapping
from .store import Store
from .validation import IDENT, MAX_TIMESTAMP, MAX_TIME_TO_LIVE, MAX_CLOCK_SKEW, MAX_CONTEXT_VERSION, is_identifier, is_timestamp

ACTIONS = frozenset({"inspect", "quarantine", "restore"})
PROPOSAL_FIELDS = frozenset({"request_id", "agent_id", "key_id", "action", "target", "nonce", "issued_at", "reason"})
APPROVAL_FIELDS = frozenset({"agent_id", "request_id", "request_hash", "policy_hash", "context_version", "review_challenge", "reviewer_id", "key_id", "nonce", "issued_at", "verdict"})
HEX256 = re.compile(r"[0-9a-fA-F]{64}\Z")


def _scalar_text(value: Any, limit: int = 512) -> bool:
    if not isinstance(value, str) or not 0 < str.__len__(value) <= limit:
        return False
    try:
        str.encode(value, "utf-8", errors="strict")
    except UnicodeError:
        return False
    return True


def _identifier(value: Any) -> bool:
    return is_identifier(value)


def _time(value: Any) -> bool:
    return is_timestamp(value)


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Project-specific canonical JSON (not claimed to implement RFC 8785)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _binding(key: bytes, purpose: str, request_hash: str) -> str:
    """Bind a pending request to the specific currently configured secret."""
    return hmac.new(key, ("edgeguardra-v050:"+purpose+":"+request_hash).encode("ascii"), hashlib.sha256).hexdigest()


def _key_fingerprint(key: bytes) -> str:
    """Identify reused secrets across active roles without storing raw keys."""
    return hmac.new(key, b'edgeguardra:key-identity:v1', hashlib.sha256).hexdigest()


def sign(payload: Mapping[str, Any], key: bytes) -> dict[str, Any]:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("a 32-byte-or-longer secret is required")
    clean = json.loads(canonical_bytes(payload))
    return {"payload": clean, "signature": hmac.new(key, canonical_bytes(clean), hashlib.sha256).hexdigest()}


def parse_json_envelope(raw: bytes | str, max_bytes: int = 16384) -> Any:
    """Decode a bounded JSON document while rejecting duplicate object keys."""
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError('invalid JSON size limit')
    if isinstance(raw, str):
        # Every UTF-8 encoded code point uses at least one byte.  Reject an
        # oversized string before allocating a second, encoded copy.
        if str.__len__(raw) > max_bytes:
            raise ValueError('invalid or oversized JSON input')
        raw = str.encode(raw, "utf-8", "strict")
    if not isinstance(raw, bytes) or bytes.__len__(raw) > max_bytes:
        raise ValueError("invalid or oversized JSON input")
    def no_duplicates(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate JSON field")
            d[k] = v
        return d
    return json.loads(bytes.decode(raw, "utf-8", "strict"), object_pairs_hook=no_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))


def _snapshot_dict(value: Any) -> dict | None:
    """Detach a dictionary and normalize string values before validation."""
    if not isinstance(value, dict):
        return None
    try:
        snapshot = dict(value)
        # JSON keys must be ordinary strings. Converting value subclasses via
        # the base implementation prevents overridden equality/encoding from
        # making validation disagree with the serialized, signed value.
        if any(type(key) is not str for key in snapshot):
            return None
        return {key: str.__str__(item) if isinstance(item, str) else item
                for key, item in snapshot.items()}
    except RuntimeError:
        return None


def _envelope(envelope: Any, expected_fields: frozenset[str]) -> tuple[dict[str, Any], bytes] | None:
    # Take shallow snapshots before checking field names or values. Signed
    # message fields are scalar, so later caller mutations cannot make the
    # authenticated payload differ from the one that passed validation.
    envelope = _snapshot_dict(envelope)
    if envelope is None or set(envelope) != {"payload", "signature"}:
        return None
    p = _snapshot_dict(envelope.get("payload"))
    mac = envelope.get("signature")
    if p is None or set(p) != expected_fields or not isinstance(mac, str) or not HEX256.fullmatch(mac):
        return None
    # Validate and authenticate this same flat snapshot.
    if expected_fields == PROPOSAL_FIELDS:
        if not all(_identifier(p[k]) for k in ("request_id", "agent_id", "key_id", "target", "nonce")):
            return None
        if (type(p["action"]) is not str or p["action"] not in ACTIONS
            or not _time(p["issued_at"]) or not _scalar_text(p["reason"])):
            return None
    else:
        if not all(_identifier(p[k]) for k in ("agent_id", "request_id", "reviewer_id", "key_id", "nonce")):
            return None
        if not all(isinstance(p[k], str) and HEX256.fullmatch(p[k]) for k in ("request_hash", "policy_hash", "review_challenge")):
            return None
        if (type(p["context_version"]) is not int or not 1 <= p["context_version"] <= MAX_CONTEXT_VERSION
            or not _time(p["issued_at"]) or type(p["verdict"]) is not str or p["verdict"] != "approve"):
            return None
    return json.loads(canonical_bytes(p)), bytes.fromhex(mac)


def _keyring(source: Mapping[str, Mapping[str, bytes]], name: str) -> dict[str, dict[str, bytes]]:
    if not isinstance(source, Mapping) or not source:
        raise ValueError(f"explicit non-empty {name} keyring required")
    out = {}
    seen = set()
    for principal, versions in source.items():
        if not _identifier(principal) or not isinstance(versions, Mapping) or not versions:
            raise ValueError(f"invalid {name} principal")
        out[principal] = {}
        for key_id, secret in versions.items():
            if not _identifier(key_id) or not isinstance(secret, bytes) or len(secret) < 32:
                raise ValueError(f"invalid {name} key")
            if secret in seen:
                raise ValueError(f"reused {name} key")
            seen.add(secret)
            out[principal][key_id] = bytes(secret)
    return out


def _policy(source: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    expected = {"version", "request_ttl", "clock_skew", "max_context_age", "risk_threshold", "weights", "critical_extra", "grants", "review_grants", "denied_actions"}
    if not isinstance(source, Mapping) or set(source) != expected:
        raise ValueError("invalid policy fields")
    p = json.loads(canonical_bytes(source))
    if not _identifier(p["version"]):
        raise ValueError("invalid policy version")
    bounds = {"request_ttl": (1, MAX_TIME_TO_LIVE), "clock_skew": (0, MAX_CLOCK_SKEW), "max_context_age": (1, 86400),
              "risk_threshold": (1, 100), "critical_extra": (0, 100)}
    for name, (lo, hi) in bounds.items():
        if type(p[name]) is not int or not lo <= p[name] <= hi:
            raise ValueError(f"invalid policy field: {name}")
    if not isinstance(p["weights"], dict) or set(p["weights"]) != ACTIONS:
        raise ValueError("weights must cover each supported action")
    if any(type(v) is not int or not 0 <= v <= 100 for v in p["weights"].values()):
        raise ValueError("invalid action weight")
    if not isinstance(p["denied_actions"], list) or any(not isinstance(x,str) or x not in ACTIONS for x in p["denied_actions"]):
        raise ValueError("invalid denied action list")
    for name in ('grants','review_grants'):
        if not isinstance(p[name], dict):
            raise ValueError("invalid grants")
        for principal, actions in p[name].items():
            if not _identifier(principal) or not isinstance(actions, dict) or any(a not in ACTIONS for a in actions):
                raise ValueError("invalid grant")
            for targets in actions.values():
                if not isinstance(targets, list) or not targets or any(not _identifier(t) for t in targets) or len(set(targets)) != len(targets):
                    raise ValueError("targets must be explicit unique device identifiers")
    return p, hashlib.sha256(canonical_bytes(p)).hexdigest()


@dataclass(frozen=True)
class Decision:
    outcome: str
    code: str
    request_id: str | None = None
    request_hash: str | None = None
    policy_hash: str | None = None
    context_version: int | None = None
    risk: int | None = None
    expires_at: int | None = None
    configuration_epoch: int | None = None
    review_challenge: str | None = None
    agent_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class Gate:
    """Safe-by-default evaluator; no sample credentials or unguarded mode."""
    def __init__(self, store: Store, policy: Mapping[str, Any], *, agent_keys: Mapping[str, Mapping[str, bytes]],
                 reviewer_keys: Mapping[str, Mapping[str, bytes]], clock: Callable[[], int] | None = None):
        if not isinstance(store, Store):
            raise ValueError("a Store is required")
        self.store = store
        self._policy, self.policy_hash = _policy(policy)
        self._agent_keys = _keyring(agent_keys, "agent")
        self._reviewer_keys = _keyring(reviewer_keys, "reviewer")
        agent_secrets = {key for versions in self._agent_keys.values() for key in versions.values()}
        reviewer_secrets = {key for versions in self._reviewer_keys.values() for key in versions.values()}
        if agent_secrets & reviewer_secrets:
            raise ValueError("agent and reviewer secrets must be distinct")
        self._clock = clock or (lambda: int(time.time()))
        commitments = {}
        for kind, ring in (("agent",self._agent_keys),("reviewer",self._reviewer_keys)):
            commitments[kind] = {principal:{key_id:_binding(key,"config-"+kind,principal+":"+key_id)
                                           for key_id,key in sorted(versions.items())}
                                 for principal,versions in sorted(ring.items())}
        self.configuration_hash=hashlib.sha256(canonical_bytes({"policy_hash":self.policy_hash,"key_commitments":commitments})).hexdigest()
        self._key_fingerprints=tuple((kind+':'+principal,key_id,_key_fingerprint(key))
                                    for kind,ring in (("agent",self._agent_keys),("reviewer",self._reviewer_keys))
                                    for principal,versions in ring.items() for key_id,key in versions.items())
        active=self.store.active_configuration('gate')
        self._configuration_epoch=active[1] if active and active[0]==self.configuration_hash else None

    def activate_configuration(self) -> None:
        """Trusted operator action; it changes the active configuration for the DB."""
        self._configuration_epoch=self.store.activate_configuration(
            self.configuration_hash,now=self._now,kind='gate',key_fingerprints=self._key_fingerprints)

    def _now(self) -> int:
        try:
            value = self._clock()
        except Exception as exc:
            # A failing trusted clock is an unavailable dependency, not an
            # exception that should escape a stateful decision boundary.
            raise ValueError('trusted clock unavailable') from exc
        if not _time(value):
            raise ValueError("trusted clock unavailable")
        return value

    def _within_time(self, issued: int, now: int) -> bool:
        return issued <= now + self._policy["clock_skew"] and now <= issued + self._policy["request_ttl"] + self._policy["clock_skew"]

    def _deny(self, code: str, now: int | None = None) -> Decision:
        # Denials remain denials even if the audit store is unavailable.
        if now is None:
            try:
                now=self._now()
            except (ValueError, TypeError, OverflowError):
                return Decision('block','invalid_clock')
        status=self.store._record_rejection('denied',code,now,clock=self._now)
        if status in ('invalid_clock','clock_rollback'):
            return Decision('block',status)
        if status != 'recorded':
            return Decision("block", "state_store_unavailable")
        return Decision("block", code)

    def evaluate_json(self, raw: bytes | str) -> Decision:
        try:
            return self.evaluate(parse_json_envelope(raw))
        except (UnicodeError, ValueError, TypeError, RecursionError):
            return self._deny("invalid_json")

    def evaluate(self, envelope: Any) -> Decision:
        now = None
        try:
            now = self._now()
            checked = _envelope(envelope, PROPOSAL_FIELDS)
            if checked is None:
                return self._deny("invalid_schema", now)
            p, supplied = checked
            secret = self._agent_keys.get(p["agent_id"], {}).get(p["key_id"])
            if secret is None:
                return self._deny("unknown_identity", now)
            expected = hmac.new(secret, canonical_bytes(p), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, supplied):
                return self._deny("invalid_signature", now)
            if not self._within_time(p["issued_at"], now):
                return self._deny("expired_or_future_request", now)
            request_hash = hashlib.sha256(canonical_bytes(p)).hexdigest()
            expires_at = p["issued_at"] + self._policy["request_ttl"] + self._policy["clock_skew"]
            before_lock = now
            with self.store.transaction() as c:
                # A lock wait may cross the expiry boundary; use a fresh clock under the lock.
                if not Store.check_clock(c,before_lock):
                    return Decision('block','clock_rollback',p['request_id'])
                try:
                    now=self._now()
                except ValueError:
                    # Commit the first valid observation without authorizing.
                    return Decision('block','invalid_clock',p['request_id'])
                if not Store.check_clock(c,now):
                    Store.append_audit(c, "denied", {"code":"clock_rollback"}, now)
                    return Decision("block", "clock_rollback", p["request_id"])
                if not Store.configuration_matches(c, self.configuration_hash, self._configuration_epoch):
                    Store.append_audit(c,"denied",{"code":"configuration_not_active"},now)
                    return Decision("block","configuration_not_active",p["request_id"])
                if not self._within_time(p['issued_at'],now):
                    Store.append_audit(c, 'denied', {'code':'expired_or_future_request'}, now)
                    return Decision('block','expired_or_future_request',p['request_id'])
                Store.prune_nonces(c, now)
                try:
                    c.execute("INSERT INTO nonces(kind,principal,nonce,expires_at) VALUES('proposal',?,?,?)",
                              (p["agent_id"], p["nonce"], expires_at))
                except sqlite3.IntegrityError:
                    Store.append_audit(c, "denied", {"code": "replay"}, now)
                    return Decision("block", "replay", p["request_id"])
                if c.execute("SELECT 1 FROM decisions WHERE agent_id=? AND request_id=?", (p['agent_id'],p['request_id'])).fetchone():
                    Store.append_audit(c, "denied", {"code":"duplicate_request_id","agent_id":p['agent_id'],"request_id":p['request_id']}, now)
                    return Decision("block", "duplicate_request_id", p["request_id"])
                row = c.execute("SELECT * FROM devices WHERE device_id=?", (p["target"],)).fetchone()
                version = int(row["version"]) if row else 0
                evidence_generation=Store.active_generation(c,'evidence')
                outcome, code, status, risk = self._decide_policy(p, row, now, evidence_generation)
                challenge=secrets.token_hex(32) if status == 'pending' else None
                c.execute("""INSERT INTO decisions(request_id,agent_id,key_id,key_binding,target,action,request_hash,policy_hash,
                    configuration_epoch,context_version,outcome,code,status,expires_at,risk,review_challenge,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (p["request_id"], p["agent_id"], p["key_id"], _binding(secret,"agent",request_hash), p["target"], p["action"], request_hash, self.policy_hash,
                     self._configuration_epoch, version, outcome, code, status, expires_at, risk, challenge, now))
                Store.append_audit(c, "decision", {"request_id":p["request_id"],"agent_id":p["agent_id"],
                    "action":p["action"],"target":p["target"],"request_hash":request_hash,"policy_hash":self.policy_hash,
                    "context_version":version,"gate_generation":self._configuration_epoch,"evidence_generation":evidence_generation,
                    "outcome":outcome,"code":code,"risk":risk,"expires_at":expires_at}, now)
                return Decision(outcome, code, p["request_id"], request_hash, self.policy_hash, version, risk, expires_at, self._configuration_epoch, challenge, p['agent_id'])
        except (UnicodeError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            # Keep a valid observation even when decoding or validation raises.
            return self._deny("invalid_input", now)
        except (sqlite3.Error, OSError):
            return Decision("block", "state_store_unavailable")

    def _decide_policy(self, p: dict[str, Any], row: sqlite3.Row | None, now: int, evidence_generation: int | None):
        action, target = p["action"], p["target"]
        if action in self._policy["denied_actions"]:
            return "block", "hard_denied", "blocked", None
        if target not in self._policy["grants"].get(p["agent_id"], {}).get(action, []):
            return "block", "unauthorized_target_or_action", "blocked", None
        if row is None:
            return "block", "unknown_target", "blocked", None
        if type(row["observed_at"]) is not int or row["observed_at"] > now:
            return "defer", "invalid_context_time", "waiting", None
        if action in {"quarantine", "restore"}:
            if row['evidence_generation'] and row['evidence_generation'] != evidence_generation:
                return 'defer','evidence_configuration_changed','waiting',None
            if now - row["observed_at"] > self._policy["max_context_age"]:
                return "defer", "stale_context", "waiting", None
            required = "compromised" if action == "quarantine" else "normal"
            if row["signal"] != required:
                return "defer", "insufficient_or_conflicting_evidence", "waiting", None
        risk = self._policy["weights"][action]
        if row["criticality"] == "critical" and action != "inspect":
            risk += self._policy["critical_extra"]
        if risk >= self._policy["risk_threshold"]:
            return "defer", "review_required", "pending", risk
        return "allow", "checks_passed", "allowed", risk

    def approve(self, envelope: Any) -> Decision:
        """Approve a pending simulated action with a distinct reviewer key.

        Possession of a reviewer key is simulated identity, not proof of a
        real human's review. It cannot override hard denials or stale evidence.
        """
        now = None
        try:
            now = self._now()
            checked = _envelope(envelope, APPROVAL_FIELDS)
            if checked is None:
                return self._deny("invalid_approval_schema", now)
            p, supplied = checked
            secret = self._reviewer_keys.get(p["reviewer_id"], {}).get(p["key_id"])
            if secret is None:
                return self._deny("unknown_reviewer", now)
            if not hmac.compare_digest(hmac.new(secret, canonical_bytes(p), hashlib.sha256).digest(), supplied):
                return self._deny("invalid_approval_signature", now)
            if not self._within_time(p["issued_at"], now):
                return self._deny("expired_or_future_approval", now)
            before_lock = now
            with self.store.transaction() as c:
                if not Store.check_clock(c,before_lock):
                    return Decision('block','clock_rollback',p['request_id'])
                try:
                    now=self._now()
                except ValueError:
                    return Decision('block','invalid_clock',p['request_id'])
                if not Store.check_clock(c,now):
                    Store.append_audit(c, "approval_denied", {"code":"clock_rollback"}, now)
                    return Decision("block", "clock_rollback", p["request_id"])
                if not Store.configuration_matches(c, self.configuration_hash, self._configuration_epoch):
                    Store.append_audit(c,"approval_denied",{"code":"configuration_not_active"},now)
                    return Decision("block","configuration_not_active",p["request_id"])
                if not self._within_time(p['issued_at'],now):
                    Store.append_audit(c,'approval_denied',{'code':'expired_or_future_approval'},now)
                    return Decision('block','expired_or_future_approval',p['request_id'])
                row = c.execute("SELECT * FROM decisions WHERE agent_id=? AND request_id=?", (p['agent_id'],p['request_id'])).fetchone()
                if row is None or row["status"] != "pending":
                    Store.append_audit(c, "approval_denied", {"code": "not_pending"}, now)
                    return Decision("block", "not_pending", p["request_id"])
                if p['issued_at'] < row['created_at']:
                    Store.append_audit(c,'approval_denied',{'code':'approval_before_decision'},now)
                    return Decision('block','approval_before_decision',p['request_id'])
                if p['reviewer_id'] == row['agent_id']:
                    Store.append_audit(c,'approval_denied',{'code':'self_approval_forbidden'},now)
                    return Decision('block','self_approval_forbidden',p['request_id'])
                if row['target'] not in self._policy['review_grants'].get(p['reviewer_id'],{}).get(row['action'],[]):
                    Store.append_audit(c,'approval_denied',{'code':'reviewer_not_authorized'},now)
                    return Decision('block','reviewer_not_authorized',p['request_id'])
                ctx = c.execute("SELECT * FROM devices WHERE device_id=?", (row["target"],)).fetchone()
                proposed = {"agent_id": row["agent_id"], "action": row["action"], "target": row["target"]}
                current_code = self._decide_policy(proposed, ctx, now, Store.active_generation(c,'evidence'))[1] if ctx is not None else "unknown_target"
                agent_secret = self._agent_keys.get(row["agent_id"], {}).get(row["key_id"])
                agent_current = agent_secret is not None and hmac.compare_digest(
                    _binding(agent_secret, "agent", row["request_hash"]), row["key_binding"])
                matches = (p["request_hash"].lower() == row["request_hash"] and p["policy_hash"].lower() == row["policy_hash"] == self.policy_hash
                           and isinstance(row['review_challenge'],str)
                           and hmac.compare_digest(p['review_challenge'].lower(),row['review_challenge'])
                           and row['configuration_epoch'] == self._configuration_epoch
                           and p["context_version"] == row["context_version"] and ctx is not None
                           and ctx["version"] == row["context_version"] and now <= row["expires_at"]
                           and current_code == "review_required" and agent_current)
                if not matches:
                    Store.append_audit(c, "approval_denied", {"code": "binding_or_expiry_mismatch"}, now)
                    return Decision("block", "binding_or_expiry_mismatch", p["request_id"])
                approval_expires = p["issued_at"] + self._policy["request_ttl"] + self._policy["clock_skew"]
                expires = min(row["expires_at"], approval_expires)
                Store.prune_nonces(c, now)
                try:
                    c.execute("INSERT INTO nonces(kind,principal,nonce,expires_at) VALUES('approval',?,?,?)",
                              (p["reviewer_id"], p["nonce"], approval_expires))
                except sqlite3.IntegrityError:
                    Store.append_audit(c, "approval_denied", {"code": "approval_replay"}, now)
                    return Decision("block", "approval_replay", p["request_id"])
                c.execute("UPDATE decisions SET status='approved',reviewer_id=?,reviewer_key_id=?,reviewer_binding=?,expires_at=? WHERE agent_id=? AND request_id=?",
                          (p["reviewer_id"], p["key_id"], _binding(secret,"reviewer",row["request_hash"]), expires, p['agent_id'],p["request_id"]))
                Store.append_audit(c, "approved", {"agent_id":p['agent_id'],"request_id":p["request_id"],"reviewer_id":p["reviewer_id"],
                    "approval_hash":hashlib.sha256(canonical_bytes(p)).hexdigest(),"request_hash":row['request_hash'],
                    "gate_generation":self._configuration_epoch,"context_version":row['context_version'],"expires_at":expires}, now)
                return Decision("allow", "approved_for_sandbox", p["request_id"], row["request_hash"], self.policy_hash,
                                row["context_version"], row["risk"], expires, self._configuration_epoch, row['review_challenge'],row['agent_id'])
        except (UnicodeError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            return self._deny("invalid_approval", now)
        except (sqlite3.Error, OSError):
            return Decision("block", "state_store_unavailable")

