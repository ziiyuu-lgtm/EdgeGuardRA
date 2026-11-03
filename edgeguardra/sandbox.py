"""Controlled simulated execution; no device/network actuator is provided."""
from __future__ import annotations
import sqlite3
import hmac
from typing import Any
from .gate import Gate, _binding, _identifier
from .store import Store


class Sandbox:
    """Apply one authorized action to simulated SQLite device state only.

    Security depends on all callers using this broker and on exclusive operator
    control of the database. Malicious code with filesystem or database access
    can bypass it. This is not an OT actuator or an OS isolation mechanism.
    """
    def __init__(self, gate: Gate):
        if not isinstance(gate, Gate):
            raise ValueError("a configured Gate is required")
        self.gate = gate

    def execute(self, request_id: Any, *, agent_id: Any = None) -> dict[str, Any]:
        if not _identifier(request_id):
            return {"executed": False, "code": "invalid_request_id"}
        if not _identifier(agent_id):
            return {"executed": False, "code": "invalid_agent_id"}
        try:
            now = self.gate._now()
            before_lock = now
            with self.gate.store.transaction() as c:
                if not Store.check_clock(c,before_lock):
                    return {'executed':False,'code':'clock_rollback'}
                try:
                    now=self.gate._now()
                except ValueError:
                    return {'executed':False,'code':'invalid_clock'}
                if not Store.check_clock(c,now):
                    Store.append_audit(c, "execution_denied", {"code":"clock_rollback"}, now)
                    return {"executed": False, "code": "clock_rollback"}
                if not Store.configuration_matches(c, self.gate.configuration_hash, self.gate._configuration_epoch):
                    Store.append_audit(c,"execution_denied",{"code":"configuration_not_active"},now)
                    return {"executed":False,"code":"configuration_not_active"}
                row = c.execute("SELECT * FROM decisions WHERE agent_id=? AND request_id=?", (agent_id,request_id)).fetchone()
                if row is None:
                    Store.append_audit(c, "execution_denied", {"code": "unknown_request"}, now)
                    return {"executed": False, "code": "unknown_request"}
                if row["status"] not in ("allowed", "approved"):
                    Store.append_audit(c, "execution_denied", {"agent_id":agent_id,"request_id":request_id,"code":"not_authorized"}, now)
                    return {"executed": False, "code": "not_authorized"}
                ctx = c.execute("SELECT * FROM devices WHERE device_id=?", (row["target"],)).fetchone()
                proposed = {"agent_id": row["agent_id"], "action": row["action"], "target": row["target"]}
                evidence_generation=Store.active_generation(c,'evidence')
                code = self.gate._decide_policy(proposed, ctx, now, evidence_generation)[1] if ctx is not None else "unknown_target"
                expected_code = "review_required" if row["status"] == "approved" else "checks_passed"
                agent_key = self.gate._agent_keys.get(row["agent_id"], {}).get(row["key_id"])
                agent_current = agent_key is not None and hmac.compare_digest(
                    _binding(agent_key,"agent",row["request_hash"]),row["key_binding"])
                reviewer_current = True
                if row["status"] == "approved":
                    reviewer_key = self.gate._reviewer_keys.get(row["reviewer_id"], {}).get(row["reviewer_key_id"])
                    reviewer_current = reviewer_key is not None and hmac.compare_digest(
                        _binding(reviewer_key,"reviewer",row["request_hash"]),row["reviewer_binding"])
                    reviewer_current = (reviewer_current and row['reviewer_id'] != row['agent_id']
                        and row['target'] in self.gate._policy['review_grants'].get(row['reviewer_id'],{}).get(row['action'],[]))
                matches = (ctx is not None and row["policy_hash"] == self.gate.policy_hash
                           and row['configuration_epoch'] == self.gate._configuration_epoch
                           and ctx["version"] == row["context_version"] and now <= row["expires_at"]
                           and code == expected_code and agent_current and reviewer_current)
                if not matches:
                    c.execute("UPDATE decisions SET status='invalidated' WHERE agent_id=? AND request_id=?", (agent_id,request_id))
                    Store.append_audit(c, "execution_denied", {"agent_id":agent_id,"request_id":request_id,"code":"state_policy_or_time_changed"}, now)
                    return {"executed": False, "code": "state_policy_or_time_changed"}
                # Recheck as close as practical to the simulated effect.
                try:
                    now=self.gate._now()
                except ValueError:
                    return {'executed':False,'code':'invalid_clock'}
                if not Store.check_clock(c,now):
                    Store.append_audit(c,'execution_denied',{'code':'clock_rollback'},now)
                    return {'executed':False,'code':'clock_rollback'}
                if now > row['expires_at'] or self.gate._decide_policy(proposed,ctx,now,evidence_generation)[1] != expected_code:
                    c.execute("UPDATE decisions SET status='invalidated' WHERE agent_id=? AND request_id=?",(agent_id,request_id))
                    Store.append_audit(c,'execution_denied',{'agent_id':agent_id,'request_id':request_id,'code':'state_policy_or_time_changed'},now)
                    return {'executed':False,'code':'state_policy_or_time_changed'}
                if row["action"] == "quarantine":
                    c.execute("UPDATE devices SET quarantined=1,version=version+1 WHERE device_id=?", (row["target"],))
                elif row["action"] == "restore":
                    c.execute("UPDATE devices SET quarantined=0,version=version+1 WHERE device_id=?", (row["target"],))
                # inspect has no simulated physical side effect.
                c.execute("UPDATE decisions SET status='executed' WHERE agent_id=? AND request_id=?", (agent_id,request_id))
                Store.append_audit(c, "sandbox_executed", {"agent_id":agent_id,"request_id":request_id,"action":row["action"],"target":row["target"],
                    "request_hash":row["request_hash"],"gate_generation":self.gate._configuration_epoch,
                    "evidence_generation":evidence_generation,"context_version":row['context_version']}, now)
                return {"executed": True, "code": "sandbox_only", "action": row["action"], "target": row["target"]}
        except (ValueError, TypeError, OverflowError, sqlite3.Error, OSError):
            return {"executed": False, "code": "state_store_or_clock_unavailable"}

