"""Self-contained, ephemeral demonstration. No real devices or people."""
from __future__ import annotations
import secrets
from pathlib import Path
from typing import Any, Callable
from .gate import Gate, Decision, sign
from .sandbox import Sandbox
from .store import Store


def example_policy() -> dict[str, Any]:
    return {"version": "demo-v1", "request_ttl": 120, "clock_skew": 5, "max_context_age": 60,
            "risk_threshold": 3, "weights": {"inspect": 0, "quarantine": 2, "restore": 1},
            "critical_extra": 2, "denied_actions": [],
            "grants": {"defender": {"inspect": ["pump-01", "plc-01"],
                                     "quarantine": ["pump-01", "plc-01"],
                                     "restore": ["pump-01", "plc-01"]},
                       "observer": {"inspect": ["pump-01"]}},
            "review_grants": {"reviewer": {"quarantine": ["plc-01"], "restore": ["plc-01"]}}}


def make_proposal(request_id: str, nonce: str, now: int, *, agent_id="defender", action="quarantine",
                  target="pump-01", reason="demo event", key_id="v1") -> dict[str, Any]:
    return {"request_id": request_id, "agent_id": agent_id, "key_id": key_id, "action": action,
            "target": target, "nonce": nonce, "issued_at": now, "reason": reason}


def make_approval(d: Decision, nonce: str, now: int, *, reviewer_id="reviewer", key_id="v1") -> dict[str, Any]:
    if d.outcome != "defer" or d.code != "review_required" or not d.review_challenge or not d.agent_id:
        raise ValueError("only a review-required decision can be approved")
    return {"agent_id":d.agent_id,"request_id": d.request_id, "request_hash": d.request_hash, "policy_hash": d.policy_hash,
            "context_version": d.context_version, "review_challenge": d.review_challenge,
            "reviewer_id": reviewer_id, "key_id": key_id,
            "nonce": nonce, "issued_at": now, "verdict": "approve"}


def setup(path: str | Path, now: int, *, clock: Callable[[], int] | None = None):
    agent_key, observer_key, reviewer_key = (secrets.token_bytes(32) for _ in range(3))
    store = Store(path, create=True)
    store.put_device("pump-01", "routine", "compromised", now-2, now=now)
    store.put_device("plc-01", "critical", "compromised", now-2, now=now)
    gate = Gate(store, example_policy(), agent_keys={"defender": {"v1": agent_key}, "observer": {"v1": observer_key}},
                reviewer_keys={"reviewer": {"v1": reviewer_key}}, clock=clock or (lambda: now))
    gate.activate_configuration()
    return gate, {"defender": agent_key, "observer": observer_key, "reviewer": reviewer_key}


def demo(path: str | Path, now: int) -> dict[str, Any]:
    gate, keys = setup(path, now)
    broker = Sandbox(gate)
    d1 = gate.evaluate(sign(make_proposal("demo-1", "n-1", now), keys["defender"]))
    result1 = broker.execute("demo-1",agent_id="defender")
    d2 = gate.evaluate(sign(make_proposal("demo-2", "n-2", now, target="plc-01"), keys["defender"]))
    reviewed = gate.approve(sign(make_approval(d2, "approve-1", now), keys["reviewer"]))
    result2 = broker.execute("demo-2",agent_id="defender")
    bad = sign(make_proposal("demo-3", "n-3", now), keys["defender"])
    bad["payload"]["target"] = "plc-01"
    d3 = gate.evaluate(bad)
    return {"routine": {"decision": d1.code, "simulation": result1},
            "critical": {"decision": d2.code, "review": reviewed.code, "simulation": result2},
            "tampered": d3.code,
            "audit": gate.store.verify_audit(),
            "scope": "simulated database only; reviewer is a test key, not a human"}

