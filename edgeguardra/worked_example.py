"""Executable evidence-to-review example, with ephemeral keys and simulated state."""
from __future__ import annotations

from pathlib import Path
import secrets
import tempfile

from . import __version__
from .demo import make_approval, make_proposal, setup
from .evidence import EvidenceIngestor
from .gate import sign
from .sandbox import Sandbox


def run_worked_example() -> dict:
    """Exercise unavailable context, authenticated evidence, review and single use."""
    now = 2_000_000_000
    with tempfile.TemporaryDirectory(prefix="edgeguardra-worked-") as tmp:
        gate, keys = setup(Path(tmp) / "state.db", now)
        store = gate.store
        # A trusted administrative initial state; the later observation is signed.
        store.put_device("plc-01", "critical", "unknown", now - 2, now=now)
        source_key = secrets.token_bytes(32)
        ingestor = EvidenceIngestor(store, source_keys={"detector": {"v1": source_key}},
                                    allowed_devices={"detector": ["plc-01"]}, clock=lambda: now)
        ingestor.activate_configuration()
        broker = Sandbox(gate)
        steps = []

        def record(stage, result):
            steps.append({"stage": stage, **result})

        unknown = gate.evaluate(sign(make_proposal("needs-context", "proposal-1", now,
                                                   target="plc-01"), keys["defender"]))
        record("unknown_context", {"outcome": unknown.outcome, "code": unknown.code})
        report = {"source_id": "detector", "key_id": "v1", "device_id": "plc-01",
                  "signal": "compromised", "observed_at": now - 1,
                  "issued_at": now, "nonce": "evidence-1"}
        record("signed_evidence", ingestor.ingest(sign(report, source_key)))
        proposal = sign(make_proposal("critical-action", "proposal-2", now,
                                     target="plc-01"), keys["defender"])
        decision = gate.evaluate(proposal)
        record("critical_proposal", {"outcome": decision.outcome, "code": decision.code,
                                      "context_version": decision.context_version})
        approval = sign(make_approval(decision, "approval-1", now), keys["reviewer"])
        record("review", {"code": gate.approve(approval).code})
        record("execute_once", broker.execute("critical-action", agent_id="defender"))
        record("execute_again", broker.execute("critical-action", agent_id="defender"))
        record("evidence_replay", ingestor.ingest(sign(report, source_key)))
        tampered = sign(make_proposal("tampered", "proposal-3", now,
                                     action="inspect"), keys["defender"])
        tampered["payload"]["target"] = "plc-01"
        rejected = gate.evaluate(tampered)
        record("tampered_proposal", {"outcome": rejected.outcome, "code": rejected.code})
        return {"version": __version__, "steps": steps,
                "final_device": store.device("plc-01"), "audit": store.verify_audit(),
                "scope": "Synthetic signed evidence, test reviewer key and SQLite device state; no real LLM, person or actuator.",
                "key_handling": "Fresh ephemeral secrets are not included in this output."}
