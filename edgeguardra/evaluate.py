"""Synthetic research evaluation; no LLM, physical device or human reviewer."""
from __future__ import annotations

from collections import Counter
from contextlib import closing
import csv
import hashlib
import hmac
import json
from pathlib import Path
import platform
import secrets
import sqlite3
import statistics
import sys
import tempfile
import time
from typing import Any

from . import __version__
from .demo import example_policy, make_approval, make_proposal
from .evidence import EvidenceIngestor
from .gate import Gate, PROPOSAL_FIELDS, _envelope, canonical_bytes, sign
from .sandbox import Sandbox
from .store import Store

NOW = 1_700_000_000
KINDS = ("normal_inspection", "valid_quarantine", "valid_restore", "critical_review",
         "unknown_signal", "conflicting_signal", "stale_context", "unauthorized_target",
         "unauthorized_actor", "unknown_target", "tampered_request", "replay",
         "expired_request", "future_request", "invalid_unicode", "false_positive_evidence", "hard_denied")
MODES = ("unguarded", "schema", "capability", "risk")
REVIEW_EXPECTED = {'valid_review':'approved_for_sandbox', 'ungranted_reviewer':'reviewer_not_authorized',
                   'self_review':'self_approval_forbidden', 'wrong_challenge':'binding_or_expiry_mismatch',
                   'approval_before_decision':'approval_before_decision', 'replayed_approval':'not_pending',
                   'context_changed':'binding_or_expiry_mismatch', 'configuration_changed':'binding_or_expiry_mismatch',
                   'evidence_revoked':'binding_or_expiry_mismatch'}


def case_specs(variants: int = 3) -> list[dict[str, Any]]:
    if type(variants) is not int or not 1 <= variants <= 20:
        raise ValueError("variants must be 1..20")
    out = []
    for kind in KINDS:
        for i in range(variants):
            case = {"id": f"{kind}-{i:02d}", "kind": kind, "variant": i,
                    "action": "quarantine", "agent": "defender", "target": "pump-01",
                    "criticality": "routine", "signal": "compromised", "ground_truth": "compromised",
                    "context_age": 2 + i, "issued_at": NOW, "desired": "allow", "group": "benign"}
            if kind == "normal_inspection": case.update(action="inspect", signal="normal", ground_truth="normal")
            elif kind == "valid_restore": case.update(action="restore", signal="normal", ground_truth="normal")
            elif kind == "critical_review": case.update(target="plc-01", criticality="critical", desired="defer", group="legitimate_review")
            elif kind == "unknown_signal": case.update(signal="unknown", ground_truth="unknown", desired="defer", group="uncertain")
            elif kind == "conflicting_signal": case.update(signal="normal", ground_truth="normal", desired="defer", group="uncertain")
            elif kind == "stale_context": case.update(context_age=61+i, desired="defer", group="uncertain")
            elif kind == "unauthorized_target": case.update(target="spare-01", desired="block", group="adverse")
            elif kind == "unauthorized_actor": case.update(agent="observer", desired="block", group="adverse")
            elif kind == "unknown_target": case.update(target="ghost-01", desired="block", group="adverse")
            elif kind in {"tampered_request", "replay", "invalid_unicode", "hard_denied"}:
                case.update(desired="block", group="adverse")
            elif kind == "expired_request": case.update(issued_at=NOW-126-i, desired="block", group="adverse")
            elif kind == "future_request": case.update(issued_at=NOW+6+i, desired="block", group="adverse")
            elif kind == "false_positive_evidence": case.update(ground_truth="normal", desired="defer", group="adverse")
            case['evidence_method'] = 'signed_source' if kind == 'false_positive_evidence' else 'operator_fixture'
            out.append(case)
    return out


def _capability_baseline(envelope: Any, mode: str, policy: dict[str, Any], keys: dict[str, bytes],
                         inventory: set[str], replay: bool) -> str:
    """Offline ablations only; never used by the runtime gate or broker."""
    if mode == "unguarded": return "allow"
    try: checked = _envelope(envelope, PROPOSAL_FIELDS)
    except (ValueError, TypeError, UnicodeError): checked = None
    if checked is None: return "block"
    if mode == "schema": return "allow"
    p, supplied = checked
    key=keys.get(p["agent_id"])
    if key is None or p["key_id"] != "v1" or not hmac.compare_digest(hmac.new(key,canonical_bytes(p),hashlib.sha256).digest(),supplied): return "block"
    if p["issued_at"] > NOW+policy["clock_skew"] or NOW > p["issued_at"]+policy["request_ttl"]+policy["clock_skew"]: return "block"
    if replay or p["action"] in policy["denied_actions"]: return "block"
    if p["target"] not in policy["grants"].get(p["agent_id"],{}).get(p["action"],[]) or p["target"] not in inventory: return "block"
    return "allow"


def run_cases(variants: int = 3) -> list[dict[str, Any]]:
    cases=case_specs(variants)
    rows=[]
    with tempfile.TemporaryDirectory(prefix="edgeguardra-eval-") as tmp:
        for case in cases:
            policy=example_policy()
            if case["kind"] == "unknown_target": policy["grants"]["defender"]["quarantine"].append("ghost-01")
            if case["kind"] == "hard_denied": policy["denied_actions"]=["quarantine"]
            keys={"defender":secrets.token_bytes(32),"observer":secrets.token_bytes(32)}
            reviewer=secrets.token_bytes(32)
            store=Store(Path(tmp)/(case["id"]+'.db'), create=True)
            false_positive = case['kind'] == 'false_positive_evidence'
            store.put_device("pump-01","routine",'normal' if false_positive else case["signal"],
                             NOW-case["context_age"]-(1 if false_positive else 0),now=NOW)
            store.put_device("plc-01","critical",case["signal"],NOW-case["context_age"],now=NOW)
            store.put_device("spare-01","routine",case["signal"],NOW-case["context_age"],now=NOW)
            if false_positive:
                sensor_key=secrets.token_bytes(32)
                ingestor=EvidenceIngestor(store,source_keys={'sensor':{'v1':sensor_key}},
                                          allowed_devices={'sensor':['pump-01']},clock=lambda:NOW)
                ingestor.activate_configuration()
                evidence={'source_id':'sensor','key_id':'v1','device_id':'pump-01',
                          'signal':'compromised','observed_at':NOW-case['context_age'],
                          'issued_at':NOW,'nonce':'evidence-'+case['id']}
                if not ingestor.ingest(sign(evidence,sensor_key))['accepted']:
                    raise RuntimeError('signed synthetic evidence setup failed')
            gate=Gate(store,policy,agent_keys={k:{"v1":v} for k,v in keys.items()},reviewer_keys={"reviewer":{"v1":reviewer}},clock=lambda:NOW)
            gate.activate_configuration()
            payload=make_proposal(case["id"],"nonce-"+case["id"],case["issued_at"],agent_id=case["agent"],
                                  action=case["action"],target=case["target"],reason=f"synthetic observation variant {case['variant']}")
            if case["kind"] == "invalid_unicode":
                payload["reason"]='\ud800'
                envelope={"payload":payload,"signature":"0"*64}
            else:
                envelope=sign(payload,keys[case["agent"]])
            if case["kind"] == "tampered_request": envelope["payload"]["target"]="plc-01"
            if case["kind"] == "replay":
                gate.evaluate(envelope)
                gate=Gate(Store(store.path),policy,agent_keys={k:{"v1":v} for k,v in keys.items()},
                          reviewer_keys={"reviewer":{"v1":reviewer}},clock=lambda:NOW)
            observed={mode:_capability_baseline(envelope,mode,policy,keys,{"pump-01","plc-01","spare-01"},case["kind"]=="replay") for mode in MODES[:-1]}
            decision=gate.evaluate(envelope)
            observed["risk"]=decision.outcome
            for mode in MODES:
                rows.append({**case,"mode":mode,"observed":observed[mode],
                             "matches_desired":observed[mode]==case["desired"],
                             "decision_code": decision.code if mode=="risk" else "synthetic_ablation"})
    return rows


def summary_for(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result={}
    for mode in MODES:
        group=[r for r in rows if r["mode"]==mode]
        counts=Counter(r["observed"] for r in group)
        per_kind={}
        for kind in KINDS:
            subset=[r for r in group if r["kind"]==kind]
            per_kind[kind]=dict(Counter(r["observed"] for r in subset))
        result[mode]={"cases":len(group),"allow":counts["allow"],"block":counts["block"],"defer":counts["defer"],
                      "matches_desired":sum(r["matches_desired"] for r in group),"by_kind":per_kind}
    return result


def run_review_cases(variants: int = 3) -> list[dict[str, Any]]:
    """Designed local reviewer-key scenarios; no real human review is implied."""
    if type(variants) is not int or not 1 <= variants <= 20:
        raise ValueError('variants must be 1..20')
    rows=[]
    with tempfile.TemporaryDirectory(prefix='edgeguardra-review-') as tmp:
        for kind,expected in REVIEW_EXPECTED.items():
            for i in range(variants):
                case_id=f'{kind}-{i:02d}'
                store=Store(Path(tmp)/(case_id+'.db'), create=True)
                store.put_device('plc-01','critical','compromised',NOW-2-i,now=NOW)
                policy=example_policy()
                policy['review_grants']['limited']={'restore':['plc-01']}
                policy['review_grants']['defender']={'quarantine':['plc-01']}
                ak,rk,lk,sk,ek,nk=(secrets.token_bytes(32) for _ in range(6))
                agent_keys={'defender':{'v1':ak}}
                reviewer_keys={'reviewer':{'v1':rk},'limited':{'v1':lk},'defender':{'v1':sk}}
                gate=Gate(store,policy,agent_keys=agent_keys,reviewer_keys=reviewer_keys,clock=lambda:NOW)
                gate.activate_configuration()
                if kind=='evidence_revoked':
                    sensor=EvidenceIngestor(store,source_keys={'sensor':{'v1':ek}},
                                            allowed_devices={'sensor':['plc-01']},clock=lambda:NOW)
                    sensor.activate_configuration()
                    observation={'source_id':'sensor','key_id':'v1','device_id':'plc-01','signal':'compromised',
                                 'observed_at':NOW-1,'issued_at':NOW,'nonce':'evidence-'+case_id}
                    if not sensor.ingest(sign(observation,ek))['accepted']:
                        raise RuntimeError('review evidence setup failed')
                decision=gate.evaluate(sign(make_proposal(case_id,'nonce-'+case_id,NOW,target='plc-01'),ak))
                if decision.code!='review_required':raise RuntimeError('review scenario setup failed')
                reviewer='limited' if kind=='ungranted_reviewer' else 'defender' if kind=='self_review' else 'reviewer'
                key=lk if reviewer=='limited' else sk if reviewer=='defender' else rk
                approval=make_approval(decision,'review-'+case_id,NOW-1 if kind=='approval_before_decision' else NOW,reviewer_id=reviewer)
                if kind=='wrong_challenge':approval['review_challenge']='0'*64
                envelope=sign(approval,key)
                if kind=='context_changed':store.put_device('plc-01','critical','compromised',NOW,now=NOW)
                if kind=='configuration_changed':
                    policy['version']='demo-v2'
                    gate=Gate(store,policy,agent_keys=agent_keys,reviewer_keys=reviewer_keys,clock=lambda:NOW)
                    gate.activate_configuration()
                if kind=='evidence_revoked':
                    replacement=EvidenceIngestor(store,source_keys={'sensor':{'v1':nk}},
                                                  allowed_devices={'sensor':['plc-01']},clock=lambda:NOW)
                    replacement.activate_configuration()
                first=''
                if kind=='replayed_approval':first=gate.approve(envelope).code
                measured=gate.approve(envelope)
                executed=''
                if kind=='valid_review':executed=Sandbox(gate).execute(case_id,agent_id='defender')['executed']
                rows.append({'id':case_id,'kind':kind,'variant':i,'expected_code':expected,'observed_code':measured.code,
                             'matches_expected':measured.code==expected,'first_approval_code':first,'simulated_execution':executed})
    return rows


def measure_local(samples=200):
    """Measure same-host SQLite gate and simulated execution, not LLM or OT."""
    if type(samples) is not int or not 10 <= samples <= 5000:
        raise ValueError("latency samples must be 10..5000")
    with tempfile.TemporaryDirectory(prefix="edgeguardra-timing-") as tmp:
        store=Store(Path(tmp)/'timing.db', create=True);store.put_device('pump-01','routine','normal',NOW-1,now=NOW)
        ak,rk=secrets.token_bytes(32),secrets.token_bytes(32)
        gate=Gate(store,example_policy(),agent_keys={'defender':{'v1':ak}},reviewer_keys={'reviewer':{'v1':rk}},clock=lambda:NOW)
        gate.activate_configuration()
        broker=Sandbox(gate);raw=[]
        for i in range(samples):
            e=sign(make_proposal(f'bench-{i}',f'nonce-{i}',NOW,action='inspect'),ak)
            start=time.perf_counter_ns();d=gate.evaluate(e);middle=time.perf_counter_ns();result=broker.execute(d.request_id,agent_id=d.agent_id);end=time.perf_counter_ns()
            if d.outcome!='allow' or not result['executed']: raise RuntimeError('timing setup failed')
            raw.append({'sample':i,'gate_ns':middle-start,'sandbox_execute_ns':end-middle,'combined_ns':end-start})
        values=sorted(r['combined_ns']/1000 for r in raw)
        perf={'samples':samples,'combined_median_us':round(statistics.median(values),3),
              'combined_p95_us':round(values[int(.95*(samples-1))],3),
              'combined_p99_us':round(values[int(.99*(samples-1))],3),
              'scope':'same-host SQLite gate plus simulated broker with identity checks and without a required checkpoint; excludes signing, LLM, network, and real devices'}
        return raw,perf


def measure_checkpoint_reads(samples: int = 20):
    """Compare identity-pinned read transactions with and without checkpoint verification."""
    if type(samples) is not int or not 2 <= samples <= 1000:
        raise ValueError('checkpoint samples must be 2..1000')
    rows=[]
    with tempfile.TemporaryDirectory(prefix='edgeguardra-anchor-timing-') as tmp:
        for entries in (10, 100, 500):
            store=Store(Path(tmp)/f'{entries}.db',create=True)
            for _ in range(entries):
                store.put_device('pump-01','routine','normal',NOW-1,now=NOW)
            checkpoint=store.audit_checkpoint()
            guarded=Store(store.path,required_checkpoint=checkpoint)
            for sample in range(samples):
                # Alternate order to reduce a consistent ordering bias.
                modes=[('unguarded',store),('checkpoint',guarded)]
                if sample % 2: modes.reverse()
                for mode,instance in modes:
                    start=time.perf_counter_ns()
                    with instance.read_transaction(): pass
                    elapsed=time.perf_counter_ns()-start
                    rows.append({'audit_entries':entries,'sample':sample,'mode':mode,'elapsed_ns':elapsed})
    summary={'samples_per_mode_and_size':samples,
             'scope':'same-host identity-pinned SQLite read transaction, with or without full audit-chain validation; excludes gate, model, network and devices',
             'by_size':{}}
    for entries in (10,100,500):
        summary['by_size'][str(entries)]={}
        for mode in ('unguarded','checkpoint'):
            values=sorted(r['elapsed_ns']/1000 for r in rows if r['audit_entries']==entries and r['mode']==mode)
            summary['by_size'][str(entries)][mode]={'median_us':round(statistics.median(values),3),
                                                    'p95_us':round(values[int(.95*(samples-1))],3)}
    return rows,summary


def run(out_path: str | Path, *, variants=3, latency_samples=200) -> dict[str, Any]:
    if type(variants) is not int or not 1 <= variants <= 20:
        raise ValueError('variants must be 1..20')
    if type(latency_samples) is not int or not 10 <= latency_samples <= 5000:
        raise ValueError('latency samples must be 10..5000')
    out=Path(out_path)
    # A run is never permitted to reuse any existing directory, including an empty one.
    out.mkdir(parents=True,exist_ok=False)
    rows=run_cases(variants)
    review_rows=run_review_cases(variants)
    raw,latency=measure_local(latency_samples)
    checkpoint_raw,checkpoint_latency=measure_checkpoint_reads()
    results=summary_for(rows)
    sources = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sorted(Path(__file__).parent.glob('*.py'))}
    from .environment import collect_environment
    summary={'version':__version__,'source_sha256':sources,
             'archetypes':len(KINDS),'variants_per_archetype':variants,
             'cases_per_mode':len(KINDS)*variants,'decision_records':len(rows),'results':results,'latency':latency,
             'checkpoint_read_latency':checkpoint_latency,
             'review_evaluation':{'archetypes':len(REVIEW_EXPECTED),'cases':len(review_rows),
                                  'matches_expected':sum(r['matches_expected'] for r in review_rows),
                                  'valid_simulated_executions':sum(r['simulated_execution'] is True for r in review_rows),
                                  'by_kind':{kind:dict(Counter(r['observed_code'] for r in review_rows if r['kind']==kind)) for kind in REVIEW_EXPECTED}},
             'environment':collect_environment(),
             'limitations':['Only synthetic labelled scenarios; variants are not independent real-world incidents.',
                'The ground-truth field is assigned by the scenario designer, not measured from equipment.',
                'No real LLM, human reviewer, network adversary or physical device was evaluated.',
                'Baselines are minimal in-process ablations, not third-party tools.',
                'The database and the application process are trusted; authenticated source data may be wrong.']}
    keys=['id','kind','variant','group','action','agent','target','criticality','signal','ground_truth','evidence_method','context_age','issued_at','desired','mode','observed','matches_desired','decision_code']
    with (out/'decisions.csv').open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(rows)
    with (out/'timing_samples.csv').open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['sample','gate_ns','sandbox_execute_ns','combined_ns']);w.writeheader();w.writerows(raw)
    with (out/'review_decisions.csv').open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['id','kind','variant','expected_code','observed_code','matches_expected','first_approval_code','simulated_execution'])
        w.writeheader();w.writerows(review_rows)
    with (out/'checkpoint_timing_samples.csv').open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['audit_entries','sample','mode','elapsed_ns'])
        w.writeheader();w.writerows(checkpoint_raw)
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    return summary

