from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sys
import tempfile
import time
from . import __version__
from .agents import LocalOllama, authorize_candidate
from .demo import demo, setup
from .evaluate import run
from .environment import check_environment
from .reproduce import run_reproduction
from .worked_example import run_worked_example
from .gate import _policy, parse_json_envelope
from .sandbox import Sandbox
from .store import Store, _validated_checkpoint


def main(argv=None):
    p=argparse.ArgumentParser(description='EdgeGuardRA offline research sandbox')
    p.add_argument('--version',action='version',version=__version__)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('demo',help='run isolated synthetic action and approval scenarios')
    ev=sub.add_parser('evaluate',help='write a NEW synthetic experiment directory')
    ev.add_argument('--out',help='must not already exist; defaults to a new runs directory')
    ev.add_argument('--variants',type=int,default=3)
    ev.add_argument('--latency-samples',type=int,default=200)
    rep=sub.add_parser('reproduce',help='repeat paper workloads in fresh processes; NEW output only')
    rep.add_argument('--out',required=True)
    rep.add_argument('--repeats',type=int,default=10)
    rep.add_argument('--latency-samples',type=int,default=200)
    rep.add_argument('--figures',action='store_true',help='requires pinned optional Matplotlib dependencies')
    sub.add_parser('worked-example',help='print the signed-evidence, review and single-use example')
    env=sub.add_parser('check-environment',help='compare versions with the supplied environment lock')
    env.add_argument('path',nargs='?',default='environment.lock.json')
    cp=sub.add_parser('check-policy',help='validate a policy file and print its digest')
    cp.add_argument('path')
    audit=sub.add_parser('verify-audit',help='read-only audit-chain verification; other state is not attested')
    audit.add_argument('path',help='existing schema-5 SQLite database')
    audit.add_argument('--checkpoint',help='independently retained checkpoint JSON file')
    audit.add_argument('--expected-head',help='independently retained lowercase SHA-256 audit head')
    llm=sub.add_parser('llm-demo',help='opt-in local model -> gate -> optional simulated execution')
    llm.add_argument('--url',default='http://127.0.0.1:11434/api/chat')
    llm.add_argument('--model',required=True)
    llm.add_argument('--telemetry',required=True,help='do not use sensitive data in demo experiments')
    llm.add_argument('--execute-simulated',action='store_true',help='execute only in temporary SQLite state')
    args=p.parse_args(argv)
    try:
        if args.command=='demo':
            with tempfile.TemporaryDirectory(prefix='edgeguardra-demo-') as t:
                result=demo(Path(t)/'state.db',int(time.time()))
            print(json.dumps(result,indent=2))
        elif args.command=='worked-example':
            print(json.dumps(run_worked_example(),indent=2))
        elif args.command=='check-environment':
            result=check_environment(args.path)
            print(json.dumps(result,indent=2))
            return 0 if result['matches'] else 1
        elif args.command=='reproduce':
            result=run_reproduction(args.out,repeats=args.repeats,
                                    latency_samples=args.latency_samples,figures=args.figures)
            print(json.dumps({'output':args.out,'repeats':result['repeats'],
                              'functional_results_identical':result['functional_results_identical'],
                              'statistics_us':result['statistics_us']},indent=2))
        elif args.command=='evaluate':
            default='runs/run-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(3)
            out=args.out or default
            result=run(out,variants=args.variants,latency_samples=args.latency_samples)
            print(json.dumps({'output':out,'cases_per_mode':result['cases_per_mode'],
                              'decision_records':result['decision_records'],'results':result['results'],
                              'review_evaluation':result['review_evaluation'],'latency':result['latency']},indent=2))
        elif args.command=='check-policy':
            with Path(args.path).open('rb') as policy_file:
                raw = policy_file.read(65537)
            policy=parse_json_envelope(raw,max_bytes=65536)
            _,digest=_policy(policy)
            print(json.dumps({'valid':True,'policy_digest':digest}))
        elif args.command=='verify-audit':
            checkpoint=None
            if args.checkpoint is not None:
                with Path(args.checkpoint).open('rb') as checkpoint_file:
                    raw=checkpoint_file.read(65537)
                checkpoint=_validated_checkpoint(parse_json_envelope(raw,max_bytes=65536))
                if checkpoint is None:
                    # An explicit null or malformed checkpoint must not
                    # silently become verification without an anchor.
                    raise ValueError('invalid audit checkpoint')
            result=Store.verify_audit_file(args.path,args.expected_head,checkpoint=checkpoint)
            print(json.dumps(result,indent=2))
            return 0 if result['valid'] else 1
        else:
            candidate=LocalOllama(args.url,args.model).propose(args.telemetry)
            with tempfile.TemporaryDirectory(prefix='edgeguardra-llm-') as tmp:
                now=int(time.time());gate,keys=setup(Path(tmp)/'state.db',now)
                envelope=authorize_candidate(candidate,agent_id='defender',key_id='v1',request_id='llm-demo',
                          nonce='llm-nonce',issued_at=now,agent_key=keys['defender'])
                decision=gate.evaluate(envelope)
                effect=Sandbox(gate).execute('llm-demo',agent_id='defender') if args.execute_simulated and decision.outcome=='allow' else None
                print(json.dumps({'candidate':candidate,'decision':decision.as_dict(),'simulated_execution':effect,
                                  'scope':'local model response; temporary simulated device state only'},indent=2))
    except (ValueError, OSError, FileExistsError, json.JSONDecodeError, RecursionError) as exc:
        print('EdgeGuardRA error:',str(exc),file=sys.stderr)
        return 2
    return 0


if __name__=='__main__': raise SystemExit(main())

