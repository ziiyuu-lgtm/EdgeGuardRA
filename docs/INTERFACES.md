# Command-line and Python interfaces

## Commands

Run `python -m edgeguardra --help` or append `--help` to a command. An installed package also provides the equivalent `edgeguardra` console entry point.

| Command | Inputs and outputs |
|---|---|
| `--version` | Prints the software version. |
| `demo` | Runs the small temporary action/review demo and prints JSON. |
| `worked-example` | Prints the complete signed-evidence-to-execution trace. |
| `check-policy PATH` | Reads bounded JSON and prints validation plus policy digest; does not activate policy. |
| `evaluate --out NEW_PATH` | Saves one synthetic study. Optional `--variants` 1..20 and `--latency-samples` 10..5000; defaults 3 and 200. |
| `reproduce --out NEW_PATH` | Runs the paper workload in fresh processes. Optional `--repeats` 2..30, `--latency-samples` 10..5000 and `--figures`; defaults 10 and 200. |
| `check-environment [PATH]` | Compares Python, SQLite and optional plotting versions with `environment.lock.json` by default. |
| `verify-audit PATH` | Opens an existing schema-5 file read-only. Optional `--checkpoint FILE` and `--expected-head HEX` are checked in the same snapshot. Output scope is always `audit_chain_only`. |
| `llm-demo --model NAME --telemetry TEXT` | Opt-in existing local model service; optional `--url` numeric loopback HTTP `/api/chat` and `--execute-simulated`. No model is downloaded or started. |

Successful commands return 0. Invalid command/input or ordinary file errors return 2 with a readable error. `verify-audit` returns 1 when verification fails or is unavailable. `check-environment` returns 1 for a reported mismatch. Reproduction retains incomplete output on failure and never overwrites it. The optional plotting command requires the pinned reproduction requirements; the other commands use the standard library.

## Python entry points

| Interface | Contract |
|---|---|
| `Store(path, create=True)` / `Store(path)` | Explicitly create a new database or open existing schema-5 state. Optional `required_checkpoint` guards transactions. Operators own file, keys, clock and recovery. |
| `Store.put_device(...)`, `device(id)` | Trusted inventory administration and inspection. Device identifiers and integer times are validated; observations are not independently verified. |
| `Gate(store, policy, agent_keys=..., reviewer_keys=..., clock=...)` | Configure the action policy and distinct role keyrings. Call `activate_configuration()` explicitly as a trusted operator. |
| `Gate.evaluate(envelope)` | Returns a Decision with allow, block or defer plus a code and binding metadata; does not execute an action. |
| `Gate.approve(envelope)` | Only a bound, eligible review-required decision can be approved. Returns a Decision. |
| `Sandbox(gate).execute(request_id, agent_id=...)` | Rechecks state, grants, generation, expiry and binding; consumes one authorized decision for a simulated update. |
| `EvidenceIngestor(store, source_keys=..., allowed_devices=..., clock=...)` | Explicitly activate evidence configuration, then `ingest(envelope)` returns accepted/code/context version where relevant. |
| `sign(payload, key)` | Produces the project-specific canonical JSON/HMAC envelope. Use independent secrets per identity, role and key version. |
| `parse_json_envelope(raw, max_bytes=...)` | Bounded, duplicate-key-rejecting JSON input parser. Schema checks remain with the receiving interface. |
| `authorize_candidate(...)` | Validates an untrusted candidate and adds trusted identity, nonce, time and signature. |
| `LocalOllama(url, model).propose(telemetry)` | Optional loopback HTTP candidate adapter. Raises ValueError on protocol failure before signing or gate logging. |
| `Store.audit_checkpoint()`, `verify_audit(...)` | Capture or inspect a prefix checkpoint/head. Retain an anchor independently if using it for continuity. |
| `Store.verify_audit_file(path, expected_head=None, checkpoint=None)` | Read-only audit-chain inspection; does not attest inventory or construct a guarded application Store. |
| `run_worked_example()` / `run_reproduction(out, ...)` | Import from `worked_example` / `reproduce`; contracts match the CLI. |

The concrete constructor arguments and message fields appear in `edgeguardra/worked_example.py`, `edgeguardra/demo.py` and `examples/signature_vectors.json`. Lower-level connection/transaction and raw SQL interfaces are trusted escape hatches, not an enforcement boundary. Read `SECURITY.md` and `MIGRATION.md` before operating persistent state.
