# EdgeGuardRA 0.22.0

EdgeGuardRA is a research toolkit for studying risk-aware authorization of proposed IoT security actions. It accepts structured, authenticated proposals, checks capabilities and local context, and applies permitted actions **only to simulated SQLite state**. It includes a separate simulated review path, authenticated evidence ingestion, synthetic evaluation, and an optional local Ollama-compatible adapter.

This prototype is **not a production gateway or safety controller**. The Python process, operator, credentials, system clock and local database are trusted. There is no physical-device adapter or network enforcement. A caller with direct database or device access can bypass this code. See `docs/SECURITY.md` before interpreting any result.

## Quick start

Requires Python 3.10 or newer; the runtime and test suite use the standard library only. Run from this extracted directory:

```sh
python -m edgeguardra --version
python -m edgeguardra demo
python -m unittest discover -s tests -v
python -m edgeguardra check-policy examples/policy.json
python -m edgeguardra evaluate --out runs/my-first-run
```

`demo` creates a temporary database and random ephemeral credentials. It demonstrates a routine action, a critical action approved with a test reviewer key, and a tampered request. The reviewer is simulated, not a person. The evaluator requires a new output directory and refuses to overwrite an existing one. Its CSV files contain individual cases and timing samples; `summary.json` records aggregates and source digests. The included `results/reproduction` contains ten fresh-process runs, all raw samples, run-level uncertainty, a completion manifest, the worked example and manuscript figures.

For an editable installation with locally available setuptools >= 61:

```sh
python -m pip install --no-deps --no-build-isolation -e .
```

## Reproduce the paper and inspect a full example

```sh
python -m edgeguardra worked-example
python -m pip install -r requirements-reproduce.txt
python -m edgeguardra check-environment environment.lock.json
python -m edgeguardra reproduce --out runs/paper --repeats 10 --figures
```

`reproduce` refuses any existing output directory. It runs sequential fresh Python processes and retains every raw sample. The reported bootstrap intervals resample whole-run statistics and describe variation on one shared host. `check-environment` compares the exact interpreter, SQLite and optional plotting package versions with the supplied lock; it reports differences rather than silently claiming a match. Without `--figures`, reproduction needs no third-party libraries. The lock is not an immutable OS image. See `docs/EXPERIMENT.md`, `docs/WORKED_EXAMPLE.md` and `docs/INTERFACES.md`.

## What is included

* Authenticated, exact-schema proposals and distinct agent/reviewer keyrings; no default production keys.
* An explicit `(agent, action, target)` policy and hard denials; configurable ordinal action/criticality weights and threshold.
* Request identifiers, approvals and simulated execution are scoped by agent identity so separate agents can use the same request identifier without colliding.
* Persistent, transactional anti-replay state with nonce records retained beyond their original expiry, and a monotonically increasing configuration generation shared by processes using one SQLite database; denial-path clock observations are also persisted, and clock dependency failures deny stateful operations.
* Authenticated, source-authorized sensor evidence ingestion and versioned simulated context; equally timed contradictory reports produce an unknown context, and evidence configuration changes invalidate earlier signed context for quarantine and restore.
* Explicit `(reviewer, action, target)` grants, self-review denial and a random per-decision review challenge; approval is bound to the request, policy, generation, context and expiry.
* Simulated execution revalidates state and consumes the decision once; audit records link decision, approval and execution hashes; an optional independently retained checkpoint can be enforced on guarded state transactions.
* An optional, opt-in loopback `/api/chat` model adapter, deterministic scripted agent, and four offline evaluation conditions.

`Gate.activate_configuration()` and `EvidenceIngestor.activate_configuration()` are trusted operator operations; callers must explicitly activate the intended key and policy configuration before evaluating proposals or ingesting evidence. Each activation advances its own generation and invalidates older instances of that configuration. Gate activation invalidates earlier decisions; evidence activation invalidates earlier source-derived contexts used by quarantine and restore and dependent pending authorizations. Configure participating workers after activation. Key material must be generated and provisioned securely; different identities, roles and key versions must use different secrets. Fixed test keys are fixtures only; minimum length does not guarantee entropy. Version 0.22 can reopen intact schema-5 state, including 0.21 state with the same active configuration. A missing clock high-water mark in a database with retained state, or an out-of-range or invalid mark, is rejected without automatic repair. All shared-database workers must use the upgraded rejection clock checks if those checks are required; older workers can still lose valid time on handled input exceptions. A database whose only fingerprint uniqueness index is partial is rejected. New database creation requires `Store(path, create=True)`; opening an existing database uses `Store(path)`. If a database is reset or prior nonce cleanup is uncertain, use fresh credentials to address outstanding signed messages; activation can invalidate pending work. Signed approvals and simulated execution require `agent_id`. See `docs/SECURITY.md` and `docs/MIGRATION.md` before migration.

## Approval versions and exceptional input rejection

Approval `context_version` must be an exact integer from 1 through 9,223,372,036,854,775,807 inclusive, the signed SQLite INTEGER range. Values outside that range are rejected as `invalid_approval_schema` before canonical JSON serialization or reviewer authentication. Ordinary in-range messages and their HMAC bytes are unchanged. An invalid envelope does not approve a pending decision or consume an approval nonce.

If proposal or approval processing raises a handled input exception after a valid clock read, its denial path now carries that observation into the rejection transaction rather than replacing it with a new initial reading. A lower subsequent reading returns `clock_rollback`; a failed subsequent reading returns `invalid_clock`. In either case the earlier valid mark can persist without an audit entry for the rejection. This requires a successful transaction commit; unavailable storage, a failed audit write or a process interruption can still lose the observation. The fix cannot reconstruct time readings lost by older code. The reproduced oversized-integer case uses the direct Python approval API and a finite Python integer-to-string conversion limit; it is not a demonstrated JSON or network exploit.

## Configuration digest input

The trusted low-level `Store.activate_configuration` API requires exactly 64 ASCII hexadecimal characters for its digest. Uppercase and mixed-case hexadecimal remain accepted and are stored in lowercase. Spaces, tabs, line endings, other whitespace, non-hexadecimal characters and wrong lengths are refused with `ValueError` before the supplied clock is invoked or a configuration transaction begins. This preflight rejection changes no digest, generation, key registration, decision, clock mark or audit entry. It is distinct from a later credential-reuse rejection after time has been observed.

Version 0.20 checked string length and `bytes.fromhex` decodability. That decoder accepts ASCII whitespace, so a 64-character string could represent fewer than 32 bytes and still activate, leaving ordinary configured workers inactive. This is an administrative input and availability issue under the trusted-operator boundary. The exact syntax check does not establish that a well-formed digest corresponds to the intended policy or keys; prefer the high-level gate/evidence activation methods, which compute their commitments.

Previously stored malformed digests are not repaired on upgrade. A hash-consistent audit chain can contain the earlier malformed activation, so `verify-audit` is not a configuration health check. Stop affected workers, assess the intended configuration and reactivate it through the appropriate trusted gate or evidence object. Reactivation advances a generation, invalidates older dependent workers or decisions, and can require fresh evidence. Do not strip, pad or guess a replacement digest. See `docs/MIGRATION.md`.

## Rejected configuration activation

When activation encounters a credential-reuse constraint after reading a valid trusted clock, the attempted key registration is rolled back while the outer transaction commits the observed clock high-water mark and a `configuration_rejected` event. The active configuration digest, generation and key registrations are preserved. `ValueError` is raised after that commit. A rejected activation can therefore advance the clock mark and audit head; callers must not assume that a failed call made no persistent writes. Existing decisions remain subject to their original time, context and policy checks.

If the clock is invalid or unavailable, or storage, audit writing, transaction commit or process execution fails, the observation and event may not persist. A clock value in the allowed range may still be wrong. Rejected activation can reduce availability after an erroneous forward clock observation; repair credentials and assess time rather than lowering the mark or deleting replay state to force a retry.

## Database identity

Each `Store` pins the database's audit identity when it opens or creates the file. Subsequent high-level read and write transactions, and `verify_audit`, check that identity in their own SQLite snapshot even when no required checkpoint was configured. If the path later refers to a different audit identity, those operations fail before reading or changing application state. `verify_audit` returns `database_identity_changed`; direct operations such as `device`, `put_device` and configuration activation raise `StoreIdentityError`, a `ValueError` subclass. A rejected operation may therefore have no audit entry in the replacement database. Raw `connect()` and direct SQL bypass these checks.

This is an in-memory continuity check for an existing instance. A stale snapshot with the same audit identity is not detected by identity alone, and a deliberately reopened instance pins whichever valid database is present. The check does not authenticate other tables or make hot file replacement safe. Stop all workers and SQLite connections before recovery, assess the correct database and replay history, and retain recent independent checkpoints where required. Reopening is not proof that history was preserved.

## Read-only audit verification

Check an existing schema-5 file from the command line:

```sh
python -m edgeguardra verify-audit /path/to/state.db
python -m edgeguardra verify-audit /path/to/state.db --checkpoint /trusted/earlier-checkpoint.json
```

The optional `--expected-head` argument requires an independently retained, lowercase 64-character SHA-256 head and must match the exact current head; unlike a prefix checkpoint, it stops matching after an append. Both arguments are checked against the same SQLite snapshot. A checkpoint file contains the `audit_id`, `seq` and `hash` object previously obtained from `store.audit_checkpoint()` and retained independently in trusted storage. A checkpoint taken from the database after an incident cannot establish its earlier authenticity.

The equivalent Python API is `Store.verify_audit_file(path, expected_head=None, checkpoint=None)`. It opens SQLite with `mode=ro` and query-only access, uses a read transaction and never constructs an application `Store` or initializes a missing database. SQLite locking and WAL access requirements still apply. It reports `scope: audit_chain_only`; it does not validate inventory, replay, clock or configuration state, pin identity between separate calls, install a guard on workers, or repair a file. Without an independent anchor, `valid: true, anchored: false` means hash-chain consistency only. `anchored: true` means the caller-supplied anchor matched; trust in that anchor remains the caller's responsibility. A self-consistent old snapshot or rewritten unanchored suffix can still pass.

The command prints JSON and exits with 0 for successful verification, 1 for failed or unavailable verification, and 2 for CLI syntax or checkpoint input errors. An explicitly supplied null, malformed, duplicate-key or oversized checkpoint file is refused rather than treated as no anchor. Hash-chain and exact-head mismatches report `audit_hash_mismatch` and `expected_head_mismatch`, respectively. These additional failure codes are also returned by the existing audit-verification API; its success results are unchanged. A malformed expected-head value is a failed check with exit status 1 and `invalid_expected_head`.

## Optional recovery checkpoint

After creating and populating an experiment database, obtain `checkpoint = store.audit_checkpoint()` and retain that small object independently in trusted storage. Reopen every worker with `Store(existing_path, required_checkpoint=checkpoint)` to enforce that previously verified audit prefix at startup and in guarded state transactions. This option is **not enabled by default**. On a guarded store, `verify_audit(checkpoint=other)` checks the required and supplied checkpoints in one database snapshot, even if the supplied object compares equal to the required checkpoint. This explicit dual check scans the chain twice. The expected head and checkpoint identifiers must have the documented lowercase hexadecimal form; the supplied checkpoint cannot replace the required one. Update and independently retain new checkpoints deliberately; a stale checkpoint cannot detect every rollback. The check scans the audit chain, protects only the anchored prefix and does not authenticate the remaining SQLite tables. Direct calls to `connect()`, database changes outside the toolkit and older unguarded workers bypass enforcement. See `docs/SECURITY.md` and `docs/MIGRATION.md` for recovery limits.

## Evidence conflicts

An authenticated, authorized report whose observation time equals the currently stored time but whose signal differs changes the context to `unknown`, increments its version and returns `accepted: true` with `code: evidence_conflict`. This result records the conflict; it does not accept the incoming signal as the device's true state. The stored `source_id` is an empty string to mark a derived conflict rather than a sensor identity, and `evidence_hash` is a digest of the conflict record, not the digest of one signed sensor report. The audit event records the previous context and incoming evidence digest. Another conflicting report at the same timestamp does not resolve the unknown state. A valid report with a strictly later observation time can replace it; trusted administrative updates can also override context.

This is a narrow equal-time rule, not sensor fusion or a quorum. Older reports are rejected, and the toolkit does not wait for all sources or know which sources are missing. A conflicting report that arrives after an action cannot undo it. Signed observations can be false, and different timestamp values or inaccurate clocks may conceal a conflict. On upgrade, previously ignored reports cannot be reconstructed from the old rejection records; review outstanding decisions and refresh observations as described in `docs/MIGRATION.md`.

## Clock and input limits

When a rejection audit entry is recorded, valid clock observations and that entry are committed together; readings before and after acquiring the database lock are compared with a persisted high-water mark. If a later clock read fails, an earlier valid observation may still be committed while the requested action remains denied. Storage failure or process interruption can prevent this, and a rollback or failed clock can prevent audit logging. Nonce records are retained for an additional 86,700 seconds after their stored expiry to cover later supported TTL and skew increases. Message validity itself is unchanged, and records already deleted by older versions cannot be reconstructed. Longer retention consumes storage; use fresh nonces. A missing high-water mark is rejected if other persistent state remains; an initialized but empty store can still record its first clock observation. This cannot identify a lost mark if all other detectable state has also been lost. With concurrent workers, these conservative checks can reduce availability. A trusted, reliable wall clock and recovery procedures remain operator responsibilities.

Trusted `Store.put_device` administration requires device identifiers of 1–128 ASCII letters, digits, `_`, `.`, `:`, or `-`, matching the action policy. `now` and `observed_at` must be integer Unix seconds in the inclusive range 0 through 4,102,444,800; booleans, millisecond values outside that range and other types are rejected before state changes. A future observation that is still in range may be stored, but the gate defers until it is not in the future. These checks cannot verify that an in-range clock or observation is accurate.

Proposal, approval, evidence and candidate dictionaries are copied before schema validation. Proposal actions, approval verdicts and evidence signals must be strings before their allowed values are compared. String-valued subclasses are normalized to their actual string value; message keys must be ordinary strings. Validation and authentication use the detached scalar message. Callers should avoid modifying their inputs while an operation is starting; the copy does not protect against malicious code in the trusted process.

JSON text inputs longer than the configured byte limit are rejected before UTF-8 encoding; inputs with fewer characters but larger UTF-8 encodings are rejected after encoding. This prevents an avoidable encoded copy of an already oversized string, but does not bound allocations made by callers before passing the input.

For cross-language checking, public test-only HMAC vectors are in `examples/signature_vectors.json`; `node examples/verify_vectors.js` verifies these fixtures independently using Node.js when installed. The Python runtime does not require Node.js. The example covers selected flat messages, not all possible inputs or a general canonical JSON standard.

## Optional local model

If the operator already runs a compatible model service on this machine, and has installed a model separately:

```sh
python -m edgeguardra llm-demo --url http://127.0.0.1:11434/api/chat \
  --model YOUR_LOCAL_MODEL --telemetry 'Simulated alert for pump-01'
```

Append `--execute-simulated` to apply an allowed action to a temporary simulated database. The adapter accepts only explicit numeric loopback HTTP endpoints, uses a direct connection without proxies or redirects, rejects ambiguous framing and truncated declared responses, and enforces a best-effort total network deadline and response-size limit. The deadline is not a hard real-time bound and excludes local JSON processing. Duplicate Content-Length headers are rejected even when identical; close-delimited responses have no independently verifiable length. The adapter requests unencoded content and accepts an absent Content-Encoding header or one identity value only. Other encodings, lists and duplicate encoding fields are rejected before JSON processing; no decompression is attempted. The non-streaming adapter requires HTTP 200; other statuses, including 201, 202 and 206, are rejected before reading the body. A parsed response object containing a top-level `error` field is rejected even when its value is empty, null or non-string and even when completion fields look valid. A model response must also include `done: true` and an `assistant` message; if `done_reason` is present, only `stop` is accepted. This is a service assertion, not proof that model output is accurate or safe. The local service may have its own network behavior; the operator is responsible for it. The model's action proposal is not an authorization. The wrapper adds identity, nonce, timestamp and a MAC independently of the model. Do not enter sensitive telemetry into a demo. No actual model was available or evaluated in the included snapshot; fake HTTP services test the protocol only. Adapter failures raise `ValueError`; the CLI exits with status 2. Service-error details are not echoed. No automatic retry or fallback candidate is used, and an adapter failure creates no gate decision or gate audit event. A later successful call still requires normal signing, gate authorization and one-time simulated execution.

## Reproduction and status

See `docs/EXPERIMENT.md` for scenario labels, ablations and measurement limits. Baselines are small in-process ablations, not external products. Scenario labels are hand designed, and variants are not independent incidents. HMAC authenticates possession of a secret but does not prove that a sensor is correct or that a human performed a review.

Citation metadata is in `CITATION.cff` and `codemeta.json`. Maintainer contact: Yang Lu, yanglu@klust.edu.cn. The public source repository and issue tracker are linked below. Release DOI and open-source license selection remain pending. No open-source permission is implied by public visibility. Archive identifiers will be inserted consistently in citation metadata and the manuscript after archiving.

## Repository and support

Source: https://github.com/ziiyuu-lgtm/EdgeGuardRA

Issue tracker: https://github.com/ziiyuu-lgtm/EdgeGuardRA/issues

License selection and permanent archive identifiers are pending. Public visibility does not grant an open-source license. The reviewed research software version is 0.22.0.
