# Synthetic evaluation and reproducibility

The runtime and tests require Python 3.10+ and the standard library. Optional figure dependencies are pinned in `requirements-reproduce.txt`. `environment.lock.json` records the exact CPython, SQLite and plotting versions used for the supplied results, plus the visible host and resource limits. It is a version manifest, not an immutable operating-system image. Other valid Python installations can run the toolkit; they may not match this reproduction environment.

## One-command reproduction

From the extracted project directory, use a NEW output path:

```sh
python -m pip install -r requirements-reproduce.txt
python -m edgeguardra check-environment environment.lock.json
python -m edgeguardra reproduce --out runs/paper --repeats 10 --figures
```

`check-environment` returns 0 on a version match, 1 on a reported mismatch and 2 on invalid input. A version mismatch is reported explicitly; the reproduction command does not claim that a different environment is identical. With optional figures disabled, `reproduce` has no third-party runtime dependencies. Existing directories are refused even if empty. An interrupted run is retained for inspection and must not be reused. Only a completed run has `manifest.json` with `complete: true` and checksums of every requested output. Checksums are not signatures or external publication identifiers.

The supplied `results/reproduction` was generated with the command above. Each `run-01` through `run-10` is a fresh sequential Python process. Each creates fresh temporary SQLite databases and ephemeral keys. No timing samples are discarded. Every run supplies action decisions, review decisions, 200 gate-plus-execution timing samples, 120 checkpoint-read timing samples and a source-hashed `summary.json`. The top level supplies `repeat_summary.csv`, `report.json`, `environment.json`, `worked_example.json`, manuscript figures and the completion manifest. The first run is a representative functional snapshot; all ten functional summaries must agree for reproduction to complete.

To repeat only one experiment or regenerate graphics from an existing snapshot:

```sh
python -m edgeguardra evaluate --out runs/single
python scripts/make_figures.py --snapshot results/reproduction/run-01/summary.json --out runs/figures
```

## Designed scenarios

Seventeen action archetypes have three parameter variants, giving 51 cases per condition and 204 action records per run. Four deliberately minimal offline conditions use the same fixtures: unguarded permits all proposals; schema validates representation; capability adds selected authentication, freshness, permission, target and replay checks; risk uses the complete gate. These ablations are not third-party baselines or runtime deployment modes. Variants are not independent devices, incidents or model outputs. Designer labels are not physical safety measurements, so no population accuracy interval is calculated for label matches.

The false-positive-evidence archetype deliberately sets the synthetic device truth to normal while a signed source reports compromised. The risk-aware gate permits routine quarantine. This retained counterexample shows that authenticated observations may be false; it is not an estimated field error rate.

Nine separate reviewer-key archetypes, each with three variants, cover valid review, missing grants, self-review, incorrect challenge, approval predating a decision, repeated approval, changed context, changed policy and revoked evidence. Expected codes were assigned with the implementation. Only the three valid-review cases attempt successful simulated execution. Repeated approval is rejected without consuming the first approval; this is not an experiment with human reviewers.

## Timing and uncertainty

Each run measures 200 pre-signed routine inspection requests through the identity-checked gate and simulated broker without a required checkpoint. The interval excludes signing, model inference, transport, review and real devices. Sample positions are retained, including early operations and database growth; no warm-up samples are removed. Per-run p95 and p99 use the sorted observation at `int(q * (n - 1))`, matching the evaluator.

The separate read experiment alternates checkpoint and unguarded transaction order for 20 reads per mode at audit lengths of 10, 100 and 500. Both modes check database identity; the checkpoint mode also scans the whole current audit chain on every read. Each run retains all 120 samples. This is not an end-to-end authorization or read-only CLI benchmark.

`repeat_summary.csv` contains the run-level median, p95 and p99, and the six read medians. `report.json` reports their mean, median, sample standard deviation, observed range and a percentile-bootstrap 95% interval for the mean, using 10,000 resamples of whole-run summaries and seed 20261031. Individual operations are not treated as 2,000 independent experiments. Intervals describe variation on one shared host and fixed workload; they do not establish performance on a population of devices or a hard real-time bound. Guest-visible CPU, logical cores, affinity, cgroup CPU/memory limits, Python, SQLite and timer resolution are recorded. Storage, co-tenancy, scheduling and physical CPU allocation are not controlled.

## Validation scope

Regression tests cover strict schemas, authenticators, scoped grants and replay state, time and integer boundaries, context conflicts, configuration changes, approval binding, single-use simulated execution, database identity, audit anchors and loopback HTTP protocol faults. Negative controls retain limitations such as false signed evidence, same-identity rollback without a sufficient anchor, lost nonce history, audit verification not attesting inventory, and storage failure preventing clock persistence. Some tests use direct local fault injection outside the trusted database/process boundary. They are not demonstrated remote attacks.

The worked example is documented in `docs/WORKED_EXAMPLE.md`. It uses fixed synthetic times and newly generated secrets; audit identifiers and hashes intentionally differ between executions. No secret key is exported. No real LLM, adaptive prompt-injection attack, person, actuator, OT network or external comparison tool was evaluated. Formal verification, independent usability review, CI, other operating systems and operational capacity remain unreported.
