# Signed evidence, review and one-time simulated execution

Run `python -m edgeguardra worked-example` from the project directory, or call `edgeguardra.worked_example.run_worked_example()`. The example uses a temporary database, fresh ephemeral secrets, a fixed synthetic clock, and a critical device called `plc-01`. It prints JSON and deletes temporary state after completion. The reproduction bundle retains one output in `worked_example.json`.

The initial detector context is unknown. The defender is granted quarantine permission on the device, and a separately keyed reviewer is granted review permission. The example then executes these steps:

| Stage | Expected result | Meaning |
|---|---|---|
| Unknown context | defer / insufficient_or_conflicting_evidence | A grant alone does not supply evidence. |
| Signed evidence | evidence_accepted | An authorized test source reports compromised with a fresh nonce and later observation time. |
| Critical proposal | defer / review_required | Action weight 2 plus critical addition 2 reaches the review threshold 3. |
| Review | approved_for_sandbox | A scoped test reviewer signs the bound challenge and context version. |
| Execute once | sandbox_only / executed=true | The broker rechecks eligibility and marks simulated inventory quarantined. |
| Execute again | not_authorized / executed=false | The consumed decision cannot be used twice. |
| Reuse evidence nonce | evidence_replay | The original signed observation cannot be accepted again. |
| Alter a signed target | block / invalid_signature | Changing a proposal after signing invalidates its MAC. |

The final inventory has `quarantined=1`, and the audit chain is internally consistent with `anchored=false`. This example does not create an independent anchor. Random audit identity, key-dependent evidence digests, review challenges and hash values change between executions; branch codes and the simulated effect are the reproducible assertions.

The source key authenticates possession of a secret, not sensor truth. The reviewer is a test key, not a human. All effects are database updates. This example does not demonstrate an LLM's behavior, physical isolation or field attack prevention.
