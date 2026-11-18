# PoC approval, timeout, cancellation and cleanup (D-043)

- Non-read-only plans require a persisted `approvals` row with action `poc.execute`,
  state `granted`, matching investigation, and unexpired approval.
- Approval requests, decisions and requester cancellation are appended to the investigation
  event store. The identity provider is still a development stub; approver identity is
  recorded as the event actor, while the nullable `decided_by` FK remains unset.
- The runner enforces total and per-step elapsed-time budgets between allowlisted actions.
- Cancellation is cooperative and process-local: an active plan can be signalled through
  the API; the runner observes it between bounded steps. It cannot interrupt an action already
  executing. This is adequate for the current in-process deterministic harness, not a claim
  of hard preemption for future external tools.
- Cleanup always runs in a `finally` path. Current local harness cleanup resets in-memory
  context; temporary-workspace cleanup records that no workspace was created.
- State-changing execution remains disabled even with approval. No state-changing adapter
  is registered in this milestone.
- Migration 0006 is additive and CI-only; downgrade refuses populated PoC run records.


## Exact plan binding (PR #49)

Each PoC approval stores a canonical SHA-256 digest of the full typed TestPlan excluding only
`approval_id`. The runner recomputes and checks the digest, so approval cannot be reused after
changing target, hypothesis set, step list, expected outcome or budgets. Expired decisions are
persisted as `expired` with an event. Migration 0007 is additive and CI-only.
