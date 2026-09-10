# WorkSpace Composite Strategy Policy v0.0.1

**Status:** Mandatory project-wide execution supplement  
**Scope:** every human, AI agent, sub-agent, automation, CI worker, or future execution role working on WorkSpace  
**Authority:** subordinate to WorkSpace security policy, `TaskContract`, and `docs/WORKSPACE_EXECUTION_GOVERNANCE_V0_0_1.md`; this policy never grants runtime capability

## 1. Purpose

WorkSpace MUST solve difficult or blocked work by combining complementary strategies rather than treating fallback methods as mutually exclusive choices.

The default recovery model is:

```text
problem / bottleneck
    |
    +--> discovery lane --------- repository/tree/history evidence
    +--> isolation lane --------- dependency boundary / minimal reproducer
    +--> contract lane ---------- protocol/schema/adapter-first progress
    +--> verification lane ------ deterministic tests / negative evidence
    +--> escape lane ------------ local snapshot/grep/instrumentation when needed
                |
                +---- evidence convergence ----+
                                             |
                                      safest verified result
```

A strategy portfolio is preferred over a single-strategy retry when multiple methods can safely progress in parallel.

## 2. Mandatory composite-strategy rules

1. A non-trivial bottleneck MUST be classified before retrying it.
2. When two or more complementary in-authority methods can reduce uncertainty independently, they MUST be combined or run in parallel instead of selecting only one by default.
3. A composite recovery plan SHOULD contain at least three distinct strategy families when the problem is materially uncertain or repeatedly failing.
4. Strategy families MUST contribute different information or progress. Cosmetic variants of the same failed method do not count as diversity.
5. Discovery failure MUST NOT automatically block contract, adapter, test, documentation, or other dependency-isolated work.
6. A concrete implementation dependency SHOULD be isolated behind a stable protocol/adapter when doing so preserves the existing source of truth and authority model.
7. Repository/code-search failure MUST be distinguished from proof that code does not exist. If search/indexing is unavailable or incomplete, combine direct tree traversal, commit archaeology, known-path reads, and exact-head local snapshot/grep as applicable.
8. Exact-head local inspection is an escape strategy, not a new authority source. Local findings MUST still be reconciled to the exact repository head before a PASS/READY claim.
9. Results from parallel strategies MUST converge through evidence comparison. Contradictory results remain unresolved until the contradiction is explained or one source is proven stale/invalid.
10. Security, confidentiality, authority, and fail-closed constraints are hard gates; composite execution cannot combine unsafe strategies merely for speed.

## 3. Strategy portfolio model

For a typical engineering bottleneck, use the following portfolio when applicable:

| Strategy family | Purpose | Example output |
|---|---|---|
| `DIRECT_DISCOVERY` | inspect exact repository/runtime structure | file/tree/import map |
| `HISTORY_ARCHAEOLOGY` | recover implementation intent and ownership | commits/PRs/changed files |
| `DEPENDENCY_ISOLATION` | prevent one unknown from blocking all work | minimal reproducer/boundary |
| `PROTOCOL_FIRST` | progress safely before concrete binding is known | protocol + test adapter |
| `LOCAL_EXACT_HEAD_INSPECTION` | escape remote search/index limitations | grep/AST/import evidence |
| `DETERMINISTIC_VERIFICATION` | prove or disprove candidate behavior | tests/checks/hashes |
| `NEGATIVE_SECURITY_TESTING` | prove authority/scope isolation | denial/tamper/cross-scope tests |

The actor SHOULD select the smallest useful portfolio that covers the uncertainty. It MUST NOT perform redundant work solely to increase the number of strategies.

## 4. Stagnation and escalation

The anti-loop rule applies to both individual strategies and the portfolio as a whole.

- Same state + same method + same failure + no new evidence => do not retry blindly.
- If one strategy fails, keep productive independent strategies running and replace only the failed lane when possible.
- If the whole portfolio stops producing new evidence, decompose the problem, introduce a genuinely different strategy family, or prove an external/security blocker.
- A `BLOCKED` claim requires evidence that viable in-authority composite alternatives were attempted or ruled out.

## 5. Selection and convergence

Correctness, security, and mandatory acceptance are hard gates. Among candidates that satisfy those gates, compare:

- verified correctness;
- evidence strength;
- implementation complexity;
- operational risk;
- maintainability;
- resource/token/tool cost;
- time to verified completion.

Prefer a hybrid solution when combining two safe candidates removes weaknesses that either candidate has alone. Do not optimize for speed by discarding required evidence or security boundaries.

## 6. WorkSpace H2 bottleneck example

If GitHub code search is not indexed, WorkSpace SHOULD combine:

```text
A: direct Contents/Tree traversal
B: commit/PR archaeology
C: protocol/adapter-first H2 implementation
D: deterministic unit/security tests
E: exact-head local snapshot + grep/AST as escape path
```

A and B discover the existing implementation, C prevents that discovery from blocking independent H2 work, D verifies invariants continuously, and E removes remote-index dependency when necessary. The final adapter binding is accepted only after the evidence converges on the exact existing source of truth.

## 7. Required session evidence

When composite recovery is used, the session report MUST include:

- bottleneck/failure signature;
- strategy families used;
- evidence produced by each strategy;
- strategies rejected and why;
- convergence decision;
- lane PASS/FAIL/BLOCKED states;
- exact-head test/CI evidence;
- completion percent and remaining percent;
- commits created or merged.
