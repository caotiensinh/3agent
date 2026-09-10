# WorkSpace Network AI V3-02C Source-Family Binding Amendment v1

## Status

**FROZEN BEFORE V3-02C-5 LANL FLOW IMPLEMENTATION**

This amendment tightens the previously frozen LANL multi-source adapter contract after harness review identified an ambiguity: LANL authentication and flow records can both contain nine comma-delimited fields, so field count alone is not a sufficient source-family boundary.

This amendment takes precedence over any weaker interpretation of `docs/WORKSPACE_NETWORK_V3_02C_LANL_SPEC_V1.md`.

## 1. Objective

Bind every staged LANL shard to an explicit source-family namespace supplied by the acquisition/manifest contract so adapters never infer family from payload shape.

```text
manifest/acquisition contract
        |
        +-- lanl/auth/...     -> LANLAuthAdapter only
        +-- lanl/process/...  -> LANLProcessAdapter only
        +-- lanl/dns/...      -> LANLDNSAdapter only
        +-- lanl/flow/...     -> LANLFlowAdapter only
        +-- lanl/redteam/...  -> LANLRedTeamTruthMatcher only
```

## 2. Canonical binding

The existing mandatory `AdapterInputContract.source_object_ref` becomes the authoritative source-family binding for LANL V3-02C.

Allowed namespace prefixes are exactly:

```text
lanl/auth/
lanl/process/
lanl/dns/
lanl/flow/
lanl/redteam/
```

The namespace is a logical manifest reference, not a host filesystem path.

## 3. Adapter rule

Before source inspection or parsing, every LANL source-family component MUST verify that `source_object_ref` starts with its exact allowed namespace.

Examples:

```text
LANLAuthAdapter    + lanl/auth/shard-0001.txt     -> allowed
LANLAuthAdapter    + lanl/flow/shard-0001.txt     -> FAIL_SCHEMA
LANLFlowAdapter    + lanl/flow/shard-0001.txt     -> allowed
LANLFlowAdapter    + lanl/auth/shard-0001.txt     -> FAIL_SCHEMA
```

The parser MUST NOT fall back to field count, content heuristics, filenames outside the logical manifest reference, model classification, nearest schema, or first successfully parsed mode.

## 4. Security rationale

Authentication and flow rows can both have nine fields. Without an explicit manifest binding, a crafted or misrouted shard could be interpreted by the wrong parser if enough fields happen to be parseable.

Therefore:

```text
wrong source-family namespace = FAIL_SCHEMA
```

regardless of whether the payload could otherwise be parsed.

## 5. Harness additions

Mandatory regression fixtures:

```text
auth_ref_to_auth_adapter             -> PASS
process_ref_to_process_adapter       -> PASS
dns_ref_to_dns_adapter               -> PASS
flow_ref_to_flow_adapter             -> PASS
redteam_ref_to_truth_matcher         -> PASS
flow_ref_to_auth_adapter             -> FAIL_SCHEMA
auth_ref_to_flow_adapter             -> FAIL_SCHEMA
process_ref_to_dns_adapter           -> FAIL_SCHEMA
dns_ref_to_process_adapter           -> FAIL_SCHEMA
```

The critical adversarial fixture is `wrong_family_auth_as_flow`: even when a row has nine fields, `LANLFlowAdapter` must reject the source before parsing because the manifest namespace is `lanl/auth/`.

## 6. PASS / FAIL

PASS requires:

- 100% exact namespace-to-adapter binding;
- 0 source-family guesses;
- 0 cross-family acceptance;
- 0 content-based fallback;
- all previous digest/path/budget/provenance gates remain enforced;
- Python 3.11/3.12 harness regression PASS;
- installer/portable/Windows regression PASS.

Any cross-family acceptance is a zero-tolerance `FAIL_SCHEMA` condition.

## 7. Implementation order after this amendment

```text
A. add deterministic LANL source-family namespace validator
B. apply validator to Auth / Process / DNS adapters
C. add cross-family regression harness
D. exact-head 4/4 CI
E. only then implement LANLFlowAdapter
F. Flow exact-head 4/4 CI
G. only then implement LANLRedTeamTruthMatcher
```
