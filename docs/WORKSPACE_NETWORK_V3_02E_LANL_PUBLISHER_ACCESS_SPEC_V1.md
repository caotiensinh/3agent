# WorkSpace Network AI V3-02E — LANL Publisher Access Gate Specification v1

Status: **CONTRACT-FROZEN BEFORE ACCESS VALIDATOR / ACQUISITION CODE**

## 1. Goal

Establish a fail-closed publisher-access boundary for the LANL Comprehensive Multi-Source Cyber-Security Events dataset before any real-source acquisition or execution code is written.

This checkpoint answers only one question:

> Has an operator legitimately completed the publisher's access workflow and supplied sufficient publisher-origin file access for a later, separately frozen LANL execution plan?

It does **not** download corpus bytes, parse LANL events, create bounded shards, run the production adapters, train a model, create a skill, or authorize V3-03.

## 2. Prerequisite main checkpoint

Required starting point:

`18ddedf8b5c714fb3144bc051133fab9d8e3d49f`

This main checkpoint includes:

- promoted V3-02E real-source acceptance contract and offline runner;
- production LANL auth/process/DNS/flow adapters and scorer-only red-team matcher;
- CIC real publisher-source PASS evidence.

## 3. Authoritative publisher page

Publisher landing page:

`https://csr.lanl.gov/data/cyber1/`

The publisher currently states that the dataset contains 58 consecutive days of de-identified events from five source families and is approximately 12 GB compressed in total.

The publisher requires the user to provide:

- an email address;
- a description of how the dataset will be used;

before downloading the data.

WorkSpace MUST NOT fabricate either value and MUST NOT silently submit the publisher form on behalf of an operator.

## 4. Required source families

The publisher page identifies five separate files:

| Source family | Publisher filename | Publisher-listed compressed size | Runtime role |
|---|---|---:|---|
| authentication | `auth.txt.gz` | 7.2G | specialist-visible evidence |
| process | `proc.txt.gz` | 2.2G | specialist-visible evidence |
| network flow | `flows.txt.gz` | 1.1G | specialist-visible evidence |
| DNS | `dns.txt.gz` | 177M | specialist-visible evidence |
| red-team | `redteam.txt.gz` | 4.8K | scorer-only truth |

All five source families are required for the complete LANL real-source acceptance checkpoint.

A subset may be inspected later for engineering diagnostics, but a subset MUST NOT be promoted as full LANL V3-02E PASS.

## 5. Publisher-enrollment boundary

Enrollment is an operator action outside the automated WorkSpace runner.

Authorized sequence:

```text
LANL publisher page
 -> operator supplies their own email + intended use to LANL
 -> LANL exposes/provides publisher-origin file access
 -> operator supplies ephemeral access handles to WorkSpace
 -> WorkSpace validates publisher origin
 -> only then may a separate execution SPEC/HARNESS be frozen
```

WorkSpace MUST NOT:

- invent an email address;
- reuse an email address from unrelated account/profile context;
- invent intended-use text and submit it as if operator-approved;
- scrape around the publisher form to bypass enrollment;
- substitute a mirror, Kaggle, Hugging Face, GitHub, torrent, cache, or third-party copy;
- persist the operator's email or form contents as project evidence.

## 6. Ephemeral access-handle contract

A future access validator may consume operator-provided access handles only from an ephemeral local input that is excluded from Git and durable CI artifacts.

For each of the five filenames, the handle MUST identify publisher-origin access from LANL.

Automatic acceptance requires all of the following:

- HTTPS;
- hostname exactly `csr.lanl.gov`;
- path begins with `/data/`;
- final path component matches the required publisher filename for that source family;
- no embedded `user:password@host` authority;
- no alternate hostname, redirect target, or mirror;
- no URL query or fragment unless a later dedicated security review explicitly authorizes the publisher's mechanism.

The access gate MUST fail closed rather than guessing when the publisher changes its delivery mechanism.

Raw access handles are **ephemeral secrets/sensitive access material** for WorkSpace purposes even when the publisher files themselves are public-release data. They MUST NOT be copied into Git, comments, logs, receipts, issue bodies, PR bodies, or uploaded artifacts.

Durable evidence may contain only a non-reversible fingerprint of a validated access-handle binding plus the canonical publisher landing-page reference and required filename.

## 7. Access readiness states

This gate has only these meaningful readiness outcomes:

### `READY_FOR_LANL_EXECUTION_SPEC`

Allowed only when all five publisher-origin handles are present and pass the frozen origin/filename rules.

This is **not** a V3-02E PASS. It only authorizes freezing the next LANL acquisition/execution contract.

### `NOT_ENOUGH_REAL_SOURCE_EVIDENCE`

Required when:

- enrollment has not been completed;
- no publisher handles were supplied;
- fewer than five required source families are available;
- publisher access mechanism cannot be validated under this contract without inventing assumptions.

### Hard failure

Use the existing V3 verdict families where applicable:

- `FAIL_SECURITY`
- `FAIL_PROVENANCE`
- `FAIL_SCHEMA`
- `FAIL_LICENSE`

There is no `PASS_WITH_WARNING`.

## 8. Zero-tolerance access failures

Any one of these blocks readiness:

- `LANL_ENROLLMENT_BYPASS_ATTEMPT`
- `LANL_OPERATOR_IDENTITY_FABRICATED`
- `LANL_OPERATOR_FORM_CONTENT_PERSISTED`
- `LANL_MIRROR_OR_ALTERNATE_HOST`
- `LANL_ACCESS_HANDLE_MISSING`
- `LANL_SOURCE_FAMILY_MISSING`
- `LANL_FILENAME_MISMATCH`
- `LANL_ACCESS_HANDLE_HAS_CREDENTIAL_AUTHORITY`
- `LANL_UNREVIEWED_QUERY_OR_FRAGMENT`
- `LANL_ACCESS_HANDLE_IN_DURABLE_OUTPUT`
- `LANL_ACQUISITION_ATTEMPT_BEFORE_EXECUTION_SPEC`
- `LANL_REDTEAM_TRUTH_USED_TO_SELECT_VISIBLE_SOURCE`
- `BOTS_DIRECT_ADAPTER_ATTEMPT`
- `V3_03_STARTED_BEFORE_LANL_REAL_SOURCE_PASS`

## 9. Known source semantics frozen from publisher documentation

The later execution plan MUST preserve these source semantics:

### `auth.txt.gz`

Fields:

`time,source user@domain,destination user@domain,source computer,destination computer,authentication type,logon type,authentication orientation,success/failure`

### `proc.txt.gz`

Fields:

`time,user@domain,computer,process name,start/end`

### `flows.txt.gz`

Fields:

`time,duration,source computer,source port,destination computer,destination port,protocol,packet count,byte count`

### `dns.txt.gz`

Fields:

`time,source computer,computer resolved`

### `redteam.txt.gz`

Fields:

`time,user@domain,source computer,destination computer`

The publisher documents red-team events as known compromise events taken from authentication data and suitable as ground truth. `redteam.txt.gz` therefore remains scorer-only.

`?` means no valid value is present.

Times are de-identified epoch offsets beginning at 1 second; the real collection timeframe is intentionally undisclosed. A later execution plan MUST NOT invent UTC or wall-clock timestamps.

## 10. Resource reality and required future bounded plan

The publisher-listed parent files are much larger than the existing V3-02E per-source bound of 256 MiB except for the tiny red-team file and potentially the compressed DNS parent.

Therefore, after valid publisher access is available, the next LANL execution contract MUST freeze deterministic streaming parent-to-bounded derivations before acquisition/execution code.

It MUST NOT raise the production limits merely to process the whole corpus.

The future plan must separately define:

- parent compressed SHA-256 and size binding;
- safe streaming gzip integrity handling;
- deterministic bounded derivation for auth/process/flow/DNS;
- exact handling of the tiny scorer-only red-team source;
- bounded object and total-byte budgets;
- record-count budgets;
- relative-time representation;
- `?` missing-value handling;
- de-identified user/computer/process/port semantics;
- exact red-team-to-auth matching;
- cleanup of parent compressed and bounded plaintext staging.

## 11. Hidden-truth rule for future LANL slicing

The future visible-source derivation MUST NOT use `redteam.txt.gz` contents, red-team labels, known compromise flags, or scorer truth to choose which authentication/process/DNS/flow records become specialist-visible evidence.

In particular:

```text
redteam truth -> may score already-selected auth evidence
redteam truth -> MUST NOT select visible auth evidence
```

If a dedicated adapter-acceptance slice needs a publisher-documented example window, that window must be frozen explicitly in a later spec and clearly classified as adapter acceptance evidence only, never held-out specialist evaluation/training data.

## 12. Durable outputs for this access gate

Allowed:

- this specification;
- machine-readable access contract;
- synthetic/adversarial access-validator fixtures;
- hash/fingerprint-only access readiness receipt after validator implementation.

Forbidden:

- operator email;
- operator intended-use text;
- raw publisher download URLs;
- URL query strings/fragments;
- cookies/session state;
- credentials/tokens;
- LANL corpus bytes;
- bounded LANL records.

## 13. PASS/FAIL contract before code

Before an access validator may be implemented, a machine-readable harness MUST freeze:

- exact publisher landing-page host;
- exact five source families and filenames;
- enrollment-required state;
- no automated form submission;
- ephemeral-only access-handle policy;
- durable-field denylist;
- readiness states;
- zero-tolerance failures;
- adversarial fixtures for mirror/credential/query/missing-family/leakage attempts.

Only after that harness is committed may validator code be written.

## 14. Current truthful state

At the time this specification is frozen:

```text
CIC real publisher source = PASS
LANL publisher access      = NOT_ENOUGH_REAL_SOURCE_EVIDENCE
BOTS direct adapter        = BLOCKED_DEPENDENCY_COST
V3-03                      = BLOCKED
```

No publisher-issued LANL access handles have been supplied to this WorkSpace execution context.

## 15. Next-step rule

After this spec and its machine harness pass exact-head CI:

- if no valid publisher access is supplied: stop at `NOT_ENOUGH_REAL_SOURCE_EVIDENCE`;
- if valid publisher access is supplied: freeze a separate LANL bounded acquisition/execution SPEC -> HARNESS -> PASS/FAIL -> FIXTURES before writing downloader/derivation/runner integration code.

Do not bypass this boundary to accelerate V3-03.
