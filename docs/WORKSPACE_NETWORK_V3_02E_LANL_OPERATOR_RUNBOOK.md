# WorkSpace Network AI V3-02E — LANL Operator Runbook

This runbook is the manual handoff procedure for the remaining LANL real-source blocker. It does not authorize corpus acquisition, processing, or V3-03.

## Prerequisites

- Use a trusted local terminal on a reviewed WorkSpace checkout.
- Confirm the checkout contains the merged LANL publisher-access validator and secure operator-handoff module.
- Do not prepare a file, environment variable, command-line argument, issue comment, or chat message containing LANL publisher handles.
- Python RAM zeroization is not claimed. The guarantee is that the reviewed handoff does not deliberately persist raw handles to files, CLI arguments, environment variables, logs, or durable receipts.

## Official LANL enrollment step

1. Open only the official publisher page in your browser:
   `https://csr.lanl.gov/data/cyber1/`
2. Review the dataset description and file list on that page.
3. LANL currently asks the operator to provide an email address and a description of how the dataset will be used before download access is provided.
4. Enter that information directly on the LANL page yourself.
5. Do not copy the email address, intended-use text, cookies, tokens, or resulting publisher handles into this repository or into project evidence.

WorkSpace must not automate this form, discover alternative download locations, or fall back to a mirror.

## Expected publisher source set

The handoff expects exactly these five publisher files:

1. `auth.txt.gz` — authentication events
2. `proc.txt.gz` — process lifecycle events
3. `flows.txt.gz` — network-flow events
4. `dns.txt.gz` — DNS lookup events
5. `redteam.txt.gz` — scorer-only red-team ground truth

Do not substitute similarly named files from another host or mirror.

## Safe local handoff

From the repository root, run exactly:

```bash
PYTHONPATH=src python -m three_agent.network_lanl_operator_handoff
```

The command requests the five publisher handles interactively in this order:

1. auth
2. process
3. flow
4. DNS
5. redteam

Input uses a no-echo prompt. Paste each publisher-issued handle only into the active no-echo prompt.

Do not paste publisher handles into GitHub, CI, chat, screenshots, shell history, environment variables, command-line arguments, or files.

If you cancel or provide an incomplete set, the handoff must stop without validating or persisting a partial handle set.

## Result interpretation

### READY_FOR_LANL_EXECUTION_SPEC

All five handles passed the reviewed offline publisher-access validation.

`READY_FOR_LANL_EXECUTION_SPEC does not authorize corpus download or execution.`

At this point, stop. The next engineering checkpoint must separately freeze Goal, Spec, Harness, PASS/FAIL criteria, bounded acquisition/derivation rules, provenance, cleanup, and execution authority before any LANL corpus bytes are downloaded or processed.

### NOT_ENOUGH_REAL_SOURCE_EVIDENCE

The required publisher evidence is incomplete or the handoff was cancelled. Do not proceed to LANL execution.

### FAIL_SECURITY / FAIL_PROVENANCE / FAIL_SCHEMA

The supplied input violated the reviewed security, publisher-origin, family/path, or schema contract. Do not attempt to work around the failure. Correct the publisher-side/operator input condition and rerun the same reviewed handoff.

## Do not store or paste

Never persist or share any of the following as project evidence:

- raw LANL publisher handles;
- operator email address used for enrollment;
- intended-use text submitted to LANL;
- cookies, tokens, credentials, query strings, or fragments;
- screenshots containing publisher handles or enrollment details;
- terminal captures containing raw handles;
- files containing a copied handle set;
- environment variables containing handles;
- command history containing handles.

Do not paste publisher handles into GitHub, CI, chat, screenshots, shell history, environment variables, command-line arguments, or files.

## Safe evidence to retain

Only retain compact non-secret evidence already allowed by the reviewed contracts, such as:

- readiness state;
- failed gate identifiers;
- reviewed durable receipt/fingerprint fields that do not contain raw handles;
- exact WorkSpace commit used for the handoff.

Do not create a second receipt schema that stores or reconstructs publisher handles.

## Stop condition

Stop after the handoff reports `READY_FOR_LANL_EXECUTION_SPEC`.

Do not download, decompress, derive shards, execute LANL adapters, or run the red-team matcher under authority from this runbook.

V3-03 remains blocked until LANL real-source acceptance is complete.
