# Network Security Intelligence v0.0.2

## Purpose

This phase strengthens WorkSpace network/security analysis while preserving the local-first confidential-data boundary. Public corpora are external evidence used for offline experience extraction, training-data preparation and evaluation. They do not grant the model Internet, LAN, shell, packet-capture, remediation or deployment authority.

Issue: #162

## Architecture

```text
operator-reviewed registry + data policy
              |
              v
operator-only bounded HTTPS fetch
  - exact dataset/variant/purpose plan
  - HTTPS only
  - allowlisted host + path prefix
  - no credentials / userinfo / query token / custom headers
  - public-IP preflight; private/special destinations denied
  - single object, bounded bytes, no full sync
  - SHA-256 receipt
              |
              v
ephemeral incoming cache
              |
              v
reviewed streaming adapter
  - exact schema
  - source digest rebound before parse
  - label/truth separated before visible evidence construction
              |
              +-----------------> scorer-only TruthRecord
              |
              v
canonical EvidenceRecord
              |
              v
truth-free deterministic security intelligence
  - vertical port fan-out
  - horizontal host fan-out
  - flow burst
  - low-variance periodic flow pattern
  - large outbound-transfer signal
              |
              v
advisory evidence-backed signals
```

## CTU-13 admission

CTU-13 is admitted as `enterprise_approved` for the `bidirectional-netflow` variant because the publisher identifies CTU-13 as Creative Commons CC-BY. WorkSpace must preserve publisher/dataset/paper attribution in provenance.

Only labelled bidirectional flow text is admitted in v0.0.2. The source dataset also contains malware-related material, including original executable artifacts. WorkSpace does **not** fetch, extract, execute, scan, unpack or train from those executables. Archive-wide synchronization is disabled by the global data policy.

The reviewed CTU-13 flow columns are:

`StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label`

`Label` is removed before `EvidenceRecord` construction. It exists only in scorer-side `TruthRecord` objects. Analysis code accepts `EvidenceRecord` only.

## Operator acquisition

The existing `workspace-network-data` command remains a no-network control-plane tool. Network I/O is deliberately separated into the new operator-only command:

```bash
workspace-network-fetch \
  ctu-13 \
  https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/<reviewed-file>.binetflow \
  scenario42.binetflow \
  --purpose training \
  --variant bidirectional-netflow \
  --estimated-bytes <exact-safe-upper-bound>
```

The URL is an explicit operator input. WorkSpace does not crawl the publisher site, recursively discover files, follow archive indexes, or automatically select malware artifacts.

The fetcher stages one object under the configured ephemeral incoming cache and returns a receipt containing SHA-256, byte count, plan/policy/registry fingerprints and source URL. An existing target is never overwritten.

## Meaning of "training"

In this phase, `training` means preparing provenance-bound, truth-separated offline evidence for downstream training/evaluation pipelines. It does **not** mean unattended parameter fine-tuning of the production model.

Existing WorkSpace rules remain controlling:

- raw public logs are ephemeral;
- normalized events are not durable after experience extraction;
- durable outputs are compact experience/evidence/evaluation artifacts plus provenance;
- dataset-derived skills are advisory candidates and cannot auto-promote;
- production knowledge promotion remains an authenticated operator action.

## Security intelligence signals

The analyzer produces signals, not attack verdicts.

### `VERTICAL_PORT_FANOUT`

One source contacts many destination ports on the same destination in a bounded window. This is scan-like behavior requiring corroboration.

### `HORIZONTAL_HOST_FANOUT`

One source contacts the same destination port across many destinations in a bounded window. This can support host-discovery/lateral-movement hypotheses but is not itself proof of compromise.

### `FLOW_BURST`

One source emits at least the configured number of flows in a bounded window.

### `PERIODIC_FLOW_PATTERN`

Repeated flows to the same peer have a mean period inside configured bounds and sufficiently low coefficient of variation. This is beacon-like periodicity, not proof of C2.

### `LARGE_OUTBOUND_TRANSFER`

A flow exceeds both the outbound byte threshold and source-byte ratio threshold. The signal deliberately avoids calling the event exfiltration without independent evidence.

Every signal is deterministic, carries evidence IDs, sets `ground_truth_used=false`, and has `authority=advisory`.

## License boundary for other corpora

WorkSpace must not convert "publicly downloadable" into "commercially approved".

- CSE-CIC-IDS2018 and LANL remain enterprise-approved under their reviewed registry decisions.
- CTU-13 is enterprise-approved for the admitted CC-BY flow variant.
- TON_IoT remains research-only under the current registry decision.
- UNSW-NB15 should remain research-only if added later because the publisher grants free academic research use while requiring author agreement for commercial use.
- UGR'16 remains `review_required` until commercial-use terms are explicitly recorded.
- Splunk BOTS v2 remains blocked for direct parsing by the existing dependency/runtime feasibility gate despite permissive dataset licensing.

## Explicit non-goals

v0.0.2 does not add autonomous remediation, vulnerability exploitation, malware execution, Internet threat-intelligence crawling, unbounded PCAP retention, arbitrary URL downloads, automatic fine-tuning, automatic skill promotion, or model-controlled network commands.

## Next deep-analysis candidates

Future phases should build on canonical evidence rather than adding unreviewed dependencies:

1. DNS entropy/cardinality/tunneling indicators using Zeek/DNS evidence.
2. Authentication graph analysis and lateral-movement chains using LANL auth/process evidence.
3. Multi-stage incident correlation across flow + DNS + auth + process + Suricata/Zeek sources.
4. Service-baseline drift and rare-peer analysis with deterministic rolling baselines.
5. Evaluation against CTU-13/CIC/LANL truth only in scorer-side evaluation, never in visible analyst input.
