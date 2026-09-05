# WorkSpace Network AI V3-02E Runner Adapter Input Binding v1

## Status

**FROZEN BEFORE RUNNER IMPLEMENTATION**

This amendment resolves the naming boundary between the V3-02E real-source acceptance manifest and the already-existing `AdapterInputContract` without inventing acquisition facts.

## Binding rule

The production `AdapterInputContract` contains an `acquisition_plan_fingerprint` field. The V3-02E acceptance manifest intentionally contains an `acquisition_receipt_fingerprint`, not the historical acquisition-plan fingerprint.

The runner SHALL NOT copy the acquisition receipt fingerprint into the acquisition plan field or claim that the two artifacts are equivalent.

For V3-02E offline execution, the runner constructs the adapter input contract as follows:

```text
AdapterInputContract.dataset_id                    <- source.dataset_id
AdapterInputContract.variant                       <- source.variant
AdapterInputContract.source_object_ref             <- source.bounded_source_object_ref
AdapterInputContract.source_sha256                 <- source.bounded_source_sha256
AdapterInputContract.actual_source_size_bytes      <- source.bounded_source_size_bytes
AdapterInputContract.max_plan_bytes                <- frozen per-source runner budget
AdapterInputContract.acquisition_plan_fingerprint  <- validated acceptance manifest fingerprint
AdapterInputContract.registry_fingerprint          <- manifest.registry_fingerprint
AdapterInputContract.policy_fingerprint            <- manifest.policy_fingerprint
AdapterInputContract.provenance_ref                <- source.provenance_ref
AdapterInputContract.adapter_version               <- source.adapter_version
```

The field is therefore an **execution-plan binding** for this V3-02E runner invocation. It does not rewrite or replace historical acquisition provenance.

The actual `source.acquisition_receipt_fingerprint` remains separately bound in the V3-02E acceptance receipt and provenance checks.

## Prohibitions

The runner SHALL NOT:

- label the acquisition receipt as an acquisition plan;
- synthesize a historical plan fingerprint;
- omit the acquisition receipt from durable provenance;
- use the parent-source hash as the bounded-source hash;
- use a wall-clock/runtime value in any content fingerprint.

Any future requirement to preserve the original acquisition-plan fingerprint must extend the manifest schema explicitly rather than overloading the receipt field.