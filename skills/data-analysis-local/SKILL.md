---
name: data-analysis-local
description: Analyze structured data rigorously using local evidence, explicit assumptions, and reproducible calculations.
license: Project-internal
---

# Local Data Analysis

Use this skill only when the task actually contains structured data or asks for quantitative analysis.

1. Inspect schema, row counts, data types, units, missingness, duplicates, and obvious parsing errors before analysis.
2. Preserve the original dataset. Perform transformations on an explicit working representation and record exclusions, coercions, imputations, and filters.
3. Separate descriptive statistics from inference. State sample size, assumptions, uncertainty, and material limitations.
4. Treat correlation as association unless a causal design supports a causal claim.
5. For surprising values, verify the underlying rows before reporting them as findings.
6. Prefer reproducible calculations over mental arithmetic. Keep derived metrics traceable to input fields.
7. Do not invent missing values or silently drop failed conversions.
8. Keep task data local. This skill grants no network, upload, credential, or external-service authority.
