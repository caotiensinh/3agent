# WorkSpace Efficient Reasoning Doctrine — Implementation Baseline

Status: **Normative architecture baseline**

This document translates the WorkSpace Efficient Reasoning Doctrine research into enforceable engineering rules. It does not replace the longer research report; it defines what the runtime must do.

## 1. Intelligence is not model size

WorkSpace intelligence is treated as a system property:

```text
Verified WorkSpace Intelligence
  = Relevant Context
  × Right Model
  × Safe Tools
  × External Verification
```

The system therefore optimizes the information path before increasing model size.

The execution doctrine is:

```text
MINIMIZE
  ↓
SELECT
  ↓
CONSTRAIN
  ↓
EXECUTE
  ↓
VERIFY
  ↓
ESCALATE ONLY WHEN REQUIRED
```

## 2. A local system must not become a stale system

"Local-first" means confidential computation and state stay local. It does **not** mean WorkSpace must be cut off from fresh public knowledge.

The required direction is:

```text
PUBLIC INTERNET
      ↓
Public Research Zone
      ↓
PUBLIC evidence bundle
      ↓
No-network Inbound Importer
      ↓
Public Knowledge Mirror
      ↓
Confidential Core reads locally
```

The forbidden direction remains:

```text
Confidential Core ─────X────→ Internet
Confidential prompt ───X────→ Public Research
Internal document ─────X────→ Egress Broker
```

A public knowledge mirror lets the Core use current external information without giving the process that holds confidential information an outbound network capability.

This software boundary is inspired by the unidirectional-gateway/data-diode security pattern, but it is **not** a physical data diode and must not be represented as providing hardware-enforced one-way assurance.

## 3. Public evidence is data, never authority

Every imported external source is stored as:

- classification: `public`
- trust domain: `system:public`
- trust: `untrusted_external`
- source URL
- retrieval timestamp
- SHA-256 content and chunk hashes
- prompt-injection risk tag
- immutable bundle ID
- explicit inbound-only direction

External text is never converted into system/developer instructions. Retrieved evidence is packed inside explicit `UNTRUSTED PUBLIC EVIDENCE` delimiters.

Prompt-injection scanning is defense-in-depth only. The decisive control remains outside the model: retrieved text does not grant tools, network, write scope, credentials, or authorization.

## 4. Task Contract before model/tool execution

All future WorkSpace execution paths must converge on `TaskContract`.

A contract contains:

- sensitivity and risk
- allowed sources
- allowed tools
- write scope
- network scope
- context/generation/execution budgets
- validators
- model tier and escalation ceiling
- cache trust domain
- raw-content logging policy

Security decisions are deterministic and evaluated before model routing.

Important invariants:

- `confidential|restricted|secret` cannot receive public egress.
- `secret` requires network deny.
- `web_gateway` is public-only.
- restricted/secret raw prompt and tool-output logging is denied.
- restricted/secret semantic answer caching is denied.
- policy denial is terminal; a stronger model cannot bypass it.

## 5. Context Engine v1

The first Context Engine deliberately starts with an inspectable lexical map/search/rank/pack implementation instead of immediately adding embeddings or a vector database.

Why:

1. establish provenance first;
2. establish hard budgets first;
3. measure retrieval quality;
4. add learned retrieval only if it improves verified outcomes.

Pipeline:

```text
MAP
 ↓
SEARCH
 ↓
RANK
 ↓
DEDUPLICATE
 ↓
HARD PACK
 ↓
PROVENANCE-CARRYING CONTEXT
```

The default tokenizer-independent counter uses UTF-8 bytes as a conservative budget unit. A serving adapter should later inject the exact tokenizer counter.

## 6. P0/P1 acceptance now implemented

### P0 slice
- deterministic `TaskContractCompiler`
- hard execution/context/generation budgets
- sensitivity-first network policy
- model-tier ceiling
- trust-domain cache policy
- raw-content logging policy

### P1 slice
- content-addressed public evidence bundles
- SHA-256 verification on import and retrieval corpus creation
- prompt-injection risk tagging
- deterministic public-knowledge map
- bounded retrieval and deduplication
- explicit untrusted-evidence packing

## 7. Knowledge freshness workflow

Typical operator flow:

```bash
# Public Research Zone performs a public-only task.
workspace-public research TASK-ID --live

# Turn the research artifact into a content-addressed PUBLIC bundle.
workspace-knowledge-export /var/lib/workspace-public/data/research/YYYY-MM-DD/TASK-ID.json

# Operator reviews/approves the bundle, then the no-network importer moves it inward.
workspace-knowledge-import /var/spool/workspace-public-export/kb_<digest>

# Core searches the local mirror without network access.
workspace-knowledge-search --query "NVIDIA inference optimization"

# Build a bounded, provenance-carrying evidence context.
workspace-knowledge-pack --query "NVIDIA inference optimization" --sensitivity confidential
```

Automatic import is intentionally not enabled in v1. Freshness can later be automated only for curated source policies with poisoning/approval tests.

## 8. Anti-pattern gates

The following remain architecture violations:

- biggest model everywhere;
- permanent planner/reviewer/critic chains;
- unlimited context or retries;
- unrestricted shell;
- self-verification as sole correctness proof;
- shared sensitive KV/cache across trust domains;
- raw confidential prompt logging;
- compression of authorization/security/user hard constraints;
- policy encoded only in model weights;
- routing/escalation used to bypass policy;
- adding overlapping frameworks without measured benefit.

## 9. Next measured steps

Do not immediately add vLLM, SGLang, LMCache, semantic routers, vector databases, or prompt compressors merely because they are promising.

Next gates are:

1. wire Task Contract into every existing workflow entry point;
2. make the Research capability search the local public mirror before requesting new public research;
3. add repository/document structural maps and semantic viewers;
4. build evaluation corpus and metrics;
5. benchmark vLLM vs SGLang on the actual dual-RTX5090 workload;
6. select one serving baseline from evidence;
7. add trust-domain prefix caching only after isolation tests;
8. add compression only after evidence-retention tests;
9. add specialist fine-tuning only for stable repetitive tasks.

The governing rule is simple:

> If a component does not improve verified success, security, or efficiency under measurement, WorkSpace does not need it.
