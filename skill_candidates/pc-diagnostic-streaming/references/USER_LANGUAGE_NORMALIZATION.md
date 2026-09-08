# User Language Normalization Layer

## Purpose
Convert non-technical customer descriptions into structured technical observations without pretending that the customer's wording is already a diagnosis.

The agent MUST treat ordinary-language descriptions as sensory/context evidence that requires normalization before technical reasoning.

Core pipeline:

`RAW CUSTOMER WORDING -> OBSERVABLE FACTS -> CANONICAL SYMPTOM CONCEPTS -> COMPETING TECHNICAL INTERPRETATIONS -> TARGETED DISCRIMINATOR -> MACHINE EVIDENCE`

Never jump directly from the customer's phrase to a root cause.

## Three-layer representation
Every important human statement should be represented in three distinct layers.

### Layer 1: Raw wording
Preserve exactly what the customer meant or said.

Example:
- `"the computer freezes"`
- `"the Internet disappears"`
- `"the screen dies"`
- `"the fan suddenly screams"`

This layer must never be overwritten by later interpretation.

### Layer 2: Normalized observable statement
Translate the wording into what was actually observed, without adding a cause.

Examples:
- `perceived_system_unresponsive`
- `user_cannot_reach_expected_network_service`
- `display_output_lost`
- `fan_speed_increased_abruptly`

### Layer 3: Technical interpretation candidates
Map the normalized observation to one or more possible technical concepts.

Example:
`"Internet disappeared"`
can map to:
- physical_link_down
- wifi_disconnected
- dhcp_address_missing_or_changed
- default_gateway_unreachable
- dns_resolution_failure
- vpn_path_failure
- proxy_failure
- application_specific_connectivity_failure
- upstream_isp_or_router_failure

These are hypotheses, not synonyms.

## Mandatory rule: user vocabulary is not a protocol
Customers describe experience, not system state. Phrases such as the following are ambiguous by default:

- freeze / hang / stuck
- crashed
- restarted by itself
- powered off
- black screen
- blue screen
- no Internet
- network is slow
- computer is slow
- disk is broken
- RAM is full
- GPU is not working
- computer is hot
- application disappeared
- update broke it
- virus

The agent MUST NOT silently convert these phrases into precise technical facts without corroboration.

## Semantic normalization examples

| Customer wording | Safe normalized concept | Possible interpretations |
|---|---|---|
| "Máy bị đơ" | perceived_unresponsiveness | app hang, UI/session hang, GPU/display stall, I/O stall, kernel lock, hardware stall |
| "Máy tự tắt" | unexpected_loss_of_visible_operation | orderly shutdown, bugcheck then reboot, power loss, thermal trip, firmware reset |
| "Máy tự restart" | unexpected_restart | bugcheck auto-reboot, watchdog, update restart, user/process initiated restart, power dip |
| "Màn hình chết" | display_output_lost | monitor/cable, GPU driver, GPU reset, sleep state, system crash |
| "Mất mạng" | expected_network_access_unavailable | link, Wi-Fi, DHCP, gateway, DNS, VPN, firewall, proxy, upstream service |
| "Máy chậm" | perceived_performance_degradation | CPU saturation, memory pressure, paging, storage latency, thermal throttling, network/app delay |
| "Ổ cứng lỗi" | user_suspects_storage_problem | SMART/NVMe fault, filesystem error, I/O timeout, application corruption, unrelated slowdown |
| "GPU không chạy" | user_suspects_gpu_underutilization_or_failure | workload not GPU-bound, wrong adapter, driver issue, low utilization expected, telemetry misunderstanding |
| "RAM đầy" | user_observed_high_memory_usage | active working set, cache, memory leak, commit pressure, shared GPU memory, normal OS caching |
| "Bị virus" | user_suspects_malicious_activity | malware, adware, browser issue, startup software, resource saturation, account compromise |

## Ambiguity classes
Assign an ambiguity class before relying on user statements.

### A0 - Direct observation
Little interpretation required.
Examples:
- "I saw stop code 0x116."
- "The Ethernet LED turned off."
- "There was a burning smell."

### A1 - Mostly observable, mildly ambiguous
Examples:
- "The screen became black but audio continued."
- "Only Chrome stopped responding."

### A2 - Common user shorthand
Requires technical normalization.
Examples:
- "The PC froze."
- "The Internet died."
- "The machine is slow."

### A3 - User-provided diagnosis or causal claim
Treat as a hypothesis only.
Examples:
- "The RAM is bad."
- "Windows Update caused it."
- "The GPU is dead."
- "It is a virus."

A3 statements must never be promoted directly to root cause without independent evidence.

## Clarification style for non-experts
Never ask the customer to translate their experience into jargon.

Bad:
- "Did the kernel hard-lock?"
- "Was this a TDR?"
- "Did DHCP renew fail?"
- "Was the issue at Layer 2 or Layer 3?"

Better:
- "When it froze, could the mouse still move?"
- "Did the screen go black while sound kept playing?"
- "Did Wi-Fi/Ethernet still show connected even though websites would not open?"
- "Could another device on the same network still reach the Internet?"

The technical meaning stays internal; the user gets observable choices.

## Do not teach before diagnosing
The agent should not force a non-expert to learn terminology merely to continue the case.
Explain jargon only when it helps the user make a decision, understand risk, or perform a required physical step.

Instead of:
`Please check whether there is a WHEA machine-check exception.`

Say:
`Tôi đang kiểm tra nhật ký phần cứng của Windows để xem CPU/RAM/PCIe có báo lỗi hay không.`

## Preserve uncertainty
Normalization is lossy. Therefore each normalized user observation should retain:
- raw wording
- normalized concept
- ambiguity class
- interpretation candidates
- interpretation confidence
- what evidence could confirm/refute it

## Correction loop
The agent must be able to revise its interpretation without changing the original statement.

Example:
1. Customer: `"máy mất điện"`
2. Normalize: `unexpected_visible_shutdown_or_restart`
3. Initial candidates: power loss, thermal trip, bugcheck auto-reboot
4. Dump is discovered
5. Revise interpretation: `bugcheck_with_fast_auto_reboot is strongly supported`
6. Preserve original wording: customer perceived the event as power loss

This avoids falsely labeling the customer as wrong.

## Contradiction policy
Many apparent contradictions are semantic rather than factual.

Example:
- User: `"mạng vẫn có nhưng không vào mạng được"`

Possible reconciliation:
- physical/Wi-Fi link is up
- IP connectivity or DNS/Internet path is failing

Do not mark this as a contradiction until the meanings of "mạng" are separated.

## Canonical symptom ontology
Use stable internal concepts for reasoning. Recommended top-level families:
- availability
- boot
- restart_shutdown
- freeze_hang
- display_gpu
- performance
- memory
- storage_filesystem
- network_connectivity
- application
- audio_input_usb
- thermal_power
- update_driver
- security_suspicion

Each family can contain more specific normalized concepts and can load the relevant micro-skill.

## Language policy
The agent may receive Vietnamese, Japanese, English, slang, vendor terms, mistranslations, or mixed-language descriptions.
Normalize meaning, not grammar.

Do not punish spelling mistakes or require exact terminology.
When multiple interpretations are plausible, preserve all reasonable candidates until machine evidence or a low-effort question separates them.

## Diagnostic objective
The goal is not to make the customer speak like an engineer.
The goal is to transform human experience into technically useful evidence with the least possible customer effort and without introducing false precision.
