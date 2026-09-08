# Adaptive Diagnostic Loop

## Goal
Minimize time-to-root-cause and customer effort by performing interview, evidence collection, hypothesis updates, and safe tests concurrently.

## Mental model
A support interaction is an event stream, not a form to complete.

Possible incoming events:
- `USER_OBSERVATION`
- `USER_ANSWER`
- `EVENT_LOG`
- `KERNEL_LOG`
- `DUMP_FOUND`
- `TELEMETRY`
- `INVENTORY`
- `COMMAND_RESULT`
- `CHANGE_HISTORY`
- `REPAIR_RESULT`
- `VERIFICATION_RESULT`

Any incoming event can change what should happen next.

## Controller pseudocode

```text
case = initialize(symptom)

while not stop_condition(case):
    observations = consume_available_inputs()

    for obs in observations:
        preserve_raw(obs)
        normalize(obs)
        correlate_timeline(obs)
        attach_to_subsystem(obs)
        update_hypotheses(obs)
        detect_contradictions(obs)

    if dangerous_condition_detected(case):
        prioritize_safety_or_escalation()
        continue

    if evidence_threshold_reached(case):
        choose_targeted_test_or_repair()
        continue

    candidate_questions = generate_discriminating_questions(case)
    candidate_tests = generate_safe_evidence_actions(case)

    next_action = rank_by(
        information_gain,
        reliability,
        customer_effort,
        system_risk,
        time_to_result
    )

    execute_or_ask(next_action)
```

## Parallelism rule
Do not serialize work unnecessarily.

Bad:
```text
Ask 15 questions -> wait -> collect logs -> wait -> analyze -> repair
```

Preferred:
```text
Q1/Q2 asked
  |-- user answers when convenient
  |-- S0 logs collected now
  |-- timeline built now
  |-- hypotheses updated now
  |-- next question changes based on logs
```

Example:

```text
USER: "PC freezes and restarts."

Agent immediately:
- begins read-only event collection
- asks: "Does it show BSOD, or does the screen instantly go black/reboot?"

Evidence arrives first:
- Event 1001 + MEMORY.DMP found
- Event 41 follows the bugcheck

Controller update:
- planned PSU question becomes lower priority
- bugcheck/driver/hardware path becomes higher priority
- next question changes to whether failure started after driver/hardware change
- dump analysis becomes the next machine action
```

The old question plan is disposable. New evidence always has permission to change it.

## Information gain policy
A question/test is valuable if its possible answers split the current leading hypotheses.

High-value example:
```text
Top hypotheses:
1. GPU/display hang
2. full kernel lock

Question: "Can the machine still be pinged/SSH'd while the screen is frozen?"
```

Low-value example:
```text
"What exact brand is your keyboard?"
```
when no hypothesis depends on keyboard hardware.

## Evidence reliability
Reliability is contextual, not absolute.

Typical strengths:
- Crash dump stack / hardware error record: strong for recorded failure mechanism
- OS/kernel event timestamp: strong for recorded state and chronology
- SMART/NVMe health counters: useful for storage state, but a clean status does not exclude every failure
- Continuous external monitoring: strong for reachability and time windows
- User sensory observation: strong for visual/audio/physical symptoms
- User memory of exact timestamps/codes: useful but may be approximate

Never discard a user statement simply because a log disagrees. Model what each source is capable of observing.

## Contradiction resolution
Contradictions are diagnostic assets.

For every conflict record:
- observation A
- observation B
- sources
- timestamps
- why they conflict
- possible reconciliation
- discriminator needed

Example:
```text
A: User reports "complete PC freeze"
B: Remote monitor shows ICMP + SSH remained alive

Reconciliation candidates:
- display/GPU/session freeze perceived as full freeze
- remote telemetry sampled before/after but not during incident

Next discriminator:
- inspect SSH/session/kernel logs in exact incident window
```

## Customer patience policy
If customer engagement is low:
1. Reduce questions.
2. Prefer automatic S0 evidence collection.
3. Ask only questions that cannot be learned from the machine.
4. Use simple language.
5. Make each question explainable by immediate diagnostic value.
6. Never punish skipped questions by restarting the interview.

## Early completion
A case can complete before the interview completes.

Example:
```text
User begins describing a random reboot.
Collector finds reproducible WHEA PCIe errors tied to a specific GPU plus matching crash timestamps.
A targeted hardware isolation confirms the error disappears with that device removed/reseated/replaced.

=> Stop asking generic reboot questions.
=> Record root cause, repair, and verification.
```

## Avoiding logic pollution
Do not accumulate every old question/guess indefinitely.
Keep:
- immutable observation history
- current active hypotheses
- excluded hypotheses and exclusion reason
- unresolved contradictions

Retire:
- questions that no longer separate active hypotheses
- tests made irrelevant by stronger evidence
- generic troubleshooting steps superseded by a confirmed path

This prevents a long support conversation from becoming logically inconsistent.
