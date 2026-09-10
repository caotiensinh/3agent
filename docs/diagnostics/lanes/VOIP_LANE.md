# VoIP Diagnostic Lane

## Goal

Build bounded local evidence for softphone and VoIP client state without registering to SIP, placing calls, probing a PBX, or capturing media.

## Safety contract

Allowed:
- local softphone process/service state
- local client presence and bounded process metadata
- bounded structured evidence

Forbidden:
- SIP registration attempts
- placing, answering, transferring, or ending calls
- microphone/speaker/media capture
- token, cookie, password, or credential extraction
- remote PBX/provider health probes
- claiming call quality or root cause from local process presence alone

## Convergence rule

This lane MUST NOT modify shared runtime wiring files. Shared registration, authority, and capability bindings are owned by the convergence lane after collector tests are green.
