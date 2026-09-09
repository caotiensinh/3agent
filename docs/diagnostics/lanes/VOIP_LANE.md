# VoIP Diagnostic Lane

## Goal

Build bounded local evidence for VoIP/softphone symptoms without placing calls, registering accounts, probing SIP servers, or capturing voice/media content.

## Safety contract

Allowed:
- local softphone process/service state
- local audio device presence through existing evidence primitives
- local client configuration presence without credential values
- bounded structured evidence

Forbidden:
- SIP registration attempts
- placing or answering calls
- RTP/media capture
- reading passwords, tokens, or private keys
- probing SIP gateways or Internet reachability
- mutating audio/network configuration
- claiming PBX/provider outage from local state

## Convergence rule

This lane MUST NOT modify shared runtime wiring files. Shared registration, authority, and capability bindings are owned by the convergence lane after collector tests are green.
