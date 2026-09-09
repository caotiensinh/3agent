# Mail / Exchange Diagnostic Lane

## Goal

Build bounded local evidence for mail-client and Exchange-related user symptoms without signing in, sending mail, reading mailbox contents, or probing remote service health.

## Safety contract

Allowed:
- local mail-client process/service state
- local account/profile presence without credential material
- local cache/database metadata such as existence/size/state where safe
- bounded structured evidence

Forbidden:
- SMTP/IMAP/POP/Exchange authentication attempts
- mailbox content reads
- sending, deleting, moving, or modifying mail
- token/cookie/credential extraction
- remote provider health claims inferred from local state
- DNS/network probing inside this collector lane

## Convergence rule

This lane MUST NOT modify shared runtime wiring files. Shared registration, authority, and capability bindings are owned by the convergence lane after collector tests are green.
