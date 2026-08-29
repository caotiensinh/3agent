# WorkSpace Public Research Zone

## Security objective

Confidential business information must not share a runtime trust domain with a process that can reach the public Internet.

DLP is defense-in-depth, but no text classifier can prove that an arbitrary string is not a transformed business secret. Therefore WorkSpace high-assurance mode removes the architectural opportunity: **Confidential Core cannot access the egress broker at all.**

## Three-zone design

```text
CONFIDENTIAL CORE                 PUBLIC RESEARCH               EGRESS BROKER
workspace-core                    workspace-public              workspace-egress
/var/lib/workspace                /var/lib/workspace-public     no business-data store
      |                                  |                            |
      | localhost Ollama                 | localhost Ollama           | DNS + HTTPS
      |                                  |                            |
      X---------------- broker ----------+---- AF_UNIX --------------> Internet
      ^             NO ACCESS
      |
confidential data never enters a process with public egress authority
```

### Confidential Core

- owns `/var/lib/workspace` mode `0700`;
- may access local Ollama ports only;
- is not a member of the egress IPC group;
- cannot connect to `/run/workspace/egress.sock`;
- nftables rejects all non-loopback network traffic for its UID;
- canonical config keeps `public_search_enabled=false`.

### Public Research worker

- separate OS identity `workspace-public`;
- separate SQLite/artifact root under `/var/lib/workspace-public`;
- cannot read `/var/lib/workspace`;
- no shell execution gateway in its canonical config;
- no direct network access; nftables permits only localhost Ollama;
- may talk to the egress broker over the Unix socket;
- queries still pass strict DLP, length limits and search-host policy.

### Egress Broker

- separate OS identity `workspace-egress`;
- systemd makes both confidential and public data roots inaccessible;
- accepts IPC only from the exact `workspace-public` UID using peer credentials;
- only `research` capability is accepted;
- arbitrary POST, upload bodies, cookies, authorization headers and caller-defined headers are unsupported;
- DNS is restricted to the local system resolver stub;
- nftables rejects LAN, loopback, link-local, CGNAT, multicast and special-use destinations;
- public network access is TCP/443 only;
- result fetching requires URLs learned from a search response and is one-time/short-lived.

## Data transfer rule

There is intentionally no automatic Confidential-Core -> Public-Research transfer.

An operator may create a **public-only research question** in the public zone. It must not contain internal filenames, source code, customer information, private IPs, internal project identifiers, credentials, unpublished specifications or confidential excerpts.

Public research results remain under `/var/lib/workspace-public`. Moving a result into the confidential zone is an **inbound-only operator action** after inspection. Web content remains untrusted evidence and cannot change WorkSpace policy.

## Why this is stronger than DLP alone

A DLP rule can catch known patterns such as private IPs, e-mail addresses, tokens and confidentiality markers. It cannot prove that encoded, paraphrased or steganographic data is harmless.

The high-assurance architecture therefore relies on capability separation:

1. the process holding confidential data has no egress channel;
2. the process able to request public research has no confidential-data read permission;
3. the process holding a network socket has neither data-store permission nor model/task authority.

This is the security invariant to preserve during future refactors.
