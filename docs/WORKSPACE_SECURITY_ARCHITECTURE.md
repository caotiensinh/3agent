# WorkSpace Confidentiality and Egress Security Architecture

## Security objective

WorkSpace is intended for internal enterprise work where prompts, source files, reports, code, research notes and business information may be confidential.

The design objective is to prevent confidential runtime data from reaching uncontrolled external destinations. Absolute zero-risk claims are not technically defensible under every host compromise, so WorkSpace uses layered controls and removes network capability from the principal that holds confidential data.

## Default policy: no public egress

`config/workspace.secure.json` sets:

```text
confidentiality_mode = confidential
public_search_enabled = false
direct_egress = false
```

Local inference, file processing, artifacts and daily reports continue to function without public Internet access.

## High-assurance Linux trust boundary

### workspace-core

Owns `/var/lib/workspace` and may read confidential task data. nftables blocks all network traffic owned by this UID except loopback TCP/11434–11436 for local Ollama workers. AF_UNIX IPC remains available.

### workspace-egress

Runs `workspace-egressd`. Its OS egress is restricted to the local DNS stub and public TCP/443, while RFC1918/link-local/special-use destinations are rejected; it has no permission to read `/var/lib/workspace`. It accepts narrowly structured requests only from the configured Core UID over `/run/workspace/egress.sock`.

This is intentional privilege separation: the component with data has no Internet; the component with Internet has no data.

## Broker protocol

Accepted actions are only:

1. `search` — research agent only, allowlisted HTTPS search host, allowlisted parameters, DLP-approved public query.
2. `fetch_result` — research agent only, exact URL must have been observed in a recent allowlisted search response.

Not supported:

- arbitrary URL fetch;
- POST/PUT/PATCH/DELETE;
- request body upload;
- cookies;
- Authorization headers;
- user-controlled headers;
- webhooks;
- file upload;
- cloud LLM calls;
- presentation/daily-report Internet access.

## Query DLP

Before a public query can leave the machine, WorkSpace rejects known identifiers/secrets such as private IPs, e-mail addresses, MAC addresses, API/token patterns, UUIDs, local filesystem paths, confidentiality markers, embedded URLs, multiline content and suspicious high-entropy tokens.

This is defense in depth, not magical business-secret detection. An unknown internal codename cannot always be detected automatically. That is why public search is disabled in confidential mode.

## Search-result capability

Arbitrary content URLs are not accepted. The direct broker observes URLs returned by the search engine and issues short-lived exact-URL capabilities internally. A result URL is consumed once. This prevents a model from constructing `https://attacker.example/<secret>` and asking the gateway to fetch it.

## SSRF and redirect controls

- HTTPS only in strict mode;
- port 443 only;
- no URL credentials;
- localhost/.local prohibited;
- every DNS resolution must produce globally routable addresses;
- nftables separately denies egress-UID access to LAN/private/link-local/special-use networks before allowing public TCP/443;
- redirects are revalidated;
- redirect count is bounded;
- response bytes are bounded.

## Minimal audit

Egress logs record:

- timestamp;
- task/agent identity;
- action;
- destination scheme/host/path without query string;
- allow/deny reason;
- query SHA-256 and character count for authorized search.

Search query plaintext is intentionally not logged.

## GitHub and updates

Runtime agents do not autonomously push internal artifacts to GitHub. Repository/software update operations are operator/deployment functions executed outside the confidential Core runtime. No agent receives GitHub credentials by default.

## Relationship to industry guidance

The design follows zero-trust/default-deny principles: explicit authorization, least privilege, segmentation/microsegmentation and egress filtering. CISA guidance recommends restricting Internet traffic from hosts that do not require it and allowlisting specific outbound destinations when needed. NIST Zero Trust guidance emphasizes granular policy enforcement rather than implicit trust from network location.

## Residual risks

- a compromised root/kernel/hypervisor can bypass process separation;
- an administrator can intentionally weaken policy;
- a public query explicitly approved by an operator may itself reveal information;
- local malware running under privileged accounts may access data outside WorkSpace controls;
- side channels are outside the current threat model.

These risks must be handled by enterprise endpoint security, OS hardening, access control, backup, monitoring and physical/administrative controls.
