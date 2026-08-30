# WorkSpace Security Analyst & Network Monitoring — Research Review Checklist v1

Before any production code is merged, reviewers should confirm:

- the project is not attempting to embed a full heavy SIEM stack by default;
- hourly polling is known-inventory read-only monitoring, not unrestricted network scanning;
- full PCAP is denied by default;
- bandwidth calculation prefers counters over payload capture;
- raw logs remain untrusted data;
- AI is downstream of deterministic normalization/detection;
- healthy hourly cycle requires zero AI calls;
- report has deterministic fallback;
- approved inventory remains separate from observed state;
- secrets are outside prompts/config/logs;
- NAS is a mounted filesystem target, not an application credential store;
- scheduled execution is deterministic and auditable;
- security controls remain runtime policy, not optional skills;
- NS-0/NS-1 are implemented before advanced sensors/ML;
- every new external dependency has a measured benefit and an independent admission review.
