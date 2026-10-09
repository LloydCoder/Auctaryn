# Security Policy

Report suspected vulnerabilities privately. Do not publish unpatched vulnerability details in GitHub Issues or pull requests.

## Supported versions

Until a formal support matrix and tagged release series are published, reports are evaluated against the latest code on the default branch. No maintenance commitment is implied for older commits, forks, or untagged snapshots.

## Reporting

Email **security@tinlance.com** with subject `[Auctaryn Security]`. Include the affected commit/file/endpoint, impact, reproduction steps, required preconditions, and known mitigations where safe. Do not send live credentials, private keys, customer data, or unnecessary personal information.

If email is unsuitable, use a private GitHub security-reporting channel if one is enabled for this repository.

## Response targets

The maintainer aims to acknowledge reports within **five business days** and provide an initial triage/status update within **ten business days**. These are targets, not guarantees or a remediation SLA. Severity, reproducibility, complexity, and maintainer availability can affect timelines. Accepted reports will be handled with a view to a fix, regression coverage, and coordinated disclosure.

## Scope

Relevant areas include authentication and authorization, tenant/session binding, gateway enforcement, runtime adapters, evidence integrity, secret handling, dependency/supply-chain controls, and security-sensitive API behavior.

Auctaryn does not claim universal agent-action interception. Caller-supplied metadata is not proof of runtime observation. Reports should identify the actual integration path and available evidence.

Act in good faith, avoid privacy violations and disruption, and give the maintainer a reasonable opportunity to investigate. This policy does not authorize access to systems or data outside your control.
