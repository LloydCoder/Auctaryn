# Repository Maintenance Checklist

Use this checklist for routine maintenance and before releases. A checked item means the action was actually performed and evidence was reviewed; it must not be pre-checked in advance.

## Every pull request

- [ ] Review the diff for secrets, sensitive data, and unintended generated artifacts.
- [ ] Run relevant Python tests, lint, dashboard build, and deployment checks.
- [ ] Confirm changed commands and relative documentation links are valid.
- [ ] Review security and authority-boundary impact.
- [ ] Update changelog and configuration/reference docs where behavior changes.
- [ ] Verify the current commit's required CI/security checks before merge.

## Monthly or before a release

- [ ] Review dependency updates and lockfile reproducibility.
- [ ] Review CodeQL, secret scanning, dependency audit, SBOM, and container scan results.
- [ ] Inspect Gitleaks ignore entries and document why each exception remains necessary.
- [ ] Confirm branch protection/rulesets require the intended checks and review policy.
- [ ] Verify private security reporting and conduct-reporting contact routes are monitored.
- [ ] Review issue templates, CODEOWNERS, repository description, homepage, and topics.
- [ ] Run link checks and test the Quick Start from a clean environment.
- [ ] Capture and review a genuine current demo screenshot or short recording; never fabricate visual proof.
- [ ] Reconcile the roadmap, audit index, and final audit with the exact tested commit SHA.
- [ ] For a release, follow [Production Release Acceptance](PRODUCTION_RELEASE_ACCEPTANCE.md), verify release evidence and attestations, and publish only after required gates pass.

## Release record

For every release, record the tag, source commit, tested commit, CI/security workflow run URLs, dependency/SBOM evidence, container digest and attestations where applicable, known limitations, rollback plan, and operator approval. Do not infer successful results from workflow definitions or historical reports.

## Repository About settings

Recommended GitHub description:

> Defense-in-depth context integrity and advisory risk assessment for supported AI-agent execution paths.

Homepage: keep the repository URL until a canonical public documentation or product URL is explicitly approved.

Suggested topics (select only those that accurately describe the current project): `ai-agents`, `agent-security`, `runtime-security`, `python`, `fastapi`, `llm-security`, `supply-chain-security`, `openshell`, `threat-modeling`, `tinlance`.

Do not add a production, compliance, certification, or universal-interception claim to the description or topics unless independently supported by evidence.
