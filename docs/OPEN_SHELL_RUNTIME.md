# Auctaryn OpenShell Runtime

Auctaryn's runtime adapter is opt-in. It is not a replacement for OpenShell's policy enforcement: Auctaryn authorizes and risk-checks a tool call; OpenShell enforces sandbox filesystem, process, and network restrictions.

Production gateway registration metadata follows NVIDIA OpenShell's current SDK/CLI contract: `gateway_endpoint` in `metadata.json` under the active gateway. See the [Python SDK guide](https://docs.nvidia.com/openshell/dev/sdk/python) and [OpenShell gateway registration script](https://github.com/NVIDIA/OpenShell/blob/main/tasks/scripts/gateway.sh). The production deploy helper accepts the legacy `endpoint` key for compatibility, but requires a valid remote HTTPS URL and rejects localhost, loopback and unspecified addresses. This validates configuration shape only; it does not prove that the live gateway is reachable or enforcing the intended effective policy.

## Restrictive baseline

When the OpenShell adapter is enabled through environment configuration, Auctaryn validates the repository-owned baseline YAML before initializing the SDK client. Startup fails closed if the policy is missing or malformed, Landlock is not set to `hard_requirement`, read/write paths exceed the explicit allowlists, required read-only system paths are missing, or the baseline introduces network rules. The validated source SHA-256 is retained on the adapter for diagnostics.

This is static validation of the checked-in baseline only. It does not prove that the active remote sandbox is enforcing the same effective policy, including provider-composed rules. OpenShell's official policy tooling distinguishes the base policy from the effective policy; operators must inspect the effective policy with `openshell policy get <sandbox> --full` or `openshell sandbox get <sandbox> --policy-only` before production enablement. See [NVIDIA's policy management guide](https://docs.nvidia.com/openshell/dev/how-it-works/policies/manage-policies).

The checked-in policy at `deploy/openshell/auctaryn-policy.yaml`:

- requires Landlock enforcement (`hard_requirement`);
- makes system paths read-only and limits writable paths to the sandbox workspace, temporary storage, and `/dev/null`;
- defines no network allow rules, so outbound access remains denied until an operator explicitly adds reviewed endpoints.

Create the sandbox using a registered, authenticated OpenShell gateway:

```bash
openshell sandbox create --name auctaryn-runtime --policy deploy/openshell/auctaryn-policy.yaml --no-auto-providers
```

Confirm the effective policy and runtime health through the OpenShell CLI before enabling Auctaryn execution. The policy's filesystem rules are static at sandbox creation; changing them requires recreating the sandbox. Network rules are dynamic and can be incrementally updated after review.

## Auctaryn configuration

Enable the adapter only when the active OpenShell CLI context points to the intended authenticated gateway:

- `AUCTARYN_RUNTIME_ADAPTER=openshell`
- `OPENSHELL_SANDBOX_NAME=auctaryn-runtime`
- `OPENSHELL_WORKSPACE=default`
- `OPENSHELL_EXECUTION_TIMEOUT_SECONDS=60` (allowed range: 1–3600)

Production requires the four OpenShell OIDC service-credential settings consumed by `create_openshell_adapter_from_environment()`. The secret is read lazily from the environment. Do not commit credentials or put them in the sandbox policy. `OPENSHELL_ALLOW_USER_CREDENTIALS=true` is for explicitly opted-in local development only.

The adapter supports only `tool_name=openshell_exec`, `action=exec`, and a bounded `parameters.argv` string array. It does not accept a caller-selected sandbox or a shell command string. A supervisor runs inside the sandbox to bound command lifetime and stdout/stderr volume. Receipts include hashes and explicit truncation flags, never raw output.

## Live readiness probe

The OpenShell adapter exposes an asynchronous health probe that calls the active authenticated gateway's health endpoint with a five-second timeout. Both `/health/ready` and `/health/detailed` use the same bounded probe; detailed health reports the OpenShell module as healthy only when it succeeds and returns a non-empty version string. Aggregate detailed health remains degraded while other enabled modules lack registered live probes. Adapter construction alone is not evidence of connectivity. Probe exceptions, missing versions, and timeouts leave readiness false; /health remains a liveness-only endpoint.

CI tests the probe contract with fake clients. It does not prove connectivity to a live deployment. Before production, run the acceptance checks below against the intended OpenShell gateway and sandbox.

## Sensitive data and secrets

Auctaryn's `SensitiveDataGuard` runs before identity/risk processing and before execution. It blocks obvious raw credentials in sensitive parameter fields, common token/key formats, and URLs containing embedded user credentials. Error responses report field paths only, never the detected value.

Values such as `vault://...` and `secret://...` are accepted as opaque references; Auctaryn does not resolve them or inject the underlying secret. A production integration must resolve such references through Tinlance Agent Platform's governed secret mechanism or an OpenShell provider profile, with endpoint-bound access. Never place a raw credential in a tool-call payload, command-line argument, log, or sandbox policy. The guard is defense in depth, not a substitute for a secret broker or DLP system.

## Effective-policy pin verification

After independently reviewing the active policy, capture the effective policy from the intended authenticated gateway:

```bash
openshell sandbox get "$OPENSHELL_SANDBOX_NAME" --policy-only > effective-policy.yaml
sha256sum effective-policy.yaml
```

Review the policy content and digest through the normal change-approval process; do not trust a digest calculated from an unreviewed current policy. Set `AUCTARYN_EXPECTED_EFFECTIVE_POLICY_SHA256` to the approved 64-character digest and run:

```bash
python scripts/verify_openshell_policy.py
```

The verifier calls the documented OpenShell CLI with an argv list, a 10-second timeout and `shell=False`; it fails if the CLI fails or the effective-policy digest differs. Run it in the same authenticated CLI context as the gateway used by Auctaryn's SDK. This is an operator-run drift check, not a live check performed by every API request, and CI cannot run it without an actual gateway.

## Required production acceptance

The repository's CI verifies the adapter contract with a fake client and executes the bounded supervisor wrapper in the CI runner. This is not proof that a live OpenShell gateway, sandbox image, credentials, and effective policy are correctly configured. Before production, run a live integration test against the intended gateway and verify:

1. the authenticated gateway health/version response;
2. sandbox identity and workspace selection;
3. the effective policy is the checked-in or explicitly approved policy revision;
4. filesystem writes outside approved paths fail;
5. unapproved network egress fails;
6. command timeout and output caps are enforced inside the sandbox;
7. an Auctaryn-denied or pending action never reaches OpenShell;
8. an explicitly operator-approved action executes once and yields a correlated receipt.

If gateway initialization or required configuration fails, Auctaryn leaves the runtime adapter disabled and governed execution returns HTTP 503. Do not downgrade Landlock to `best_effort` to make a production deployment start.
