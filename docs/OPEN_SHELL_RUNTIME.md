# Auctaryn OpenShell Runtime

Auctaryn's runtime adapter is opt-in. It is not a replacement for OpenShell's policy enforcement: Auctaryn authorizes and risk-checks a tool call; OpenShell enforces sandbox filesystem, process, and network restrictions.

## Restrictive baseline

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

## Sensitive data and secrets

Auctaryn's `SensitiveDataGuard` runs before identity/risk processing and before execution. It blocks obvious raw credentials in sensitive parameter fields, common token/key formats, and URLs containing embedded user credentials. Error responses report field paths only, never the detected value.

Values such as `vault://...` and `secret://...` are accepted as opaque references; Auctaryn does not resolve them or inject the underlying secret. A production integration must resolve such references through Tinlance Agent Platform's governed secret mechanism or an OpenShell provider profile, with endpoint-bound access. Never place a raw credential in a tool-call payload, command-line argument, log, or sandbox policy. The guard is defense in depth, not a substitute for a secret broker or DLP system.

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
